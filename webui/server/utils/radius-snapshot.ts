// RADIUS actif / passif dans le cluster (0.15.0) : RADIUS ne tourne que sur le leader, derrière l'adresse virtuelle. Les réglages et les secrets sont déjà dans la
// base répliquée ; ce qui manque au nouveau leader, c'est CE QUI A ÉTÉ DÉPLOYÉ (les réglages en cours d'édition ne doivent pas partir en production à la bascule).
// On garde donc, chiffrée comme les autres secrets de la console, la dernière demande « apply » que root a ACCEPTÉE ; la console du nouveau leader la rejoue.
// Ce fichier ne contient que de la logique pure (testée sans base ni disque) ; l'orchestration est dans radius-follow.ts.
import { decryptSecret, encryptSecret } from './auth'
import type { ClusterState } from './cluster'
import type { AuthzDeposit, RadiusRequest, RadiusResult, RadiusStatus } from './radius'
import type { PkiDeposit } from './radius-pki'

export type ApplyRequest = Extract<RadiusRequest, { action: 'apply' }>
/** Dernière reprise automatique : ok = null tant que root n'a pas répondu. */
export interface Attempt { at: number; ok: boolean | null; message: string }
export interface Pending { kind: 'apply' | 'stop'; enc?: string; at: number; auto: boolean; prev: string }   // prev : le dernier résultat de root AVANT le dépôt (une réponse identique est l'ancienne, pas la nôtre)
export interface SnapshotState {
  deployed: string | null    // dernière demande « apply » acceptée par root (JSON chiffré) ; null : rien de déployé ou service arrêté volontairement
  pending: Pending | null    // demande déposée, réponse de root pas encore lue
  follow: Attempt | null     // dernière reprise automatique par ce nœud
}
export const EMPTY_SNAPSHOT: SnapshotState = { deployed: null, pending: null, follow: null }
export const SNAPSHOT_KEY = 'radius_snapshot'
export const PENDING_TIMEOUT_S = 600     // sans réponse de root au bout de 10 minutes, la demande est abandonnée
export const RETRY_AFTER_S = 300         // deux reprises automatiques sont toujours séparées d'au moins 5 minutes
export const BUSY_S = 90                 // tant que root n'a pas répondu (90 s au plus), un nouveau dépôt est refusé : sa réponse ne serait pas attribuable
const MAX_CLIENTS_CHARS = 1_048_576

const isStr = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max

/** Empreinte d'un résultat de root : sert à reconnaître l'ancien résultat quand il porte la même seconde que la nouvelle demande. */
export const resultKey = (r: RadiusResult | null): string => (r ? `${r.at}|${r.action}|${r.ok ? 1 : 0}|${r.message}` : '')
/** Une demande attend encore la réponse de root. */
export const snapshotBusy = (s: SnapshotState, now: number): boolean => !!s.pending && now - s.pending.at < BUSY_S

export function sealApply(req: ApplyRequest): string { return encryptSecret(JSON.stringify(req)) }

/** Relit une demande chiffrée ; null si elle est illisible ou n'a pas la forme attendue (une valeur de la base n'est jamais crue sur parole). */
export function openApply(enc: string | null | undefined): ApplyRequest | null {
  if (!enc) return null
  let j: any
  try { j = JSON.parse(decryptSecret(enc)) } catch { return null }
  if (!j || typeof j !== 'object' || j.action !== 'apply' || !isStr(j.clients, MAX_CLIENTS_CHARS)) return null
  const out: ApplyRequest = { action: 'apply', clients: j.clients }
  if (j.pki !== undefined) {
    const p = j.pki
    if (!p || typeof p !== 'object' || typeof p.checkCrl !== 'boolean' || !isStr(p.ca, 200_000) || !isStr(p.server, 100_000) || !isStr(p.key, 20_000)) return null
    const crls: Record<string, string> = {}
    if (p.crls && typeof p.crls === 'object') for (const [k, v] of Object.entries(p.crls)) { if (/^[A-Za-z0-9._-]{1,64}\.pem$/.test(k) && isStr(v, 2_000_000)) crls[k] = v }
    out.pki = { checkCrl: p.checkCrl, ca: p.ca, server: p.server, key: p.key, crls } satisfies PkiDeposit
  }
  if (j.authz !== undefined) {
    const a = j.authz
    if (!out.pki || !a || typeof a !== 'object' || !isStr(a.rules, 2_000_000) || !isStr(a.ldap, 100_000) || (a.caPem !== undefined && !isStr(a.caPem, 200_000)) || (a.auth !== undefined && !isStr(a.auth, 4096))) return null
    out.authz = { rules: a.rules, ldap: a.ldap, ...(a.caPem !== undefined ? { caPem: a.caPem } : {}), ...(a.auth !== undefined ? { auth: a.auth } : {}) } satisfies AuthzDeposit
  }
  return out
}

/** Valeur lue dans la base → état sûr (les champs inattendus sont ignorés). */
export function parseSnapshot(v: unknown): SnapshotState {
  const j: any = v && typeof v === 'object' ? v : {}
  const at = (x: any) => (Number.isFinite(x?.at) ? Math.floor(x.at) : 0)
  const p = j.pending
  const pending: Pending | null = p && (p.kind === 'apply' || p.kind === 'stop') && at(p) > 0
    ? { kind: p.kind, ...(typeof p.enc === 'string' ? { enc: p.enc } : {}), at: at(p), auto: p.auto === true, prev: typeof p.prev === 'string' ? p.prev.slice(0, 400) : '' } : null
  const f = j.follow
  const follow: Attempt | null = f && at(f) > 0 ? { at: at(f), ok: f.ok === true ? true : f.ok === false ? false : null, message: String(f.message ?? '').slice(0, 300) } : null
  return { deployed: typeof j.deployed === 'string' && j.deployed ? j.deployed : null, pending, follow }
}

/** Fait avancer l'état avec la réponse de root : demande acceptée → c'est le nouveau « déployé » ; refusée → l'ancien reste ; sans réponse trop longtemps → abandon. */
export function reconcile(s: SnapshotState, result: RadiusResult | null, now: number): SnapshotState {
  const p = s.pending
  if (!p) return s
  const answered = !!result && result.action === p.kind && result.at >= p.at && resultKey(result) !== p.prev
  if (!answered && now - p.at <= PENDING_TIMEOUT_S) return s
  const follow: Attempt | null = p.auto ? { at: p.at, ok: answered ? result!.ok : false, message: answered ? result!.message : "aucune réponse de root (demande abandonnée)" } : s.follow
  if (answered && result!.ok) return { deployed: p.kind === 'apply' ? (p.enc ?? s.deployed) : null, pending: null, follow }
  return { deployed: s.deployed, pending: null, follow }
}

export interface FollowInput {
  cluster: ClusterState | null
  recovery: boolean            // la base locale est une réplique : ce nœud n'est pas le leader
  state: SnapshotState
  status: RadiusStatus | null
  requestPending: boolean      // une demande attend déjà root
  now: number
}
/** Ce nœud doit-il rejouer le dernier déploiement ? Seulement le leader d'un cluster, quand rien ne tourne alors que quelque chose a été déployé. */
export function followDecision(i: FollowInput): { act: boolean; reason: string } {
  const no = (reason: string) => ({ act: false, reason })
  if (!i.cluster) return no('hors cluster')
  if (i.cluster.nodeRole !== 'data') return no('arbitre')
  if (i.recovery || i.cluster.localRole !== 'leader') return no('ce nœud n\'est pas le leader')
  if (!i.state.deployed) return no('rien de déployé')
  if (i.requestPending || i.state.pending) return no('demande en cours')
  if (!i.status) return no('état du service inconnu')
  if (!i.status.installed) return no('freeradius n\'est pas installé sur ce nœud')
  if (i.status.active) return no('le service tourne')
  if (i.state.follow && i.now - i.state.follow.at < RETRY_AFTER_S) return no('dernier essai trop récent')
  return { act: true, reason: 'le service ne tourne pas sur le leader' }
}
