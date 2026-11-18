// Service PKI (0.14.0) : EJBCA Community dans un conteneur Podman, piloté par root (ddibuntu-pki). La console ne démarre rien et ne touche à aucune
// configuration système : elle dépose .pki-request (une demande JSON courte : image, nom public, réseaux) que root revalide champ par champ, puis
// elle lit l'état et le résultat que root publie. Aucun secret ne transite par ici : root crée lui-même les secrets de l'instance.
import { promises as fs } from 'node:fs'
import os from 'node:os'
import { join } from 'node:path'
import { z } from 'zod'
import { cfg } from './config'
import { getSetting, setSetting } from './db'
import { cidrToString, parseCidr, parseIp } from './net'
import { pkiUpdateRunning } from './pki-update'
import { fail } from './router'
import type { Cidr } from './net'

export const IMAGE_REPO = 'docker.io/keyfactor/ejbca-ce'
/** Version d'EJBCA Community installée par défaut (dernière version publiée vérifiée avec le DDI). La mise à jour d'une instance existante a son propre parcours (0.14.5). */
export const DEFAULT_VERSION = '9.6.3'
/** Port public d'EJBCA (CRL, SCEP, OCSP) : gravé dans les certificats avec le nom public, il ne change donc jamais. */
export const PUBLIC_PORT = 8080
export const MAX_NETS = 64
export const VERSION_RE = /^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}$/
/** Nom public : au moins deux étiquettes, minuscules, chiffres et tirets, 253 caractères au plus, dernière étiquette non numérique (jamais une adresse IP). Mêmes bornes que root. */
export const HOST_RE = /^(?=.{3,253}$)(?!.*\.[0-9]+$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

export const imageOf = (version: string) => `${IMAGE_REPO}:${version}`

/** Réseau ou adresse d'un client de la PKI → réseau normalisé, ou null. Pas de /0 (même règle que le pare-feu). */
export function normPkiNet(raw: string): string | null {
  const v = raw.trim()
  if (!v || v.length > 64) return null
  let c: Cidr | null
  if (v.includes('/')) c = parseCidr(v)
  else { const ip = parseIp(v); c = ip ? { v: ip.v, n: ip.n, prefix: ip.v === 4 ? 32 : 128 } : null }
  if (!c || c.prefix === 0) return null
  return cidrToString(c)
}

export const applyBody = z.object({
  hostname: z.string().trim().toLowerCase().regex(HOST_RE),
  version: z.string().trim().regex(VERSION_RE).default(DEFAULT_VERSION),
  nets: z.array(z.string().trim().max(64)).max(MAX_NETS).default([]),
}).strict().transform((b, ctx) => {
  const nets: string[] = []
  for (const [i, raw] of b.nets.entries()) {
    const n = normPkiNet(raw)
    if (!n) { ctx.addIssue({ code: 'custom', path: ['nets', i], message: 'net' }); return z.NEVER }
    if (!nets.includes(n)) nets.push(n)
  }
  return { hostname: b.hostname, version: b.version, nets }
})
export type ApplyBody = z.infer<typeof applyBody>

// ---- Réglages (choix de l'administrateur, conservés même avant l'installation) ----
export interface PkiSettings { hostname: string; version: string; nets: string[] }
export const PKI_KEY = 'pki_settings'
export const PKI_DEFAULTS: PkiSettings = { hostname: '', version: DEFAULT_VERSION, nets: [] }
export const loadPkiSettings = async (): Promise<PkiSettings> => ({ ...PKI_DEFAULTS, ...(await getSetting<PkiSettings>(PKI_KEY, PKI_DEFAULTS)) })
export const savePkiSettings = (s: PkiSettings) => setSetting(PKI_KEY, s)

/** Nom public proposé : « pki. » + domaine du nœud (domaine de recherche du système, sinon celui du nom d'hôte). Vide si introuvable. */
export async function suggestHostname(): Promise<string> {
  const norm = (d: string) => d.trim().toLowerCase().replace(/\.$/, '')
  const ok = (d: string) => HOST_RE.test(`pki.${d}`)
  try {
    const m = /^(?:search|domain)\s+(\S+)/m.exec(await fs.readFile('/etc/resolv.conf', 'utf8'))
    if (m && ok(norm(m[1]!))) return `pki.${norm(m[1]!)}`
  } catch { /* fichier illisible : on essaie le nom d'hôte */ }
  const h = norm(os.hostname()), dot = h.indexOf('.')
  if (dot > 0 && ok(h.slice(dot + 1))) return `pki.${h.slice(dot + 1)}`
  return ''
}

/** Adresses IPv4 de ce nœud (hors bouclage et lien local) : proposées pour l'enregistrement DNS du nom public. */
export function nodeAddresses(): string[] {
  const out: string[] = []
  for (const list of Object.values(os.networkInterfaces())) for (const a of list ?? []) {
    if (a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.') && !out.includes(a.address)) out.push(a.address)
  }
  return out
}

// ---- Dépôt de la demande et lecture de l'état publié par root ----
export type PkiState = 'absent' | 'starting' | 'healthy' | 'unhealthy' | 'stopped'
export const STATES: readonly PkiState[] = ['absent', 'starting', 'healthy', 'unhealthy', 'stopped']
export interface PkiStatus {
  at: number; podman: boolean; installed: boolean; active: boolean; state: PkiState; hostname: string; version: string; digest: string; nets: string[]; health: string; port: number
  /** La base « ejbca » contient des données (même si le conteneur est désinstallé), nom public de ces données, nombre d'autorités avec clé, et remise à zéro permise. */
  dataPresent: boolean; secretsPresent: boolean; dataHostname: string; casCount: number | null; resetAllowed: boolean
  /** Clé de récupération (0.14.5) : certificat PUBLIC enregistré par root ; la clé privée correspondante n'est jamais sur l'appliance. null = aucune. */
  recovery: PkiRecovery | null
}
export interface PkiRecovery { fingerprint: string; bits: number; notAfter: number; subject: string; registeredAt: number }
/** `ref` : identifiant de la demande d'émission à laquelle ce résultat répond (root le recopie ; vide pour les autres actions). */
export interface PkiResult { at: number; action: string; ok: boolean; message: string; ref?: string }

export function parseRecovery(r: any): PkiRecovery | null {
  if (!r || typeof r !== 'object' || !/^[0-9a-f]{64}$/.test(r.fingerprint ?? '')) return null
  const n = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : 0)
  return { fingerprint: r.fingerprint, bits: n(r.bits), notAfter: n(r.notAfter), subject: String(r.subject ?? '').replace(/[^\x20-\x7e]/g, '').slice(0, 100), registeredAt: n(r.registeredAt) }
}
export async function readPkiStatus(): Promise<PkiStatus | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().pkiStatusFile, 'utf8'))
    if (typeof j?.at !== 'number') return null
    const state = STATES.includes(j.state) ? (j.state as PkiState) : 'absent'
    return { at: j.at, podman: j.podman === true, installed: j.installed === true, active: j.active === true, state,
      hostname: String(j.hostname ?? '').slice(0, 253), version: String(j.version ?? '').slice(0, 24), digest: String(j.digest ?? '').slice(0, 80),
      nets: (Array.isArray(j.nets) ? j.nets : []).slice(0, MAX_NETS).map((x: unknown) => String(x).slice(0, 64)), health: String(j.health ?? '').slice(0, 64),
      port: Number(j.port) || PUBLIC_PORT, dataPresent: j.dataPresent === true, secretsPresent: j.secretsPresent === true, dataHostname: String(j.dataHostname ?? '').slice(0, 253),
      casCount: Number.isInteger(j.casCount) && j.casCount >= 0 ? j.casCount : null, resetAllowed: j.resetAllowed === true, recovery: parseRecovery(j.recovery) }
  } catch { return null }
}
/** PKI et cluster, vus de CE nœud (écrits par « ddibuntu-pki align », chaque minute) : rôle, unité, image de secours, consigne d'arrêt, blocage éventuel. */
export interface PkiClusterLocal {
  at: number; ageSeconds: number; stale: boolean
  role: 'leader' | 'replica' | 'unknown'; installed: boolean; unit: 'active' | 'inactive'; image: 'none' | 'ready' | 'pulling' | 'missing'
  desired: 'running' | 'stopped'; version: string
  blocked: { reason: 'update-interrupted' | 'cluster-unreachable'; node?: string; at?: number; from?: string; to?: string } | null
}
export function parsePkiClusterLocal(raw: string, nowSec = Date.now() / 1000): PkiClusterLocal | null {
  let j: any
  try { j = JSON.parse(raw) } catch { return null }
  if (!j || typeof j !== 'object' || typeof j.at !== 'number' || !Number.isFinite(j.at)) return null
  const age = Math.max(0, Math.round(nowSec - j.at))
  const b = j.blocked
  const blocked = b && typeof b === 'object' && (b.reason === 'update-interrupted' || b.reason === 'cluster-unreachable')
    ? { reason: b.reason as 'update-interrupted' | 'cluster-unreachable', ...(typeof b.node === 'string' && /^[a-z][a-z0-9-]{1,30}$/.test(b.node) ? { node: b.node } : {}),
        ...(Number.isFinite(b.at) ? { at: Math.trunc(b.at) } : {}), ...(typeof b.from === 'string' ? { from: b.from.replace(/[^0-9A-Za-z._-]/g, '').slice(0, 40) } : {}),
        ...(typeof b.to === 'string' ? { to: b.to.replace(/[^0-9A-Za-z._:/@-]/g, '').slice(0, 60) } : {}) } : null
  return {
    at: Math.trunc(j.at), ageSeconds: age, stale: age > 180, role: j.role === 'leader' || j.role === 'replica' ? j.role : 'unknown', installed: j.installed === true,
    unit: j.unit === 'active' ? 'active' : 'inactive', image: j.image === 'ready' || j.image === 'pulling' || j.image === 'missing' ? j.image : 'none',
    desired: j.desired === 'stopped' ? 'stopped' : 'running', version: typeof j.version === 'string' && /^[0-9.]{0,20}$/.test(j.version) ? j.version : '', blocked,
  }
}
export async function readPkiClusterLocal(): Promise<PkiClusterLocal | null> {
  try {
    const f = cfg().pkiClusterFile
    const st = await fs.stat(f)
    if (!st.isFile() || st.size > 16 * 1024) return null
    return parsePkiClusterLocal(await fs.readFile(f, 'utf8'))
  } catch { return null }
}
export async function readPkiResult(): Promise<PkiResult | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().pkiResultFile, 'utf8'))
    if (typeof j?.at !== 'number') return null
    return { at: j.at, action: String(j.action ?? '').slice(0, 24), ok: j.ok === true, message: String(j.message ?? '').slice(0, 300), ...(typeof j.ref === 'string' && /^[0-9a-f]{16}$/.test(j.ref) ? { ref: j.ref } : {}) }
  } catch { return null }
}
export async function pkiRequestPending(): Promise<boolean> {
  try { await fs.lstat(join(cfg().generatedDir, '.pki-request')); return true } catch { return false }
}
export interface CaDn { cn: string; ou?: string; o?: string; c?: string }
export type PkiRequest =
  | { action: 'apply'; image: string; hostname: string; nets: string[] }
  | { action: 'start' | 'stop' | 'restart' | 'status' | 'uninstall' | 'reset' | 'recovery_set' | 'update_check' | 'update_validate' | 'update_rollback' }
  | { action: 'update_apply'; image: string }
  | ({ action: 'ca_root'; name: string; alg: string; days: number } & CaDn)
  | ({ action: 'ca_issuing'; name: string; alg: string; days: number; signedBy: string } & CaDn)
  | { action: 'ca_import' | 'ca_import_p12' | 'ca_crl' | 'ca_rootcrl'; name: string }
  | ({ action: 'cert_issue'; id: string; ca: string; profile: string; dns?: string[]; ip?: string[]; mail?: string[]; upn?: string[] } & CaDn)
  | { action: 'cert_revoke'; ca: string; serial: string; reason: number }
  | { action: 'scep_enable' | 'scep_disable' }
  | ({ action: 'scep_offer'; id: string; ca: string; profile: string; dns?: string[]; ip?: string[]; mail?: string[]; upn?: string[] } & CaDn)
  | { action: 'scep_rearm'; id: string; cn: string }
  | { action: 'scep_cancel'; cn: string }
export async function depositPkiRequest(req: PkiRequest): Promise<{ requestedAt: number }> {
  // 0.14.7 : pendant une mise à jour (le conteneur est arrêté puis relancé), aucune autre demande n'est déposée : elle attendrait le verrou de root, puis agirait sur une PKI qui a changé
  if (await pkiUpdateRunning()) fail(409, 'pki_update_running')
  await fs.writeFile(join(cfg().generatedDir, '.pki-request'), JSON.stringify(req) + '\n', { mode: 0o640 })
  return { requestedAt: Math.floor(Date.now() / 1000) }
}
