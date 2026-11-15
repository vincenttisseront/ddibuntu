// Garde-fou d'activation de l'authentification par annuaire (AD / LDAP) : on ne peut l'activer que si la connexion de service a réussi
// avec EXACTEMENT les réglages de connexion enregistrés. Toute modification de la connexion (serveurs, DN, mot de passe, TLS, CA) exige un nouveau test.
// Les installations où l'authentification est déjà active ne sont pas coupées : seule une modification de la connexion redemande un test.
import { createHash } from 'node:crypto'
import { getSetting, setSetting } from './db'

export type AuthKind = 'ad' | 'ldap'
interface Conn { enabled?: boolean; urls?: string[]; baseDn?: string; bindDn?: string; bindPasswordEnc?: string; tlsRejectUnauthorized?: boolean; caPem?: string }

export const connFingerprint = (s: Conn): string =>
  createHash('sha256').update(JSON.stringify([s.urls ?? [], s.baseDn ?? '', s.bindDn ?? '', s.bindPasswordEnc ?? '', s.tlsRejectUnauthorized !== false, (s.caPem ?? '').trim()])).digest('hex')

/** Enregistre que la connexion de service fonctionne avec ces réglages (appelé après une liaison réussie). */
export async function markVerified(kind: AuthKind, s: Conn): Promise<void> { await setSetting(`${kind}_verified`, { fp: connFingerprint(s), at: Math.floor(Date.now() / 1000) }) }
export async function isVerified(kind: AuthKind, s: Conn): Promise<boolean> {
  const v = await getSetting<{ fp?: string } | null>(`${kind}_verified`, null)
  return !!v && v.fp === connFingerprint(s)
}
/** Activation permise : connexion testée avec ces réglages, ou déjà active avec une connexion inchangée. Test uniquement : DDI_ALLOW_UNVERIFIED_AUTH=1. */
export async function mayEnable(kind: AuthKind, cur: Conn, next: Conn): Promise<boolean> {
  if (process.env.DDI_ALLOW_UNVERIFIED_AUTH === '1') return true
  if (cur.enabled && connFingerprint(cur) === connFingerprint(next)) return true
  return isVerified(kind, next)
}
