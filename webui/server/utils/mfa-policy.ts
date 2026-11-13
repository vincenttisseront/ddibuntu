// MFA obligatoire par rôle (0.9.52). Réglage COMMUN au cluster (table « settings », clé « mfa_policy »), lu avec 15 s de cache.
// Ne concerne que les comptes LOCAUX : les comptes AD / LDAP / SSO relèvent du second facteur de leur fournisseur ; les jetons d'API n'ont pas de session.
// Un compte concerné sans second facteur garde une session, mais celle-ci est limitée à l'inscription (voir ENROL_PATHS) jusqu'à l'activation.
import { getSetting, one, setSetting } from './db'

export const MFA_ROLES = ['admin', 'operator', 'viewer'] as const
export type MfaRole = (typeof MFA_ROLES)[number]
export interface MfaPolicy { roles: MfaRole[] }
export const MFA_POLICY_DEFAULT: MfaPolicy = { roles: [] }
/** Seules routes ouvertes à une session dont l'inscription au second facteur reste à faire. */
export const ENROL_PATHS = new Set(['/auth/me', '/auth/logout', '/auth/profile', '/auth/mfa', '/auth/mfa/setup', '/auth/mfa/enable', '/health'])

/** Relecture stricte : tout ce qui n'est pas un rôle connu est ignoré, doublons retirés, ordre fixe. */
export function parseMfaPolicy(raw: unknown): MfaPolicy {
  const r = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>).roles : null
  const set = new Set(Array.isArray(r) ? r : [])
  return { roles: MFA_ROLES.filter((x) => set.has(x)) }
}
/** Fonction pure : ce compte doit-il encore s'inscrire ? */
export function enrolRequired(u: { source: string; role: string; totpEnabled: boolean }, p: MfaPolicy): boolean {
  return u.source === 'local' && !u.totpEnabled && (p.roles as string[]).includes(u.role)
}

let cache: { at: number; v: MfaPolicy } | null = null
export async function mfaPolicy(): Promise<MfaPolicy> {
  const now = Date.now()
  if (cache && now - cache.at < 15000) return cache.v
  let raw: unknown = null
  try { raw = await getSetting<unknown>('mfa_policy', null) } catch { raw = null }
  cache = { at: now, v: parseMfaPolicy(raw) }
  return cache.v
}
export async function saveMfaPolicy(p: MfaPolicy): Promise<void> { await setSetting('mfa_policy', p); cache = null }
export const _resetMfaPolicyCache = () => { cache = null }

/** Vrai si l'utilisateur de la session doit encore activer son second facteur (une requête seulement si la politique le concerne). */
export async function mfaEnrolPending(u: { id: number; source: string; role: string }): Promise<boolean> {
  if (u.source !== 'local') return false
  const p = await mfaPolicy()
  if (!(p.roles as string[]).includes(u.role)) return false
  const r = await one<any>('select totp_enabled from users where id = $1', [u.id]).catch(() => null)
  return !!r && enrolRequired({ source: u.source, role: u.role, totpEnabled: !!r.totp_enabled }, p)
}
