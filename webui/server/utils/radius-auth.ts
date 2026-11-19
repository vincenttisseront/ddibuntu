// Identifiant et mot de passe (0.16.0) : PEAP-MSCHAPv2 (postes Windows et mobiles, compte AD) et EAP-TTLS/PAP (liaison LDAPS de l'utilisateur). Les deux sont
// DÉSACTIVÉES par défaut : seul EAP-TLS (certificat) est actif tant qu'un administrateur n'a rien choisi. Les mêmes règles d'accès s'appliquent aux trois méthodes.
// PEAP-MSCHAPv2 exige que l'appliance soit jointe au domaine (compte machine propre à chaque nœud) : la jonction se fait par une demande à root (voir radius-join).
import { z } from 'zod'
import { getSetting, setSetting } from './db'

export interface AuthSettings { peap: boolean; ttls: boolean; netbios: string }
export const AUTH_DEFAULTS: AuthSettings = { peap: false, ttls: false, netbios: '' }
export const AUTH_KEY = 'radius_auth'
/** Nom NetBIOS du domaine (« AR-SYSTEMS ») : 15 caractères au plus, comme le contrôle de root. */
export const NETBIOS_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,14}$/

export const authBody = z.object({
  peap: z.boolean(), ttls: z.boolean(),
  netbios: z.string().trim().max(15).refine((v) => v === '' || NETBIOS_RE.test(v), 'netbios'),
}).strict()

/** Lecture tolérante : une valeur absente ou abîmée retombe sur « désactivé ». */
export function normAuth(x: unknown): AuthSettings {
  const o = (x && typeof x === 'object' ? x : {}) as Record<string, unknown>
  const nb = typeof o.netbios === 'string' && NETBIOS_RE.test(o.netbios) ? o.netbios : ''
  return { peap: o.peap === true, ttls: o.ttls === true, netbios: nb }
}
export const loadAuth = async (): Promise<AuthSettings> => normAuth(await getSetting<unknown>(AUTH_KEY, AUTH_DEFAULTS))
export const saveAuth = (a: AuthSettings) => setSetting(AUTH_KEY, a)
export const passwordMethods = (a: AuthSettings) => a.peap || a.ttls

/** auth.json déposé pour root, ou undefined quand rien n'est activé (EAP-TLS seulement : le dépôt reste identique à celui de la 0.15). */
export function authJson(a: AuthSettings): string | undefined {
  if (!passwordMethods(a) && !a.netbios) return undefined
  return JSON.stringify({ peap: a.peap, ttls: a.ttls, ...(a.netbios ? { netbios: a.netbios } : {}) }) + '\n'
}
