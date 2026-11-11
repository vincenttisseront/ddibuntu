// Vues DNS : validation des listes de clients, ordre d'évaluation (première vue dont la liste correspond) et contrôle de couverture.
// Aucune dépendance base de données : tout ce qui est ici se teste sans serveur.
import { cidrContainsIp, cidrToString, normIp, parseCidr, parseIp } from './net'
import type { Ip } from './net'

export const VIEW_NAME_RE = /^[a-z][a-z0-9-]{0,30}$/
export const MAX_VIEWS = 16
export const MAX_ACL = 50
const KEYWORDS = new Set(['any', 'none', 'localhost', 'localnets'])

export interface ViewInfo { id: number; name: string; position: number; match_clients: string[]; match_destinations: string[]; recursion: boolean }

/** Élément de liste d'adresses : any · none · localhost · localnets · IP · réseau CIDR, éventuellement précédé de « ! ». Renvoie la forme normalisée ou null. */
export function normalizeAclToken(raw: string): string | null {
  let t = raw.trim().toLowerCase(), neg = ''
  if (t.startsWith('!')) { neg = '!'; t = t.slice(1).trim() }
  if (KEYWORDS.has(t)) return neg && (t === 'any' || t === 'none') ? null : neg + t   // « !any » n'a aucun sens
  const ip = normIp(t); if (ip) return neg + ip
  const c = parseCidr(t); return c ? neg + cidrToString(c) : null
}
export function normalizeAcl(list: string[]): string[] | null {
  if (list.length > MAX_ACL) return null
  const out: string[] = []
  for (const x of list) { const n = normalizeAclToken(x); if (!n) return null; out.push(n) }
  return out
}

const LOCAL = ['127.0.0.1', '::1'].map((x) => parseIp(x)!)
/** Première correspondance gagne (comme BIND) : true / false (exclu par « ! ») / null (aucun élément ne correspond). */
export function aclDecision(acl: string[], ip: Ip, localNets: Ip[] = []): boolean | null {
  for (const e of acl) {
    const neg = e.startsWith('!'), t = neg ? e.slice(1) : e
    let hit = false
    if (t === 'any') hit = true
    else if (t === 'none') hit = false
    else if (t === 'localhost') hit = LOCAL.some((l) => l.v === ip.v && l.n === ip.n)
    else if (t === 'localnets') hit = localNets.some((l) => l.v === ip.v && l.n === ip.n)
    else {
      const one = parseIp(t)   // adresse seule (sans préfixe)
      if (one) hit = one.v === ip.v && one.n === ip.n
      else { const c = parseCidr(t); hit = !!c && c.v === ip.v && cidrContainsIp(c, ip) }
    }
    if (hit) return !neg
  }
  return null
}
/** Vue qui répond à ce client (ordre de position) ; null = aucune : BIND refuse la requête. */
export function viewForClient(views: ViewInfo[], ip: Ip): ViewInfo | null {
  for (const v of [...views].sort((a, b) => a.position - b.position)) if (aclDecision(v.match_clients, ip) === true) return v
  return null
}
/** Le serveur doit pouvoir se résoudre lui-même (127.0.0.1 et ::1) : sinon contrôles de santé, journaux et mises à jour dynamiques locales échouent. */
export function uncoveredLocal(views: ViewInfo[]): string[] {
  return LOCAL.filter((ip) => !viewForClient(views, ip)).map((ip) => (ip.v === 4 ? '127.0.0.1' : '::1'))
}
/** Vues dont la liste est entièrement masquée par une vue précédente « any » : jamais atteintes. */
export function shadowedViews(views: ViewInfo[]): string[] {
  const s = [...views].sort((a, b) => a.position - b.position), out: string[] = []
  let seenAny = false
  for (const v of s) { if (seenAny) out.push(v.name); if (v.match_clients.includes('any') && !v.match_destinations.length) seenAny = true }
  return out
}
