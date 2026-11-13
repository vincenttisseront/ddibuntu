// Authentification par annuaire LDAP générique (OpenLDAP, FreeIPA, 389-ds, Samba…), en complément d'Active Directory (ad.ts).
// Principe : liaison de service → recherche de l'utilisateur (filtre à gabarit) → groupes (attribut memberOf OU recherche de groupes) →
// liaison avec le mot de passe de l'utilisateur sur une connexion distincte. Le mot de passe de liaison n'est jamais renvoyé ni journalisé.
import { delegatedSpaces, escapeFilter } from './ad'
import type { LdapLike } from './ad'
import type { Role } from './auth'

export interface LdapSettings {
  enabled: boolean; urls: string[]; baseDn: string; bindDn: string; bindPasswordEnc?: string
  userFilter: string                  // gabarit : {u} = identifiant saisi (échappé)
  userAttr: string; displayAttr: string
  groupMode: 'memberOf' | 'search'
  groupBaseDn: string; groupFilter: string   // mode « search » : gabarit avec {dn} et/ou {u}
  groupMap: Array<{ groupDn: string; role: Role; spaceIds?: number[] }>
  tlsRejectUnauthorized: boolean; caPem?: string
}
export const LDAP_DEFAULTS: LdapSettings = {
  enabled: false, urls: [], baseDn: '', bindDn: '', userFilter: '(&(objectClass=inetOrgPerson)(uid={u}))', userAttr: 'uid', displayAttr: 'cn',
  groupMode: 'memberOf', groupBaseDn: '', groupFilter: '(&(objectClass=groupOfNames)(member={dn}))', groupMap: [], tlsRejectUnauthorized: true,
}
const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 }
const arr = (x: any): any[] => (x === undefined || x === null || x === '' ? [] : Array.isArray(x) ? x : [x])
const dnNorm = (s: string) => s.replace(/\s*,\s*/g, ',').replace(/\s*=\s*/g, '=').toLowerCase()
/** Un filtre LDAP valide pour nous : parenthèses équilibrées, commence par « ( », et contient les marqueurs exigés. */
export function validFilter(f: string, markers: string[]): boolean {
  if (!/^\(.*\)$/.test(f) || f.length > 500 || /[\0\n\r]/.test(f)) return false
  let d = 0; for (const ch of f) { if (ch === '(') d++; else if (ch === ')') { d--; if (d < 0) return false } }
  return d === 0 && markers.every((m) => f.includes(m))
}
const fill = (tpl: string, v: Record<string, string>) => tpl.replace(/\{(u|dn)\}/g, (_m, k: string) => escapeFilter(v[k] ?? ''))

export type LdapResult = { ok: true; dn: string; displayName: string; username: string; role: Role; spaceIds: number[] | null }
  | { ok: false; reason: 'disabled' | 'empty_password' | 'service_bind' | 'not_found' | 'bad_credentials' | 'no_group' | 'unreachable' }

export async function authenticateLdap(username: string, password: string, s: LdapSettings, bindPassword: string, factory: (url: string) => LdapLike): Promise<LdapResult> {
  if (!s.enabled || !s.urls.length) return { ok: false, reason: 'disabled' }
  if (!password) return { ok: false, reason: 'empty_password' }                                   // liaison sans mot de passe = « anonyme » : refusée avant tout
  if (!/^[\w.@\- ]{1,256}$/.test(username)) return { ok: false, reason: 'not_found' }
  let lastErr: 'service_bind' | 'unreachable' = 'unreachable'
  for (const url of s.urls) {
    const svc = factory(url)
    try {
      try { await svc.bind(s.bindDn, bindPassword) } catch { lastErr = 'service_bind'; continue }
      const attrs = ['dn', s.userAttr, s.displayAttr, ...(s.groupMode === 'memberOf' ? ['memberOf'] : [])]
      const found = await svc.search(s.baseDn, { scope: 'sub', filter: fill(s.userFilter, { u: username }), attributes: attrs, sizeLimit: 2 })
      if (found.searchEntries.length !== 1) return { ok: false, reason: 'not_found' }
      const e = found.searchEntries[0]!, dn = String(e.dn)
      let groups: string[]
      if (s.groupMode === 'memberOf') groups = arr(e.memberOf).map((g) => dnNorm(String(g)))
      else {
        const g = await svc.search(s.groupBaseDn || s.baseDn, { scope: 'sub', filter: fill(s.groupFilter, { u: username, dn }), attributes: ['dn'], sizeLimit: 500 })
        groups = g.searchEntries.map((x) => dnNorm(String(x.dn)))
      }
      const matched = s.groupMap.filter((m) => groups.includes(dnNorm(m.groupDn)))
      const role = matched.reduce<Role | null>((r, m) => (!r || RANK[m.role] > RANK[r] ? m.role : r), null)
      const usr = factory(url)
      try { await usr.bind(dn, password) } catch { return { ok: false, reason: 'bad_credentials' } } finally { await usr.unbind().catch(() => undefined) }
      if (!role) return { ok: false, reason: 'no_group' }
      const name = String(arr(e[s.userAttr])[0] ?? username).slice(0, 64)
      return { ok: true, dn, role, spaceIds: delegatedSpaces(role, matched.filter((m) => m.role === role)), displayName: String(arr(e[s.displayAttr])[0] ?? username).slice(0, 200), username: name }
    } catch { lastErr = 'unreachable' } finally { await svc.unbind().catch(() => undefined) }
  }
  return { ok: false, reason: lastErr }
}
