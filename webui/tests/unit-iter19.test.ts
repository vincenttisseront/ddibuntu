import { describe, expect, it } from 'vitest'
import { authenticateLdap, LDAP_DEFAULTS, validFilter } from '../server/utils/ldap'
import type { LdapSettings } from '../server/utils/ldap'
import type { LdapLike } from '../server/utils/ad'

const S: LdapSettings = { ...LDAP_DEFAULTS, enabled: true, urls: ['ldaps://a', 'ldaps://b'], baseDn: 'ou=people,dc=x', bindDn: 'cn=svc,dc=x', groupBaseDn: 'ou=groups,dc=x',
  groupMap: [{ groupDn: 'cn=admins,ou=groups,dc=x', role: 'admin' }, { groupDn: 'cn=paris,ou=groups,dc=x', role: 'operator', spaceIds: [2] }, { groupDn: 'cn=lyon,ou=groups,dc=x', role: 'operator', spaceIds: [3] }, { groupDn: 'cn=ro,ou=groups,dc=x', role: 'viewer' }] }

/** Annuaire factice : un utilisateur, des groupes ; enregistre filtres et liaisons pour les vérifier. */
function dir(o: { groups?: string[]; memberOf?: string[]; users?: number; pw?: string; badSvc?: string[]; down?: string[] } = {}) {
  const log = { filters: [] as string[], binds: [] as string[], urls: [] as string[] }
  const factory = (url: string): LdapLike => ({
    async bind(dn, pw) {
      log.binds.push(`${dn}:${pw}`)
      if (dn === 'cn=svc,dc=x') { if (o.badSvc?.includes(url)) throw new Error('bad'); return }
      if (dn !== 'uid=bob,ou=people,dc=x' || pw !== (o.pw ?? 'secret')) throw new Error('invalid')
    },
    async unbind() { /* ok */ },
    async search(base, opts) {
      log.filters.push(opts.filter); log.urls.push(url)
      if (o.down?.includes(url)) throw new Error('down')
      if (base === 'ou=groups,dc=x') return { searchEntries: (o.groups ?? []).map((dn) => ({ dn })) }
      const n = o.users ?? 1
      return { searchEntries: Array.from({ length: n }, () => ({ dn: 'uid=bob,ou=people,dc=x', uid: ['bob'], cn: 'Bob Durand', memberOf: o.memberOf ?? [] })) }
    },
  })
  return { factory, log }
}

describe('LDAP générique : filtres', () => {
  it('validFilter : parenthèses équilibrées et marqueur exigé', () => {
    expect(validFilter('(uid={u})', ['{u}'])).toBe(true); expect(validFilter('(&(a=1)(uid={u}))', ['{u}'])).toBe(true)
    expect(validFilter('uid={u}', ['{u}'])).toBe(false); expect(validFilter('(uid={u}', ['{u}'])).toBe(false); expect(validFilter('(uid=x)', ['{u}'])).toBe(false)
    expect(validFilter('(uid={u})\n(x)', ['{u}'])).toBe(false); expect(validFilter(')(uid={u})(', ['{u}'])).toBe(false)
  })
  it('l’identifiant est échappé : aucune injection de filtre', async () => {
    const d = dir({ memberOf: ['cn=ro,ou=groups,dc=x'] })
    expect(await authenticateLdap('bob)(uid=*', 'secret', S, 'x', d.factory)).toEqual({ ok: false, reason: 'not_found' })      // refusé avant tout : caractères interdits
    expect(d.log.filters).toEqual([])
    await authenticateLdap('b*b', 'secret', S, 'x', d.factory); expect(d.log.filters).toEqual([])
  })
})
describe('LDAP générique : connexion', () => {
  it('mode memberOf : rôle le plus élevé, périmètres fusionnés, nom et identifiant venant de l’annuaire', async () => {
    const s = { ...S, groupMode: 'memberOf' as const }
    expect(await authenticateLdap('bob', 'secret', s, 'x', dir({ memberOf: ['CN=Paris, OU=groups,DC=x', 'cn=lyon,ou=groups,dc=x', 'cn=ro,ou=groups,dc=x'] }).factory)).toEqual({ ok: true, dn: 'uid=bob,ou=people,dc=x', role: 'operator', spaceIds: [2, 3], displayName: 'Bob Durand', username: 'bob' })
    expect(await authenticateLdap('bob', 'secret', s, 'x', dir({ memberOf: ['cn=admins,ou=groups,dc=x'] }).factory)).toMatchObject({ ok: true, role: 'admin', spaceIds: null })
  })
  it('mode recherche de groupes : {dn} et {u} substitués, groupes comparés sans casse', async () => {
    const s = { ...S, groupMode: 'search' as const, groupFilter: '(&(objectClass=groupOfNames)(member={dn}))' }
    const d = dir({ groups: ['CN=RO,OU=groups,DC=x'] })
    expect(await authenticateLdap('bob', 'secret', s, 'x', d.factory)).toMatchObject({ ok: true, role: 'viewer' })
    expect(d.log.filters).toContain('(&(objectClass=groupOfNames)(member=uid=bob,ou=people,dc=x))')
    const d2 = dir({ groups: ['cn=ro,ou=groups,dc=x'] }); await authenticateLdap('bob', 'secret', { ...s, groupFilter: '(memberUid={u})' }, 'x', d2.factory); expect(d2.log.filters).toContain('(memberUid=bob)')
  })
  it('refus : mot de passe vide, mauvais mot de passe, aucun groupe, utilisateur absent ou ambigu, désactivé', async () => {
    const m = { memberOf: ['cn=ro,ou=groups,dc=x'] }
    expect(await authenticateLdap('bob', '', S, 'x', dir(m).factory)).toEqual({ ok: false, reason: 'empty_password' })
    expect(await authenticateLdap('bob', 'faux', S, 'x', dir(m).factory)).toEqual({ ok: false, reason: 'bad_credentials' })
    expect(await authenticateLdap('bob', 'secret', S, 'x', dir({ memberOf: ['cn=autre,dc=x'] }).factory)).toEqual({ ok: false, reason: 'no_group' })
    expect(await authenticateLdap('bob', 'secret', S, 'x', dir({ ...m, users: 0 }).factory)).toEqual({ ok: false, reason: 'not_found' })
    expect(await authenticateLdap('bob', 'secret', S, 'x', dir({ ...m, users: 2 }).factory)).toEqual({ ok: false, reason: 'not_found' })
    expect(await authenticateLdap('bob', 'secret', { ...S, enabled: false }, 'x', dir(m).factory)).toEqual({ ok: false, reason: 'disabled' })
  })
  it('le mot de passe de l’utilisateur n’est jamais essayé sans groupe trouvé en premier lieu ; liaison sur connexion distincte', async () => {
    const d = dir({ memberOf: ['cn=ro,ou=groups,dc=x'] }); await authenticateLdap('bob', 'secret', S, 'mdp-service', d.factory)
    expect(d.log.binds).toEqual(['cn=svc,dc=x:mdp-service', 'uid=bob,ou=people,dc=x:secret'])
  })
  it('bascule sur le second serveur ; erreurs de liaison de service et d’injoignabilité distinguées', async () => {
    const m = { memberOf: ['cn=ro,ou=groups,dc=x'] }
    const d = dir({ ...m, down: ['ldaps://a'] }); expect(await authenticateLdap('bob', 'secret', S, 'x', d.factory)).toMatchObject({ ok: true }); expect(d.log.urls).toEqual(['ldaps://a', 'ldaps://b'])
    expect(await authenticateLdap('bob', 'secret', S, 'x', dir({ ...m, badSvc: ['ldaps://a', 'ldaps://b'] }).factory)).toEqual({ ok: false, reason: 'service_bind' })
    expect(await authenticateLdap('bob', 'secret', S, 'x', dir({ ...m, down: ['ldaps://a', 'ldaps://b'] }).factory)).toEqual({ ok: false, reason: 'unreachable' })
  })
})
