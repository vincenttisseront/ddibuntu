import { describe, expect, it } from 'vitest'
import { authenticateAd, delegatedSpaces, AD_DEFAULTS } from '~~/server/utils/ad'
import type { AdSettings, LdapLike } from '~~/server/utils/ad'

describe('périmètre délégué (AD)', () => {
  it('administrateur ou groupe sans espaces : tout', () => {
    expect(delegatedSpaces('admin', [{ spaceIds: [1] }])).toBeNull()
    expect(delegatedSpaces('operator', [{}])).toBeNull()
    expect(delegatedSpaces('operator', [{ spaceIds: [2] }, {}])).toBeNull()       // un groupe sans périmètre lève la restriction
    expect(delegatedSpaces('operator', [])).toBeNull()
  })
  it('opérateur : union triée et dédoublonnée des espaces', () => {
    expect(delegatedSpaces('operator', [{ spaceIds: [3, 1] }, { spaceIds: [3, 2] }])).toEqual([1, 2, 3])
  })
  it('connexion : le périmètre vient des groupes du rôle retenu', async () => {
    const S: AdSettings = { ...AD_DEFAULTS, enabled: true, urls: ['ldaps://x'], baseDn: 'DC=c', bindDn: 'CN=svc', nestedGroups: false,
      groupMap: [{ groupDn: 'CN=Ops-Paris,OU=G', role: 'operator', spaceIds: [2] }, { groupDn: 'CN=Ops-Lyon,OU=G', role: 'operator', spaceIds: [3] }, { groupDn: 'CN=Lecteurs,OU=G', role: 'viewer' }] }
    const dir = (memberOf: string[]): ((u: string) => LdapLike) => () => ({
      async bind() { /* ok */ }, async unbind() { /* ok */ },
      async search() { return { searchEntries: [{ dn: 'CN=U,OU=U', displayName: 'U', memberOf, sAMAccountName: 'u' }] } },
    })
    expect(await authenticateAd('u', 'pw', S, 'x', dir(['CN=Ops-Paris,OU=G', 'CN=Ops-Lyon,OU=G', 'CN=Lecteurs,OU=G']))).toMatchObject({ ok: true, role: 'operator', spaceIds: [2, 3] })
    expect(await authenticateAd('u', 'pw', S, 'x', dir(['CN=Lecteurs,OU=G']))).toMatchObject({ ok: true, role: 'viewer', spaceIds: null })
  })
})
