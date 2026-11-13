import { describe, expect, it } from 'vitest'
import { mapClaims, newPkce, randomToken, OIDC_DEFAULTS } from '../server/utils/oidc'
import { createHash } from 'node:crypto'

const base = { ...OIDC_DEFAULTS, enabled: true, issuer: 'https://idp', clientId: 'c', groupMap: [{ group: 'A', role: 'admin' }, { group: 'B', role: 'operator', spaceIds: [4] }, { group: 'C', role: 'viewer' }] } as any

describe('PKCE et jetons aléatoires', () => {
  it('le challenge est le SHA-256 base64url du verifier', () => {
    const p = newPkce(); expect(p.challenge).toBe(createHash('sha256').update(p.verifier).digest('base64url')); expect(p.verifier.length).toBeGreaterThanOrEqual(43)
    expect(newPkce().verifier).not.toBe(p.verifier); expect(randomToken()).not.toBe(randomToken())
  })
})
describe('mapClaims', () => {
  it('prend le rôle le plus élevé et fusionne les périmètres', () => {
    expect(mapClaims(base, { preferred_username: 'u', groups: ['C', 'B'] })).toMatchObject({ ok: true, role: 'operator', spaceIds: [4] })
    expect(mapClaims(base, { preferred_username: 'u', groups: ['a'] })).toMatchObject({ ok: true, role: 'admin' })
  })
  it('refuse sans groupe ni rôle par défaut, accepte avec', () => {
    expect(mapClaims(base, { preferred_username: 'u', groups: ['Z'] })).toEqual({ ok: false, reason: 'no_group' })
    expect(mapClaims({ ...base, defaultRole: 'viewer' }, { preferred_username: 'u' })).toMatchObject({ ok: true, role: 'viewer' })
  })
  it('identifiant : assaini, repli e-mail, sinon refus', () => {
    expect(mapClaims(base, { preferred_username: 'a b!', groups: ['A'] })).toMatchObject({ username: 'a_b_' })
    expect(mapClaims(base, { email: 'x@y.fr', groups: ['A'] })).toMatchObject({ username: 'x@y.fr' })
    expect(mapClaims(base, { groups: ['A'] })).toEqual({ ok: false, reason: 'no_username' })
    expect((mapClaims(base, { preferred_username: 'x'.repeat(200), groups: ['A'] }) as any).username.length).toBe(64)
  })
  it('groupes fournis en chaîne unique', () => {
    expect(mapClaims(base, { preferred_username: 'u', groups: 'A' })).toMatchObject({ ok: true, role: 'admin' })
  })
})
