// Audit de sécurité 0.24.1 : refus des réglages « test » sur une console de production, et zone DNS imposée à un utilisateur à périmètre restreint.
import { describe, expect, it } from 'vitest'
import { productionGuardError } from '~~/server/utils/config'
import { resolveDnsZone } from '~~/server/utils/smartddi'

describe('réglages réservés aux tests', () => {
  const TLS = { NITRO_SSL_CERT: '-----BEGIN CERTIFICATE-----' }
  it('console de production (HTTPS du service) : chacun des trois réglages est refusé, le message nomme la variable', () => {
    for (const k of ['DDI_TEST_MODE', 'DDI_OIDC_ALLOW_HTTP', 'DDI_ALLOW_UNVERIFIED_AUTH']) {
      const m = productionGuardError({ ...TLS, [k]: '1' })
      expect(m, k).toContain(`${k}=1`); expect(m).toContain('démarrage refusé')
    }
  })
  it('console de production sans ces réglages (ou à « 0 ») : démarrage normal', () => {
    expect(productionGuardError({ ...TLS })).toBeNull()
    expect(productionGuardError({ ...TLS, DDI_TEST_MODE: '0', DDI_OIDC_ALLOW_HTTP: '', DDI_COOKIE_SECURE: 'true' })).toBeNull()
  })
  it('tests (HTTP clair, pas de certificat du service) : ces réglages restent permis', () => {
    expect(productionGuardError({ DDI_TEST_MODE: '1', DDI_OIDC_ALLOW_HTTP: '1', DDI_ALLOW_UNVERIFIED_AUTH: '1' })).toBeNull()
    expect(productionGuardError({})).toBeNull()
  })
})

describe('zone DNS d\'une adresse IPAM', () => {
  // doublure de la base : seul « network_templates » est interrogé
  const q = (zone: number | null) => ({ query: async () => ({ rows: zone === undefined ? [] : [{ dns_zone_id: zone }] }) }) as any
  const refused = async (p: Promise<unknown>) => { try { await p } catch (e: any) { return [e?.statusCode, e?.data?.code] } return 'accepté' }
  it('utilisateur restreint : une autre zone que celle du gabarit est refusée (403 out_of_scope)', async () => {
    expect(await refused(resolveDnsZone(q(5), 1, 9, { scoped: true }))).toEqual([403, 'out_of_scope'])
    expect(await refused(resolveDnsZone(q(null), 1, 9, { scoped: true }))).toEqual([403, 'out_of_scope'])   // réseau sans zone de gabarit : aucune zone au choix
  })
  it('utilisateur restreint : zone du gabarit, absence de choix et « aucune zone » restent permis', async () => {
    expect(await resolveDnsZone(q(5), 1, 5, { scoped: true })).toBe(5)
    expect(await resolveDnsZone(q(5), 1, undefined, { scoped: true })).toBe(5)
    expect(await resolveDnsZone(q(5), 1, null, { scoped: true })).toBeNull()
  })
  it('sans périmètre (administrateur, opérateur complet, jeton) : la zone demandée est acceptée', async () => {
    expect(await resolveDnsZone(q(5), 1, 9)).toBe(9)
    expect(await resolveDnsZone(q(5), 1, 9, { scoped: false })).toBe(9)
    expect(await resolveDnsZone(q(5), 1, undefined)).toBe(5)
  })
})
