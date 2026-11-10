import { describe, expect, it } from 'vitest'
import { KDC_RE, REALM_RE, parseAdState } from '../server/utils/adkrb'
import { DNS_DEFAULTS, renderNamedZones, secureGrants } from '../server/utils/render'

const NOW = 1_800_000_000
const z = (o: any = {}) => ({ id: 1, name: 'lan.corp.test', type: 'primary' as const, masters: [], forwarders: [], allow_transfer: [], ddns_enabled: false, disabled: false, ddns_secure: null, default_ttl: 3600, serial: 1,
  soa_mname: null, soa_rname: null, soa_refresh: 3600, soa_retry: 600, soa_expire: 1209600, soa_minimum: 3600, ...o })

describe('mises à jour sécurisées : octrois update-policy', () => {
  it('rien sans domaine Kerberos ni sans option sur la zone', () => {
    expect(secureGrants({ ddns_enabled: true, ddns_secure: 'both' }, '')).toEqual([])
    expect(secureGrants({ ddns_enabled: true, ddns_secure: null }, 'CORP.TEST')).toEqual([])
  })
  it('chaque politique donne les octrois attendus, la clé DDNS s’y ajoute si elle est activée', () => {
    expect(secureGrants({ ddns_enabled: false, ddns_secure: 'ms-self' }, 'CORP.TEST')).toEqual(['grant CORP.TEST ms-self . A AAAA'])
    expect(secureGrants({ ddns_enabled: false, ddns_secure: 'krb5-self' }, 'CORP.TEST')).toEqual(['grant CORP.TEST krb5-self . A AAAA'])
    expect(secureGrants({ ddns_enabled: true, ddns_secure: 'both' }, 'CORP.TEST')).toEqual(['grant ddi-ddns zonesub ANY', 'grant CORP.TEST ms-self . A AAAA', 'grant CORP.TEST krb5-self . A AAAA'])
  })
  it('un domaine douteux n’est jamais injecté dans la configuration', () => {
    for (const bad of ['corp.test', 'CORP TEST', 'CORP.TEST; };', 'A"B', '']) expect(secureGrants({ ddns_enabled: false, ddns_secure: 'ms-self' }, bad)).toEqual([])
  })
  it('« allow-update » et « update-policy » ne sont jamais émis ensemble', () => {
    const out = renderNamedZones([z({ ddns_enabled: true, ddns_secure: 'ms-self' })], { ...DNS_DEFAULTS, kerberosRealm: 'CORP.TEST' })
    expect(out).toContain('update-policy { grant ddi-ddns zonesub ANY; grant CORP.TEST ms-self . A AAAA; };')
    expect(out).not.toContain('allow-update')
    const plain = renderNamedZones([z({ ddns_enabled: true })], { ...DNS_DEFAULTS, kerberosRealm: 'CORP.TEST' })
    expect(plain).toContain('allow-update { key "ddi-ddns"; };'); expect(plain).not.toContain('update-policy')
  })
  it('sans domaine configuré par root, la zone retombe sur la clé DDNS seule', () => {
    const out = renderNamedZones([z({ ddns_enabled: true, ddns_secure: 'both' })], { ...DNS_DEFAULTS, kerberosRealm: '' })
    expect(out).toContain('allow-update { key "ddi-ddns"; };'); expect(out).not.toContain('update-policy')
  })
  it('le rendu ne contient jamais de directive tkey (réservée à root)', () => {
    expect(renderNamedZones([z({ ddns_secure: 'both' })], { ...DNS_DEFAULTS, kerberosRealm: 'CORP.TEST' })).not.toMatch(/tkey/)
  })
})

describe('état Kerberos publié par root', () => {
  const base = { at: NOW - 20, configured: true, realm: 'CORP.TEST', kdcs: ['dc1.corp.test', 'dc2.corp.test:88'],
    keytab: { present: true, principals: ['DNS/ns1.corp.test@CORP.TEST'], enctypes: ['aes256-cts-hmac-sha1-96'], kvno: { 'DNS/ns1.corp.test@CORP.TEST': 3 }, mtime: NOW - 100, size: 160 } }
  it('lit le domaine, les contrôleurs et le keytab', () => {
    const s = parseAdState(JSON.stringify(base), NOW)!
    expect(s).toMatchObject({ configured: true, realm: 'CORP.TEST', ageSeconds: 20 }); expect(s.kdcs).toHaveLength(2)
    expect(s.keytab).toMatchObject({ present: true, principals: ['DNS/ns1.corp.test@CORP.TEST'], size: 160 }); expect(s.keytab.kvno['DNS/ns1.corp.test@CORP.TEST']).toBe(3)
  })
  it('fichier mal formé ou hostile : ignoré, champs inconnus et valeurs douteuses écartés', () => {
    expect(parseAdState('pas du json', NOW)).toBeNull(); expect(parseAdState('[]', NOW)).toBeNull()
    const s = parseAdState(JSON.stringify({ ...base, realm: 'corp; };', kdcs: ['ok.test', 'a b', 5], secret: 'x', keytab: { present: true, principals: 'x', kvno: { a: 'z' } } }), NOW)!
    expect(s.realm).toBe(''); expect(s.configured).toBe(false); expect(s.kdcs).toEqual(['ok.test']); expect(s.keytab.principals).toEqual([]); expect(s.keytab.kvno).toEqual({})
    expect(JSON.stringify(s)).not.toContain('secret')
  })
  it('validation du domaine et des contrôleurs', () => {
    for (const ok of ['CORP.LOCAL', 'A', 'AD-1.EXAMPLE.COM']) expect(REALM_RE.test(ok)).toBe(true)
    for (const bad of ['corp.local', '.CORP', 'CORP.', 'CORP LOCAL', 'A'.repeat(70), 'CORP\nX']) expect(REALM_RE.test(bad)).toBe(false)
    for (const ok of ['dc1.corp.local', '10.0.0.1', 'dc1:88', 'dc1.corp.local:464']) expect(KDC_RE.test(ok)).toBe(true)
    for (const bad of ['dc 1', 'dc1;rm', '-dc', 'dc1:', 'dc1:abc', '']) expect(KDC_RE.test(bad)).toBe(false)
  })
})
