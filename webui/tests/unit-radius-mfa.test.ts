// 0.17.0 — second facteur (mot de passe + code à usage unique) : réglages du fournisseur générique, dépôt mfa.json pour root, drapeau MFA des clients,
// empreinte, problèmes de déploiement, secrets jamais relus.
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { MFA_DEFAULTS, mfaBody, mfaConfigured, mfaDigestPart, mfaJson, mfaSecret, normMfa, publicMfa, sealMfaSecret } from '../server/utils/radius-mfa'
import type { MfaSettings } from '../server/utils/radius-mfa'
import { authzDigest, authzProblems, buildAuthzDeposit } from '../server/utils/radius-authz'
import { depositRadiusRequest, MFA_SECRET_LEN, MFA_SECRET_MIN, renderClientsConf, sealSecret } from '../server/utils/radius'
import type { DirSettings } from '../server/utils/radius-dir'
import type { CompiledRule } from '../server/utils/radius-rules'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-mfa-'))
process.env.DDI_GENERATED_DIR = TMP; process.env.DDI_SECRET_KEY ??= 'k'.repeat(48)
afterAll(() => rmSync(TMP, { recursive: true, force: true }))

const dir: DirSettings = { urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc@lab.test', tlsRejectUnauthorized: true, bindPasswordEnc: 'x' }
const rules: CompiledRule[] = [{ n: 1, id: 1, name: 'r1', action: 'accept', kind: null, groups: ['g'], nas: null, ssids: [], reply: {} }]
const body = { type: 'oauth2_password', tokenUrl: 'https://sso.example.local/realms/corp/protocol/openid-connect/token', clientId: 'ddi-radius', clientSecret: 'abc-DEF_123.~x',
  fields: { identity: 'username', password: 'password', otp: 'totp' }, identity: 'typed', otpDigits: 6, extra: [{ name: 'scope', value: 'openid profile' }], timeoutSec: 5, tlsVerify: true, caPem: '' }
const settings = (over: Partial<MfaSettings> = {}): MfaSettings => ({ ...MFA_DEFAULTS, tokenUrl: body.tokenUrl, clientId: 'ddi-radius', clientSecretEnc: sealMfaSecret('abc-DEF_123.~x'), ...over })

describe('réglages du fournisseur', () => {
  it('aucun fournisseur par défaut ; lecture tolérante d\'une valeur abîmée', () => {
    expect(mfaConfigured(normMfa(undefined))).toBe(false)
    expect(normMfa({ tokenUrl: 12, tlsVerify: 'non', otpDigits: 7 })).toEqual(MFA_DEFAULTS)
  })
  it('corps de la route : cas valide, puis chaque refus', () => {
    expect(mfaBody.safeParse(body).success).toBe(true)
    const ko = (over: any) => expect(mfaBody.safeParse({ ...body, ...over }).success, JSON.stringify(over)).toBe(false)
    ko({ tokenUrl: 'http://sso.example.local/token' })                      // HTTPS obligatoire
    ko({ tokenUrl: 'https://sso.example.local/t?x=1' })                     // pas de paramètres dans l'adresse
    ko({ tokenUrl: 'https://u:p@sso.example.local/t' })
    ko({ clientId: 'a b' }); ko({ clientSecret: 'a"b' }); ko({ clientSecret: 'a%{b' })
    ko({ fields: { identity: 'u', password: 'u', otp: 'totp' } })           // noms distincts
    ko({ fields: { identity: 'client_id', password: 'password', otp: 'totp' } })   // noms réservés
    ko({ extra: [{ name: 'grant_type', value: 'x' }] }); ko({ extra: [{ name: 'username', value: 'x' }] })
    ko({ extra: [{ name: 'a', value: 'x' }, { name: 'a', value: 'y' }] }); ko({ extra: Array.from({ length: 6 }, (_, i) => ({ name: `p${i}`, value: 'x' })) })
    ko({ extra: [{ name: 'a', value: '${x}' }] }); ko({ extra: [{ name: 'a', value: 'x%{y}' }] })
    ko({ otpDigits: 7 }); ko({ timeoutSec: 1 }); ko({ timeoutSec: 16 }); ko({ identity: 'autre' }); ko({ type: 'ldap' }); ko({ caPem: 'pas un certificat' }); ko({ x: 1 })
    expect(mfaBody.safeParse({ ...body, clientSecret: '' }).success).toBe(true)         // client public
    expect(mfaBody.safeParse({ ...body, clientSecret: null }).success).toBe(true)       // inchangé
    const { clientSecret: _s, ...sans } = body; expect(mfaBody.safeParse(sans).success).toBe(true)
  })
  it('le secret est chiffré, relu en clair seulement côté serveur, jamais renvoyé par la lecture publique', () => {
    const s = settings()
    expect(s.clientSecretEnc).not.toContain('abc-DEF'); expect(mfaSecret(s)).toBe('abc-DEF_123.~x')
    const pub: any = publicMfa(s); expect(pub.clientSecretSet).toBe(true); expect(JSON.stringify(pub)).not.toContain('abc-DEF'); expect('clientSecretEnc' in pub).toBe(false)
    expect(publicMfa(settings({ clientSecretEnc: '' })).clientSecretSet).toBe(false)
  })
})

describe('mfa.json et empreinte', () => {
  it('mfa.json : tout ce dont root a besoin, secret en clair (fichier 0600 effacé par root)', () => {
    expect(JSON.parse(mfaJson(settings()))).toEqual({ type: 'oauth2_password', tokenUrl: body.tokenUrl, clientId: 'ddi-radius', clientSecret: 'abc-DEF_123.~x', fields: body.fields, identity: 'typed',
      otpDigits: 6, extra: [], timeoutSec: 5, tlsVerify: true })
  })
  it('l\'empreinte ne contient pas le secret et change avec chaque réglage', () => {
    const base = JSON.stringify(mfaDigestPart(settings())); expect(base).not.toContain('abc-DEF')
    for (const over of [{ tokenUrl: 'https://autre.example.local/t' }, { clientId: 'x' }, { clientSecretEnc: sealMfaSecret('autre') }, { identity: 'account' as const }, { otpDigits: 8 as const },
      { timeoutSec: 9 }, { tlsVerify: false }, { extra: [{ name: 'a', value: 'b' }] }, { fields: { identity: 'login', password: 'password', otp: 'totp' } }, { caPem: '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----' }])
      expect(JSON.stringify(mfaDigestPart(settings(over))), JSON.stringify(over)).not.toBe(base)
    expect(JSON.stringify(mfaDigestPart(settings({ clientSecretEnc: sealMfaSecret('abc-DEF_123.~x') })))).toBe(base)   // chiffré autrement, même secret : même empreinte
  })
})

describe('clients', () => {
  const row = (name: string, mfa: boolean, secret: string) => ({ name, address: '10.0.0.' + (name === 'fw-vpn' ? 2 : 1) + '/32', secret_enc: sealSecret(secret), enabled: true, mfa })
  it('seul un client marqué MFA est routé vers le serveur virtuel dédié ; le client d\'essai jamais', () => {
    const conf = renderClientsConf([row('fw-vpn', true, 'S'.repeat(40)), row('wifi', false, 'w'.repeat(32))])
    const blocks = conf.split(/\n(?=client ")/)
    const of = (n: string) => blocks.find((b) => b.startsWith(`client "${n}"`))!
    expect(of('fw-vpn')).toContain('virtual_server = ddibuntu-mfa'); expect(of('wifi')).not.toContain('virtual_server'); expect(of('ddi-selftest')).not.toContain('virtual_server')
    for (const b of blocks.filter((x) => x.startsWith('client "'))) expect(b).toContain('require_message_authenticator = yes')
  })
  it('un client désactivé n\'est pas écrit ; sans drapeau, rien ne change par rapport à la 0.16', () => {
    expect(renderClientsConf([{ ...row('fw-vpn', true, 'S'.repeat(40)), enabled: false }])).not.toContain('fw-vpn')
    expect(renderClientsConf([{ name: 'a', address: '10.0.0.1/32', secret_enc: sealSecret('x'.repeat(32)), enabled: true }])).not.toContain('virtual_server')
  })
  it('longueurs : minimum 32, généré 40', () => { expect(MFA_SECRET_MIN).toBe(32); expect(MFA_SECRET_LEN).toBe(40) })
})

describe('déploiement', () => {
  const mfa = (over: any = {}) => ({ clients: ['fw-vpn'], settings: settings(), restModule: true as boolean | null, ...over })
  const p = (over: any = {}) => authzProblems({ rules, pkiEmpty: false, pkiReady: true, dir, password: 'pw', ldapModule: true, ...over })
  it('sans client MFA : aucun nouveau problème, quel que soit le fournisseur', () => {
    expect(p({ mfa: mfa({ clients: [], settings: MFA_DEFAULTS, restModule: false }) })).toEqual([]); expect(p()).toEqual([])
  })
  it('client MFA : règles d\'accès, fournisseur et module REST exigés', () => {
    expect(p({ mfa: mfa(), rules: [] })).toEqual(['mfa_needs_rules'])
    expect(p({ mfa: mfa({ settings: MFA_DEFAULTS }) })).toEqual(['mfa_needs_provider'])
    expect(p({ mfa: mfa({ restModule: false }) })).toEqual(['rest_module_missing'])
    expect(p({ mfa: mfa({ restModule: null }) })).toEqual([]); expect(p({ mfa: mfa() })).toEqual([])
  })
  it('empreinte : celle d\'un déploiement sans client MFA ne change pas (mises à jour sans « modifications non déployées » parasites)', () => {
    const base = authzDigest(rules, dir, 'pw')
    expect(authzDigest(rules, dir, 'pw', undefined, mfa({ clients: [], settings: settings({ tokenUrl: 'https://x.example.local/t' }) }))).toBe(base)
    const a = authzDigest(rules, dir, 'pw', undefined, mfa()); expect(a).not.toBe(base)
    expect(authzDigest(rules, dir, 'pw', undefined, mfa({ clients: ['fw-vpn', 'autre'] }))).not.toBe(a)
    expect(authzDigest(rules, dir, 'pw', undefined, mfa({ settings: settings({ otpDigits: 8 }) }))).not.toBe(a)
    expect(authzDigest(rules, dir, 'pw', undefined, mfa())).toBe(a)
  })
  it('le dépôt porte mfa.json (et mfa-ca.pem) seulement avec un client MFA', () => {
    expect(buildAuthzDeposit(rules, dir, 'pw', undefined, mfa({ clients: [] })).mfa).toBeUndefined()
    expect(buildAuthzDeposit(rules, dir, 'pw').mfa).toBeUndefined()
    const d = buildAuthzDeposit(rules, dir, 'pw', undefined, mfa()); expect(JSON.parse(d.mfa!).clientId).toBe('ddi-radius'); expect(d.mfaCa).toBeUndefined()
    const ca = '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----'
    expect(buildAuthzDeposit(rules, dir, 'pw', undefined, mfa({ settings: settings({ caPem: ca }) })).mfaCa).toBe(ca + '\n')
  })
  it('dépôt pour root : mfa.json et mfa-ca.pem en 0600, jamais relus d\'un dépôt précédent', async () => {
    const pki = { checkCrl: false, ca: 'ca', server: 's', key: 'k', crls: {} }
    await depositRadiusRequest({ action: 'apply', clients: '# c\n', pki, authz: { rules: '{}', ldap: '{}', mfa: '{"x":1}\n', mfaCa: 'PEM\n' } })
    for (const f of ['mfa.json', 'mfa-ca.pem']) expect(statSync(join(TMP, 'radius-authz', f)).mode & 0o777).toBe(0o600)
    expect(readFileSync(join(TMP, 'radius-authz', 'mfa.json'), 'utf8')).toBe('{"x":1}\n')
    await depositRadiusRequest({ action: 'apply', clients: '# c\n', pki, authz: { rules: '{}', ldap: '{}' } })
    expect(existsSync(join(TMP, 'radius-authz', 'mfa.json'))).toBe(false); expect(existsSync(join(TMP, 'radius-authz', 'mfa-ca.pem'))).toBe(false)
  })
})
