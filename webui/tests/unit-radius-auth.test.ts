// 0.16.0 — identifiant et mot de passe : réglages, dépôt auth.json pour root, empreinte, problèmes de déploiement, instantané du cluster, fichiers de jonction.
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { authBody, authJson, normAuth, NETBIOS_RE } from '../server/utils/radius-auth'
import { authzDigest, authzProblems, buildAuthzDeposit } from '../server/utils/radius-authz'
import { depositRadiusRequest } from '../server/utils/radius'
import { openApply, sealApply } from '../server/utils/radius-snapshot'
import type { DirSettings } from '../server/utils/radius-dir'
import type { CompiledRule } from '../server/utils/radius-rules'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-auth-'))
process.env.DDI_GENERATED_DIR = TMP; process.env.DDI_SECRET_KEY ??= 'k'.repeat(48)
afterAll(() => rmSync(TMP, { recursive: true, force: true }))

const dir: DirSettings = { urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc@lab.test', tlsRejectUnauthorized: true, bindPasswordEnc: 'x' }
const rules: CompiledRule[] = [{ n: 1, id: 1, name: 'r1', action: 'accept', kind: null, groups: ['g'], nas: null, ssids: [], reply: {} }]

describe('réglages', () => {
  it('désactivé par défaut, lecture tolérante', () => {
    expect(normAuth(undefined)).toEqual({ peap: false, ttls: false, netbios: '' })
    expect(normAuth({ peap: 'oui', ttls: 1, netbios: 'x; rm' })).toEqual({ peap: false, ttls: false, netbios: '' })
    expect(normAuth({ peap: true, ttls: true, netbios: 'AR-SYSTEMS' })).toEqual({ peap: true, ttls: true, netbios: 'AR-SYSTEMS' })
  })
  it('nom NetBIOS : 15 caractères, lettres chiffres tiret', () => {
    for (const ok of ['AR-SYSTEMS', 'LAB', 'A1', 'a'.repeat(15)]) expect(NETBIOS_RE.test(ok), ok).toBe(true)
    for (const ko of ['', '-X', 'a'.repeat(16), 'A B', 'A\\B', 'A;B', 'é']) expect(NETBIOS_RE.test(ko), ko).toBe(false)
  })
  it('corps de la route : champ inconnu et NetBIOS invalide refusés, NetBIOS vide admis', () => {
    expect(authBody.safeParse({ peap: true, ttls: false, netbios: 'LAB' }).success).toBe(true)
    expect(authBody.safeParse({ peap: false, ttls: false, netbios: '' }).success).toBe(true)
    expect(authBody.safeParse({ peap: true, ttls: false, netbios: 'A B' }).success).toBe(false)
    expect(authBody.safeParse({ peap: true, ttls: false, netbios: 'LAB', extra: 1 }).success).toBe(false)
  })
})

describe('auth.json', () => {
  it('rien à déposer quand tout est désactivé et sans nom NetBIOS (dépôt identique à la 0.15)', () => expect(authJson({ peap: false, ttls: false, netbios: '' })).toBeUndefined())
  it('contenu : méthodes et NetBIOS', () => {
    expect(JSON.parse(authJson({ peap: true, ttls: false, netbios: 'LAB' })!)).toEqual({ peap: true, ttls: false, netbios: 'LAB' })
    expect(JSON.parse(authJson({ peap: false, ttls: true, netbios: '' })!)).toEqual({ peap: false, ttls: true })
  })
})

describe('règles et empreinte', () => {
  const none = { peap: false, ttls: false, netbios: '' }
  const p = (auth: any, over: any = {}) => authzProblems({ rules, pkiEmpty: false, pkiReady: true, dir, password: 'pw', ldapModule: true, auth, ...over })
  it('sans méthode par mot de passe, aucun nouveau problème', () => expect(p(none)).toEqual([]))
  it('PEAP exige le nom NetBIOS ; TTLS seul non', () => {
    expect(p({ peap: true, ttls: false, netbios: '' })).toEqual(['auth_needs_netbios'])
    expect(p({ peap: true, ttls: false, netbios: 'LAB' })).toEqual([])
    expect(p({ peap: false, ttls: true, netbios: '' })).toEqual([])
  })
  it('méthode par mot de passe sans aucune règle : refusé (personne ne pourrait entrer)', () => {
    expect(p({ peap: false, ttls: true, netbios: '' }, { rules: [] })).toEqual(['auth_needs_rules'])
    expect(p(none, { rules: [] })).toEqual([])
  })
  it('l\'empreinte d\'un déploiement sans méthode reste celle de la 0.15 ; elle change quand on règle une méthode', () => {
    const r = rules, base = authzDigest(r, dir, 'pw')
    expect(authzDigest(r, dir, 'pw', none)).toBe(base)
    const a = authzDigest(r, dir, 'pw', { peap: true, ttls: false, netbios: 'LAB' })
    expect(a).not.toBe(base); expect(a).toMatch(/^[0-9a-f]{64}$/)
    expect(authzDigest(r, dir, 'pw', { peap: true, ttls: true, netbios: 'LAB' })).not.toBe(a)
    expect(authzDigest(r, dir, 'pw', { peap: true, ttls: false, netbios: 'LAB' })).toBe(a)
  })
  it('le dépôt porte auth.json seulement quand il existe', () => {
    expect(buildAuthzDeposit(rules, dir, 'pw', none).auth).toBeUndefined()
    expect(JSON.parse(buildAuthzDeposit(rules, dir, 'pw', { peap: true, ttls: true, netbios: 'LAB' }).auth!)).toEqual({ peap: true, ttls: true, netbios: 'LAB' })
  })
})

describe('dépôt pour root', () => {
  it('apply : radius-authz/auth.json en 0600', async () => {
    const pki = { checkCrl: false, ca: 'ca', server: 's', key: 'k', crls: {} }
    await depositRadiusRequest({ action: 'apply', clients: '# c\n', pki, authz: { rules: '{}', ldap: '{}', auth: '{"peap":true}\n' } })
    const f = join(TMP, 'radius-authz', 'auth.json')
    expect(readFileSync(f, 'utf8')).toBe('{"peap":true}\n'); expect(statSync(f).mode & 0o777).toBe(0o600)
    await depositRadiusRequest({ action: 'apply', clients: '# c\n', pki, authz: { rules: '{}', ldap: '{}' } })
    expect(existsSync(join(TMP, 'radius-authz', 'auth.json'))).toBe(false)   // un ancien dépôt n'est jamais relu
  })
  it('join : radius-join/join.json en 0600, la demande ne porte que l\'action', async () => {
    await depositRadiusRequest({ action: 'join', join: { realm: 'lab.test', netbios: 'LAB', servers: ['dc1.lab.test'], user: 'Administrator', password: 'Secret-9' } })
    const f = join(TMP, 'radius-join', 'join.json')
    expect(statSync(f).mode & 0o777).toBe(0o600); expect(readdirSync(join(TMP, 'radius-join'))).toEqual(['join.json'])
    expect(JSON.parse(readFileSync(f, 'utf8'))).toMatchObject({ realm: 'lab.test', netbios: 'LAB', user: 'Administrator' })
    expect(readFileSync(join(TMP, '.radius-request'), 'utf8').trim()).toBe('{"action":"join"}')
  })
  it('leave sans compte : aucun fichier de jonction (un ancien dépôt est effacé)', async () => {
    await depositRadiusRequest({ action: 'leave' })
    expect(existsSync(join(TMP, 'radius-join'))).toBe(false)
    expect(readFileSync(join(TMP, '.radius-request'), 'utf8').trim()).toBe('{"action":"leave"}')
  })
})

describe('instantané du cluster', () => {
  it('auth.json survit au chiffrement et à la relecture', () => {
    const req = { action: 'apply' as const, clients: '# c\n', pki: { checkCrl: false, ca: 'ca', server: 's', key: 'k', crls: {} }, authz: { rules: '{}', ldap: '{}', auth: '{"ttls":true}\n' } }
    const back = openApply(sealApply(req))
    expect(back?.authz?.auth).toBe('{"ttls":true}\n')
  })
  it('un auth.json démesuré rend l\'instantané illisible', () => {
    const req = { action: 'apply' as const, clients: '# c\n', pki: { checkCrl: false, ca: 'ca', server: 's', key: 'k', crls: {} }, authz: { rules: '{}', ldap: '{}', auth: 'x'.repeat(5000) } }
    expect(openApply(sealApply(req))).toBeNull()
  })
})
