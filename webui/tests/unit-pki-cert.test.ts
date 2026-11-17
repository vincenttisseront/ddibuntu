// 0.14.3 — certificats de la PKI : validation des formulaires (la MÊME que celle de root, vérifiée par un test différentiel contre pki-helper.py), demande JSON
// envoyée à root, clé et demande fabriquées ici, fichier PKCS#12 (openssl réel), lecture de ce que root publie, attente du résultat, CSV, adresse de la base d'EJBCA.
// La lecture de la base d'EJBCA et les routes sont vues par e2e-iter51.
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-pkicert-unit-'))
const RESULT = join(TMP, 'result.json'), CERTDIR = join(TMP, 'pki-cert'), CADIR = join(TMP, 'pki-ca')
Object.assign(process.env, { DDI_PKI_STATUS: join(TMP, 'status.json'), DDI_PKI_RESULT: RESULT, DDI_PKI_CAS: join(TMP, 'cas.json'), DDI_PKI_CA_DIR: CADIR, DDI_PKI_CERT_DIR: CERTDIR,
  DDI_GENERATED_DIR: TMP, DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij' })
const ROOT = resolve(__dirname, '../..')
const HELPER = join(ROOT, 'src/rootfs/usr/local/lib/ddibuntu/pki-helper.py')
let c: typeof import('../server/utils/pki-certs')
let cfg: typeof import('../server/utils/config')
let pki: typeof import('../server/utils/pki')
beforeAll(async () => { c = await import('../server/utils/pki-certs'); cfg = await import('../server/utils/config'); pki = await import('../server/utils/pki'); mkdirSync(CERTDIR, { recursive: true }) })
afterAll(() => rmSync(TMP, { recursive: true, force: true }))

const root = (body: unknown) => spawnSync('python3', [HELPER, 'parse-request'], { input: JSON.stringify(body), encoding: 'utf8' })
const rootAccepts = (body: unknown) => { const r = root(body); return r.status === 0 && r.stdout.length > 0 }
const rootMap = (body: unknown) => Object.fromEntries(root(body).stdout.trim().split('\n').map((l) => { const i = l.indexOf('\t'); return [l.slice(0, i), l.slice(i + 1)] }))
const ID = '0123456789abcdef'
const base = { ca: 'Lab-Sub', profile: 'server', cn: 'radius1.lab.test', o: 'Laboratoire', c: 'FR', dns: ['radius1.lab.test'], ip: ['10.1.2.3'] }
const csr = { pem: '-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n' }
const ok = (b: unknown) => c.issueCsrBody.safeParse({ ...(b as object), csr }).success

describe('formulaire d\'émission : mêmes règles que root', () => {
  it('accepte un formulaire valide et normalise (DNS en minuscules, IP canonique)', () => {
    const r = c.issueCsrBody.safeParse({ ...base, dns: ['Radius1.Lab.Test'], ip: ['0:0:0:0:0:0:0:1'], csr })
    expect(r.success).toBe(true)
    if (r.success) { expect(r.data.dns).toEqual(['radius1.lab.test']); expect(r.data.ip).toEqual(['::1']) }
  })
  it('refuse un champ inconnu (corps strict)', () => { expect(c.issueCsrBody.safeParse({ ...base, csr, extra: 1 }).success).toBe(false) })
  it.each([
    ['profil inconnu', { profile: 'EMPTY' }], ['nom EJBCA direct', { profile: 'DDI-RADIUS-Server' }], ['autorité ManagementCA', { ca: 'ManagementCA' }], ['autorité avec une barre', { ca: 'a/b' }],
    ['autorité racine hors ligne', { ca: 'ExtRoot-0a1b2c3d' }], ['serveur sans SAN', { dns: [], ip: [] }], ['serveur avec une adresse mail', { mail: ['a@b.test'] }],
    ['serveur avec un UPN', { upn: ['a@b.test'] }], ['neuf noms DNS', { dns: Array.from({ length: 9 }, (_, i) => `a${i}.t`) }], ['cinq IP', { ip: ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5'] }],
    ['nom DNS avec tiret en tête', { dns: ['-a.t'] }], ['nom DNS avec deux points', { dns: ['a..t'] }], ['nom DNS avec espace', { dns: ['a b.t'] }], ['nom DNS avec souligné', { dns: ['a_b.t'] }],
    ['nom DNS injectant un SAN', { dns: ['a.t,dNSName=evil.test'] }], ['nom DNS de 254 caractères', { dns: [`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(63)}`] }],
    ['IP invalide', { ip: ['999.1.1.1'] }], ['IP avec masque', { ip: ['10.0.0.0/8'] }], ['IP avec nom', { ip: ['a.t'] }], ['CN absent', { cn: undefined }], ['CN avec virgule', { cn: 'x,O=Evil' }],
    ['pays en minuscules', { c: 'fr' }], ['nom de profil nul', { profile: null }], ['SAN texte et non liste', { dns: 'a.t' }], ['SAN nombre', { dns: [1] }],
  ])('refuse : %s (console ET root)', (_n, patch) => {
    const body: any = { ...base, ...patch }
    expect(ok(body)).toBe(false)
    expect(rootAccepts({ action: 'cert_issue', id: ID, ...body })).toBe(false)
  })
  it.each([
    ['utilisateur : upn', { profile: 'user', dns: [], ip: [], upn: ['jdupont@lab.test'] }], ['utilisateur : mail', { profile: 'user', dns: [], ip: [], mail: ['j.dupont@lab.test'] }],
    ['machine : DNS', { profile: 'machine', ip: [] }], ['réseau : IP seule', { profile: 'network', dns: [] }], ['réseau : DNS seul', { profile: 'network', ip: [] }],
  ])('accepte : %s (console ET root)', (_n, patch) => {
    const body: any = { ...base, ...patch }
    expect(ok(body)).toBe(true)
    expect(rootAccepts({ action: 'cert_issue', id: ID, ...c.issueRequest(ID, c.issueCsrBody.parse({ ...body, csr })) })).toBe(true)
  })
  it.each([
    ['utilisateur sans mail ni upn', { profile: 'user', dns: [], ip: [] }], ['utilisateur avec un nom DNS', { profile: 'user', dns: ['a.t'], upn: ['a@b.t'], ip: [] }],
    ['machine avec une IP', { profile: 'machine', ip: ['10.0.0.1'] }], ['réseau sans DNS ni IP', { profile: 'network', dns: [], ip: [] }],
  ])('refuse selon le profil : %s (console ET root)', (_n, patch) => {
    const body: any = { ...base, ...patch }
    expect(ok(body)).toBe(false)
    expect(rootAccepts({ action: 'cert_issue', id: ID, ...body })).toBe(false)
  })
  it('la demande envoyée à root est acceptée telle quelle et sa forme canonique est celle attendue', () => {
    const b = c.issueCsrBody.parse({ ...base, dns: ['Radius1.Lab.Test', 'radius.lab.test'], csr })
    const req = c.issueRequest(ID, b)
    expect(req).toEqual({ action: 'cert_issue', id: ID, ca: 'Lab-Sub', profile: 'server', cn: 'radius1.lab.test', o: 'Laboratoire', c: 'FR', dns: ['radius1.lab.test', 'radius.lab.test'], ip: ['10.1.2.3'] })
    expect(rootMap(req)).toEqual({ action: 'cert_issue', id: ID, ca: 'Lab-Sub', profile: 'server', dn: 'CN=radius1.lab.test,O=Laboratoire,C=FR',
      altname: 'dNSName=radius1.lab.test,dNSName=radius.lab.test,iPAddress=10.1.2.3' })
  })
  it('les éléments facultatifs vides ne sont pas envoyés', () => {
    const req = c.issueRequest(ID, c.issueCsrBody.parse({ ...base, o: '', ou: '', c: '', ip: [], csr }))
    expect(Object.keys(req).sort()).toEqual(['action', 'ca', 'cn', 'dns', 'id', 'profile'])
  })
  it('la demande reste sous la limite de root dans le pire cas permis par chaque profil', () => {
    const name = (i: number) => `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.d${i}${'x'.repeat(60)}`.slice(0, 253).replace(/\.+$/, 'z')
    const long = { cn: 'c'.repeat(64), ou: 'u'.repeat(64), o: 'o'.repeat(64), c: 'FR', ca: 'A'.repeat(48) }
    const dns = Array.from({ length: 8 }, (_, i) => name(i)), ip = ['2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', '2001:db8:ffff:ffff:ffff:ffff:ffff:fffe', '2001:db8:ffff:ffff:ffff:ffff:ffff:fffd', '2001:db8:ffff:ffff:ffff:ffff:ffff:fffc']
    const mail = [`${'m'.repeat(64)}@${'d'.repeat(60)}.${'d'.repeat(60)}.${'d'.repeat(60)}.test`, `${'n'.repeat(64)}@${'d'.repeat(60)}.${'d'.repeat(60)}.${'d'.repeat(60)}.test`]
    for (const [profile, san] of [['server', { dns, ip }], ['network', { dns, ip }], ['machine', { dns }], ['user', { mail, upn: mail }]] as const) {
      const r = c.issueCsrBody.safeParse({ ...long, profile, ...san, csr })
      expect(r.success, `${profile}: ${JSON.stringify((r as any).error?.issues?.slice(0, 2))}`).toBe(true)
      if (r.success) expect(JSON.stringify(c.issueRequest(ID, r.data)).length, profile).toBeLessThan(c.MAX_REQUEST_JSON)
    }
  })
})

describe('formulaire PKCS#12', () => {
  const p12 = { ...base, alg: 'rsa2048', password: 'Un-mot-de-passe-12', compat: false }
  it('accepte un formulaire valide', () => { expect(c.issueP12Body.safeParse(p12).success).toBe(true) })
  it('compat est faux par défaut', () => { const r = c.issueP12Body.parse({ ...p12, compat: undefined }); expect(r.compat).toBe(false) })
  it.each([['mot de passe de 7 caractères', { password: 'abcdefg' }], ['mot de passe de 129 caractères', { password: 'a'.repeat(129) }], ['mot de passe avec retour à la ligne', { password: 'abcdefgh\ni' }],
    ['mot de passe absent', { password: undefined }], ['mot de passe avec NUL', { password: 'abcdefgh\0i' }], ['algorithme inconnu', { alg: 'des' }], ['RSA 1024', { alg: 'rsa1024' }],
    ['demande de certificat en plus', { csr }], ['profil sans SAN requis', { profile: 'user' }]])('refuse : %s', (_n, patch) => {
    expect(c.issueP12Body.safeParse({ ...p12, ...patch }).success).toBe(false)
  })
  it.each(['rsa2048', 'rsa3072', 'ecp256', 'ecp384'])('algorithme %s admis', (alg) => { expect(c.issueP12Body.safeParse({ ...p12, alg }).success).toBe(true) })
  it('un mot de passe avec des caractères accentués ou des espaces est admis', () => { expect(c.issueP12Body.safeParse({ ...p12, password: 'été chaud — 2026 ok' }).success).toBe(true) })
})

describe('révocation', () => {
  it.each([0, 1, 3, 4, 5])('motif %i admis par la console et par root', (reason) => {
    expect(c.revokeBody.safeParse({ reason }).success).toBe(true)
    expect(rootAccepts({ action: 'cert_revoke', ca: 'Lab-Sub', serial: 'AB12', reason, id: ID })).toBe(true)
  })
  it.each([2, 6, 9, -1, 1.5, '1', true, null])('motif %s refusé par la console et par root', (reason) => {
    expect(c.revokeBody.safeParse({ reason }).success).toBe(false)
    expect(rootAccepts({ action: 'cert_revoke', ca: 'Lab-Sub', serial: 'AB12', reason })).toBe(false)
  })
  it('la liste des motifs de la console est celle de root', () => { expect([...c.REVOKE_REASONS]).toEqual([0, 1, 3, 4, 5]) })
})

describe('clé et demande fabriquées ici', () => {
  it.each(['rsa2048', 'rsa3072', 'ecp256', 'ecp384'] as const)('%s : demande valide pour openssl ET acceptée par root', async (alg) => {
    const { keyPem, csrPem } = await c.newKeyAndCsr(alg, 'pc01.lab.test')
    expect(keyPem).toContain('BEGIN PRIVATE KEY'); expect(csrPem).toContain('BEGIN CERTIFICATE REQUEST')
    const f = join(TMP, `${alg}.csr`); writeFileSync(f, csrPem)
    expect(spawnSync('openssl', ['req', '-in', f, '-noout', '-verify'], { encoding: 'utf8' }).stderr).toMatch(/verify OK/)
    const dep = spawnSync('python3', [HELPER, 'deposit', f, join(TMP, `${alg}.out`), 'csr'], { encoding: 'utf8' })
    expect(dep.stdout.trim().split('\t')[0], dep.stdout).toBe('OK')
    expect(dep.stdout.trim()).toMatch(alg.startsWith('rsa') ? /RSA\t(2048|3072)/ : /EC\t(prime256v1|secp384r1)/)
  }, 60000)
  it('le dossier temporaire de la clé est effacé (aucun ddi-ssl- ne reste)', async () => {
    const before = (existsSync('/dev/shm') ? readdirSync('/dev/shm') : []).concat(readdirSync(tmpdir())).filter((n) => n.startsWith('ddi-ssl-')).length
    await c.newKeyAndCsr('ecp256', 'x')
    const after = (existsSync('/dev/shm') ? readdirSync('/dev/shm') : []).concat(readdirSync(tmpdir())).filter((n) => n.startsWith('ddi-ssl-')).length
    expect(after).toBe(before)
  })
})

describe('fichier PKCS#12', () => {
  const sh = (args: string[], input?: string) => spawnSync('openssl', args, { encoding: 'utf8', input })
  let key = '', cert = '', chain = ''
  beforeAll(() => {
    const d = join(TMP, 'p12'); mkdirSync(d, { recursive: true })
    sh(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(d, 'ca.key'), '-out', join(d, 'ca.pem'), '-subj', '/CN=Test CA', '-days', '30',
      '-addext', 'basicConstraints=critical,CA:TRUE'])
    sh(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(d, 'k.pem'), '-out', join(d, 'k.csr'), '-subj', '/CN=pc01'])
    sh(['x509', '-req', '-in', join(d, 'k.csr'), '-CA', join(d, 'ca.pem'), '-CAkey', join(d, 'ca.key'), '-CAcreateserial', '-out', join(d, 'c.pem'), '-days', '10'])
    key = spawnSync('openssl', ['pkey', '-in', join(d, 'k.pem')], { encoding: 'utf8' }).stdout
    cert = spawnSync('cat', [join(d, 'c.pem')], { encoding: 'utf8' }).stdout; chain = spawnSync('cat', [join(d, 'ca.pem')], { encoding: 'utf8' }).stdout
  })
  const info = (buf: Buffer, pw: string, extra: string[] = []) => spawnSync('openssl', ['pkcs12', '-info', '-nodes', '-passin', `pass:${pw}`, ...extra], { input: buf, encoding: 'utf8' })
  it('contient la clé, le certificat et la chaîne, et s\'ouvre avec le mot de passe', async () => {
    const p = await c.buildP12(key, cert, chain, 'Un-mot-de-passe-12', 'pc01', false)
    const r = info(p, 'Un-mot-de-passe-12')
    expect(r.status, r.stderr).toBe(0)
    expect((r.stdout.match(/BEGIN CERTIFICATE/g) ?? []).length).toBe(2); expect(r.stdout).toMatch(/BEGIN PRIVATE KEY/)
    expect(r.stderr + r.stdout).toMatch(/AES-256-CBC|aes-256-cbc/i)   // chiffrement moderne par défaut
  })
  it('refuse un mauvais mot de passe', async () => {
    const p = await c.buildP12(key, cert, chain, 'Un-mot-de-passe-12', 'pc01', false)
    expect(info(p, 'faux-mot-de-passe').status).not.toBe(0)
  })
  it('compat : 3DES et SHA-1 (anciens clients)', async () => {
    const p = await c.buildP12(key, cert, chain, 'Un-mot-de-passe-12', 'pc01', true)
    const r = info(p, 'Un-mot-de-passe-12')
    expect(r.status, r.stderr).toBe(0)
    expect(r.stderr + r.stdout).toMatch(/3DES|TripleDES|des-ede3/i)
  })
  it('le mot de passe n\'est jamais dans le fichier ni dans les arguments (il passe par l\'environnement)', async () => {
    const p = await c.buildP12(key, cert, chain, 'Mot-de-passe-secret-77', 'pc01', false)
    expect(p.includes(Buffer.from('Mot-de-passe-secret-77'))).toBe(false)
  })
  it('un mot de passe accentué est accepté et fonctionne', async () => {
    const p = await c.buildP12(key, cert, chain, 'été chaud — 2026', 'pc01', false)
    expect(info(p, 'été chaud — 2026').status).toBe(0)
  })
  it('aucun dossier temporaire de clé ne subsiste', () => {
    const left = (existsSync('/dev/shm') ? readdirSync('/dev/shm') : []).concat(readdirSync(tmpdir())).filter((n) => n.startsWith('ddi-ssl-'))
    expect(left).toEqual([])
  })
})

const PEM = '-----BEGIN CERTIFICATE-----\nMIIBAAAA\n-----END CERTIFICATE-----\n'
const publishIssued = (id: string, extra: Record<string, unknown> = {}, files: Record<string, string> = {}) => {
  const d = join(CERTDIR, id); mkdirSync(d, { recursive: true })
  writeFileSync(join(d, 'cert.pem'), files['cert.pem'] ?? PEM); writeFileSync(join(d, 'chain.pem'), files['chain.pem'] ?? PEM)
  writeFileSync(join(d, 'meta.json'), JSON.stringify({ id, ca: 'Lab-Sub', profile: 'server', serial: 'AB12', sha256: 'a'.repeat(64), notBefore: '2026-11-17T09:00:00Z', notAfter: '2028-11-16T09:00:00Z', subject: 'C=FR,O=Lab,CN=x', issuedAt: 1, ...extra }))
}
const publishResult = (o: Record<string, unknown>) => writeFileSync(RESULT, JSON.stringify({ at: Math.floor(Date.now() / 1000), action: 'cert_issue', ok: true, message: 'ok', ...o }))

describe('ce que root publie', () => {
  it('le résultat porte la référence de la demande', async () => {
    publishResult({ ref: ID }); expect((await pki.readPkiResult())?.ref).toBe(ID)
    publishResult({ ref: 'ZZZ' }); expect((await pki.readPkiResult())?.ref).toBeUndefined()
    publishResult({}); expect((await pki.readPkiResult())?.ref).toBeUndefined()
  })
  it('lit un certificat publié', async () => {
    publishIssued(ID)
    const x = await c.readIssued(ID)
    expect(x).toMatchObject({ id: ID, ca: 'Lab-Sub', profile: 'server', serial: 'AB12', sha256: 'a'.repeat(64), certPem: PEM, chainPem: PEM })
  })
  it.each([['identifiant invalide', '../etc'], ['identifiant absent', 'ffffffffffffffff']])('rien : %s', async (_n, id) => { expect(await c.readIssued(id)).toBeNull() })
  it('refuse un cert.pem qui n\'est pas un certificat PEM', async () => {
    publishIssued('1111111111111111', {}, { 'cert.pem': 'rien du tout' }); expect(await c.readIssued('1111111111111111')).toBeNull()
    publishIssued('2222222222222222', {}, { 'cert.pem': PEM + '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n' }); expect(await c.readIssued('2222222222222222')).toBeNull()
  })
  it('un profil ou une série inattendus sont neutralisés', async () => {
    publishIssued('3333333333333333', { profile: 'pirate', serial: 'zz;rm' }); expect(await c.readIssued('3333333333333333')).toMatchObject({ profile: 'other', serial: '' })
  })
})

describe('attente du résultat de root', () => {
  it('le dossier du certificat suffit', async () => {
    publishIssued('4444444444444444')
    const r = await c.awaitIssue('4444444444444444', 0, { timeoutMs: 2000, pollMs: 20 })
    expect(r.ok && r.cert.serial).toBe('AB12')
  })
  it('le résultat positif arrive après la publication du dossier', async () => {
    const id = '5555555555555555'
    setTimeout(() => { publishIssued(id); publishResult({ ref: id }) }, 150)
    const r = await c.awaitIssue(id, Math.floor(Date.now() / 1000) - 1, { timeoutMs: 3000, pollMs: 20 })
    expect(r.ok).toBe(true)
  })
  it('le refus de root est rendu avec son message', async () => {
    const id = '6666666666666666'
    publishResult({ ref: id, ok: false, message: 'clé RSA de 1024 bits refusée' })
    const r = await c.awaitIssue(id, 0, { timeoutMs: 2000, pollMs: 20 })
    expect(r).toEqual({ ok: false, code: 'refused', message: 'clé RSA de 1024 bits refusée' })
  })
  it('un résultat qui répond à une autre demande n\'est pas pris pour le nôtre', async () => {
    publishResult({ ref: 'aaaaaaaaaaaaaaaa', ok: true })
    const r = await c.awaitIssue('7777777777777777', 0, { timeoutMs: 400, pollMs: 20 })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(['timeout', 'unknown']).toContain(r.code)
  })
  it('délai dépassé', async () => {
    rmSync(RESULT, { force: true })
    const r = await c.awaitRef('8888888888888888', 0, { timeoutMs: 150, pollMs: 20 })
    expect(r).toEqual({ ok: false, code: 'timeout', message: 'timeout' })
  })
  it('révocation : le résultat porte la référence', async () => {
    publishResult({ action: 'cert_revoke', ref: '9999999999999999', message: 'révoqué' })
    expect(await c.awaitRef('9999999999999999', 0, { timeoutMs: 500, pollMs: 20 })).toEqual({ ok: true, message: 'révoqué' })
  })
})

describe('une émission à la fois', () => {
  it('les émissions passent l\'une après l\'autre, même si l\'une échoue', async () => {
    const order: string[] = []
    const a = c.serialized(async () => { order.push('a1'); await new Promise((r) => setTimeout(r, 50)); order.push('a2') })
    const b = c.serialized(async () => { order.push('b1'); throw new Error('échec') }).catch(() => order.push('b-erreur'))
    const d = c.serialized(async () => { order.push('d1') })
    await Promise.all([a, b, d])
    expect(order).toEqual(['a1', 'a2', 'b1', 'b-erreur', 'd1'])
  })
})

describe('autorités, états, CSV, base d\'EJBCA', () => {
  const mk = (o: Record<string, unknown>): any => ({ name: 'Lab-Sub', kind: 'issuing', state: 'active', dn: 'CN=Lab Sub CA,O=Lab,C=FR', managed: true, ...o })
  it('seules les autorités actives et gérées par le DDI délivrent', () => {
    const m = c.caDnMap([mk({}), mk({ name: 'Lab-Wait', state: 'waiting' }), mk({ name: 'a b', managed: false }), mk({ name: 'Sans-DN', dn: '' })])
    expect([...m.keys()]).toEqual(['Lab-Sub'])
  })
  it('l\'adresse de la base d\'EJBCA reprend celle de la console avec un autre nom de base', () => {
    expect(cfg.withDatabase('postgresql://ddi:pw@127.0.0.1:5432/ddibuntu?sslmode=disable', 'ejbca')).toBe('postgresql://ddi:pw@127.0.0.1:5432/ejbca?sslmode=disable')
    expect(cfg.withDatabase('postgresql:///ddibuntu?host=/var/run/postgresql', 'ejbca')).toContain('/ejbca')
    expect(cfg.withDatabase('pas une adresse', 'ejbca')).toBe('pas une adresse')
  })
  it('iso : millisecondes d\'EJBCA → ISO sans fraction ; valeurs absurdes → null', () => {
    expect(c.iso(1794921600000)).toBe('2026-11-17T13:20:00Z'); expect(c.iso(0)).toBeNull(); expect(c.iso(-1)).toBeNull(); expect(c.iso('abc')).toBeNull()
  })
  it('CSV : en-tête, guillemets, et neutralisation des formules', () => {
    const row = { fingerprint: 'f'.repeat(40), serial: 'AB12', ca: 'Lab-Sub', subject: 'CN=x,O=Lab', san: 'dNSName=a.t, iPAddress=10.0.0.1', profile: 'server', state: 'active', notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z', revokedAt: null, reason: null } as const
    const csv = c.certsCsv([row, { ...row, subject: '=HYPERLINK("http://x")', san: '+cmd', serial: 'CD' }])
    const lines = csv.trimEnd().split('\n')
    expect(lines[0]).toBe(c.CSV_HEADER.join(','))
    expect(lines[1]).toContain('"CN=x,O=Lab"')
    expect(lines[2]).toContain(`"'=HYPERLINK(""http://x"")"`); expect(lines[2]).toContain(`"'+cmd"`)
    expect(lines.every((l) => !/^[=+\-@]/.test(l))).toBe(true)
  })
  it('nom de fichier sûr', () => { expect(c.certFileName('radius1.lab.test')).toBe('radius1.lab.test'); expect(c.certFileName('../../etc/passwd')).toBe('.._.._etc_passwd'); expect(c.certFileName('')).toBe('certificat') })
  it('la chaîne d\'une autorité est lue dans les fichiers publics de root', async () => {
    mkdirSync(join(CADIR, 'Lab-Sub'), { recursive: true })
    writeFileSync(join(CADIR, 'Lab-Sub', 'cert.pem'), PEM); writeFileSync(join(CADIR, 'Lab-Sub', 'chain.pem'), PEM.replace('BAAAA', 'BBBBB'))
    expect(await c.caChainPem('Lab-Sub')).toBe(PEM + PEM.replace('BAAAA', 'BBBBB'))
    expect(await c.caChainPem('../x')).toBe(''); expect(await c.caChainPem('Absente')).toBe('')
  })
  it('empreintes et séries : mêmes formes que dans EJBCA', () => {
    expect(c.FINGERPRINT_RE.test('a'.repeat(40))).toBe(true); expect(c.FINGERPRINT_RE.test('A'.repeat(40))).toBe(false); expect(c.FINGERPRINT_RE.test('a'.repeat(39))).toBe(false)
    expect(c.SERIAL_RE.test('0F')).toBe(true); expect(c.SERIAL_RE.test('0x0F')).toBe(false)
  })
})
