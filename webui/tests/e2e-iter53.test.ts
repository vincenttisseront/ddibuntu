// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.4 — reprise d'une autorité EXISTANTE depuis un fichier PKCS#12 déposé dans la console. La clé d'une autorité entre
// ici dans la PKI : elle ne traverse la console que le temps de la requête (deux dépôts 0600 que « root » efface dès qu'il les a lus), jamais dans la demande, l'audit, le
// journal ni la base de la console. « root » est simulé par ce test : il lit la demande et les dépôts (sans les contrôler : c'est le travail de pki-helper.py, vérifié par
// tests/b32-pki-ca.sh et, avec le vrai EJBCA, par tests/b33-pki-ca-live.sh), les efface, puis publie le résultat et la liste des autorités comme ddibuntu-pki.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3481, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s53-')), GEN = join(TMP, 'gen'), IN = join(GEN, 'pki-in'), REQ = join(GEN, '.pki-request')
const STATUS = join(TMP, 'ps.json'), RESULT = join(TMP, 'pr.json'), CAS = join(TMP, 'pki-cas.json'), CADIR = join(TMP, 'pki-ca'), SSL = join(TMP, 'ssl')
let srv: ChildProcess, db: pg.Client, srvLog = ''

class Client {
  cookie = ''; csrf = ''
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { cookie: this.cookie }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* texte */ }
    return { status: r.status, json, text, headers: r.headers }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 100)) } throw new Error('délai dépassé') }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const read = (p: string) => readFileSync(p, 'utf8')
const sh = (args: string[], input?: string | Buffer) => spawnSync('openssl', args, { encoding: 'utf8', input })
const setStatus = (o: Record<string, unknown>) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', digest: '', nets: [], health: 'ALLOK', port: 8080,
  dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab.test', casCount: 1, resetAllowed: false, ...o }))
const pubCa = (o: Record<string, unknown>) => ({ name: 'Lab-Root', kind: 'root', state: 'active', dn: 'CN=Lab Root CA,O=Lab,C=FR', issuer: 'CN=Lab Root CA,O=Lab,C=FR', selfSigned: true, serial: 'ab', notBefore: '2026-01-01T00:00:00Z',
  notAfter: '2036-01-01T00:00:00Z', keyAlg: 'EC', keyBits: 256, curve: 'prime256v1', sigAlg: 'ecdsa-with-SHA256', pathLen: null, sha256: 'a'.repeat(64), signedBy: 'self', alg: 'ecp256', createdAt: 1700000000, extRoot: '',
  crlUrl: 'http://pki.lab.test:8080/crl/Lab-Root', certUrl: 'http://pki.lab.test:8080/cert/Lab-Root', crl: null, files: { cert: true, chain: false, csr: false, crl: false }, ...o })
let published: any[] = [pubCa({})]
const publish = () => writeFileSync(CAS, JSON.stringify({ at: 1700000000, ok: true, hostname: 'pki.lab.test', port: 8080, cas: published }))

// Mot de passe volontairement difficile : accents, espace, guillemets, dollar, apostrophe.
const P12PW = 'Pä55 "wörd\'$x'
let P12: Buffer, P12B64 = ''

// ---- « root » simulé : lit la demande et les dépôts, les efface, publie ----
interface Seen { req: any; reqText: string; p12: Buffer | null; pw: string | null; modes: { p12: number; pw: number } | null }
const rootLog: Seen[] = []
let rootBusy = false, rootMute = false, rootRefuse: string | null = null, rootTimer: NodeJS.Timeout | null = null
const publishResult = (action: string, ok: boolean, message: string) => writeFileSync(RESULT, JSON.stringify({ at: Math.floor(Date.now() / 1000), action, ok, message }))
function startRoot() {
  rootTimer = setInterval(() => {
    if (rootBusy || rootMute || !existsSync(REQ)) return
    rootBusy = true
    try {
      const reqText = read(REQ); const req = JSON.parse(reqText); rmSync(REQ, { force: true })
      const fp = join(IN, `${req.name}.p12`), fw = join(IN, `${req.name}.p12pw`)
      const seen: Seen = { req, reqText, p12: existsSync(fp) ? readFileSync(fp) : null, pw: existsSync(fw) ? read(fw) : null,
        modes: existsSync(fp) && existsSync(fw) ? { p12: statSync(fp).mode & 0o777, pw: statSync(fw).mode & 0o777 } : null }
      rootLog.push(seen)
      rmSync(fp, { force: true }); rmSync(fw, { force: true })   // consommés quoi qu'il arrive
      if (rootRefuse) { publishResult(req.action, false, rootRefuse); return }
      const isRoot = req.name === 'Imp-Root'
      mkdirSync(join(CADIR, req.name), { recursive: true }); writeFileSync(join(CADIR, req.name, 'cert.pem'), read(join(SSL, 'k.pem')))   // le certificat PUBLIC que root publie
      published.push(pubCa(isRoot
        ? { name: req.name, dn: `CN=${req.name},O=Import,C=FR`, imported: true }
        : { name: req.name, kind: 'issuing', dn: `CN=${req.name},O=Import,C=FR`, issuer: 'CN=Import Root,O=Import,C=FR', selfSigned: false, signedBy: 'external', imported: true, files: { cert: true, chain: true, csr: false, crl: true } }))
      publish(); setStatus({ casCount: published.length })
      publishResult(req.action, true, `Autorité « ${req.name} » reprise du fichier PKCS#12 : sa clé est maintenant dans la base du DDI.`)
    } catch (e) { publishResult('ca_import_p12', false, `erreur du root simulé : ${(e as Error).message}`) } finally { rootBusy = false }
  }, 40)
}
const clear = () => { rmSync(REQ, { force: true }); rmSync(RESULT, { force: true }); rootLog.length = 0; for (const f of existsSync(IN) ? readdirSync(IN) : []) rmSync(join(IN, f), { force: true }) }
const inDir = () => (existsSync(IN) ? readdirSync(IN) : [])
const body = (o: Record<string, unknown> = {}) => ({ name: 'Imp-Iss', p12: P12B64, password: P12PW, confirm: 'Imp-Iss', ...o })
const URL = '/api/pki/cas/p12'

beforeAll(async () => {
  for (const d of [GEN, IN, SSL, CADIR]) mkdirSync(d, { recursive: true })
  // un vrai fichier PKCS#12 (clé + certificat) : la console ne l'ouvre jamais, mais sa forme (DER commençant par une SEQUENCE) est contrôlée
  sh(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(SSL, 'k.key'), '-out', join(SSL, 'k.pem'), '-days', '3650', '-subj', '/CN=Import Issuing/O=Import/C=FR',
    '-addext', 'basicConstraints=critical,CA:TRUE'])
  const r = spawnSync('openssl', ['pkcs12', '-export', '-inkey', join(SSL, 'k.key'), '-in', join(SSL, 'k.pem'), '-passout', `pass:${P12PW}`, '-out', join(SSL, 'k.p12')])
  expect(r.status, String(r.stderr)).toBe(0)
  P12 = readFileSync(join(SSL, 'k.p12')); P12B64 = P12.toString('base64')
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT, DDI_PKI_CAS: CAS, DDI_PKI_CA_DIR: CADIR } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  for (const [u, ro, c] of [['lect', 'viewer', viewer], ['oper', 'operator', oper]] as const) { expect((await admin.post('/api/users', { username: u, role: ro, password: PW })).status).toBe(200); expect((await c.login(u, PW)).status).toBe(200) }
  setStatus({}); publish(); startRoot()
}, 300000)
afterAll(async () => { if (rootTimer) clearInterval(rootTimer); srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('droits et validation (rien n\'est déposé tant que la demande est refusée)', () => {
  it('réservé à l\'administrateur', async () => {
    code(await anon.post(URL, body()), 401, 'unauthenticated')
    for (const c of [viewer, oper]) code(await c.post(URL, body()), 403, 'forbidden')
    expect(inDir()).toEqual([]); expect(existsSync(REQ)).toBe(false)
  })
  it('corps strict : champs manquants, inconnus, mal formés', async () => {
    clear()
    const bad: Array<[string, Record<string, unknown>]> = [
      ['nom absent', { name: undefined }], ['fichier absent', { p12: undefined }], ['mot de passe absent', { password: undefined }], ['confirmation absente', { confirm: undefined }],
      ['mot de passe vide', { password: '' }], ['mot de passe de 129 caractères', { password: 'a'.repeat(129) }], ['mot de passe avec caractère de contrôle', { password: 'ab\ncd' }],
      ['champ inconnu', { extra: 1 }], ['nom avec espace', { name: 'a b', confirm: 'a b' }], ['nom ManagementCA', { name: 'ManagementCA', confirm: 'ManagementCA' }],
      ['nom réservé ExtRoot-…', { name: 'ExtRoot-0a1b2c3d', confirm: 'ExtRoot-0a1b2c3d' }], ['nom qui remonte l\'arborescence', { name: '../x', confirm: '../x' }],
      ['fichier qui n\'est pas du base64', { p12: 'pas du base64 !!' }], ['fichier trop gros (plus de 64 Ko)', { p12: Buffer.alloc(70000, 0x30).toString('base64') }],
      ['nom numérique', { name: 123 }], ['mot de passe en nombre', { password: 123456 }],
    ]
    for (const [what, o] of bad) { const r = await admin.post(URL, body(o)); expect(r.status, `${what} : ${r.text}`).toBe(400); expect(r.json?.data?.code, what).toBe('validation') }
    expect(inDir(), 'aucun dépôt laissé par une demande refusée').toEqual([]); expect(existsSync(REQ)).toBe(false)
  })
  it('confirmation par le nom : refusée si elle diffère', async () => {
    code(await admin.post(URL, body({ confirm: 'imp-iss' })), 400, 'pki_p12_confirm')
    code(await admin.post(URL, body({ confirm: '' })), 400, 'pki_p12_confirm')
    expect(inDir()).toEqual([])
  })
  it('un fichier qui n\'est pas un PKCS#12 (pas un DER) est refusé avant tout dépôt', async () => {
    code(await admin.post(URL, body({ p12: Buffer.from('-----BEGIN CERTIFICATE-----\nMIIB\n').toString('base64') })), 400, 'pki_bad_p12')
    code(await admin.post(URL, body({ p12: Buffer.alloc(40, 0).toString('base64') })), 400, 'pki_bad_p12')
    code(await admin.post(URL, body({ p12: 'AAAA' })), 400, 'validation')   // trop court : refusé dès la validation
    expect(inDir()).toEqual([]); expect(existsSync(REQ)).toBe(false)
  })
})

describe('préconditions', () => {
  it('PKI absente ou pas en service : 409 sans dépôt', async () => {
    setStatus({ installed: false, state: 'absent' }); code(await admin.post(URL, body()), 409, 'pki_not_installed')
    setStatus({ state: 'stopped', health: '' }); code(await admin.post(URL, body()), 409, 'pki_not_ready')
    setStatus({}); expect(inDir()).toEqual([]); expect(existsSync(REQ)).toBe(false)
  })
  it('nom déjà pris (casse ignorée) : 409 sans dépôt', async () => {
    code(await admin.post(URL, body({ name: 'Lab-Root', confirm: 'Lab-Root' })), 409, 'pki_ca_exists')
    code(await admin.post(URL, body({ name: 'lab-root', confirm: 'lab-root' })), 409, 'pki_ca_exists')
    expect(inDir()).toEqual([])
  })
  it('une demande déjà en cours : 409, et ses dépôts ne sont pas touchés', async () => {
    rootMute = true
    writeFileSync(REQ, '{"action":"status"}\n'); writeFileSync(join(IN, 'Autre.p12'), 'x')
    code(await admin.post(URL, body()), 409, 'request_pending')
    expect(inDir()).toEqual(['Autre.p12']); expect(read(REQ)).toBe('{"action":"status"}\n')
    clear(); rootMute = false
  })
})

describe('import accepté : le fichier et son mot de passe ne vont qu\'à root', () => {
  it('dépôts 0600 + demande sans aucun secret ; root les efface', async () => {
    clear(); rootRefuse = null
    const r = await admin.post(URL, body())
    expect(r.status, r.text).toBe(200); expect(r.json).toMatchObject({ accepted: true })
    await until(async () => rootLog.length === 1 && existsSync(RESULT))
    const s = rootLog[0]!
    expect(s.req).toEqual({ action: 'ca_import_p12', name: 'Imp-Iss' })
    expect(s.reqText).not.toContain(P12PW); expect(s.reqText).not.toContain(P12B64); expect(s.reqText.length).toBeLessThan(200)
    expect(s.p12 && Buffer.compare(s.p12, P12)).toBe(0)                   // les octets du fichier, décodés du base64
    expect(s.pw).toBe(P12PW)                                              // mot de passe exact (UTF-8), sans retour à la ligne ajouté
    expect(s.modes).toEqual({ p12: 0o600, pw: 0o600 })                    // jamais lisibles par un autre compte
    expect(inDir()).toEqual([])                                           // root les a effacés
    expect(JSON.parse(read(RESULT))).toMatchObject({ action: 'ca_import_p12', ok: true })
  })
  it('l\'autorité publiée est marquée « importée » ; une racine reprise devient un signataire possible', async () => {
    const l = (await admin.get('/api/pki/cas')).json
    expect(l.cas.find((c: any) => c.name === 'Imp-Iss')).toMatchObject({ kind: 'issuing', state: 'active', imported: true, managed: true })
    expect(l.cas.find((c: any) => c.name === 'Lab-Root').imported).toBe(false)
    expect(l.signers).toEqual(['Lab-Root'])
    clear()
    expect((await admin.post(URL, body({ name: 'Imp-Root', confirm: 'Imp-Root' }))).status).toBe(200)
    await until(async () => rootLog.length === 1 && existsSync(RESULT))
    const l2 = (await admin.get('/api/pki/cas')).json
    expect(l2.cas.find((c: any) => c.name === 'Imp-Root')).toMatchObject({ kind: 'root', imported: true, selfSigned: true })
    expect(l2.signers).toEqual(['Lab-Root', 'Imp-Root'])
  })
  it('les autorités reprises sont publiables dans l\'Active Directory comme les autres (racine → Certification Authorities, émettrice → AIA)', async () => {
    const r = await admin.get('/api/pki/ad')
    expect(r.status, r.text).toBe(200)
    expect(r.json.publications.map((p: any) => [p.name, p.container, p.state])).toEqual(expect.arrayContaining([['Imp-Iss', 'aia', 'not_published'], ['Imp-Root', 'roots', 'not_published']]))
  })
  it('le nom repris est ensuite refusé comme déjà utilisé', async () => {
    clear(); code(await admin.post(URL, body({ name: 'Imp-Iss', confirm: 'Imp-Iss' })), 409, 'pki_ca_exists'); expect(inDir()).toEqual([])
  })
  it('un fichier ou un mot de passe de plus de la limite acceptée passe, au-delà la validation refuse', async () => {
    clear()
    // 64 Ko pile (DER fictif commençant par 0x30) : accepté par la console, c'est root qui dira si c'est un PKCS#12
    const big = Buffer.alloc(65536, 0x31); big[0] = 0x30
    expect((await admin.post(URL, body({ name: 'Imp-Big', confirm: 'Imp-Big', p12: big.toString('base64'), password: 'x'.repeat(128) }))).status).toBe(200)
    await until(async () => rootLog.length === 1 && existsSync(RESULT))
    expect(rootLog[0]!.p12!.length).toBe(65536); expect(rootLog[0]!.pw!.length).toBe(128)
    clear()
    const over = Buffer.alloc(65537, 0x31); over[0] = 0x30
    code(await admin.post(URL, body({ name: 'Imp-Over', confirm: 'Imp-Over', p12: over.toString('base64') })), 400, 'pki_bad_p12')
    expect(inDir()).toEqual([])
  })
})

describe('refus de root, audit, journal', () => {
  it('root refuse le fichier : le résultat négatif est relayé, les dépôts sont déjà effacés', async () => {
    clear(); rootRefuse = 'fichier PKCS#12 refusé : mot de passe du fichier incorrect'
    expect((await admin.post(URL, body({ name: 'Imp-Mauvais', confirm: 'Imp-Mauvais' }))).status).toBe(200)
    await until(async () => rootLog.length === 1 && existsSync(RESULT))
    const st = (await admin.get('/api/pki')).json
    expect(st.result).toMatchObject({ action: 'ca_import_p12', ok: false, message: 'fichier PKCS#12 refusé : mot de passe du fichier incorrect' })
    expect(inDir()).toEqual([])
    expect((await admin.get('/api/pki/cas')).json.cas.some((c: any) => c.name === 'Imp-Mauvais')).toBe(false)
    rootRefuse = null
  })
  it('root ne répond pas : les dépôts restent 0600 (purgés par root après 10 minutes), une seconde demande est refusée', async () => {
    clear(); rootMute = true
    expect((await admin.post(URL, body({ name: 'Imp-Muet', confirm: 'Imp-Muet' }))).status).toBe(200)
    await sleep(300)
    expect(inDir().sort()).toEqual(['Imp-Muet.p12', 'Imp-Muet.p12pw'])
    for (const f of inDir()) expect(statSync(join(IN, f)).mode & 0o777).toBe(0o600)
    code(await admin.post(URL, body({ name: 'Imp-Autre', confirm: 'Imp-Autre' })), 409, 'request_pending')
    expect(inDir().sort()).toEqual(['Imp-Muet.p12', 'Imp-Muet.p12pw'])   // la seconde demande n'a rien déposé
    rootMute = false
    await until(async () => rootLog.length === 1 && existsSync(RESULT))   // root reprend : il consomme
    expect(inDir()).toEqual([])
  })
  it('l\'audit nomme l\'action et l\'autorité, jamais le mot de passe ni le fichier', async () => {
    const a = await rows(`select detail::text as d from audit_log where action = 'pki.ca_import_p12' order by id`)
    expect(a.length).toBeGreaterThanOrEqual(4)
    expect(a[0].d).toMatch(/"name": "Imp-Iss"/); expect(a[0].d).toMatch(/"bytes": \d+/)
    const all = JSON.stringify(await rows('select * from audit_log'))
    expect(all).not.toContain(P12PW); expect(all).not.toContain(P12B64); expect(all).not.toContain('wörd')
    expect(all).not.toMatch(/PRIVATE KEY|ENCRYPTED/)
  })
  it('ni le journal du serveur ni la base de la console ne contiennent le mot de passe ou le fichier', async () => {
    expect(srvLog).not.toContain(P12PW); expect(srvLog).not.toContain(P12B64.slice(0, 60))
    for (const t of (await rows(`select table_name from information_schema.tables where table_schema = 'public' and table_type = 'BASE TABLE'`)).map((x) => x.table_name as string)) {
      const dump = JSON.stringify(await rows(`select * from "${t}"`))
      expect(dump, `table ${t}`).not.toContain(P12PW); expect(dump, `table ${t}`).not.toContain(P12B64.slice(0, 60))
    }
  })
})
