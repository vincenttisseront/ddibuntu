// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.1 — autorités de la PKI : droits, validation, dépôts pour root (demande JSON minuscule + fichiers publics
// pki-in/), préconditions lues dans ce que root publie, téléchargements de fichiers publics, remise à zéro confirmée, nom public imposé par des données existantes,
// audit sans contenu de fichier. Ce que root en fait (EJBCA réel) est vérifié par tests/b32-pki-ca.sh et tests/b33-pki-ca-live.sh.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3446, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s45-')), GEN = join(TMP, 'gen'), IN = join(GEN, 'pki-in'), REQ = join(GEN, '.pki-request')
const STATUS = join(TMP, 'ps.json'), RESULT = join(TMP, 'pr.json'), CAS = join(TMP, 'pki-cas.json'), CADIR = join(TMP, 'pki-ca')
let srv: ChildProcess, db: pg.Client, srvLog = ''

class Client {
  cookie = ''; csrf = ''
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { cookie: this.cookie }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const buf = Buffer.from(await r.arrayBuffer()); const text = buf.toString('utf8'); let json: any = null; try { json = JSON.parse(text) } catch { /* fichier */ }
    return { status: r.status, json, text, buf, headers: r.headers }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const setStatus = (o: Record<string, unknown>) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', digest: '', nets: [], health: 'ALLOK', port: 8080,
  dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab.test', casCount: 0, resetAllowed: true, ...o }))
const rootDone = () => rmSync(REQ, { force: true })   // root a traité la demande
const sent = () => JSON.parse(readFileSync(REQ, 'utf8'))
const noDeposit = () => (existsSync(IN) ? readdirSync(IN) : [])
const clearDeposits = () => { if (existsSync(IN)) for (const f of readdirSync(IN)) rmSync(join(IN, f), { force: true }) }
const CERT = '-----BEGIN CERTIFICATE-----\nMIIBAAAA\n-----END CERTIFICATE-----\n', CRLPEM = '-----BEGIN X509 CRL-----\nMIIBAAAA\n-----END X509 CRL-----\n'
const ca = (o: Record<string, unknown>) => ({ name: 'Lab-Root', kind: 'root', state: 'active', status: 1, dn: 'CN=Lab Root CA,O=Lab,C=FR', issuer: 'CN=Lab Root CA,O=Lab,C=FR', selfSigned: true, serial: 'ab', notBefore: '2026-01-01T00:00:00Z', notAfter: '2036-01-01T00:00:00Z',
  keyAlg: 'RSA', keyBits: 3072, curve: '', sigAlg: 'sha256WithRSAEncryption', pathLen: null, sha256: 'a'.repeat(64), signedBy: 'self', alg: 'rsa3072', createdAt: 1700000000, extRoot: null,
  crlUrl: 'http://pki.lab.test:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3DLab', certUrl: 'http://pki.lab.test:8080/ejbca/publicweb/webdist/certdist?cmd=cacert&issuer=CN%3DLab',
  crl: { number: 2, thisUpdate: '2026-11-17T09:00:00Z', nextUpdate: '2026-11-24T09:00:00Z', bytes: 500 }, files: { cert: true, chain: false, csr: false, crl: true }, ...o })
const publish = (cas: unknown[]) => writeFileSync(CAS, JSON.stringify({ at: 1700000000, ok: true, hostname: 'pki.lab.test', port: 8080, cas }))
const FIXTURE = [
  ca({}),
  ca({ name: 'Lab-Sub', kind: 'issuing', state: 'active', signedBy: 'Lab-Root', selfSigned: false, files: { cert: true, chain: true, csr: false, crl: true } }),
  ca({ name: 'Lab-Wait', kind: 'issuing', state: 'waiting', status: 2, signedBy: 'external', extRoot: 'ExtRoot-0a1b2c3d', crl: null, files: { cert: false, chain: true, csr: true, crl: false } }),
  ca({ name: 'ExtRoot-0a1b2c3d', kind: 'extroot', state: 'external', status: 6, signedBy: '', files: { cert: true, chain: false, csr: false, crl: false }, crl: null }),
  ca({ name: 'a b', kind: 'unknown', state: 'other', files: { cert: false, chain: false, csr: false, crl: false } }),
]

beforeAll(async () => {
  mkdirSync(GEN, { recursive: true })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT,
    DDI_PKI_CAS: CAS, DDI_PKI_CA_DIR: CADIR } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  expect((await oper.login('oper', PW)).status).toBe(200)
}, 300000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('droits', () => {
  it('les autorités sont réservées à l\'administrateur', async () => {
    setStatus({}); publish(FIXTURE)
    code(await anon.get('/api/pki/cas'), 401, 'unauthenticated')
    for (const c of [viewer, oper]) {
      code(await c.get('/api/pki/cas'), 403, 'forbidden')
      code(await c.post('/api/pki/cas/root', { name: 'R', alg: 'rsa3072', days: 3650, cn: 'X' }), 403, 'forbidden')
      code(await c.post('/api/pki/cas/issuing', { name: 'I', alg: 'rsa3072', days: 1825, cn: 'X', signedBy: 'Lab-Root' }), 403, 'forbidden')
      code(await c.post('/api/pki/cas/Lab-Wait/import', { certificate: { pem: CERT } }), 403, 'forbidden')
      code(await c.post('/api/pki/cas/Lab-Root/crl', {}), 403, 'forbidden')
      code(await c.post('/api/pki/cas/ExtRoot-0a1b2c3d/rootcrl', { crl: { pem: CRLPEM } }), 403, 'forbidden')
      code(await c.get('/api/pki/cas/Lab-Root/cert'), 403, 'forbidden')
      code(await c.post('/api/pki/reset', { confirm: 'pki.lab.test' }), 403, 'forbidden')
    }
    expect(existsSync(REQ)).toBe(false); expect(noDeposit()).toEqual([])
  })
})

describe('liste', () => {
  it('rien de publié : liste vide, PKI pas prête', async () => {
    rmSync(CAS, { force: true }); setStatus({ installed: false, state: 'absent', active: false })
    const r = await admin.get('/api/pki/cas'); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ at: null, cas: [], signers: [], ready: false })
  })
  it('liste ce que root publie ; seules les racines actives du DDI peuvent signer', async () => {
    setStatus({}); publish(FIXTURE)
    const r = (await admin.get('/api/pki/cas')).json
    expect(r.cas.map((c: any) => c.name)).toEqual(['Lab-Root', 'Lab-Sub', 'Lab-Wait', 'ExtRoot-0a1b2c3d', 'a b'])
    expect(r.signers).toEqual(['Lab-Root']); expect(r.ready).toBe(true); expect(r.hostname).toBe('pki.lab.test')
    expect(r.cas.find((c: any) => c.name === 'a b').managed).toBe(false)
    expect(r.cas.find((c: any) => c.name === 'Lab-Wait')).toMatchObject({ extRoot: 'ExtRoot-0a1b2c3d', state: 'waiting', files: { csr: true } })
  })
})

describe('préconditions', () => {
  it('PKI non installée ou qui ne répond pas : refus avant tout dépôt', async () => {
    setStatus({ installed: false, state: 'absent', active: false })
    code(await admin.post('/api/pki/cas/root', { name: 'R1', alg: 'rsa3072', days: 3650, cn: 'X' }), 409, 'pki_not_installed')
    setStatus({ state: 'starting', health: '' })
    code(await admin.post('/api/pki/cas/root', { name: 'R1', alg: 'rsa3072', days: 3650, cn: 'X' }), 409, 'pki_not_ready')
    code(await admin.post('/api/pki/cas/Lab-Root/crl', {}), 409, 'pki_not_ready')
    code(await admin.post('/api/pki/cas/Lab-Wait/import', { certificate: { pem: CERT } }), 409, 'pki_not_ready')
    expect(existsSync(REQ)).toBe(false); expect(noDeposit()).toEqual([])
    setStatus({})
  })
})

describe('racine de laboratoire', () => {
  it('validation : noms, algorithmes, durées, éléments du nom distinctif, champs inconnus', async () => {
    const base = { name: 'R1', alg: 'rsa3072', days: 3650, cn: 'X' }
    const bad: Array<Record<string, unknown>> = [
      { name: '' }, { name: 'a b' }, { name: 'ManagementCA' }, { name: 'ExtRoot-0a1b2c3d' }, { name: '../etc' }, { name: 'x'.repeat(49) }, { alg: 'des' }, { alg: undefined },
      { days: 364 }, { days: 7306 }, { days: '3650' }, { days: 1.5 }, { cn: '' }, { cn: undefined }, { cn: 'X,O=pirate' }, { cn: 'X+UID=1' }, { cn: 'X/Y' }, { cn: 'X\nY' }, { cn: 'a'.repeat(65) },
      { c: 'FRA' }, { c: 'fr' }, { o: 'A;B' }, { ou: 'A=B' }, { extra: 1 }, { image: 'docker.io/evil/x:1.0.0' }, { key: '-----BEGIN PRIVATE KEY-----' },
    ]
    for (const b of bad) { const r = await admin.post('/api/pki/cas/root', { ...base, ...b }); expect([400], `${JSON.stringify(b)} → ${r.status} ${r.text}`).toContain(r.status) }
    expect(existsSync(REQ)).toBe(false)
  })
  it('dépose pour root une demande minuscule : valeurs facultatives vides ignorées, nom distinctif en éléments séparés', async () => {
    const r = await admin.post('/api/pki/cas/root', { name: 'Lab-Root2', alg: 'ecp384', days: 3650, cn: ' Lab Root 2 ', o: 'Laboratoire', ou: '', c: 'FR' })
    expect(r.status, r.text).toBe(200); expect(r.json).toMatchObject({ accepted: true })
    expect(sent()).toEqual({ action: 'ca_root', name: 'Lab-Root2', alg: 'ecp384', days: 3650, cn: 'Lab Root 2', o: 'Laboratoire', c: 'FR' })
    expect((statSync(REQ).mode & 0o777).toString(8)).toBe('640'); expect(readFileSync(REQ, 'utf8').length).toBeLessThan(4096)
  })
  it('une demande en attente bloque la suivante', async () => {
    code(await admin.post('/api/pki/cas/root', { name: 'R3', alg: 'rsa3072', days: 3650, cn: 'X' }), 409, 'request_pending')
    code(await admin.post('/api/pki/cas/Lab-Root/crl', {}), 409, 'request_pending')
    rootDone()
  })
  it('un nom déjà pris est refusé, majuscules comprises', async () => {
    code(await admin.post('/api/pki/cas/root', { name: 'Lab-Root', alg: 'rsa3072', days: 3650, cn: 'X' }), 409, 'pki_ca_exists')
    code(await admin.post('/api/pki/cas/root', { name: 'lab-root', alg: 'rsa3072', days: 3650, cn: 'X' }), 409, 'pki_ca_exists')
    expect(existsSync(REQ)).toBe(false)
  })
})

describe('émettrice', () => {
  const body = { name: 'Lab-Sub2', alg: 'ecp256', days: 1825, cn: 'Lab Sub 2', o: 'Lab', c: 'FR' }
  it('signée par une racine du DDI : racine active obligatoire, aucune chaîne déposée', async () => {
    for (const s of ['Inconnue', 'Lab-Sub', 'Lab-Wait', 'ExtRoot-0a1b2c3d']) {
      const r = await admin.post('/api/pki/cas/issuing', { ...body, signedBy: s }); expect([r.status, r.json?.data?.code], `${s} : ${r.text}`).toEqual(s.startsWith('ExtRoot') ? [400, 'validation'] : [409, 'pki_signer_invalid'])
    }
    expect(existsSync(REQ)).toBe(false)
    const r = await admin.post('/api/pki/cas/issuing', { ...body, signedBy: 'Lab-Root' }); expect(r.status, r.text).toBe(200)
    expect(sent()).toEqual({ action: 'ca_issuing', name: 'Lab-Sub2', alg: 'ecp256', days: 1825, signedBy: 'Lab-Root', cn: 'Lab Sub 2', o: 'Lab', c: 'FR' }); rootDone()
    expect(noDeposit()).toEqual([])
    const extra = await admin.post('/api/pki/cas/issuing', { ...body, signedBy: 'Lab-Root', chain: { pem: CERT } }); expect(extra.status).toBe(400)
  })
  it('hors ligne : la chaîne est obligatoire, vérifiée sommairement, puis déposée pour root', async () => {
    code(await admin.post('/api/pki/cas/issuing', body), 400, 'validation')   // « external » par défaut : chaîne absente
    code(await admin.post('/api/pki/cas/issuing', { ...body, chain: { pem: 'pas un certificat' } }), 400, 'pki_bad_file')
    code(await admin.post('/api/pki/cas/issuing', { ...body, chain: { pem: CRLPEM } }), 400, 'pki_bad_file')
    code(await admin.post('/api/pki/cas/issuing', { ...body, chain: { pem: CERT + 'A'.repeat(17000) } }), 400, 'pki_bad_file')
    code(await admin.post('/api/pki/cas/issuing', { ...body, chain: { der: Buffer.from('AB').toString('base64') } }), 400, 'pki_bad_file')
    expect(existsSync(REQ)).toBe(false); expect(noDeposit()).toEqual([])
    const r = await admin.post('/api/pki/cas/issuing', { ...body, signedBy: 'external', chain: { pem: CERT.replace(/\n/g, '\r\n') } }); expect(r.status, r.text).toBe(200)
    expect(sent()).toEqual({ action: 'ca_issuing', name: 'Lab-Sub2', alg: 'ecp256', days: 1825, signedBy: 'external', cn: 'Lab Sub 2', o: 'Lab', c: 'FR' })
    expect(noDeposit()).toEqual(['Lab-Sub2.chain.pem']); expect(readFileSync(join(IN, 'Lab-Sub2.chain.pem'), 'utf8')).toBe(CERT)
    expect((statSync(join(IN, 'Lab-Sub2.chain.pem')).mode & 0o777).toString(8)).toBe('640')
    rootDone(); clearDeposits()
  })
  it('demande déjà en cours : aucun fichier n\'est déposé', async () => {
    writeFileSync(REQ, '{"action":"status"}\n')
    code(await admin.post('/api/pki/cas/issuing', { ...body, chain: { pem: CERT } }), 409, 'request_pending')
    expect(noDeposit()).toEqual([]); rootDone()
  })
  it('nom déjà pris : refus avant tout dépôt', async () => {
    code(await admin.post('/api/pki/cas/issuing', { ...body, name: 'Lab-Sub', chain: { pem: CERT } }), 409, 'pki_ca_exists')
    expect(noDeposit()).toEqual([]); expect(existsSync(REQ)).toBe(false)
  })
})

describe('import du certificat signé', () => {
  it('seule une émettrice en attente reçoit un certificat', async () => {
    code(await admin.post('/api/pki/cas/Lab-Sub/import', { certificate: { pem: CERT } }), 409, 'pki_ca_not_waiting')
    code(await admin.post('/api/pki/cas/Inconnue/import', { certificate: { pem: CERT } }), 404, 'not_found')
    code(await admin.post('/api/pki/cas/ManagementCA/import', { certificate: { pem: CERT } }), 400, 'invalid_name')
    code(await admin.post('/api/pki/cas/a%20b/import', { certificate: { pem: CERT } }), 400, 'invalid_name')
    code(await admin.post('/api/pki/cas/Lab-Wait/import', { certificate: { pem: 'rien' } }), 400, 'pki_bad_file')
    code(await admin.post('/api/pki/cas/Lab-Wait/import', { certificate: { pem: CERT }, extra: 1 }), 400, 'validation')
    code(await admin.post('/api/pki/cas/Lab-Wait/import', {}), 400, 'validation')
    expect(existsSync(REQ)).toBe(false); expect(noDeposit()).toEqual([])
  })
  it('PEM : déposé tel quel pour root avec une demande qui ne porte que le nom', async () => {
    const r = await admin.post('/api/pki/cas/Lab-Wait/import', { certificate: { pem: CERT } }); expect(r.status, r.text).toBe(200)
    expect(sent()).toEqual({ action: 'ca_import', name: 'Lab-Wait' }); expect(readFileSync(join(IN, 'Lab-Wait.cert.pem'), 'utf8')).toBe(CERT)
    rootDone(); clearDeposits()
  })
  it('DER (en base64) : déposé en binaire', async () => {
    const der = Buffer.from([0x30, 0x82, 0x01, 0x00, 0xde, 0xad])
    expect((await admin.post('/api/pki/cas/Lab-Wait/import', { certificate: { der: der.toString('base64') } })).status).toBe(200)
    expect(readFileSync(join(IN, 'Lab-Wait.cert.pem')).equals(der)).toBe(true); rootDone(); clearDeposits()
  })
})

describe('CRL', () => {
  it('renouvellement : autorité active du DDI seulement', async () => {
    code(await admin.post('/api/pki/cas/Lab-Wait/crl', {}), 409, 'pki_ca_not_active')
    code(await admin.post('/api/pki/cas/ExtRoot-0a1b2c3d/crl', {}), 400, 'invalid_name')
    code(await admin.post('/api/pki/cas/Inconnue/crl', {}), 404, 'not_found')
    expect(existsSync(REQ)).toBe(false)
    expect((await admin.post('/api/pki/cas/Lab-Sub/crl', {})).status).toBe(200); expect(sent()).toEqual({ action: 'ca_crl', name: 'Lab-Sub' }); rootDone()
  })
  it('CRL de la racine hors ligne : nom ExtRoot-…, fichier CRL, dépôt pour root', async () => {
    code(await admin.post('/api/pki/cas/Lab-Root/rootcrl', { crl: { pem: CRLPEM } }), 400, 'invalid_name')
    code(await admin.post('/api/pki/cas/ExtRoot-ffffffff/rootcrl', { crl: { pem: CRLPEM } }), 404, 'not_found')
    code(await admin.post('/api/pki/cas/ExtRoot-0a1b2c3d/rootcrl', { crl: { pem: CERT } }), 400, 'pki_bad_file')
    code(await admin.post('/api/pki/cas/ExtRoot-0a1b2c3d/rootcrl', { crl: { pem: 'x' } }), 400, 'pki_bad_file')
    expect(existsSync(REQ)).toBe(false); expect(noDeposit()).toEqual([])
    expect((await admin.post('/api/pki/cas/ExtRoot-0a1b2c3d/rootcrl', { crl: { pem: CRLPEM } })).status).toBe(200)
    expect(sent()).toEqual({ action: 'ca_rootcrl', name: 'ExtRoot-0a1b2c3d' }); expect(readFileSync(join(IN, 'ExtRoot-0a1b2c3d.crl'), 'utf8')).toBe(CRLPEM); rootDone(); clearDeposits()
  })
})

describe('téléchargements de fichiers publics', () => {
  it('sert le certificat, la chaîne, la demande et la CRL avec le bon type et un nom de fichier sûr', async () => {
    mkdirSync(join(CADIR, 'Lab-Wait'), { recursive: true }); writeFileSync(join(CADIR, 'Lab-Wait', 'csr.pem'), '-----BEGIN CERTIFICATE REQUEST-----\nAA\n-----END CERTIFICATE REQUEST-----\n')
    writeFileSync(join(CADIR, 'Lab-Wait', 'chain.pem'), CERT)
    mkdirSync(join(CADIR, 'Lab-Root'), { recursive: true }); writeFileSync(join(CADIR, 'Lab-Root', 'cert.pem'), CERT); writeFileSync(join(CADIR, 'Lab-Root', 'crl.der'), Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]))
    const csr = await admin.get('/api/pki/cas/Lab-Wait/csr'); expect(csr.status).toBe(200)
    expect(csr.headers.get('content-type')).toContain('application/pkcs10'); expect(csr.headers.get('content-disposition')).toBe('attachment; filename="Lab-Wait.csr"'); expect(csr.text).toContain('CERTIFICATE REQUEST')
    const cert = await admin.get('/api/pki/cas/Lab-Root/cert'); expect(cert.text).toBe(CERT); expect(cert.headers.get('content-disposition')).toBe('attachment; filename="Lab-Root.pem"')
    expect((await admin.get('/api/pki/cas/Lab-Wait/chain')).text).toBe(CERT)
    const crl = await admin.get('/api/pki/cas/Lab-Root/crl'); expect(crl.headers.get('content-type')).toContain('application/pkix-crl'); expect([...crl.buf]).toEqual([0x30, 0x03, 0x02, 0x01, 0x01])
  })
  it('fichier absent, nom ou type invalide, lien symbolique : 404', async () => {
    code(await admin.get('/api/pki/cas/Lab-Root/chain'), 404, 'not_found')
    code(await admin.get('/api/pki/cas/Lab-Root/key'), 404, 'not_found'); code(await admin.get('/api/pki/cas/Lab-Root/cert.pem'), 404, 'not_found')
    code(await admin.get('/api/pki/cas/..%2Fx/cert'), 404, 'not_found'); code(await admin.get('/api/pki/cas/a%20b/cert'), 404, 'not_found')
    writeFileSync(join(TMP, 'secret.txt'), 'secret'); symlinkSync(join(TMP, 'secret.txt'), join(CADIR, 'Lab-Root', 'chain.pem'))
    code(await admin.get('/api/pki/cas/Lab-Root/chain'), 404, 'not_found')
  })
})

describe('remise à zéro', () => {
  it('rien à effacer, ou refusée tant qu\'une autorité porte une clé', async () => {
    setStatus({ installed: false, state: 'absent', active: false, dataPresent: false, dataHostname: '', secretsPresent: false, casCount: null })
    code(await admin.post('/api/pki/reset', { confirm: 'x' }), 409, 'pki_reset_nothing')
    setStatus({ casCount: 2, resetAllowed: false })
    code(await admin.post('/api/pki/reset', { confirm: 'pki.lab.test' }), 409, 'pki_reset_refused')
    expect(existsSync(REQ)).toBe(false)
  })
  it('confirmation par le nom public des données', async () => {
    setStatus({ casCount: 0, resetAllowed: true })
    code(await admin.post('/api/pki/reset', { confirm: 'autre.lab.test' }), 400, 'pki_confirm_mismatch')
    code(await admin.post('/api/pki/reset', {}), 400, 'validation')
    expect(existsSync(REQ)).toBe(false)
    expect((await admin.post('/api/pki/reset', { confirm: 'PKI.Lab.Test' })).status).toBe(200); expect(sent()).toEqual({ action: 'reset' })
    code(await admin.post('/api/pki/reset', { confirm: 'pki.lab.test' }), 409, 'request_pending'); rootDone()
  })
  it('sans nom connu (secrets perdus) : on tape « reset »', async () => {
    setStatus({ installed: false, state: 'absent', active: false, dataHostname: '', hostname: '', secretsPresent: false, casCount: 0, resetAllowed: true })
    code(await admin.post('/api/pki/reset', { confirm: 'pki.lab.test' }), 400, 'pki_confirm_mismatch')
    expect((await admin.post('/api/pki/reset', { confirm: 'reset' })).status).toBe(200); rootDone()
  })
})

describe('données existantes : nom public imposé', () => {
  it('la page reçoit le nom des données et ne peut pas en choisir un autre', async () => {
    setStatus({ installed: false, state: 'absent', active: false, hostname: '', dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab.test', casCount: 1, resetAllowed: false })
    const r = (await admin.get('/api/pki')).json
    expect(r).toMatchObject({ hostname: 'pki.lab.test', hostnameFixed: true, locked: false })
    code(await admin.post('/api/pki/apply', { hostname: 'autre.lab.test' }), 409, 'pki_hostname_locked')
    expect(existsSync(REQ)).toBe(false)
    expect((await admin.post('/api/pki/apply', { hostname: 'pki.lab.test' })).status).toBe(200); rootDone()
  })
  it('installée : même comportement qu\'avant, aucun nom imposé en plus', async () => {
    setStatus({})
    expect((await admin.get('/api/pki')).json).toMatchObject({ locked: true, hostnameFixed: false, hostname: 'pki.lab.test' })
  })
})

describe('traçabilité', () => {
  it('chaque action est auditée, sans aucun contenu de fichier ni clé', async () => {
    const a = (await rows("select action from audit_log where action like 'pki.ca_%' or action = 'pki.reset' order by id")).map((x: any) => x.action)
    expect(a).toEqual(expect.arrayContaining(['pki.ca_root', 'pki.ca_issuing', 'pki.ca_import', 'pki.ca_crl', 'pki.ca_rootcrl', 'pki.reset']))
    const detail = JSON.stringify(await rows("select detail from audit_log where action like 'pki.%'"))
    expect(detail).not.toMatch(/BEGIN CERTIFICATE|BEGIN X509 CRL|PRIVATE KEY|MIIB/)
    expect(detail).toContain('Lab-Root2')
  })
})
