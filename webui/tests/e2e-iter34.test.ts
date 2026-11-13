// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.14 — pare-feu : réseaux autorisés à administrer (demande déposée pour root, confirmation, retour arrière), empreinte TLS.
import { execFileSync, spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3435, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s34-')); mkdirSync(join(TMP, 'gen'))
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(TMP, 'k.pem'), '-out', join(TMP, 'c.pem'), '-days', '2', '-subj', '/CN=ddi.test'], { stdio: 'ignore' })
const CRT = readFileSync(join(TMP, 'c.pem'), 'utf8')
let srv: ChildProcess, db: pg.Client, srvLog = ''


class Client {
  cookie = ''; csrf = ''
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { cookie: this.cookie }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* HTML */ }
    return { status: r.status, json, text }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b); delete = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }

beforeAll(async () => {
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_DIG: join(TMP, 'dig.sh'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json'), DDI_FW_CONF: join(TMP, 'fw.conf'), DDI_FW_RESULT: join(TMP, 'fw-result.json'), DDI_FW_PENDING: join(TMP, 'fw-pending.json'), DDI_TLS_CERT_PEM: CRT, DDI_OIDC_ALLOW_HTTP: '1' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  expect((await oper.login('oper', PW)).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })


const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const GEN = join(TMP, 'gen'), REQ = join(GEN, '.fw-request')
const conf = (n: string) => writeFileSync(join(TMP, 'fw.conf'), `ADMIN_NETS="${n}"\nADMIN_TCP="22,443"\n`)
describe('pare-feu', () => {
  it('réservé à l\'administrateur ; lecture de la configuration et de l\'adresse du poste', async () => {
    code(await viewer.get('/api/system/firewall'), 403, 'forbidden'); code(await oper.put('/api/system/firewall/nets', { nets: ['10.0.0.0/8'] }), 403, 'forbidden')
    conf('127.0.0.0/8, 10.20.0.0/24')
    const r = await admin.get('/api/system/firewall'); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ adminNets: ['127.0.0.0/8', '10.20.0.0/24'], adminTcp: '22,443', meCovered: true, pending: null, requestPending: false })
  })
  it('validation : réseau invalide, /0, liste vide, doublons', async () => {
    for (const bad of [['pas-un-reseau'], ['0.0.0.0/0'], ['::/0'], ['10.0.0.0/33'], ["10.0.0.1'; rm -rf /"]]) code(await admin.put('/api/system/firewall/nets', { nets: bad, force: true }), 400, 'invalid_network')
    expect((await admin.put('/api/system/firewall/nets', { nets: [] })).status).toBe(400)
  })
  it('garde-fou : refus si le poste serait coupé, sauf confirmation explicite', async () => {
    code(await admin.put('/api/system/firewall/nets', { nets: ['10.99.0.0/24'] }), 409, 'firewall_self_lockout')
    expect(existsSync(REQ)).toBe(false)
  })
  it('dépôt de la demande normalisée (adresse seule → /32, doublons retirés) ; une seule demande à la fois', async () => {
    const r = await admin.put('/api/system/firewall/nets', { nets: ['10.20.0.15', '10.20.0.15/32', '127.0.0.1', '2001:db8::1'] }); expect(r.status, r.text).toBe(200)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'set', nets: ['10.20.0.15/32', '127.0.0.1/32', '2001:db8::1/128'] })
    expect((await admin.get('/api/system/firewall')).json.requestPending).toBe(true)
    code(await admin.put('/api/system/firewall/nets', { nets: ['127.0.0.1'] }), 409, 'request_pending')
    expect((await rows("select 1 from audit_log where action = 'firewall.set'")).length).toBe(1)
    rmSync(REQ)
  })
  it('confirmation et retour arrière : seulement si une application est en attente', async () => {
    code(await admin.post('/api/system/firewall/confirm'), 409, 'firewall_nothing_pending'); code(await admin.post('/api/system/firewall/rollback'), 409, 'firewall_nothing_pending')
    const until = Math.floor(Date.now() / 1000) + 60
    writeFileSync(join(TMP, 'fw-pending.json'), JSON.stringify({ at: until - 60, until })); writeFileSync(join(TMP, 'fw-result.json'), JSON.stringify({ at: until - 59, action: 'set', ok: true, message: 'Appliqué' }))
    const v = (await admin.get('/api/system/firewall')).json
    expect(v.pending.until).toBe(until); expect(v.result).toMatchObject({ ok: true, action: 'set' })
    code(await admin.put('/api/system/firewall/nets', { nets: ['127.0.0.1'] }), 409, 'firewall_pending')
    expect((await admin.post('/api/system/firewall/confirm')).status).toBe(200)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'confirm' }); rmSync(REQ)
    expect((await admin.post('/api/system/firewall/rollback')).status).toBe(200)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'rollback' }); rmSync(REQ)
    writeFileSync(join(TMP, 'fw-pending.json'), JSON.stringify({ at: 1, until: 2 }))   // délai écoulé : plus en attente
    expect((await admin.get('/api/system/firewall')).json.pending).toBeNull()
  })
})
describe('empreinte TLS (certificat autosigné)', () => {
  it('SHA-256 du certificat de la console ; réservé aux opérateurs', async () => {
    code(await anon.get('/api/system/tls-fingerprint'), 401, 'unauthenticated'); code(await viewer.get('/api/system/tls-fingerprint'), 403, 'forbidden')
    const want = execFileSync('openssl', ['x509', '-in', join(TMP, 'c.pem'), '-noout', '-fingerprint', '-sha256']).toString().trim().split('=')[1]!.replace(/:/g, '')
    const r = await oper.get('/api/system/tls-fingerprint'); expect(r.status, r.text).toBe(200); expect(r.json.sha256).toBe(want)
  })
})
