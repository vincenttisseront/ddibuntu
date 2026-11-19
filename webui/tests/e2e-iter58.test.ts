// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.18 — journal des authentifications RADIUS de ce nœud : route GET /api/radius/events (accès,
// paramètres, filtres, compteurs, fichier absent), compteurs de l'onglet « Service » dans GET /api/radius, et un journal piégé (valeurs hostiles) lu tel quel.
// Le format écrit par FreeRADIUS est vérifié contre un vrai démon par tests/b28..b30.
import { spawn, type ChildProcess } from 'node:child_process'
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3486, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s58-')), LOGDIR = join(TMP, 'authlog'), AL = join(LOGDIR, 'radius-auth.log')
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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); del = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), oper = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 200)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows

const NOW = () => Math.floor(Date.now() / 1000)
const F = ['v1', '0', 'accept', 'PC001.lab.test', 'wifi-hq', '10.0.0.5', 'aa-bb-cc-dd-ee-ff', 'AA-BB-CC-00-11-22:Corp', 'ap-hq', '/CN=3Dpc001', '/CN=3DLab Issuing CA', '1001', '271119151329Z', '', 'pc001.lab.test', 'computer:pc001.lab.test', 'regle 2 : Postes', '']
const line = (o: Record<number, string> = {}) => F.map((v, i) => o[i] ?? v).join('|')

beforeAll(async () => {
  mkdirSync(TMP, { recursive: true })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RADIUS_AUTHLOG_DIR: LOGDIR } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  for (const [u, ro, c] of [['lect', 'viewer', viewer]] as const) { expect((await admin.post('/api/users', { username: u, role: ro, password: PW })).status).toBe(200); expect((await c.login(u, PW)).status).toBe(200) }
}, 300000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('journal des authentifications RADIUS', () => {
  it('accès : authentification obligatoire, lecteur autorisé, paramètres contrôlés', async () => {
    code(await anon.get('/api/radius/events'), 401, 'unauthenticated')
    expect((await viewer.get('/api/radius/events')).status).toBe(200)
    code(await viewer.get('/api/radius/events?kind=autre'), 400, 'invalid_query')
    code(await viewer.get('/api/radius/events?limit=abc'), 400, 'invalid_query')
    code(await viewer.get('/api/radius/events?minutes=-1'), 400, 'invalid_query')
    code(await viewer.get('/api/radius/events?q=' + 'x'.repeat(101)), 400, 'invalid_query')
  })
  it('fichier absent : indisponible, compteurs à zéro, l\'onglet Service le sait', async () => {
    const r = await viewer.get('/api/radius/events')
    expect(r.json).toMatchObject({ available: false, events: [], counts: { accept: 0, reject: 0, diag: 0 } })
    expect((await viewer.get('/api/radius')).json.journal).toEqual({ available: false, accept: 0, reject: 0, diag: 0, truncated: false })
  })
  it('lit le fichier : événements, compteurs, filtres ; valeurs hostiles rendues telles quelles (texte)', async () => {
    mkdirSync(LOGDIR, { recursive: true })
    const n = NOW()
    writeFileSync(AL, [
      line({ 1: String(n - 300), 3: 'alice@lab.test', 15: 'user:alice@lab.test', 16: 'regle 1 : Employes' }),
      line({ 1: String(n - 200), 2: 'reject', 3: 'bob', 17: 'eap_tls: (TLS) OpenSSL says error 23 : certificate revoked' }),
      line({ 1: String(n - 100), 2: 'reject', 3: '=3Cimg src=3Dx onerror=3Dalert(1)=3E=0A=7C', 6: 'aa-bb', 17: 'ddibuntu : compte desactive' }),
      line({ 1: String(n - 50), 2: 'reject', 3: 'essai', 4: 'ddi-selftest', 17: 'ddibuntu : aucune regle ne correspond' }),
    ].join('\n') + '\n')
    const r = (await viewer.get('/api/radius/events')).json
    expect(r.available).toBe(true)
    expect(r.counts).toMatchObject({ accept: 1, reject: 2 })
    expect(r.events.map((e: any) => e.user)).toEqual(['<img src=x onerror=alert(1)>·|', 'bob', 'alice@lab.test'])   // test de la console masqué ; contrôle neutralisé
    expect(r.events[1]).toMatchObject({ kind: 'reject', why: 'revoked', subject: '/CN=pc001', issuer: '/CN=Lab Issuing CA', serial: '1001', identity: 'computer:pc001.lab.test' })
    expect(r.reasons.map((x: any) => x.why).sort()).toEqual(['account_disabled', 'revoked'])
    expect((await viewer.get('/api/radius/events?kind=accept')).json.events.map((e: any) => e.user)).toEqual(['alice@lab.test'])
    expect((await viewer.get('/api/radius/events?q=REVOKED')).json.events.map((e: any) => e.user)).toEqual(['bob'])
    expect((await viewer.get('/api/radius/events?limit=1')).json.events).toHaveLength(1)
    expect((await viewer.get('/api/radius/events?selftest=1&q=ddi-selftest')).json.events.map((e: any) => e.user)).toEqual(['essai'])
    expect((await viewer.get('/api/radius/events?minutes=3')).json.events.map((e: any) => e.user)).toEqual(['<img src=x onerror=alert(1)>·|'])
    expect((await viewer.get('/api/radius')).json.journal).toEqual({ available: true, accept: 1, reject: 2, diag: 0, truncated: false })
  })
  it('une ligne ajoutée apparaît au chargement suivant', async () => {
    appendFileSync(AL, line({ 1: String(NOW()), 3: 'nouveau' }) + '\n')
    expect((await viewer.get('/api/radius/events?limit=1')).json.events[0].user).toBe('nouveau')
  })
})
