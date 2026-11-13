// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.0 — assistant de migration Windows.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3424, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s23-')); mkdirSync(join(TMP, 'gen'))
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
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json'), DDI_OIDC_ALLOW_HTTP: '1' } })
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
const DHCP_XML = `<?xml version="1.0"?><DHCPServer><IPv4><Scopes><Scope><ScopeId>192.168.1.0</ScopeId><Name>LAN Paris</Name><SubnetMask>255.255.255.0</SubnetMask><StartRange>192.168.1.100</StartRange><EndRange>192.168.1.200</EndRange><LeaseDuration>8.00:00:00</LeaseDuration><State>Active</State></Scope></Scopes></IPv4></DHCPServer>`
const step = (r: any, id: string) => r.json.steps.find((s: any) => s.id === id)

describe('assistant de migration Windows', () => {
  it('état initial : sept étapes, rien de fait ; lecture pour tous les connectés, anonyme refusé', async () => {
    code(await anon.get('/api/migration'), 401, 'unauthenticated')
    const r = await viewer.get('/api/migration'); expect(r.status).toBe(200)
    expect(r.json.steps.map((s: any) => s.id)).toEqual(['scripts', 'subnets', 'dhcp', 'dns', 'review', 'cutover', 'retire'])
    expect(r.json.steps.every((s: any) => !s.manual && !s.auto)).toBe(true)
    expect(step(r, 'dhcp').detectable).toBe(true); expect(step(r, 'cutover').detectable).toBe(false)
  })
  it('cocher à la main : opérateur seulement, étape inconnue refusée, persistant, audité, décochable', async () => {
    code(await viewer.put('/api/migration', { step: 'scripts', done: true }), 403, 'forbidden')
    expect((await admin.put('/api/migration', { step: 'bidon', done: true })).status).toBe(400)
    expect((await admin.put('/api/migration', { step: 'scripts', done: 'oui' })).status).toBe(400)
    const r = await oper.put('/api/migration', { step: 'scripts', done: true }); expect(r.status, r.text).toBe(200)
    expect(step(r, 'scripts').manual).toBe(true)
    expect(step(await admin.get('/api/migration'), 'scripts').manual).toBe(true)
    expect((await rows("select 1 from audit_log where action = 'migration_step'")).length).toBe(1)
    expect(step(await admin.put('/api/migration', { step: 'scripts', done: false }), 'scripts').manual).toBe(false)
  })
  it('un import DHCP réussi est détecté tout seul ; les totaux suivent', async () => {
    expect((await admin.post('/api/import/dhcp/commit', { content: DHCP_XML, filename: 'dhcp-export.xml' })).status).toBe(200)
    const r = await admin.get('/api/migration')
    expect(step(r, 'dhcp')).toMatchObject({ auto: true, runs: 1 }); expect(step(r, 'dns').auto).toBe(false)
    expect(r.json.totals).toMatchObject({ scopes: 1, subnets: 1 })
  })
})
