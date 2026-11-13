// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.10.1 — contrôle de cohérence DNS ↔ IPAM.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3422, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s21-')); mkdirSync(join(TMP, 'gen'))
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
const admin = new Client(), viewer = new Client(), anon = new Client()
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
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })

const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const zone = (o: Record<string, unknown>) => ({ type: 'primary', soa_mname: 'ns1.corp.test.', soa_rname: 'hostmaster.corp.test.', ...o })
const rec = (zone_id: number, name: string, type: string, rdata: string) => admin.post('/api/dns/records', { zone_id, name, type, rdata })
const keys = (r: any) => r.json.findings.map((f: any) => f.key).sort()
let zF = 0, zR = 0, sn = 0

describe('cohérence DNS ↔ IPAM', () => {
  it('mise en place : zones, gabarit, réseau, adresse IPAM nommée', async () => {
    zF = (await admin.post('/api/dns/zones', zone({ name: 'corp.test' }))).json.id; zR = (await admin.post('/api/dns/zones', zone({ name: '0.70.10.in-addr.arpa' }))).json.id
    const t = await db.query("insert into network_templates (name, dns_zone_id) values ('t', $1) returning id", [zF])
    sn = (await admin.post('/api/ipam/subnets', { cidr: '10.70.0.0/24', name: 'lan', template_id: t.rows[0].id })).json.id; expect(sn).toBeTruthy()
    expect((await rec(zF, 'web', 'A', '10.70.0.5')).status).toBe(200); expect((await rec(zR, '5', 'PTR', 'web.corp.test.')).status).toBe(200)
    expect((await admin.post(`/api/ipam/subnets/${sn}/addresses`, { ip: '10.70.0.5', hostname: 'web' })).status).toBe(200)
  })
  it('droits ; base cohérente : aucun constat, score 100', async () => {
    code(await anon.get('/api/dns/health'), 401, 'unauthenticated'); code(await viewer.post('/api/dns/health/fix', { keys: ['x'] }), 403, 'forbidden')
    expect((await admin.post('/api/dns/health/fix', { keys: [] })).status).toBe(400)
    const r = await viewer.get('/api/dns/health'); expect(r.status).toBe(200)
    expect(r.json).toMatchObject({ score: 100, findings: [] })
  })
  it('incohérences détectées avec leur correctif', async () => {
    await rec(zR, '9', 'PTR', 'fantome.corp.test.')       // PTR orphelin
    await rec(zF, 'db', 'A', '10.70.0.7')                 // A sans PTR, sans fiche IPAM
    await rec(zF, 'alias', 'CNAME', 'absent')             // CNAME pendant
    await db.query("insert into addresses (subnet_id, ip, status, hostname) values ($1, '10.70.0.8', 'used', 'app')", [sn])   // IP nommée non publiée (import, SQL…) ; l'API, elle, publie d'office
    const r = await admin.get('/api/dns/health'); expect(r.status).toBe(200)
    expect(r.json.findings.map((f: any) => f.kind).sort()).toEqual(['a_no_ipam', 'a_no_ptr', 'dangling_cname', 'ip_no_name', 'orphan_ptr'])
    expect(r.json.score).toBeLessThan(100); expect(r.json.zones.find((z: any) => z.zone === 'corp.test').score).toBeLessThan(100)
    expect(r.json.counts).toMatchObject({ orphan_ptr: 1, a_no_ptr: 1, a_no_ipam: 1, ip_no_name: 1, dangling_cname: 1 })
  })
  it('correction : tout est réparé, zones à déployer, audité, second passage sans effet', async () => {
    await db.query('update dns_zones set dirty = false')
    const all = keys(await admin.get('/api/dns/health'))
    const r = await admin.post('/api/dns/health/fix', { keys: all }); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ done: 5, gone: 0, unfixable: 0 })
    expect(r.json.report.findings).toEqual([]); expect(r.json.report.score).toBe(100)
    expect((await rows("select 1 from dns_records where name = '9' and type = 'PTR'")).length).toBe(0)
    expect((await rows("select disabled from dns_records where name = 'alias'"))[0].disabled).toBe(true)
    expect((await rows("select hostname from addresses where host(ip) = '10.70.0.7'"))[0].hostname).toBe('db')
    expect((await rows("select rdata from dns_records where name = 'app' and type = 'A'"))[0].rdata).toBe('10.70.0.8')
    expect((await rows('select count(*)::int n from dns_zones where dirty'))[0].n).toBe(2)
    expect((await rows("select 1 from audit_log where action = 'dns_health_fix'")).length).toBe(1)
    expect(await admin.post('/api/dns/health/fix', { keys: all }).then((x) => x.json)).toMatchObject({ done: 0, gone: 5 })
  })
  it('clés inventées ignorées ; enregistrement protégé non corrigeable ; dynamique jamais signalé', async () => {
    expect((await admin.post('/api/dns/health/fix', { keys: ['orphan_ptr:999999', 'drop table'] })).json).toMatchObject({ done: 0, gone: 2 })
    await db.query("insert into dns_records (zone_id, name, type, rdata, protected) values ($1,'77','PTR','nope.corp.test.', true)", [zR])
    await db.query("insert into dns_records (zone_id, name, type, rdata, source) values ($1,'78','PTR','nope.corp.test.', 'dhcp')", [zR])
    const r = await admin.get('/api/dns/health'); expect(r.json.findings.map((f: any) => [f.kind, f.fixable])).toEqual([['orphan_ptr', false]])
    expect((await admin.post('/api/dns/health/fix', { keys: r.json.findings.map((f: any) => f.key) })).json).toMatchObject({ done: 0, unfixable: 1 })
  })
})
