// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.2 — reprise des baux actifs Windows.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3425, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s24-')); mkdirSync(join(TMP, 'gen'))
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
const XML = `<?xml version="1.0"?><DHCPServer><IPv4><Scopes><Scope><ScopeId>10.90.0.0</ScopeId><Name>LAN</Name><SubnetMask>255.255.255.0</SubnetMask><StartRange>10.90.0.100</StartRange><EndRange>10.90.0.200</EndRange><LeaseDuration>1.00:00:00</LeaseDuration><State>Active</State></Scope></Scopes></IPv4></DHCPServer>`
const future = (h: number) => new Date(Date.now() + h * 3600_000).toISOString().slice(0, 19)
const CSV = () => `"IPAddress","ClientId","HostName","AddressState","ExpiryUtc"
"10.90.0.20","aa-bb-cc-00-00-20","PC-Alice.corp.local","Active","${future(5)}"
"10.90.0.21","aa-bb-cc-00-00-21","imprimante","Active","${future(5)}"
"10.90.0.22","aa-bb-cc-00-00-22","expire","Active","${future(-5)}"
"10.90.0.23","aa-bb-cc-00-00-23","declin","Declined","${future(5)}"
"10.99.0.1","aa-bb-cc-00-00-24","ailleurs","Active","${future(5)}"`
let scopeId = 0

describe('reprise des baux actifs', () => {
  it('mise en place : étendue importée ; droits ; CSV invalide refusé', async () => {
    expect((await admin.post('/api/import/dhcp/commit', { content: XML })).status).toBe(200)
    scopeId = (await rows('select id from dhcp_scopes'))[0].id
    code(await viewer.post('/api/migration/leases/preview', { content: 'x' }), 403, 'forbidden'); code(await anon.post('/api/migration/leases/commit', { content: 'x' }), 401, 'unauthenticated')
    expect((await oper.post('/api/migration/leases/preview', { content: 'a,b\n1,2' })).json.errors).toEqual(['leases_csv_invalid'])
    code(await oper.post('/api/migration/leases/commit', { content: 'a,b\n1,2' }), 400, 'leases_csv_invalid')
  })
  it('analyse : sans base de baux Kea, rien ne s’écrit et la reprise est refusée', async () => {
    const p = await oper.post('/api/migration/leases/preview', { content: CSV() }); expect(p.status, p.text).toBe(200)
    expect(p.json).toMatchObject({ available: false, total: 5, toImport: 2, skipped: { expired: 1, not_active: 1, no_scope: 1, invalid: 0 } })
    code(await oper.post('/api/migration/leases/commit', { content: CSV() }), 409, 'lease_db_missing')
  })
  it('reprise : baux inscrits dans lease4 avec l’identifiant d’étendue de Kea ; instantané, historique et audit', async () => {
    await db.query('create table lease4 (address bigint primary key, hwaddr bytea, client_id bytea, valid_lifetime bigint, expire timestamp, subnet_id bigint, fqdn_fwd boolean not null, fqdn_rev boolean not null, hostname varchar, state bigint default 0)')
    const r = await oper.post('/api/migration/leases/commit', { content: CSV(), filename: 'dhcp-leases.csv' }); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ imported: 2, existing: 0 }); expect(r.json.snapshotId).toBeGreaterThan(0)
    const l = await rows("select ((address >> 8) & 255) || '.' || (address & 255) as ip, encode(hwaddr, 'hex') as mac, hostname, subnet_id, valid_lifetime, expire > now() as live from lease4 order by address")
    expect(l).toEqual([{ ip: '0.20', mac: 'aabbcc000020', hostname: 'pc-alice', subnet_id: String(scopeId), valid_lifetime: '86400', live: true }, { ip: '0.21', mac: 'aabbcc000021', hostname: 'imprimante', subnet_id: String(scopeId), valid_lifetime: '86400', live: true }])
    expect((await rows("select 1 from import_runs where kind = 'dhcp-leases'")).length).toBe(1)
    expect((await rows("select 1 from audit_log where action = 'migration_leases'")).length).toBe(1)
    expect((await admin.get('/api/dhcp/leases')).json.items.length).toBe(2)   // visibles dans la console
  })
  it('second passage : aucun écrasement, les baux existants sont comptés', async () => {
    await db.query("update lease4 set hostname = 'garde' where hostname = 'imprimante'")
    const r = await oper.post('/api/migration/leases/commit', { content: CSV() }); expect(r.json).toMatchObject({ imported: 0, existing: 2 })
    expect((await rows("select hostname from lease4 where hostname = 'garde'")).length).toBe(1)
  })
})
