// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.5 — vérification avant bascule Windows ↔ DDI.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3428, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s27-')); mkdirSync(join(TMP, 'gen'))
let srv: ChildProcess, db: pg.Client, srvLog = ''


writeFileSync(join(TMP, 'dig.sh'), `#!/bin/sh
for a in "$@"; do case "$a" in @*) S="$a";; esac; done
N=""; T=""; for a in "$@"; do case "$a" in @*|+*) ;; *) if [ -z "$N" ]; then N="$a"; else T="$a"; fi;; esac; done
case "$S/$N/$T" in
  @192.0.2.1/www.corp.test/A) echo 10.0.0.10;;
  @127.0.0.1/www.corp.test/A) echo 10.0.0.10;;
  @192.0.2.1/db.corp.test/A) echo 10.0.0.20;;
  @127.0.0.1/db.corp.test/A) echo 10.0.0.21;;
  @192.0.2.1/mail.corp.test/A) echo 10.0.0.30;;
  @192.0.2.1/ok.corp.test/A) echo 10.0.0.40; echo 10.0.0.41;;
  @127.0.0.1/ok.corp.test/A) echo 10.0.0.41; echo 10.0.0.40;;
esac
`, { mode: 0o755 })

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
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_DIG: join(TMP, 'dig.sh'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json'), DDI_OIDC_ALLOW_HTTP: '1' } })
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

const step = (r: any, id: string) => r.json.steps.find((s: any) => s.id === id)

const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const XML = (extra = '', lease = '1.00:00:00', end = '10.90.0.200') => `<?xml version="1.0"?><DHCPServer><IPv4><Scopes><Scope><ScopeId>10.90.0.0</ScopeId><Name>LAN</Name><SubnetMask>255.255.255.0</SubnetMask><StartRange>10.90.0.100</StartRange><EndRange>${end}</EndRange><LeaseDuration>${lease}</LeaseDuration><State>Active</State><Reservations><Reservation><IPAddress>10.90.0.50</IPAddress><ClientId>aa-bb-cc-00-00-01</ClientId><Name>poste1</Name></Reservation></Reservations></Scope>${extra}</Scopes></IPv4></DHCPServer>`

describe('vérification avant bascule', () => {
  it('DHCP : identique après import, puis écarts nommés (réservation, plage, durée, étendue absente)', async () => {
    expect((await admin.post('/api/import/dhcp/commit', { content: XML() })).status).toBe(200)
    const ok = await oper.post('/api/migration/verify/dhcp', { content: XML() }); expect(ok.status, ok.text).toBe(200); expect(ok.json).toEqual({ scopes: 1, findings: [] })
    expect(step(await admin.get('/api/migration'), 'review').manual).toBe(true)
    await admin.put('/api/migration', { step: 'review', done: false })
    const extra = '<Scope><ScopeId>10.91.0.0</ScopeId><Name>X</Name><SubnetMask>255.255.255.0</SubnetMask><StartRange>10.91.0.10</StartRange><EndRange>10.91.0.20</EndRange><State>Active</State></Scope>'
    const r = await oper.post('/api/migration/verify/dhcp', { content: XML(extra, '2.00:00:00', '10.90.0.210') })
    expect(r.json.findings.map((f: any) => f.kind).sort()).toEqual(['lease_differs', 'pool_extra', 'pool_missing', 'scope_missing'])
    expect(step(await admin.get('/api/migration'), 'review').manual).toBe(false)
    await db.query("delete from dhcp_reservations")
    expect((await oper.post('/api/migration/verify/dhcp', { content: XML() })).json.findings.map((f: any) => f.kind)).toEqual(['reservation_missing'])
  })
  it('DHCP : fichier invalide ou sans étendue refusé ; spectateur refusé', async () => {
    code(await oper.post('/api/migration/verify/dhcp', { content: '<pas du xml' }), 400, 'dhcp_xml_invalid')
    code(await oper.post('/api/migration/verify/dhcp', { content: '<DHCPServer><IPv4><Scopes/></IPv4></DHCPServer>' }), 400, 'dhcp_no_scopes')
    code(await viewer.post('/api/migration/verify/dhcp', { content: XML() }), 403, 'forbidden')
  })
  it('DNS : compare chaque enregistrement sur les deux serveurs ; écarts, silence, ordre des réponses ignoré ; administrateur seulement', async () => {
    await db.query("insert into dns_zones (name, type) values ('corp.test', 'primary')")
    const zid = (await rows("select id from dns_zones where name = 'corp.test'"))[0].id
    for (const [n, v] of [['www', '10.0.0.10'], ['db', '10.0.0.21'], ['mail', '10.0.0.30'], ['ok', '10.0.0.40'], ['ok', '10.0.0.41']]) await db.query("insert into dns_records (zone_id, name, type, rdata) values ($1, $2, 'A', $3)", [zid, n, v])
    code(await oper.post('/api/migration/verify/dns', { server: '192.0.2.1' }), 403, 'forbidden')
    code(await admin.post('/api/migration/verify/dns', { server: '-oBad' }), 400, 'axfr_server_invalid')
    const r = await admin.post('/api/migration/verify/dns', { server: '192.0.2.1' }); expect(r.status, r.text).toBe(200)
    expect(r.json.checked).toBe(4)
    expect(r.json.diffs).toEqual([
      { name: 'db.corp.test', type: 'A', windows: ['10.0.0.20'], ddi: ['10.0.0.21'] },
      { name: 'mail.corp.test', type: 'A', windows: ['10.0.0.30'], ddi: [] }])
    expect(step(await admin.get('/api/migration'), 'review').manual).toBe(false)
    await db.query("delete from dns_records where name in ('db', 'mail')")
    const ok = await admin.post('/api/migration/verify/dns', { server: '192.0.2.1' }); expect(ok.json).toMatchObject({ checked: 2, diffs: [], truncated: false })
    expect(step(await admin.get('/api/migration'), 'review').manual).toBe(true)
  })
})
