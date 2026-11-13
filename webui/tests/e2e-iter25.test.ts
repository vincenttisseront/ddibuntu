// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.3 — zones DNS depuis Windows (inventaire, AXFR).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3426, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s25-')); mkdirSync(join(TMP, 'gen'))
let srv: ChildProcess, db: pg.Client, srvLog = ''


const ZONE = `corp.test.\t3600\tIN\tSOA\tdc1.corp.test. hostmaster.corp.test. 12 900 600 86400 3600
corp.test.\t600\tIN\tNS\tdc1.corp.test.
dc1.corp.test.\t3600\tIN\tA\t10.0.0.10
_ldap._tcp.corp.test.\t600\tIN\tSRV\t0 100 389 dc1.corp.test.
www.corp.test.\t3600\tIN\tCNAME\tdc1.corp.test.
corp.test.\t3600\tIN\tSOA\tdc1.corp.test. hostmaster.corp.test. 12 900 600 86400 3600`
writeFileSync(join(TMP, 'zone.txt'), ZONE + '\n')
writeFileSync(join(TMP, 'dig.sh'), `#!/bin/sh\necho "$@" >> ${join(TMP, 'dig.log')}\ncase "$*" in *@192.0.2.2*) echo "; Transfer failed." >&2; exit 9;; esac\ncat ${join(TMP, 'zone.txt')}\n`, { mode: 0o755 })

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

const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const CSV = `"ZoneName","ZoneType","IsDsIntegrated","IsSigned","MasterServers"
"corp.test","Primary","True","False",""
"sec.test","Secondary","False","False","10.0.0.5"
"partner.test","Forwarder","False","False","203.0.113.7"
"stub.test","Stub","False","False","10.0.0.9"`
let zid = 0

describe('zones depuis Windows', () => {
  it('droits ; CSV invalide ; analyse sans effet de bord', async () => {
    code(await viewer.post('/api/migration/zones/preview', { content: CSV }), 403, 'forbidden'); code(await anon.post('/api/migration/zones/commit', { content: CSV }), 401, 'unauthenticated')
    expect((await oper.post('/api/migration/zones/preview', { content: 'a,b\n1,2' })).json.errors).toEqual(['dns_csv_invalid'])
    const p = await oper.post('/api/migration/zones/preview', { content: CSV }); expect(p.status, p.text).toBe(200)
    expect(p.json.toCreate).toBe(3); expect(p.json.items.find((i: any) => i.name === 'stub.test')).toMatchObject({ action: 'skip', reason: 'stub' })
    expect((await rows('select count(*)::int n from dns_zones'))[0].n).toBe(0)
  })
  it('création : primaires, secondaires (maîtres) et redirecteurs ; instantané, historique, audit ; second passage sans effet', async () => {
    const r = await oper.post('/api/migration/zones/commit', { content: CSV, filename: 'dns-zones.csv' }); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ created: 3 }); expect(r.json.snapshotId).toBeGreaterThan(0)
    expect(await rows('select name, type, masters, forwarders, ad_integrated from dns_zones order by name')).toEqual([
      { name: 'corp.test', type: 'primary', masters: [], forwarders: [], ad_integrated: true },
      { name: 'partner.test', type: 'forward', masters: [], forwarders: ['203.0.113.7'], ad_integrated: false },
      { name: 'sec.test', type: 'secondary', masters: ['10.0.0.5'], forwarders: [], ad_integrated: false }])
    expect((await rows("select 1 from import_runs where kind = 'dns-zones'")).length).toBe(1); expect((await rows("select 1 from audit_log where action = 'migration_zones'")).length).toBe(1)
    expect((await oper.post('/api/migration/zones/commit', { content: CSV })).json).toMatchObject({ created: 0 })
    zid = (await rows("select id from dns_zones where name = 'corp.test'"))[0].id
  })
  it('transfert : administrateur seulement ; serveur invalide, zone non primaire, refus du serveur', async () => {
    code(await oper.post('/api/migration/axfr/preview', { server: '192.0.2.1', zone_id: zid }), 403, 'forbidden')
    for (const bad of ['-f /etc/passwd', '; id', 'a b']) code(await admin.post('/api/migration/axfr/preview', { server: bad, zone_id: zid }), 400, 'axfr_server_invalid')
    const sec = (await rows("select id from dns_zones where name = 'sec.test'"))[0].id
    code(await admin.post('/api/migration/axfr/preview', { server: '192.0.2.1', zone_id: sec }), 400, 'zone_not_primary')
    code(await admin.post('/api/migration/axfr/preview', { server: '192.0.2.1', zone_id: 999999 }), 404, 'not_found')
    code(await admin.post('/api/migration/axfr/preview', { server: '192.0.2.2', zone_id: zid }), 502, 'axfr_refused')
  })
  it('transfert : analyse puis import ; critiques AD protégés ; arguments de dig sans shell ; rien d’écrasé au second passage', async () => {
    const p = await admin.post('/api/migration/axfr/preview', { server: '192.0.2.1', zone_id: zid }); expect(p.status, p.text).toBe(200)
    expect(p.json).toMatchObject({ new: 4, identical: 0, conflicts: 0 }); expect((await rows('select count(*)::int n from dns_records'))[0].n).toBe(0)
    const r = await admin.post('/api/migration/axfr/commit', { server: '192.0.2.1', zone_id: zid }); expect(r.status, r.text).toBe(200)
    expect(r.json.inserted).toBe(4)
    expect((await rows('select name, type from dns_records order by name, type')).map((x) => `${x.name}/${x.type}`)).toEqual(['@/NS', '_ldap._tcp/SRV', 'dc1/A', 'www/CNAME'])
    expect((await rows("select protected from dns_records where name = '_ldap._tcp'"))[0].protected).toBe(true)
    expect((await rows('select count(*)::int n from dns_zones where dirty and name = $1', ['corp.test']))[0].n).toBe(1)
    expect((await admin.post('/api/migration/axfr/commit', { server: '192.0.2.1', zone_id: zid })).json.inserted).toBe(0)
    const log = readFileSync(join(TMP, 'dig.log'), 'utf8').trim().split('\n').filter((l) => l.includes('@192.0.2.1'))
    expect(log[0]).toBe('+noall +answer +nocomments +time=10 +tries=1 +tcp @192.0.2.1 corp.test AXFR')
  })
})
