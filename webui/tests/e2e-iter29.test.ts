// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.7 — après la migration (SRV de localisation, GSS-TSIG, retrait).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3430, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s29-')); mkdirSync(join(TMP, 'gen'))
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
describe('après la migration', () => {
  let zid = 0
  it('SRV de localisation : zone inconnue 404 ; absents signalés ; complets = aucun écart', async () => {
    code(await viewer.get('/api/migration/post/locator?zone_id=999'), 404, 'not_found')
    await db.query("insert into dns_zones (name, type) values ('corp.test', 'primary')"); zid = (await rows("select id from dns_zones where name = 'corp.test'"))[0].id
    await db.query("insert into dns_records (zone_id, name, type, rdata) values ($1, 'dc1', 'A', '10.0.0.10'), ($1, '_ldap._tcp', 'SRV', '0 100 389 dc1.corp.test.'), ($1, '_kerberos._tcp', 'SRV', '0 100 88 dc2.corp.test.')", [zid])
    const r = await viewer.get(`/api/migration/post/locator?zone_id=${zid}`); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ zone: 'corp.test', present: 2, expected: 8 })
    expect(r.json.findings.filter((f: any) => f.kind === 'target_unresolved')).toEqual([{ name: '_kerberos._tcp', kind: 'target_unresolved', detail: 'dc2.corp.test' }])
    expect(r.json.findings.filter((f: any) => f.kind === 'missing').length).toBe(6)
    for (const n of ['_kerberos._udp', '_kpasswd._tcp', '_kpasswd._udp', '_gc._tcp', '_ldap._tcp.dc._msdcs', '_kerberos._tcp.dc._msdcs']) await db.query("insert into dns_records (zone_id, name, type, rdata) values ($1, $2, 'SRV', '0 100 88 dc1.corp.test.')", [zid, n])
    await db.query("update dns_records set rdata = '0 100 88 dc1.corp.test.' where name = '_kerberos._tcp'")
    expect((await viewer.get(`/api/migration/post/locator?zone_id=${zid}`)).json).toMatchObject({ findings: [], present: 8 })
  })
  it('gabarit GSS-TSIG : opérateur, noms validés', async () => {
    code(await viewer.post('/api/migration/post/gss', { zone: 'corp.test', realm: 'corp.test' }), 403, 'forbidden')
    code(await oper.post('/api/migration/post/gss', { zone: 'corp', realm: 'corp.test' }), 400, 'realm_invalid')
    const r = await oper.post('/api/migration/post/gss', { zone: 'corp.test', realm: 'corp.test' }); expect(r.status, r.text).toBe(200); expect(r.json.template).toContain('grant CORP.TEST ms-self')
  })
  it('retrait des rôles : disponible seulement une fois la bascule terminée', async () => {
    expect((await viewer.get('/api/migration/post')).json).toEqual({ cutoverFinished: false, finishedAt: null })
    await db.query("insert into settings (key, value) values ('migration_cutover', $1)", [JSON.stringify({ started: { at: 'x', by: 'a', snapshotId: 1 }, manual: {}, finishedAt: '2026-11-13T12:00:00Z' })])
    expect((await viewer.get('/api/migration/post')).json).toEqual({ cutoverFinished: true, finishedAt: '2026-11-13T12:00:00Z' })
  })
})
