// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.10.3 — historique DNS, retour arrière, aperçu de zone.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3432, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s31-')); mkdirSync(join(TMP, 'gen'))
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
const zoneFile = async () => (await admin.get('/api/system/render')).json.files.find((f: any) => f.path === 'zones/db.corp.test')
describe('historique et aperçu', () => {
  let zid = 0, rid = 0, h: any[] = []
  const hist = async () => (await viewer.get(`/api/dns/zones/${zid}/history`)).json.items
  it('création, modification, suppression sont journalisées avec avant / après', async () => {
    zid = (await admin.post('/api/dns/zones', { name: 'corp.test', type: 'primary' })).json.id
    rid = (await oper.post('/api/dns/records', { zone_id: zid, name: 'www', type: 'A', rdata: '10.0.0.1' })).json.id
    expect((await oper.put(`/api/dns/records/${rid}`, { zone_id: zid, name: 'www', type: 'A', rdata: '10.0.0.2', ttl: 300 })).status).toBe(200)
    h = await hist(); expect(h.map((x: any) => x.action)).toEqual(['update', 'create']); expect(h[0]).toMatchObject({ username: 'oper', before: { rdata: '10.0.0.1' }, after: { rdata: '10.0.0.2', ttl: 300 } })
    expect((await viewer.get(`/api/dns/records/${rid}/history`)).json.items.length).toBe(2)
    code(await viewer.get('/api/dns/zones/9999/history'), 404, 'not_found')
  })
  it('retour arrière d\'une modification ; refusé si l\'enregistrement a encore changé ; spectateur refusé', async () => {
    code(await viewer.post(`/api/dns/history/${h[0].id}/revert`, {}), 403, 'forbidden')
    expect((await oper.post(`/api/dns/history/${h[0].id}/revert`, {})).status).toBe(200)
    expect((await rows('select rdata, ttl from dns_records where id = $1', [rid]))[0]).toEqual({ rdata: '10.0.0.1', ttl: null })
    code(await oper.post(`/api/dns/history/${h[0].id}/revert`, {}), 409, 'history_stale')
    const last = (await hist())[0]; expect(last.action).toBe('revert'); code(await oper.post(`/api/dns/history/${last.id}/revert`, {}), 400, 'history_not_revertible')
  })
  it('suppression annulée = enregistrement recréé ; création annulée = enregistrement supprimé', async () => {
    expect((await oper.delete(`/api/dns/records/${rid}`)).status).toBe(200)
    const d = (await hist())[0]; expect(d).toMatchObject({ action: 'delete', before: { name: 'www', rdata: '10.0.0.1' } })
    const r = await oper.post(`/api/dns/history/${d.id}/revert`, {}); expect(r.status, r.text).toBe(200)
    expect((await rows('select name, rdata from dns_records where zone_id = $1', [zid]))).toEqual([{ name: 'www', rdata: '10.0.0.1' }])
    const created = (await hist()).find((x: any) => x.action === 'create'); code(await oper.post(`/api/dns/history/${created.id}/revert`, {}), 409, 'history_stale')   // l'id a changé : plus le même enregistrement
    const r2 = (await oper.post('/api/dns/records', { zone_id: zid, name: 'tmp', type: 'A', rdata: '10.0.0.9' })).json.id
    const c2 = (await hist())[0]; expect((await oper.post(`/api/dns/history/${c2.id}/revert`, {})).status).toBe(200)
    expect((await rows('select count(*)::int n from dns_records where id = $1', [r2]))[0].n).toBe(0)
  })
  it('enregistrement protégé : retour arrière réservé à l\'administrateur', async () => {
    const id = (await admin.post('/api/dns/records', { zone_id: zid, name: '_ldap._tcp', type: 'SRV', rdata: '0 100 389 dc1.corp.test.' })).json.id
    expect((await admin.delete(`/api/dns/records/${id}`)).status).toBe(200)
    const d = (await hist())[0]; expect(d.before.protected).toBe(true)
    code(await oper.post(`/api/dns/history/${d.id}/revert`, {}), 403, 'protected_record')
    expect((await admin.post(`/api/dns/history/${d.id}/revert`, {})).status).toBe(200)
  })
  it('aperçu de zone : pas déployée, puis identique, puis différences nommées', async () => {
    code(await viewer.get('/api/dns/zones/9999/preview'), 404, 'not_found')
    const p0 = (await viewer.get(`/api/dns/zones/${zid}/preview`)).json; expect(p0).toMatchObject({ zone: 'corp.test', deployed: false, diff: null }); expect(p0.checks[0].ok === false ? p0.checks[0].output : '').toMatch(/NS|^$/)   // sans NS, named-checkzone refuse : c'est le bon retour
    await admin.post('/api/dns/records', { zone_id: zid, name: '@', type: 'NS', rdata: 'ns1.corp.test.' }); await admin.post('/api/dns/records', { zone_id: zid, name: 'ns1', type: 'A', rdata: '10.0.0.53' })
    const ok = (await viewer.get(`/api/dns/zones/${zid}/preview`)).json.checks[0].ok; expect(ok === null || ok === true).toBe(true)
    const f = await zoneFile(); mkdirSync(join(TMP, 'gen', 'zones'), { recursive: true }); writeFileSync(join(TMP, 'gen', f.path), f.content)
    expect((await viewer.get(`/api/dns/zones/${zid}/preview`)).json.diff).toEqual({ added: [], removed: [] })
    await oper.post('/api/dns/records', { zone_id: zid, name: 'nouveau', type: 'A', rdata: '10.0.0.77' })
    await db.query("delete from dns_records where name = 'www'")
    const p = (await viewer.get(`/api/dns/zones/${zid}/preview`)).json
    expect(p.diff.added.some((l: string) => l.includes('10.0.0.77'))).toBe(true); expect(p.diff.removed.some((l: string) => l.includes('10.0.0.1'))).toBe(true)
  })
})
