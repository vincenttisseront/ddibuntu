// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.10.5 — règles et formats de nommage (VLAN, gabarit), contrôle de convention.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3434, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s33-')); mkdirSync(join(TMP, 'gen'))
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
describe('nommage', () => {
  let vid = 0, tid = 0, sid = 0
  it('VLAN : règle et format validés, enregistrés, modifiables', async () => {
    code(await oper.post('/api/ipam/vlans', { vlan_id: 20, name: 'srv', hostname_pattern: 'a b' }), 400, 'pattern_chars')
    code(await oper.post('/api/ipam/vlans', { vlan_id: 20, name: 'srv', name_format: 'x-{nope}' }), 400, 'format_token')
    const r = await oper.post('/api/ipam/vlans', { vlan_id: 20, name: 'srv', hostname_pattern: 'v20-###', name_format: 'v20-{o4:3}' }); expect(r.status, r.text).toBe(200); vid = r.json.id
    expect((await viewer.get('/api/ipam/vlans')).json.items[0]).toMatchObject({ hostname_pattern: 'v20-###', name_format: 'v20-{o4:3}' })
    expect((await oper.put(`/api/ipam/vlans/${vid}`, { name: 'srv2' })).status).toBe(200)
    expect((await rows('select name, hostname_pattern from vlans'))[0]).toEqual({ name: 'srv2', hostname_pattern: 'v20-###' })
  })
  it('gabarit : format enregistré ; le VLAN l\'emporte sur le gabarit', async () => {
    const t = await oper.post('/api/ipam/templates', { name: 'g', hostname_pattern: 'gen-###', name_format: 'gen-{o4:3}' }); expect(t.status, t.text).toBe(200); tid = t.json.id
    code(await oper.post('/api/ipam/templates', { name: 'h', name_format: 'x y' }), 400, 'format_chars')
    sid = (await admin.post('/api/ipam/subnets', { cidr: '10.20.0.0/24', name: 'srv', template_id: tid })).json.id
    let sg = (await viewer.get(`/api/ipam/naming/suggest?subnet_id=${sid}&ip=10.20.0.7`)).json; expect(sg).toMatchObject({ name: 'gen-007', source: 'template', valid: true })
    await db.query('update subnets set vlan_id = $1 where id = $2', [vid, sid])
    sg = (await viewer.get(`/api/ipam/naming/suggest?subnet_id=${sid}&ip=10.20.0.7`)).json; expect(sg).toMatchObject({ name: 'v20-007', source: 'vlan', pattern: 'v20-###', valid: true })
    code(await viewer.get('/api/ipam/naming/suggest?subnet_id=1'), 400, 'invalid_query')
  })
  it('la règle du VLAN s\'applique aux adresses saisies', async () => {
    const bad = await oper.post(`/api/ipam/subnets/${sid}/addresses`, { ip: '10.20.0.50', hostname: 'gen-050' }); code(bad, 400, 'hostname_rule')
    expect((await oper.post(`/api/ipam/subnets/${sid}/addresses`, { ip: '10.20.0.51', hostname: 'v20-051' })).status).toBe(200)
  })
  it('prochaine adresse libre : nom généré si demandé ; refusé sans format', async () => {
    const r = await oper.post(`/api/ipam/subnets/${sid}/next`, { auto_name: true }); expect(r.status, r.text).toBe(200); expect(r.json.hostname).toBe(`v20-${String(r.json.ip.split('.')[3]).padStart(3, '0')}`)
    const s2 = (await admin.post('/api/ipam/subnets', { cidr: '10.30.0.0/24', name: 'nofmt' })).json.id
    code(await oper.post(`/api/ipam/subnets/${s2}/next`, { auto_name: true }), 400, 'name_not_generated')
    expect((await oper.post(`/api/ipam/subnets/${s2}/next`, {})).json.hostname).toBeNull()
  })
  it('contrôle de convention : les noms hors règle sont listés', async () => {
    await db.query("insert into addresses (subnet_id, ip, status, hostname) values ($1, '10.20.0.99', 'used', 'portable-jean'), ($1, '10.20.0.98', 'used', null)", [sid])
    const r = (await viewer.get(`/api/ipam/naming/audit?subnet_id=${sid}`)).json
    expect(r.items.map((i: any) => i.hostname)).toEqual(['portable-jean']); expect(r.violations).toBe(1); expect(r.unnamed).toBeGreaterThanOrEqual(1); expect(r.items[0]).toMatchObject({ pattern: 'v20-###' })
    expect((await viewer.get('/api/ipam/naming/audit')).json.violations).toBe(1)
    code(await anon.get('/api/ipam/naming/audit'), 401, 'unauthenticated')
  })
})
