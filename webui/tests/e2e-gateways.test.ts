// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.22.0 — passerelles dans la liste des adresses (routeurs DHCP et passerelle du réseau automatiques, drapeau manuel)
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3491, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s63-')); mkdirSync(join(TMP, 'gen'))
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
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_DIG: join(TMP, 'dig.sh'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json'),  DDI_OIDC_ALLOW_HTTP: '1' } })
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



const rowsOf = async (netId: number, q = '') => (await viewer.get(`/api/ipam/addresses?subnet_id=${netId}&limit=500${q}`)).json.items as any[]
const find = (items: any[], ip: string) => items.filter((i) => i.ip === ip)

describe('0.22.0 — passerelles dans la liste des adresses', () => {
  let net = 0, scope = 0
  it('un routeur d\'une étendue DHCP apparaît seul, en lecture seule ; une IP hors du réseau est ignorée', async () => {
    const n = await admin.post('/api/ipam/subnets', { cidr: '10.88.1.0/24', name: 'Postes' }); expect(n.status, n.text).toBe(200); net = n.json.id
    const sc = await admin.post('/api/dhcp/scopes', { subnet_id: net, options: { routers: ['10.88.1.1', '10.99.9.9'] } }); expect(sc.status, sc.text).toBe(200); scope = sc.json.id
    const items = await rowsOf(net)
    expect(find(items, '10.88.1.1')).toEqual([expect.objectContaining({ id: null, status: 'gateway', gw: 'dhcp', is_gateway: false, hostname: null })])
    expect(find(items, '10.99.9.9')).toEqual([])
    const per = (await viewer.get(`/api/ipam/subnets/${net}/addresses`)).json.items
    expect(find(per, '10.88.1.1')).toEqual([expect.objectContaining({ id: null, status: 'gateway', gw: 'dhcp' })])
    expect(find(per, '10.99.9.9')).toEqual([])
  })
  it('déclarée dans l\'IPAM, la ligne reste unique et garde l\'origine automatique, sans poser le drapeau', async () => {
    const a = await admin.post(`/api/ipam/subnets/${net}/addresses`, { ip: '10.88.1.1', hostname: 'fw-lan' }); expect(a.status, a.text).toBe(200)
    const items = await rowsOf(net), r = find(items, '10.88.1.1')
    expect(r).toHaveLength(1); expect(r[0]).toMatchObject({ id: a.json.id, status: 'used', hostname: 'fw-lan', gw: 'dhcp', is_gateway: false })
    expect(find((await viewer.get(`/api/ipam/subnets/${net}/addresses`)).json.items, '10.88.1.1')).toHaveLength(1)
  })
  it('le drapeau manuel : posé à la création, retiré, posé par le statut passerelle, retiré par un autre statut', async () => {
    const a = await admin.post(`/api/ipam/subnets/${net}/addresses`, { ip: '10.88.1.2', hostname: 'rtr-b', is_gateway: true }); expect(a.status, a.text).toBe(200)
    const state = async () => find(await rowsOf(net), '10.88.1.2')[0]
    expect(await state()).toMatchObject({ gw: 'flag', is_gateway: true, status: 'used' })
    expect((await admin.put(`/api/ipam/addresses/${a.json.id}`, { is_gateway: false })).status).toBe(200)
    expect(await state()).toMatchObject({ gw: null, is_gateway: false })
    expect((await admin.put(`/api/ipam/addresses/${a.json.id}`, { status: 'gateway' })).status).toBe(200)
    expect(await state()).toMatchObject({ gw: 'flag', is_gateway: true, status: 'gateway' })
    expect((await admin.put(`/api/ipam/addresses/${a.json.id}`, { is_gateway: false })).status).toBe(200)   // le statut passerelle l'emporte
    expect(await state()).toMatchObject({ gw: 'flag', is_gateway: true })
    expect((await admin.put(`/api/ipam/addresses/${a.json.id}`, { status: 'infra' })).status).toBe(200)
    expect(await state()).toMatchObject({ gw: null, is_gateway: false, status: 'infra' })
    code(await admin.put(`/api/ipam/addresses/${a.json.id}`, { is_gateway: 'oui' }), 400, 'validation')
  })
  it('la passerelle déclarée sur le réseau est automatique ; sans ligne dans l\'IPAM elle s\'affiche aussi', async () => {
    const n2 = await admin.post('/api/ipam/subnets', { cidr: '10.88.2.0/24', name: 'Serveurs', gateway: '10.88.2.254' }); expect(n2.status, n2.text).toBe(200)
    expect(find(await rowsOf(n2.json.id), '10.88.2.254')).toEqual([expect.objectContaining({ id: expect.any(Number), status: 'gateway', gw: 'subnet', is_gateway: true })])
    const n3 = await admin.post('/api/ipam/subnets', { cidr: '10.88.3.0/24', name: 'Vide' }); expect(n3.status).toBe(200)
    expect(await rowsOf(n3.json.id)).toEqual([])
    expect((await admin.put(`/api/ipam/subnets/${n3.json.id}`, { gateway: '10.88.3.1' })).status).toBe(200)
    expect(find(await rowsOf(n3.json.id), '10.88.3.1')).toEqual([expect.objectContaining({ id: null, status: 'gateway', gw: 'subnet' })])
  })
  it('le filtre « gw » ne garde que les passerelles (toutes origines) ; le filtre de statut ordinaire est inchangé', async () => {
    expect((await rowsOf(net, '&status=gw')).map((i) => i.ip).sort()).toEqual(['10.88.1.1'])
    const used = await rowsOf(net, '&status=used'); expect(used.map((i) => i.ip)).toEqual(['10.88.1.1'])   // 10.88.1.1 a le statut « used » : le filtre porte sur le statut
    expect((await viewer.get(`/api/ipam/subnets/${net}/addresses?status=gw`)).json.items.map((i: any) => i.ip)).toEqual(['10.88.1.1'])
  })
  it('« prochaine adresse libre » ne propose jamais un routeur DHCP', async () => {
    const n4 = await admin.post('/api/ipam/subnets', { cidr: '10.88.4.0/29', name: 'Petit' }); expect(n4.status).toBe(200)
    expect((await admin.post('/api/dhcp/scopes', { subnet_id: n4.json.id, options: { routers: ['10.88.4.1'] } })).status).toBe(200)
    const nx = await admin.post(`/api/ipam/subnets/${n4.json.id}/next`, { hostname: 'h1' }); expect(nx.status, nx.text).toBe(200)
    expect(nx.json.ip).toBe('10.88.4.2')
  })
  it('un routeur retiré de l\'étendue disparaît de la liste', async () => {
    const n5 = await admin.post('/api/ipam/subnets', { cidr: '10.88.5.0/24', name: 'Temp' }); const sc = await admin.post('/api/dhcp/scopes', { subnet_id: n5.json.id, options: { routers: ['10.88.5.1'] } })
    expect(find(await rowsOf(n5.json.id), '10.88.5.1')).toHaveLength(1)
    expect((await admin.put(`/api/dhcp/scopes/${sc.json.id}`, { subnet_id: n5.json.id, options: {} })).status).toBe(200)
    expect(find(await rowsOf(n5.json.id), '10.88.5.1')).toHaveLength(0)
  })
})
