// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.21 — les plages DHCP figurent parmi les pools IPAM, les baux actifs parmi les adresses, la traçabilité s'ouvre sur les associations récentes. Précédemment : 0.12.17 — l'authentification AD / LDAP ne s'active qu'avec une connexion testée (liaison réussie) ; toute modification de la connexion exige un nouveau test.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3438, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s37-')); mkdirSync(join(TMP, 'gen'))
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


const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const lease = (n: number, mac: string, host: string | null, scope: number, ttl = '1 hour') =>
  db.query(`insert into lease4 (address, hwaddr, hostname, subnet_id, expire) values ($1, decode($2,'hex'), $3, $4, now() + $5::interval)`, [n, mac, host, scope, ttl])
const ipn = (a: number, b: number, c: number, d: number) => ((a * 256 + b) * 256 + c) * 256 + d
describe('IPAM : plages DHCP, baux actifs, traçabilité', () => {
  let sid = 0, scope = 0
  it('mise en place : réseau, pool IPAM, étendue DHCP avec plage, baux Kea', async () => {
    await db.query('create table lease4 (address bigint primary key, hwaddr bytea, hostname varchar, subnet_id bigint, expire timestamp)')
    const s = await admin.post('/api/ipam/subnets', { cidr: '10.88.0.0/24', name: 'LAN test' }); expect(s.status).toBe(200); sid = s.json.id
    expect((await admin.post(`/api/ipam/subnets/${sid}/pools`, { name: 'Serveurs', start_ip: '10.88.0.10', end_ip: '10.88.0.19' })).status).toBe(200)
    const d = await admin.post('/api/dhcp/scopes', { subnet_id: sid, name: 'Étendue LAN' }); expect(d.status).toBe(200); scope = d.json.id
    expect((await admin.post(`/api/dhcp/scopes/${scope}/pools`, { start: '10.88.0.100', end: '10.88.0.199' })).status).toBe(200)
    await lease(ipn(10, 88, 0, 101), 'aabbcc000101', 'pc101.lan.test', scope)
    await lease(ipn(10, 88, 0, 102), 'aabbcc000102', null, scope)
    await lease(ipn(10, 88, 0, 103), 'aabbcc000103', 'expire.lan.test', scope, '-1 hour')   // bail expiré : ignoré
    await lease(ipn(10, 88, 0, 104), 'aabbcc000104', 'connu.lan.test', scope)
    expect((await admin.post(`/api/ipam/subnets/${sid}/addresses`, { ip: '10.88.0.104', status: 'used', hostname: 'connu' })).status).toBe(200)   // déjà dans l'IPAM
  })
  it('pools : le pool IPAM et la plage DHCP figurent ensemble ; la plage DHCP compte ses baux ; lecture seule', async () => {
    const r = await viewer.get('/api/ipam/pools'); expect(r.status).toBe(200)
    const mine = r.json.items.find((p: any) => p.source === 'ipam'), dhcp = r.json.items.find((p: any) => p.source === 'dhcp')
    expect(mine).toMatchObject({ name: 'Serveurs', start_ip: '10.88.0.10', end_ip: '10.88.0.19', size: 10, used: 0 })
    expect(dhcp).toMatchObject({ name: 'Étendue LAN', start_ip: '10.88.0.100', end_ip: '10.88.0.199', cidr: '10.88.0.0/24', size: 100, used: 3 })   // 101, 102 (baux) + 104 (adresse IPAM ET bail : une seule fois)
    expect(dhcp.id).toBeLessThan(0)
    expect((await viewer.get(`/api/ipam/pools?subnet_id=${sid}`)).json.items).toHaveLength(2)
    expect((await viewer.get('/api/ipam/pools?q=Serveurs')).json.items.map((p: any) => p.source)).toEqual(['ipam'])
    code(await admin.put(`/api/ipam/pools/${dhcp.id}`, { name: 'x' }), 400, 'invalid_id')   // une plage DHCP ne se modifie pas depuis l'IPAM
  })
  it('adresses : les baux actifs apparaissent (lecture seule), sans doublon avec l\'IPAM ; filtres, comptage, MAC formatée', async () => {
    const all = await viewer.get(`/api/ipam/addresses?subnet_id=${sid}`); expect(all.status).toBe(200)
    expect(all.json.total).toBe(3)   // 101, 102 (baux) + 104 (adresse IPAM)
    const byIp = Object.fromEntries(all.json.items.map((a: any) => [a.ip, a]))
    expect(byIp['10.88.0.101']).toMatchObject({ id: null, status: 'lease', hostname: 'pc101.lan.test', mac: 'aa:bb:cc:00:01:01', cidr: '10.88.0.0/24' })
    expect(byIp['10.88.0.102']).toMatchObject({ id: null, status: 'lease', hostname: null })
    expect(byIp['10.88.0.104']).toMatchObject({ status: 'used' }); expect(byIp['10.88.0.104'].id).toBeGreaterThan(0)
    expect(byIp['10.88.0.103']).toBeUndefined()
    const only = await viewer.get(`/api/ipam/addresses?subnet_id=${sid}&status=lease`); expect(only.json.items.map((a: any) => a.ip)).toEqual(['10.88.0.101', '10.88.0.102']); expect(only.json.total).toBe(2)
    expect((await viewer.get(`/api/ipam/addresses?subnet_id=${sid}&status=used`)).json.items.map((a: any) => a.ip)).toEqual(['10.88.0.104'])
    expect((await viewer.get(`/api/ipam/addresses?subnet_id=${sid}&q=aa:bb:cc:00:01:01`)).json.items.map((a: any) => a.ip)).toEqual(['10.88.0.101'])
    expect((await viewer.get(`/api/ipam/addresses?subnet_id=${sid}&limit=1&offset=1`)).json.items).toHaveLength(1)
  })
  it('un bail sans étendue connue n\'est pas inventé dans un réseau ; sans table lease4 la liste reste celle de l\'IPAM', async () => {
    await lease(ipn(10, 99, 0, 5), 'aabbcc000999', 'orphelin', 99999)
    expect((await viewer.get('/api/ipam/addresses?status=lease')).json.items.map((a: any) => a.ip)).toEqual(['10.88.0.101', '10.88.0.102'])
  })
  it('traçabilité : sans recherche, les associations récentes ; filtre actifs / terminés ; sous-réseau', async () => {
    expect((await oper.post('/api/trace/collect')).status).toBe(200)
    const r = await viewer.get('/api/trace'); expect(r.status).toBe(200)
    expect(r.json.items.map((i: any) => i.ip).sort()).toEqual(['10.88.0.101', '10.88.0.102', '10.88.0.104', '10.99.0.5'])   // l'historique suit TOUS les baux, même sans étendue connue
    expect(r.json.items.find((i: any) => i.ip === '10.88.0.101')).toMatchObject({ open: true, subnet: '10.88.0.0/24', hostname: 'pc101.lan.test' })
    await db.query("delete from lease4 where address = $1", [ipn(10, 88, 0, 102)])
    expect((await oper.post('/api/trace/collect')).status).toBe(200)
    expect((await viewer.get('/api/trace?state=open')).json.items.map((i: any) => i.ip).sort()).toEqual(['10.88.0.101', '10.88.0.104', '10.99.0.5'])
    expect((await viewer.get('/api/trace?state=closed')).json.items.map((i: any) => i.ip)).toEqual(['10.88.0.102'])
    expect((await viewer.get('/api/trace?state=closed&q=10.88.0.101')).json.items).toEqual([])
    expect((await viewer.get('/api/trace?q=pc101')).json.items).toHaveLength(1)
    expect((await viewer.get('/api/trace?q=%25%25')).json.items).toEqual([])   // terme sans critère valable : rien (et jamais tout l'historique)
    code(await anon.get('/api/trace'), 401, 'unauthenticated')
  })
})
