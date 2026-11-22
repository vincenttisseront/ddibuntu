// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.13.7 — baux DHCP : réseau et état de réservation, bouton « réserver »
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3446, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s45-')); mkdirSync(join(TMP, 'gen'))
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


afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })


afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })


afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })


const lease = (n: number, mac: string | null, host: string | null, scope: number, ttl = '1 hour') =>
  db.query(`insert into lease4 (address, hwaddr, hostname, subnet_id, expire) values ($1, ${mac ? "decode($2,'hex')" : '$2::bytea'}, $3, $4, now() + $5::interval)`, [n, mac, host, scope, ttl])
const ipn = (a: number, b: number, c: number, d: number) => ((a * 256 + b) * 256 + c) * 256 + d
describe('0.13.7 — baux : réserver depuis un bail', () => {
  let sid = 0, scope = 0
  it('liste enrichie : réseau, étendue, état de réservation', async () => {
    await db.query('create table lease4 (address bigint primary key, hwaddr bytea, hostname varchar, subnet_id bigint, expire timestamp)')
    sid = (await admin.post('/api/ipam/subnets', { cidr: '10.99.0.0/24', name: 'Baux' })).json.id
    scope = (await admin.post('/api/dhcp/scopes', { subnet_id: sid, name: 'Étendue baux' })).json.id
    await lease(ipn(10, 99, 0, 101), 'aabbcc000101', 'PC101.corp.test', scope)
    await lease(ipn(10, 99, 0, 102), 'aabbcc000102', 'Mon_PC', scope, '2 hours')
    await lease(ipn(10, 99, 0, 103), null, null, scope)
    await lease(ipn(10, 99, 0, 104), 'aabbcc000104', 'ghost', 424242)
    await lease(ipn(10, 99, 0, 105), 'aabbcc000105', 'old', scope, '-1 hour')
    const r = (await viewer.get('/api/dhcp/leases')).json
    expect(r.available).toBe(true)
    const by = Object.fromEntries(r.items.map((l: any) => [l.ip, l]))
    expect(by['10.99.0.101']).toMatchObject({ mac: 'aa:bb:cc:00:01:01', hostname: 'PC101.corp.test', scope_id: scope, network: '10.99.0.0/24', reservation_id: null })
    expect(by['10.99.0.104'].network).toBeNull()
    expect(by['10.99.0.105']).toBeUndefined()   // bail expiré
  })
  it('réserver : MAC et IP relues dans le bail, nom d\'hôte nettoyé, reflet IPAM, doublon refusé', async () => {
    const r = await oper.post('/api/dhcp/leases/reserve', { ip: '10.99.0.101' })
    expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ ip: '10.99.0.101', mac: 'aa:bb:cc:00:01:01', hostname: 'pc101' })
    const res = (await db.query('select host(ip) ip, mac::text mac, hostname, address_id from dhcp_reservations where scope_id = $1', [scope])).rows
    expect(res).toMatchObject([{ ip: '10.99.0.101', mac: 'aa:bb:cc:00:01:01', hostname: 'pc101' }])
    expect((await db.query("select status from addresses where id = $1", [res[0].address_id])).rows[0].status).toBe('dhcp')
    expect((await viewer.get('/api/dhcp/leases')).json.items.find((l: any) => l.ip === '10.99.0.101').reservation_id).toBe(r.json.id)
    code(await admin.post('/api/dhcp/leases/reserve', { ip: '10.99.0.101' }), 409, 'reservation_exists')
    // nom d'hôte invalide (souligné) : la réservation est créée sans nom
    const r2 = await admin.post('/api/dhcp/leases/reserve', { ip: '10.99.0.102' })
    expect(r2.json).toMatchObject({ ip: '10.99.0.102', hostname: null })
  })
  it('0.22.1 — nom du bail dans l\'IPAM : point final retiré, repli sur un enregistrement A, nom d\'une adresse vide complété', async () => {
    const z = (await admin.post('/api/dns/zones', { name: 'baux.test', type: 'primary', soa_mname: 'ns1.baux.test.', soa_rname: 'hostmaster.baux.test.' })).json
    await admin.post('/api/dns/records', { zone_id: z.id, name: 'imprimante', type: 'A', rdata: '10.99.0.111' })
    await lease(ipn(10, 99, 0, 110), 'aabbcc000110', 'WinPort03.Baux.Test.', scope)   // FQDN absolu envoyé par le client (option 81)
    await lease(ipn(10, 99, 0, 111), 'aabbcc000111', null, scope)                      // client sans nom, mais un A existe dans la zone
    await lease(ipn(10, 99, 0, 112), 'aabbcc000112', null, scope)                      // client sans nom, rien dans le DNS
    await lease(ipn(10, 99, 0, 113), 'aabbcc000113', 'poste113', scope)                // adresse IPAM existante, sans nom
    await db.query("insert into addresses (subnet_id, ip, status) values ($1, '10.99.0.113', 'used')", [sid])
    const by = Object.fromEntries((await viewer.get(`/api/ipam/addresses?subnet_id=${sid}&limit=200`)).json.items.map((a: any) => [a.ip, a]))
    expect(by['10.99.0.110']).toMatchObject({ status: 'lease', hostname: 'winport03.baux.test' })
    expect(by['10.99.0.111']).toMatchObject({ status: 'lease', hostname: 'imprimante.baux.test' })
    expect(by['10.99.0.112']).toMatchObject({ status: 'lease', hostname: null })
    expect(by['10.99.0.113']).toMatchObject({ status: 'used', hostname: 'poste113' })
    const sub = Object.fromEntries((await viewer.get(`/api/ipam/subnets/${sid}/addresses`)).json.items.map((a: any) => [a.ip, a]))
    expect(sub['10.99.0.113'].hostname).toBe('poste113')
    // la page « Baux » du DHCP n'affiche plus le point final
    expect((await viewer.get('/api/dhcp/leases')).json.items.find((l: any) => l.ip === '10.99.0.110').hostname).toBe('WinPort03.Baux.Test')
  })
  it('refus : sans MAC, sans étendue, bail inconnu, droits', async () => {
    code(await admin.post('/api/dhcp/leases/reserve', { ip: '10.99.0.103' }), 400, 'lease_without_mac')
    code(await admin.post('/api/dhcp/leases/reserve', { ip: '10.99.0.104' }), 409, 'no_scope')
    code(await admin.post('/api/dhcp/leases/reserve', { ip: '10.99.0.200' }), 404, 'not_found')
    code(await admin.post('/api/dhcp/leases/reserve', { ip: '10.99.0.105' }), 404, 'not_found')
    code(await admin.post('/api/dhcp/leases/reserve', { ip: 'pas-une-ip' }), 400, 'validation')
    code(await viewer.post('/api/dhcp/leases/reserve', { ip: '10.99.0.101' }), 403, 'forbidden')
    expect((await anon.post('/api/dhcp/leases/reserve', { ip: '10.99.0.101' })).status).toBe(401)
  })
})
