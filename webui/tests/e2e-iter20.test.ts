// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.10.0 — synchronisation bail DHCP → DNS.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3421, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s20-')); mkdirSync(join(TMP, 'gen'))
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

const ip2n = (ip: string) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0)
const lease = (ip: string, mac: string, host: string | null, mins = 60) =>
  db.query("insert into lease4 (address, hwaddr, hostname, subnet_id, expire) values ($1, decode($2, 'hex'), $3, 1, now() + make_interval(mins => $4)) on conflict (address) do update set hostname = excluded.hostname, expire = excluded.expire", [ip2n(ip), mac.replace(/:/g, ''), host, mins])
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const dyn = () => rows("select z.name as zone, r.name, r.type, r.rdata from dns_records r join dns_zones z on z.id = r.zone_id where r.source = 'dhcp' order by z.name, r.name, r.type")
const zone = (o: Record<string, unknown>) => ({ type: 'primary', soa_mname: 'ns1.corp.test.', soa_rname: 'hostmaster.corp.test.', ...o })
let zF = 0, zR = 0, sn = 0

describe('bail DHCP → DNS', () => {
  it('mise en place : zones directe et inverse, gabarit avec zone DNS, réseau, table de baux', async () => {
    zF = (await admin.post('/api/dns/zones', zone({ name: 'corp.test' }))).json.id; zR = (await admin.post('/api/dns/zones', zone({ name: '0.60.10.in-addr.arpa' }))).json.id
    expect(zF && zR).toBeTruthy()
    const t = await db.query("insert into network_templates (name, dns_zone_id) values ('t', $1) returning id", [zF])
    sn = (await admin.post('/api/ipam/subnets', { cidr: '10.60.0.0/24', name: 'lan', template_id: t.rows[0].id })).json.id; expect(sn).toBeTruthy()
    await db.query('create table lease4 (address bigint primary key, hwaddr bytea, hostname varchar, subnet_id bigint, expire timestamp)')
  })
  it('désactivée par défaut : rien n\'est créé ; droits : lecteur lit, seul l\'admin règle', async () => {
    await lease('10.60.0.20', 'aa:bb:cc:00:00:20', 'PC-Alice')
    const r = await admin.post('/api/dns/lease-sync/run'); expect(r.status).toBe(200); expect(r.json).toMatchObject({ enabled: false, records: 0 })
    expect(await dyn()).toEqual([])
    expect((await viewer.get('/api/dns/lease-sync')).status).toBe(200)
    code(await viewer.put('/api/dns/lease-sync', { enabled: true }), 403, 'forbidden'); code(await anon.get('/api/dns/lease-sync'), 401, 'unauthenticated')
    code(await viewer.post('/api/dns/lease-sync/run'), 403, 'forbidden')
    expect((await admin.put('/api/dns/lease-sync', { enabled: 'oui' })).status).toBe(400)
  })
  it('activée : A + PTR créés pour le bail, zones à déployer, passage répété sans effet', async () => {
    await db.query('update dns_zones set dirty = false')
    const r = await admin.put('/api/dns/lease-sync', { enabled: true }); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ enabled: true, records: 2, zones: 2, run: { added: 2, removed: 0 } })
    expect(await dyn()).toEqual([{ zone: '0.60.10.in-addr.arpa', name: '20', type: 'PTR', rdata: 'pc-alice.corp.test.' }, { zone: 'corp.test', name: 'pc-alice', type: 'A', rdata: '10.60.0.20' }])
    expect((await rows('select count(*)::int n from dns_zones where dirty'))[0].n).toBe(2)
    expect((await admin.post('/api/dns/lease-sync/run')).json.run).toMatchObject({ added: 0, removed: 0 })
  })
  it('enregistrement dynamique : visible comme tel, non modifiable ni supprimable à la main', async () => {
    const l = await admin.get(`/api/dns/records?zone_id=${zF}`); const rec = l.json.items.find((x: any) => x.name === 'pc-alice')
    expect(rec.dynamic).toBe(true)
    code(await admin.delete(`/api/dns/records/${rec.id}`), 409, 'record_dynamic')
    code(await admin.put(`/api/dns/records/${rec.id}`, { zone_id: zF, name: 'pc-alice', type: 'A', rdata: '10.60.0.99' }), 409, 'record_dynamic')
  })
  it('le client change d\'IP, un autre bail apparaît, un bail expire : les enregistrements suivent', async () => {
    await db.query('delete from lease4'); await lease('10.60.0.21', 'aa:bb:cc:00:00:20', 'pc-alice.corp.test.'); await lease('10.60.0.30', 'aa:bb:cc:00:00:30', 'imprimante')
    await lease('10.60.0.31', 'aa:bb:cc:00:00:31', 'perime', -5)
    const r = await admin.post('/api/dns/lease-sync/run'); expect(r.json.run).toMatchObject({ added: 4, removed: 2 })
    expect((await dyn()).map((x: any) => `${x.name}/${x.type}/${x.rdata}`)).toEqual(['21/PTR/pc-alice.corp.test.', '30/PTR/imprimante.corp.test.', 'imprimante/A/10.60.0.30', 'pc-alice/A/10.60.0.21'])
  })
  it('jamais d\'écrasement : nom saisi à la main, adresse IPAM nommée, nom en double, sans zone', async () => {
    expect((await admin.post('/api/dns/records', { zone_id: zF, name: 'serveur', type: 'A', rdata: '10.60.0.40' })).status).toBe(200)
    expect((await admin.post(`/api/ipam/subnets/${sn}/addresses`, { ip: '10.60.0.41', hostname: 'fixe' })).status).toBe(200)
    await lease('10.60.0.50', 'aa:bb:cc:00:00:50', 'serveur'); await lease('10.60.0.41', 'aa:bb:cc:00:00:41', 'autre'); await lease('10.60.0.51', 'aa:bb:cc:00:00:51', 'dup'); await lease('10.60.0.52', 'aa:bb:cc:00:00:52', 'dup')
    await lease('192.168.9.9', 'aa:bb:cc:00:00:99', 'horszone')
    const r = (await admin.post('/api/dns/lease-sync/run')).json.run
    expect(r).toMatchObject({ conflicts: 2, static: 1, nozone: 1 })
    const names = (await dyn()).filter((x: any) => x.type === 'A').map((x: any) => `${x.name}/${x.rdata}`)
    expect(names).toEqual(['dup/10.60.0.51', 'imprimante/10.60.0.30', 'pc-alice/10.60.0.21'])
    expect((await rows("select rdata from dns_records where name = 'serveur' and source = 'manual'")).map((x) => x.rdata)).toEqual(['10.60.0.40'])
  })
  it('un enregistrement manuel créé après coup reprend la main sur le dynamique', async () => {
    expect((await admin.post('/api/dns/records', { zone_id: zF, name: 'imprimante', type: 'A', rdata: '10.60.0.77' })).status).toBe(200)
    await admin.post('/api/dns/lease-sync/run')
    expect((await dyn()).filter((x: any) => x.name === 'imprimante' && x.type === 'A')).toEqual([])
    expect((await rows("select rdata from dns_records where name = 'imprimante' and source = 'manual'")).map((x) => x.rdata)).toEqual(['10.60.0.77'])
  })
  it('désactivée : seuls les enregistrements dynamiques disparaissent', async () => {
    const r = await admin.put('/api/dns/lease-sync', { enabled: false }); expect(r.json).toMatchObject({ enabled: false, records: 0 })
    expect((await rows("select count(*)::int n from dns_records where source = 'manual' and name in ('serveur','imprimante')"))[0].n).toBe(2)
    expect((await rows("select action from audit_log where action like 'lease_dns%' limit 1")).length).toBe(1)
  })
})
