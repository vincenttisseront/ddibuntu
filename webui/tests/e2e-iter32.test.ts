// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.10.4 — zones inverses automatiques et délégation classless (RFC 2317).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3433, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s32-')); mkdirSync(join(TMP, 'gen'))
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
describe('zones inverses automatiques', () => {
  let s24 = 0, s26 = 0, s22 = 0
  it('sous-réseaux sans zone inverse listés ; plan d\'un /26 avec CNAME', async () => {
    const mk = async (cidr: string) => (await admin.post('/api/ipam/subnets', { cidr, name: cidr })).json.id
    s24 = await mk('192.168.1.0/24'); s26 = await mk('192.168.2.64/26'); s22 = await mk('10.4.0.0/22')
    expect(s26).toBeGreaterThan(0)
    const m = (await viewer.get('/api/dns/reverse/missing')).json.items
    expect(m.map((x: any) => x.cidr).sort()).toEqual(['10.4.0.0/22', '192.168.1.0/24', '192.168.2.64/26'])
    expect(m.find((x: any) => x.cidr === '192.168.2.64/26').missing).toEqual(['2.168.192.in-addr.arpa', '64-26.2.168.192.in-addr.arpa'])
    const p = (await viewer.get(`/api/dns/reverse/plan?subnet_id=${s26}`)).json; expect(p.cnames).toHaveLength(64); expect(p.zones.every((z: any) => !z.exists)).toBe(true)
    code(await viewer.get('/api/dns/reverse/plan?subnet_id=99999'), 404, 'not_found'); code(await viewer.get('/api/dns/reverse/plan'), 400, 'invalid_query')
  })
  it('création : droits, zones, NS copiés du modèle, CNAME classless, idempotence', async () => {
    const fwd = (await admin.post('/api/dns/zones', { name: 'corp.test', type: 'primary', soa_mname: 'ns1.corp.test.' })).json.id
    await db.query("insert into dns_records (zone_id, name, type, rdata) values ($1, '@', 'NS', 'ns1.corp.test.')", [fwd])
    code(await viewer.post('/api/dns/reverse/create', { subnet_id: s24 }), 403, 'forbidden')
    const r = await oper.post('/api/dns/reverse/create', { subnet_id: s26, from_zone_id: fwd }); expect(r.status, r.text).toBe(200); expect(r.json).toEqual({ zones: 2, cnames: 64 })
    expect((await rows("select name, type, soa_mname from dns_zones where name like '%in-addr.arpa' order by name")).map((z: any) => `${z.name}|${z.soa_mname}`)).toEqual(['2.168.192.in-addr.arpa|ns1.corp.test.', '64-26.2.168.192.in-addr.arpa|ns1.corp.test.'])
    expect((await rows("select count(*)::int n from dns_records r join dns_zones z on z.id = r.zone_id where z.name = '64-26.2.168.192.in-addr.arpa' and r.type = 'NS'"))[0].n).toBe(1)
    expect((await rows("select name, rdata from dns_records r where type = 'CNAME' and zone_id = (select id from dns_zones where name = '2.168.192.in-addr.arpa') order by (name)::int limit 1"))[0]).toEqual({ name: '64', rdata: '64.64-26.2.168.192.in-addr.arpa.' })
    expect((await oper.post('/api/dns/reverse/create', { subnet_id: s26 })).json).toEqual({ zones: 0, cnames: 0 })
    expect((await oper.post('/api/dns/reverse/create', { subnet_id: s22 })).json.zones).toBe(1); expect((await rows("select 1 from dns_zones where name = '4.10.in-addr.arpa'")).length).toBe(1)
    expect((await viewer.get('/api/dns/reverse/missing')).json.items.map((x: any) => x.cidr)).toEqual(['192.168.1.0/24'])
  })
  it('un PTR publié dans un bloc classless va dans la zone fille, le parent le délègue', async () => {
    const fwd = (await rows("select id from dns_zones where name = 'corp.test'"))[0].id
    const r = await oper.post(`/api/ipam/subnets/${s26}/addresses`, { ip: '192.168.2.70', hostname: 'srv', dns_zone_id: fwd }); expect(r.status, r.text).toBe(200)
    expect((await rows("select r.name, r.rdata from dns_records r join dns_zones z on z.id = r.zone_id where z.name = '64-26.2.168.192.in-addr.arpa' and r.type = 'PTR'"))).toEqual([{ name: '70', rdata: 'srv.corp.test.' }])
    expect((await rows("select r.type, r.rdata from dns_records r join dns_zones z on z.id = r.zone_id where z.name = '2.168.192.in-addr.arpa' and r.name = '70'"))).toEqual([{ type: 'CNAME', rdata: '70.64-26.2.168.192.in-addr.arpa.' }])
  })
  it('adresse hors bloc classless : PTR classique dans la zone du /24', async () => {
    const fwd = (await rows("select id from dns_zones where name = 'corp.test'"))[0].id
    await oper.post(`/api/ipam/subnets/${s24}/addresses`, { ip: '192.168.1.9', hostname: 'a', dns_zone_id: fwd })
    expect((await rows("select 1 from dns_records r join dns_zones z on z.id = r.zone_id where z.name = '1.168.192.in-addr.arpa' and r.type = 'PTR'")).length).toBe(0)   // la zone du /24 n'existe pas encore
    await oper.post('/api/dns/reverse/create', { subnet_id: s24 })
    await oper.post(`/api/ipam/subnets/${s24}/addresses`, { ip: '192.168.1.10', hostname: 'b', dns_zone_id: fwd })
    expect((await rows("select r.name from dns_records r join dns_zones z on z.id = r.zone_id where z.name = '1.168.192.in-addr.arpa' and r.type = 'PTR'")).map((x: any) => x.name)).toEqual(['10'])
  })
})
