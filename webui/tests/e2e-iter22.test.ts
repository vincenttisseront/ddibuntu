// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.10.2 — libération d’une adresse (IPAM + DNS).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3423, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s22-')); mkdirSync(join(TMP, 'gen'))
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
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json'), DDI_OIDC_ALLOW_HTTP: '1' } })
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
const zone = (o: Record<string, unknown>) => ({ type: 'primary', soa_mname: 'ns1.corp.test.', soa_rname: 'hostmaster.corp.test.', ...o })
let zF = 0, zR = 0, sn = 0
const mk = async (ip: string, host: string) => {
  const r = await admin.post(`/api/ipam/subnets/${sn}/addresses`, { ip, hostname: host }); expect(r.status, r.text).toBe(200); return r.json.id as number
}

describe('libération d’une adresse', () => {
  it('mise en place : zones, gabarit, réseau, adresse nommée (A + PTR), alias', async () => {
    zF = (await admin.post('/api/dns/zones', zone({ name: 'corp.test' }))).json.id; zR = (await admin.post('/api/dns/zones', zone({ name: '0.80.10.in-addr.arpa' }))).json.id
    const t = await db.query("insert into network_templates (name, dns_zone_id) values ('t', $1) returning id", [zF])
    sn = (await admin.post('/api/ipam/subnets', { cidr: '10.80.0.0/24', name: 'lan', template_id: t.rows[0].id })).json.id
    const id = await mk('10.80.0.5', 'web')
    const a = await admin.post(`/api/ipam/addresses/${id}/aliases`, { name: 'www' }); expect(a.status, a.text).toBe(200)
  })
  it('récapitulatif : A, PTR, alias ; droits (opérateur au moins)', async () => {
    const id = (await rows("select id from addresses where host(ip) = '10.80.0.5'"))[0].id
    code(await viewer.get(`/api/ipam/addresses/${id}/release-plan`), 403, 'forbidden'); code(await anon.get(`/api/ipam/addresses/${id}/release-plan`), 401, 'unauthenticated')
    code(await admin.get('/api/ipam/addresses/999999/release-plan'), 404, 'not_found')
    const p = await oper.get(`/api/ipam/addresses/${id}/release-plan`); expect(p.status, p.text).toBe(200)
    expect(p.json.records.map((r: any) => `${r.type}:${r.fqdn}`).sort()).toEqual(['A:web.corp.test', 'CNAME:www.corp.test', 'PTR:5.0.80.10.in-addr.arpa'])
    expect(p.json).toMatchObject({ ip: '10.80.0.5', hostname: 'web', reservation: false, dynamic: 0, blocked: false })
    expect((await rows('select count(*)::int n from addresses'))[0].n).toBe(1)   // lecture seule
  })
  it('sans l’option DNS : seule la fiche disparaît', async () => {
    const id = (await rows("select id from addresses where host(ip) = '10.80.0.5'"))[0].id
    expect((await admin.post(`/api/ipam/addresses/${id}/release`, { dns: 'oui' })).status).toBe(400)
    const r = await admin.post(`/api/ipam/addresses/${id}/release`, { dns: false }); expect(r.json).toMatchObject({ ok: true, records: 0 })
    expect((await rows('select count(*)::int n from addresses'))[0].n).toBe(0)
    expect((await rows("select count(*)::int n from dns_records where type in ('A','PTR','CNAME')"))[0].n).toBe(3)
  })
  it('avec l’option DNS : A, PTR et alias partent avec la fiche, zones à déployer, audité ; le dynamique reste', async () => {
    await db.query("delete from dns_records"); await db.query("delete from addresses")
    const id = await mk('10.80.0.6', 'srv'); await admin.post(`/api/ipam/addresses/${id}/aliases`, { name: 'srv-alias' })
    await db.query("insert into dns_records (zone_id, name, type, rdata, source) values ($1,'bail','A','10.80.0.6','dhcp')", [zF])
    await db.query('update dns_zones set dirty = false')
    const p = await admin.get(`/api/ipam/addresses/${id}/release-plan`); expect(p.json.dynamic).toBe(1); expect(p.json.records.length).toBe(3)
    const r = await oper.post(`/api/ipam/addresses/${id}/release`, { dns: true }); expect(r.json).toMatchObject({ ok: true, records: 3 })
    expect((await rows('select count(*)::int n from addresses'))[0].n).toBe(0)
    expect((await rows('select name from dns_records order by name')).map((x) => x.name)).toEqual(['bail'])
    expect((await rows('select count(*)::int n from dns_zones where dirty'))[0].n).toBe(2)
    expect((await rows("select 1 from audit_log where action = 'address_release' and detail->>'records' = '3'")).length).toBe(1)
    code(await admin.post(`/api/ipam/addresses/${id}/release`, { dns: true }), 404, 'not_found')
  })
  it('enregistrement protégé : refusé à l’opérateur sans rien supprimer, accepté pour l’administrateur', async () => {
    const id = await mk('10.80.0.7', 'garde')
    await db.query("update dns_records set protected = true where name = 'garde'")
    const p = await oper.get(`/api/ipam/addresses/${id}/release-plan`); expect(p.json.blocked).toBe(true)
    code(await oper.post(`/api/ipam/addresses/${id}/release`, { dns: true }), 403, 'protected_record')
    expect((await rows('select count(*)::int n from addresses'))[0].n).toBe(1)
    expect((await rows("select count(*)::int n from dns_records where name = 'garde'"))[0].n).toBe(1)
    expect((await oper.post(`/api/ipam/addresses/${id}/release`, { dns: false })).status).toBe(200)   // sans le DNS, l’opérateur peut libérer
    const id2 = await mk('10.80.0.8', 'garde2'); await db.query("update dns_records set protected = true where name = 'garde2'")
    expect((await admin.post(`/api/ipam/addresses/${id2}/release`, { dns: true })).json).toMatchObject({ ok: true, records: 2 })
  })
})
