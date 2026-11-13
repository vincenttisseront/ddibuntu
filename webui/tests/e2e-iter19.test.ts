// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.9.53 — alias (CNAME) gérés depuis l'adresse IP.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3420, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s19-')); mkdirSync(join(TMP, 'gen'))
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

const zone = (o: Record<string, unknown>) => ({ type: 'primary', soa_mname: 'ns1.example.test.', soa_rname: 'hostmaster.example.test.', ...o })
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
let zEx = 0, zOt = 0, sn = 0, a1 = 0, a2 = 0, a3 = 0
const dns = (id: number) => admin.get(`/api/ipam/addresses/${id}/dns`)
const al = (id: number, o: Record<string, unknown>) => admin.post(`/api/ipam/addresses/${id}/aliases`, o)

describe('alias CNAME depuis l\'adresse IP', () => {
  it('mise en place : deux zones, un réseau, une adresse avec son nom A', async () => {
    zEx = (await admin.post('/api/dns/zones', zone({ name: 'example.test' }))).json.id; zOt = (await admin.post('/api/dns/zones', zone({ name: 'other.test' }))).json.id
    expect(zEx && zOt).toBeTruthy()
    sn = (await admin.post('/api/ipam/subnets', { cidr: '10.50.0.0/24', name: 'lan' })).json.id
    const r = await admin.post(`/api/ipam/subnets/${sn}/addresses`, { ip: '10.50.0.10', hostname: 'srv', dns_zone_id: zEx }); expect(r.status, r.text).toBe(200); a1 = r.json.id
    a2 = (await admin.post(`/api/ipam/subnets/${sn}/addresses`, { ip: '10.50.0.11', hostname: 'bd', dns_zone_id: zEx })).json.id
    a3 = (await admin.post(`/api/ipam/subnets/${sn}/addresses`, { ip: '10.50.0.12', hostname: 'nu' })).json.id    // sans zone : pas d'enregistrement
  })
  it('vue de l\'adresse : noms, aucun alias ; lecture pour tous, écriture refusée au lecteur', async () => {
    const r = await dns(a1); expect(r.status).toBe(200)
    expect(r.json.hosts.map((h: any) => h.fqdn)).toEqual(['srv.example.test']); expect(r.json.aliases).toEqual([]); expect(r.json.zones.map((z: any) => z.name).sort()).toEqual(['example.test', 'other.test'])
    expect((await viewer.get(`/api/ipam/addresses/${a1}/dns`)).status).toBe(200)
    code(await viewer.post(`/api/ipam/addresses/${a1}/aliases`, { name: 'www' }), 403, 'forbidden')
    code(await anon.get(`/api/ipam/addresses/${a1}/dns`), 401, 'unauthenticated')
    code(await admin.get('/api/ipam/addresses/999999/dns'), 404, 'not_found')
  })
  it('création : nom court (zone de la cible), nom complet dans une autre zone, alias d\'un alias', async () => {
    expect((await al(a1, { name: 'www' })).json).toMatchObject({ fqdn: 'www.example.test', target: 'srv.example.test' })
    expect((await al(a1, { name: 'shop.other.test', ttl: 300, comment: 'boutique' })).json.fqdn).toBe('shop.other.test')
    expect((await al(a1, { name: 'front', target: 'www.example.test' })).json.fqdn).toBe('front.example.test')
    const rec = await rows("select name, type, rdata, ttl, zone_id from dns_records where type = 'CNAME' order by name")
    expect(rec.map((r: any) => [r.name, r.rdata, r.ttl])).toEqual([['front', 'www.example.test.', null], ['shop', 'srv.example.test.', 300], ['www', 'srv.example.test.', null]])
    expect((await rows('select dirty from dns_zones where id = any($1)', [[zEx, zOt]])).every((z: any) => z.dirty)).toBe(true)
    const v = (await dns(a1)).json; expect(v.aliases.map((a: any) => [a.fqdn, a.depth]).sort()).toEqual([['front.example.test', 2], ['shop.other.test', 1], ['www.example.test', 1]])
  })
  it('refus : nom déjà pris, sommet de zone, boucle, cible inconnue, zone inconnue, nom invalide', async () => {
    code(await al(a1, { name: 'srv' }), 409, 'cname_conflict')
    code(await al(a1, { name: 'www' }), 409, 'cname_conflict')
    code(await al(a1, { name: 'example.test' }), 409, 'cname_apex')
    code(await al(a1, { name: 'x', target: 'inconnu.example.test' }), 400, 'alias_target_unknown')
    code(await al(a1, { name: 'x.nulle-part.fr' }), 400, 'alias_zone_unknown')
    code(await al(a1, { name: 'bad name!' }), 400, 'name_invalid')
    code(await al(a1, { name: 'x', zone_id: 999999 }), 400, 'zone_not_primary')
    code(await al(a1, { name: 'x', ttl: -1 }), 400, 'validation')
    code(await al(a3, { name: 'y' }), 409, 'no_host_record')
    expect((await rows("select count(*)::int c from dns_records where type = 'CNAME'"))[0].c).toBe(3)
  })
  it('liste des adresses : colonne alias (globale et par réseau)', async () => {
    const g = (await admin.get('/api/ipam/addresses')).json.items.find((i: any) => i.id === a1); expect(g.aliases.sort()).toEqual(['front.example.test', 'shop.other.test', 'www.example.test'])
    const l = (await admin.get(`/api/ipam/subnets/${sn}/addresses`)).json.items; expect(l.find((i: any) => i.id === a1).aliases.length).toBe(3); expect(l.find((i: any) => i.id === a2).aliases).toEqual([])
  })
  it('modification : TTL, commentaire, désactivation ; boucle et renommage d\'un alias porteur refusés', async () => {
    const v = (await dns(a1)).json, www = v.aliases.find((a: any) => a.name === 'www'), front = v.aliases.find((a: any) => a.name === 'front'), shop = v.aliases.find((a: any) => a.name === 'shop')
    expect((await admin.put(`/api/ipam/addresses/${a1}/aliases/${shop.id}`, { ttl: 60, comment: null, disabled: true })).status).toBe(200)
    expect((await rows('select ttl, comment, disabled from dns_records where id = $1', [shop.id]))[0]).toEqual({ ttl: 60, comment: null, disabled: true })
    code(await admin.put(`/api/ipam/addresses/${a1}/aliases/${www.id}`, { target: 'front.example.test' }), 409, 'cname_loop')
    code(await admin.put(`/api/ipam/addresses/${a1}/aliases/${www.id}`, { name: 'www2' }), 409, 'alias_has_dependents')
    expect((await admin.put(`/api/ipam/addresses/${a1}/aliases/${front.id}`, { name: 'avant', target: 'srv.example.test' })).status).toBe(200)
    expect((await dns(a1)).json.aliases.map((a: any) => [a.fqdn, a.depth]).sort()).toEqual([['avant.example.test', 1], ['shop.other.test', 1], ['www.example.test', 1]])
    code(await admin.put(`/api/ipam/addresses/${a1}/aliases/${front.id}`, { target: 'avant.example.test' }), 409, 'cname_self')
  })
  it('un alias ne se manipule que depuis SON adresse', async () => {
    const www = (await dns(a1)).json.aliases.find((a: any) => a.name === 'www')
    code(await admin.put(`/api/ipam/addresses/${a2}/aliases/${www.id}`, { ttl: 1 }), 404, 'alias_not_found')
    code(await admin.delete(`/api/ipam/addresses/${a2}/aliases/${www.id}`), 404, 'alias_not_found')
    const other = (await rows("select id from dns_records where type = 'A' limit 1"))[0].id
    code(await admin.delete(`/api/ipam/addresses/${a1}/aliases/${other}`), 404, 'alias_not_found')
  })
  it('suppression : un alias porteur demande la cascade', async () => {
    expect((await al(a1, { name: 'sous', target: 'www.example.test' })).status).toBe(200)
    const www = (await dns(a1)).json.aliases.find((a: any) => a.name === 'www')
    const r = await admin.delete(`/api/ipam/addresses/${a1}/aliases/${www.id}`); code(r, 409, 'alias_has_dependents'); expect(r.json.data.count ?? r.json.data.details?.count).toBe(1)
    const c = await admin.delete(`/api/ipam/addresses/${a1}/aliases/${www.id}?cascade=1`); expect(c.status).toBe(200); expect(c.json.removed).toBe(2)
    expect((await dns(a1)).json.aliases.map((a: any) => a.name).sort()).toEqual(['avant', 'shop'])
  })
  it('adresse sans nom DNS : création du A depuis le nom d\'hôte, puis alias ; pas de doublon', async () => {
    code(await admin.post(`/api/ipam/addresses/${a3}/dns`, { zone_id: 999999 }), 400, 'zone_not_primary')
    expect((await admin.post(`/api/ipam/addresses/${a3}/dns`, { zone_id: zEx })).status).toBe(200)
    code(await admin.post(`/api/ipam/addresses/${a3}/dns`, { zone_id: zEx }), 409, 'host_exists')
    expect((await al(a3, { name: 'nouveau' })).json.target).toBe('nu.example.test')
    const nh = (await admin.post(`/api/ipam/subnets/${sn}/addresses`, { ip: '10.50.0.13' })).json.id
    code(await admin.post(`/api/ipam/addresses/${nh}/dns`, { zone_id: zEx }), 400, 'no_hostname')
  })
  it('une adresse à deux noms exige la cible', async () => {
    await db.query("insert into dns_records (zone_id, name, type, rdata) values ($1, 'srv-bis', 'A', '10.50.0.10')", [zOt])
    code(await al(a1, { name: 'deux' }), 400, 'alias_target_required')
    expect((await al(a1, { name: 'deux', target: 'srv-bis.other.test' })).status).toBe(200)
    const v = (await dns(a1)).json; expect(v.hosts.length).toBe(2)
  })
  it('audit et suppression de l\'adresse sans effet de bord sur les enregistrements DNS', async () => {
    const acts = (await rows("select distinct action from audit_log where action like 'alias_%' or action = 'address_dns_create'")).map((r: any) => r.action).sort()
    expect(acts).toEqual(['address_dns_create', 'alias_create', 'alias_delete', 'alias_update'])
  })
})
