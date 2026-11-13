// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.4 — coexistence (zones secondaires, bascule, baux rafraîchis).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3427, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s26-')); mkdirSync(join(TMP, 'gen'))
let srv: ChildProcess, db: pg.Client, srvLog = ''


const ZONE = `corp.test.\t3600\tIN\tSOA\tdc1.corp.test. hostmaster.corp.test. 12 900 600 86400 3600
corp.test.\t600\tIN\tNS\tdc1.corp.test.
dc1.corp.test.\t3600\tIN\tA\t10.0.0.10
_ldap._tcp.corp.test.\t600\tIN\tSRV\t0 100 389 dc1.corp.test.
www.corp.test.\t3600\tIN\tCNAME\tdc1.corp.test.
corp.test.\t3600\tIN\tSOA\tdc1.corp.test. hostmaster.corp.test. 12 900 600 86400 3600`
writeFileSync(join(TMP, 'zone.txt'), ZONE + '\n')
writeFileSync(join(TMP, 'dig.sh'), `#!/bin/sh\necho "$@" >> ${join(TMP, 'dig.log')}\ncase "$*" in *@192.0.2.2*) echo "; Transfer failed." >&2; exit 9;; esac\ncat ${join(TMP, 'zone.txt')}\n`, { mode: 0o755 })

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
const step = (r: any, id: string) => r.json.steps.find((s: any) => s.id === id)
const CSV = `"ZoneName","ZoneType","IsDsIntegrated","IsSigned","MasterServers"
"corp.test","Primary","True","False",""
"autre.test","Primary","False","False",""
"partner.test","Forwarder","False","False","203.0.113.7"`
const XML = `<?xml version="1.0"?><DHCPServer><IPv4><Scopes><Scope><ScopeId>10.90.0.0</ScopeId><Name>LAN</Name><SubnetMask>255.255.255.0</SubnetMask><StartRange>10.90.0.100</StartRange><EndRange>10.90.0.200</EndRange><LeaseDuration>1.00:00:00</LeaseDuration><State>Active</State></Scope></Scopes></IPv4></DHCPServer>`
const future = (h: number) => new Date(Date.now() + h * 3600_000).toISOString().slice(0, 19)
const leases = (host: string) => `"IPAddress","ClientId","HostName","AddressState","ExpiryUtc"\n"10.90.0.20","aa-bb-cc-00-00-20","${host}","Active","${future(5)}"`

describe('coexistence', () => {
  it('zones primaires Windows créées en secondaires derrière le serveur Windows ; adresse invalide refusée', async () => {
    code(await oper.post('/api/migration/zones/preview', { content: CSV, coexist: 'pas-une-ip' }), 400, 'axfr_server_invalid')
    const r = await oper.post('/api/migration/zones/commit', { content: CSV, coexist: '192.0.2.1' }); expect(r.status, r.text).toBe(200); expect(r.json.created).toBe(3)
    expect(await rows('select name, type, masters, forwarders from dns_zones order by name')).toEqual([
      { name: 'autre.test', type: 'secondary', masters: ['192.0.2.1'], forwarders: [] }, { name: 'corp.test', type: 'secondary', masters: ['192.0.2.1'], forwarders: [] },
      { name: 'partner.test', type: 'forward', masters: [], forwarders: ['203.0.113.7'] }])
    await db.query("update dns_zones set masters = '{192.0.2.2}' where name = 'autre.test'")
    expect((await viewer.get('/api/migration/coexist')).json.items.map((z: any) => z.name)).toEqual(['autre.test', 'corp.test'])
  })
  it('vérification du transfert : administrateur seulement ; ok ou refusé, sans rien modifier', async () => {
    const [a, c] = ['autre.test', 'corp.test'].map((n) => rows('select id from dns_zones where name = $1', [n]))
    const aid = (await a)[0].id, cid = (await c)[0].id
    code(await oper.post('/api/migration/coexist/check', { zone_id: cid }), 403, 'forbidden')
    expect((await admin.post('/api/migration/coexist/check', { zone_id: cid })).json).toMatchObject({ ok: true, records: 4, master: '192.0.2.1', error: null })
    expect((await admin.post('/api/migration/coexist/check', { zone_id: aid })).json).toMatchObject({ ok: false, error: 'axfr_refused' })
    code(await admin.post('/api/migration/coexist/check', { zone_id: 999999 }), 404, 'not_found')
    const pid = (await rows("select id from dns_zones where name = 'partner.test'"))[0].id
    code(await admin.post('/api/migration/coexist/check', { zone_id: pid }), 400, 'zone_not_secondary')
  })
  it('bascule : transfert refusé = rien ne change ; transfert réussi = zone primaire avec son contenu et le SOA de Windows', async () => {
    const aid = (await rows("select id from dns_zones where name = 'autre.test'"))[0].id, cid = (await rows("select id from dns_zones where name = 'corp.test'"))[0].id
    code(await admin.post('/api/migration/coexist/promote', { zone_id: aid }), 502, 'axfr_refused')
    expect((await rows("select type, masters from dns_zones where name = 'autre.test'"))[0]).toMatchObject({ type: 'secondary', masters: ['192.0.2.2'] })
    code(await oper.post('/api/migration/coexist/promote', { zone_id: cid }), 403, 'forbidden')
    const r = await admin.post('/api/migration/coexist/promote', { zone_id: cid }); expect(r.status, r.text).toBe(200); expect(r.json).toMatchObject({ ok: true, inserted: 4 })
    expect((await rows("select type, masters, soa_mname from dns_zones where name = 'corp.test'"))[0]).toMatchObject({ type: 'primary', masters: [], soa_mname: 'dc1.corp.test.' })
    expect((await rows('select count(*)::int n from dns_records where zone_id = $1', [cid]))[0].n).toBe(4)
    expect((await rows("select protected from dns_records where name = '_ldap._tcp'"))[0].protected).toBe(true)
    expect((await rows("select 1 from audit_log where action = 'migration_promote'")).length).toBe(1)
    expect((await viewer.get('/api/migration/coexist')).json.items.map((z: any) => z.name)).toEqual(['autre.test'])
    code(await admin.post('/api/migration/coexist/promote', { zone_id: cid }), 400, 'zone_not_secondary')
  })
  it('baux : envoi planifié (rafraîchir) met à jour sans instantané ni historique ; refusé une fois la bascule cochée', async () => {
    expect((await admin.post('/api/import/dhcp/commit', { content: XML })).status).toBe(200)
    await db.query('create table lease4 (address bigint primary key, hwaddr bytea, client_id bytea, valid_lifetime bigint, expire timestamp, subnet_id bigint, fqdn_fwd boolean not null, fqdn_rev boolean not null, hostname varchar, state bigint default 0)')
    expect((await oper.post('/api/migration/leases/commit', { content: leases('premier') })).json.imported).toBe(1)
    expect((await oper.post('/api/migration/leases/commit', { content: leases('change') })).json.imported).toBe(0)   // sans « refresh » : jamais d'écrasement
    expect((await rows('select hostname from lease4'))[0].hostname).toBe('premier')
    const runs = (await rows("select count(*)::int n from import_runs where kind = 'dhcp-leases'"))[0].n, snaps = (await rows('select count(*)::int n from config_snapshots'))[0].n
    const r = await oper.post('/api/migration/leases/commit', { content: leases('change'), refresh: true }); expect(r.status, r.text).toBe(200); expect(r.json).toMatchObject({ imported: 1, snapshotId: null })
    expect((await rows('select hostname from lease4'))[0].hostname).toBe('change')
    expect([(await rows("select count(*)::int n from import_runs where kind = 'dhcp-leases'"))[0].n, (await rows('select count(*)::int n from config_snapshots'))[0].n]).toEqual([runs, snaps])
    expect((await admin.get('/api/migration')).json.leasePush).toMatchObject({ imported: 1, total: 1 })
    await admin.put('/api/migration', { step: 'cutover', done: true })
    code(await oper.post('/api/migration/leases/commit', { content: leases('apres'), refresh: true }), 409, 'cutover_done')
    expect((await rows('select hostname from lease4'))[0].hostname).toBe('change')
    expect(step(await admin.get('/api/migration'), 'cutover').manual).toBe(true)
  })
})
