// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.9.28 — traçabilité des baux (historique IP / MAC / nom).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3415, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s15-')); mkdirSync(join(TMP, 'gen'))
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
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json') } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })


const ip2n = (ip: string) => ip.split('.').reduce((a, b) => a * 256 + Number(b), 0)
const lease = (ip: string, mac: string, host: string | null, minutes = 60) =>
  db.query("insert into lease4 (address, hwaddr, hostname, subnet_id, expire) values ($1, decode($2, 'hex'), $3, 1, now() + make_interval(mins => $4))", [ip2n(ip), mac.replace(/:/g, ''), host, minutes])

describe('traçabilité des baux', () => {
  it('sans table lease4 : relevé ignoré, recherche vide', async () => {
    const r = await admin.post('/api/trace/collect'); expect(r.status).toBe(200); expect(r.json.skipped).toBe('unavailable')
    const s = await admin.get('/api/trace?q=10.0.0.1'); expect(s.status).toBe(200); expect(s.json.items).toEqual([])
  })
  it('droits : lecteur peut chercher, pas relever ; anonyme refusé', async () => {
    expect((await viewer.get('/api/trace?q=x')).status).toBe(200)
    code(await viewer.post('/api/trace/collect'), 403, 'forbidden')
    expect((await anon.get('/api/trace?q=x')).status).toBe(401)
  })
  it('ouvre, prolonge, referme et change d\'association', async () => {
    await db.query('create table lease4 (address bigint primary key, hwaddr bytea, hostname varchar, subnet_id bigint, expire timestamp)')
    await lease('10.1.0.5', 'aa:bb:cc:00:00:01', 'PC-Alice.corp.')
    await lease('10.1.0.6', 'aa:bb:cc:00:00:02', null)
    let r = await admin.post('/api/trace/collect'); expect(r.json).toMatchObject({ active: 2, opened: 2, closed: 0 })
    r = await admin.post('/api/trace/collect'); expect(r.json).toMatchObject({ active: 2, opened: 0, closed: 0 })
    // l'adresse .5 passe à un autre poste : l'ancienne association est fermée, une nouvelle s'ouvre
    await db.query('update lease4 set hwaddr = decode($1, \'hex\'), hostname = $2 where address = $3', ['aabbcc000099', 'pc-bob', ip2n('10.1.0.5')])
    r = await admin.post('/api/trace/collect'); expect(r.json).toMatchObject({ active: 2, opened: 1, closed: 1 })
    // le bail .6 disparaît
    await db.query('delete from lease4 where address = $1', [ip2n('10.1.0.6')])
    r = await admin.post('/api/trace/collect'); expect(r.json).toMatchObject({ active: 1, opened: 0, closed: 1 })
  })
  it('recherche par IP, MAC (tout format, préfixe) et nom ; nom normalisé', async () => {
    const byIp = await viewer.get('/api/trace?q=10.1.0.5')
    expect(byIp.json.items.map((i: any) => [i.mac, i.hostname, i.open])).toEqual([['aa:bb:cc:00:00:99', 'pc-bob', true], ['aa:bb:cc:00:00:01', 'pc-alice.corp', false]])
    const byMac = await viewer.get('/api/trace?q=' + encodeURIComponent('AA-BB-CC-00-00-02'))
    expect(byMac.json.items).toHaveLength(1); expect(byMac.json.items[0]).toMatchObject({ ip: '10.1.0.6', hostname: null, open: false })
    expect((await viewer.get('/api/trace?q=aabbcc')).json.items).toHaveLength(3)
    expect((await viewer.get('/api/trace?q=alice')).json.items).toHaveLength(1)
    expect((await viewer.get('/api/trace?q=10.1.0.')).json.items).toHaveLength(3)
    expect((await viewer.get('/api/trace?q=%25')).json.items).toHaveLength(0)    // % n'est pas un joker
    expect((await viewer.get('/api/trace')).json.items).toEqual([])
    expect((await viewer.get('/api/trace?q=pc')).json.stats).toMatchObject({ total: 3, open: 1 })
  })
  it('corrèle avec l\'IPAM', async () => {
    const sp = await admin.get('/api/ipam/spaces'); const space = sp.json.items[0].id
    const n = await admin.post('/api/ipam/subnets', { space_id: space, cidr: '10.1.0.0/24', name: 'lan' }); expect(n.status, n.text).toBe(200)
    const a = await admin.post(`/api/ipam/subnets/${n.json.id}/addresses`, { ip: '10.1.0.5', hostname: 'bob-ipam', status: 'used' }); expect(a.status, a.text).toBe(200)
    const r = await viewer.get('/api/trace?q=10.1.0.5')
    expect(r.json.items[0].ipam_hostname).toBe('bob-ipam')
  })
})

describe('découverte planifiée et alertes d\'hygiène', () => {
  it('réglage : droits, validation, enregistrement', async () => {
    const g = await viewer.get('/api/discovery/schedule'); code(g, 403, 'forbidden')
    const a = await admin.get('/api/discovery/schedule'); expect(a.status).toBe(200); expect(a.json.schedule).toMatchObject({ enabled: false, intervalHours: 24 }); expect(a.json.last).toBeNull()
    const ok = { enabled: true, intervalHours: 6, subnetIds: [], methods: { tcp: false, icmp: false, arp: false, reverse: false, leases: true } }
    code(await viewer.put('/api/discovery/schedule', ok), 403, 'forbidden')
    expect((await admin.put('/api/discovery/schedule', { ...ok, intervalHours: 0 })).status).toBe(400)
    expect((await admin.put('/api/discovery/schedule', { ...ok, extra: 1 })).status).toBe(400)
    code(await admin.put('/api/discovery/schedule', { ...ok, methods: { tcp: false, icmp: false, arp: false, reverse: false, leases: false } }), 400, 'discovery_no_method')
    code(await admin.put('/api/discovery/schedule', { ...ok, subnetIds: [999999] }), 404, 'not_found')
    expect((await admin.put('/api/discovery/schedule', ok)).status).toBe(200)
    expect((await admin.get('/api/discovery/schedule')).json.schedule).toMatchObject({ enabled: true, intervalHours: 6, methods: { leases: true, icmp: false } })
  })
  it('passage à la demande : marque les connues, compte les inconnues, ne crée rien ; l\'alerte d\'hygiène apparaît puis se résout', async () => {
    await db.query('delete from addresses; delete from subnets')
    const s = (await db.query("insert into subnets (cidr, name) values ('10.77.0.0/29', 'labo') returning id")).rows[0].id
    await db.query("insert into addresses (subnet_id, ip, status, hostname) values ($1, '10.77.0.2', 'used', 'connu')", [s])
    await db.query('delete from lease4')
    await lease('10.77.0.2', 'aa:bb:cc:01:01:01', 'connu'); await lease('10.77.0.3', 'aa:bb:cc:01:01:02', 'inconnu')
    code(await viewer.post('/api/discovery/schedule/run'), 403, 'forbidden')
    expect((await admin.post('/api/discovery/schedule/run')).status).toBe(200)
    await until(async () => (await admin.get('/api/discovery/schedule')).json.last !== null, 40000)
    const last = (await admin.get('/api/discovery/schedule')).json.last
    expect(last, JSON.stringify(last)).toMatchObject({ ok: true, known: 1, unknown: 1, macChanged: 0 })
    const n = (await db.query('select count(*)::int as n, count(last_seen)::int as seen from addresses')).rows[0]
    expect(n).toEqual({ n: 1, seen: 1 })      // aucune adresse créée, la connue est marquée vue
    const ev = await admin.post('/api/alerts/evaluate'); expect(ev.status).toBe(200)
    const act = (await admin.get('/api/alerts')).json.active
    expect(act.find((x: any) => x.rule === 'ipam.unknown_hosts')).toMatchObject({ severity: 'warning', params: { count: 1 } })
  })
  it('fantômes : adresse silencieuse depuis longtemps → alerte d\'information', async () => {
    await db.query("update addresses set last_seen = now() - interval '40 days' where ip = '10.77.0.2'")
    await admin.post('/api/alerts/evaluate')
    const act = (await admin.get('/api/alerts')).json.active
    expect(act.find((x: any) => x.rule === 'ipam.ghosts')).toMatchObject({ severity: 'info', params: { count: 1, days: 30 } })
  })
})
