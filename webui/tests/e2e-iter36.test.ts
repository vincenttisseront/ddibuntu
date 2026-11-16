// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.20 — hôtes découverts absents de l'IPAM : liste puis import au choix (point de restauration, compteur d'alerte). Précédemment : 0.12.17 — l'authentification AD / LDAP ne s'active qu'avec une connexion testée (liaison réussie) ; toute modification de la connexion exige un nouveau test.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3437, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s36-')); mkdirSync(join(TMP, 'gen'))
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
const setJson = (key: string, v: unknown) => db.query("insert into settings (key, value) values ($1, $2::jsonb) on conflict (key) do update set value = excluded.value", [key, JSON.stringify(v)])
describe('hôtes découverts : liste puis import', () => {
  let sid = 0
  it('droits : lecteur refusé, opérateur admis ; sans passage planifié : liste vide', async () => {
    code(await viewer.get('/api/discovery/found'), 403, 'forbidden')
    const r = await oper.get('/api/discovery/found'); expect(r.status).toBe(200); expect(r.json).toMatchObject({ at: null, hosts: [] })
    code(await anon.get('/api/discovery/found'), 401, 'unauthenticated')
  })
  it('liste : hôtes mémorisés par le passage planifié, avec le sous-réseau ; ceux déjà présents dans l\'IPAM disparaissent', async () => {
    const s = await admin.post('/api/ipam/subnets', { cidr: '10.77.0.0/24', name: 'Découverte' }); expect(s.status).toBe(200); sid = s.json.id
    await setJson('discovery_found', { at: 1_700_000_000, hosts: [
      { ip: '10.77.0.10', subnetId: sid, mac: 'aa:bb:cc:00:00:10', name: 'srv10.example.test', via: ['arp', 'reverse'] },
      { ip: '10.77.0.11', subnetId: sid, mac: null, name: null, via: ['icmp'] },
      { ip: '10.77.0.12', subnetId: sid, mac: 'aa:bb:cc:00:00:12', name: 'nom invalide !', via: ['arp'] },
      { ip: '10.77.0.50', subnetId: sid, mac: 'aa:bb:cc:00:00:50', name: 'iphone', via: ['tcp', 'dhcp'] }] })   // poste DHCP : jamais proposé
    await setJson('discovery_schedule_last', { at: 1_700_000_000, ok: true, scanned: 254, alive: 3, known: 0, unknown: 3, macChanged: 0, unreachable: 0 })
    const r = await oper.get('/api/discovery/found'); expect(r.status).toBe(200)
    expect(r.json.at).toBe(1_700_000_000); expect(r.json.hosts.map((h: any) => h.ip)).toEqual(['10.77.0.10', '10.77.0.11', '10.77.0.12'])   // 10.77.0.50 (vu par le DHCP) n'y est pas
    expect(r.json.hosts[0]).toMatchObject({ subnet: '10.77.0.0/24', subnetName: 'Découverte', name: 'srv10.example.test' })
    await db.query("insert into addresses (subnet_id, ip, status) values ($1, '10.77.0.11', 'used')", [sid])   // saisie à la main entre-temps
    expect((await oper.get('/api/discovery/found')).json.hosts.map((h: any) => h.ip)).toEqual(['10.77.0.10', '10.77.0.12'])
  })
  it('import : lecteur refusé ; IP hors liste refusée ; point de restauration, adresses créées, liste et alerte mises à jour', async () => {
    code(await viewer.post('/api/discovery/found/import', { ips: ['10.77.0.10'] }), 403, 'forbidden')
    code(await oper.post('/api/discovery/found/import', { ips: ['10.99.9.9'] }), 404, 'not_found')
    code(await oper.post('/api/discovery/found/import', { ips: ['10.77.0.50'] }), 404, 'not_found')   // poste DHCP : pas importable par cette liste
    expect((await oper.post('/api/discovery/found/import', { ips: [] })).status).toBe(400)
    const before = Number((await rows("select count(*)::int n from config_snapshots where kind = 'pre-import'"))[0]!.n)
    const r = await oper.post('/api/discovery/found/import', { ips: ['10.77.0.10', '10.77.0.12'] }); expect(r.status).toBe(200)
    expect(r.json).toMatchObject({ created: 2, skipped: 0 }); expect(r.json.snapshotId).toBeGreaterThan(0)
    expect(Number((await rows("select count(*)::int n from config_snapshots where kind = 'pre-import'"))[0]!.n)).toBe(before + 1)
    const a = await rows("select host(ip) ip, hostname, mac::text mac, source, status from addresses where subnet_id = $1 order by ip", [sid])
    expect(a.find((x: any) => x.ip === '10.77.0.10')).toMatchObject({ hostname: 'srv10.example.test', mac: 'aa:bb:cc:00:00:10', source: 'discovery', status: 'used' })
    expect(a.find((x: any) => x.ip === '10.77.0.12')).toMatchObject({ hostname: null, mac: 'aa:bb:cc:00:00:12' })   // nom invalide : jamais enregistré
    expect((await oper.get('/api/discovery/found')).json.hosts).toEqual([])
    expect((await rows("select value->>'unknown' u from settings where key = 'discovery_schedule_last'"))[0]!.u).toBe('0')
    expect((await rows("select count(*)::int n from audit_log where action = 'discovery_import'"))[0]!.n).toBeGreaterThanOrEqual(1)
  })
  it('un second import des mêmes adresses : refusé (plus dans la liste)', async () => {
    code(await oper.post('/api/discovery/found/import', { ips: ['10.77.0.10'] }), 404, 'not_found')
  })
})
