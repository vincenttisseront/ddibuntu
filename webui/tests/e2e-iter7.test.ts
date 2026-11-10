// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : RRL, adresses fantômes (IPAM) et détection de tunnels DNS.
import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3395, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s8-'))
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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b)
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

const S: Record<string, any> = {}

describe('RRL (limitation de débit des réponses)', () => {
  it('désactivé par défaut, bornes validées, persistance', async () => {
    const cur = (await admin.get('/api/dns/settings')).json
    expect(cur.rrlEnabled).toBe(false)
    expect(cur.rrlResponsesPerSecond).toBe(20)
    for (const bad of [{ rrlResponsesPerSecond: 0 }, { rrlResponsesPerSecond: 1001 }, { rrlWindow: 4 }, { rrlWindow: 3601 }, { rrlSlip: 11 }, { rrlSlip: -1 }, { rrlExempt: ['pas-une-ip'] }, { rrlEnabled: 'oui' }])
      code(await admin.put('/api/dns/settings', { ...cur, ...bad }), 400, 'validation')
    const ok = await admin.put('/api/dns/settings', { ...cur, rrlEnabled: true, rrlResponsesPerSecond: 5, rrlWindow: 30, rrlSlip: 0, rrlLogOnly: false, rrlExempt: ['10.0.0.0/8'] })
    expect(ok.status, ok.text).toBe(200)
    const back = (await admin.get('/api/dns/settings')).json
    expect(back).toMatchObject({ rrlEnabled: true, rrlResponsesPerSecond: 5, rrlWindow: 30, rrlSlip: 0, rrlLogOnly: false, rrlExempt: ['10.0.0.0/8'] })
  })
  it('seul un administrateur modifie les réglages', async () => {
    const cur = (await admin.get('/api/dns/settings')).json
    code(await viewer.put('/api/dns/settings', { ...cur, rrlEnabled: false }), 403, 'forbidden')
    expect((await admin.get('/api/dns/settings')).json.rrlEnabled).toBe(true)
  })
})

describe('adresses fantômes', () => {
  it('jeu de données : seules les adresses vues autrefois et silencieuses sont fantômes', async () => {
    S.net = (await admin.post('/api/ipam/subnets', { cidr: '10.70.0.0/24', name: 'Ghost LAN' })).json
    S.net2 = (await admin.post('/api/ipam/subnets', { cidr: '10.71.0.0/24', name: 'Ghost LAN 2' })).json
    const mk = async (ip: string, status: string, hostname: string) => (await admin.post(`/api/ipam/subnets/${S.net.id}/addresses`, { ip, status, hostname })).json.id
    S.old = await mk('10.70.0.10', 'used', 'vieux')
    S.oldDhcp = await mk('10.70.0.11', 'used', 'vieux-dhcp')
    S.fresh = await mk('10.70.0.12', 'used', 'recent')
    S.never = await mk('10.70.0.13', 'used', 'jamais-scanne')
    S.infra = await mk('10.70.0.14', 'infra', 'switch')
    S.mid = await mk('10.70.0.15', 'used', 'moyen')
    for (const id of [S.old, S.oldDhcp, S.infra]) expect(id).toBeGreaterThan(0)
    await db.query("update addresses set last_seen = now() - interval '90 days' where id = any($1)", [[S.old, S.oldDhcp, S.infra]])
    await db.query("update addresses set status = 'dhcp' where id = $1", [S.oldDhcp])
    await db.query("update addresses set last_seen = now() - interval '2 days' where id = $1", [S.fresh])
    await db.query("update addresses set last_seen = now() - interval '45 days' where id = $1", [S.mid])
  })
  it('liste : critère de silence, statuts alloués uniquement, jamais scannée exclue', async () => {
    const r = await viewer.get('/api/ipam/ghosts?days=30')
    expect(r.status).toBe(200)
    const ips = r.json.items.map((x: any) => x.ip).sort()
    expect(ips).toEqual(['10.70.0.10', '10.70.0.11', '10.70.0.15'])
    expect(r.json.total).toBe(3)
    expect(r.json.items[0]).toMatchObject({ ip: expect.any(String), cidr: '10.70.0.0/24', network: 'Ghost LAN' })
    expect(r.json.items.find((x: any) => x.ip === '10.70.0.10').silent_days).toBe(90)
    expect((await viewer.get('/api/ipam/ghosts?days=60')).json.items.map((x: any) => x.ip).sort()).toEqual(['10.70.0.10', '10.70.0.11'])
    expect((await viewer.get('/api/ipam/ghosts?days=1')).json.total).toBe(4)
    expect((await viewer.get(`/api/ipam/ghosts?days=30&subnet_id=${S.net2.id}`)).json.total).toBe(0)
  })
  it('paramètres invalides refusés, accès anonyme refusé', async () => {
    code(await viewer.get('/api/ipam/ghosts?days=abc'), 400, 'invalid_query')
    expect((await viewer.get('/api/ipam/ghosts?days=99999')).json.days).toBe(3650)
    expect((await anon.get('/api/ipam/ghosts')).status).toBe(401)
  })
  it('libération : rôle opérateur requis, validation, revérification serveur', async () => {
    code(await viewer.post('/api/ipam/ghosts/release', { ids: [S.old], days: 30 }), 403, 'forbidden')
    code(await admin.post('/api/ipam/ghosts/release', { ids: [], days: 30 }), 400, 'validation')
    code(await admin.post('/api/ipam/ghosts/release', { ids: [S.old], days: 0 }), 400, 'validation')
    code(await admin.post('/api/ipam/ghosts/release', { ids: Array.from({ length: 501 }, (_, i) => i + 1), days: 30 }), 400, 'validation')
    // une adresse récente, une jamais scannée et une d'infrastructure ne sont jamais supprimées, même si on les désigne
    code(await admin.post('/api/ipam/ghosts/release', { ids: [S.fresh, S.never, S.infra], days: 30 }), 409, 'ghost_none_released')
    const q = async (id: number) => (await db.query('select 1 from addresses where id = $1', [id])).rowCount
    expect([await q(S.fresh), await q(S.never), await q(S.infra)]).toEqual([1, 1, 1])
    // mélange : seules les vraies fantômes partent
    const r = await admin.post('/api/ipam/ghosts/release', { ids: [S.old, S.old, S.fresh, S.oldDhcp], days: 30 })
    expect(r.status, r.text).toBe(200)
    expect(r.json).toEqual({ released: 2, skipped: 1 })
    expect([await q(S.old), await q(S.oldDhcp), await q(S.fresh)]).toEqual([0, 0, 1])
    const a = await db.query("select detail from audit_log where action = 'ghost_release'")
    expect(a.rowCount).toBe(1)
    expect(a.rows[0].detail).toMatchObject({ released: 2, requested: 3 })
  })
})

describe('détection de tunnels DNS', () => {
  const rnd = (n: number) => { let s = ''; const a = 'abcdefghijklmnopqrstuvwxyz234567'; for (let i = 0; i < n; i++) s += a[Math.floor(Math.random() * a.length)]; return s }
  it('jeu de données : un client tunnel, un client normal, un CDN autorisé', async () => {
    const rows: any[] = []
    for (let i = 0; i < 120; i++) rows.push(['10.50.0.5', `${rnd(40)}.${rnd(20)}.t.evil-tunnel.com`, 'TXT'])
    for (let i = 0; i < 30; i++) rows.push(['10.50.0.6', `www${i % 3}.example.org`, 'A'], ['10.50.0.6', `mail.example.org`, 'A'])
    for (let i = 0; i < 80; i++) rows.push(['10.50.0.7', `${rnd(36)}.cdn-legit.net`, 'A'])
    for (const [client, domain, qtype] of rows) await db.query("insert into dns_queries (at, client, domain, qtype, status) values (now() - interval '10 minutes', $1, $2, $3, 'allowed')", [client, domain, qtype])
  })
  it('le tunnel ressort en gravité élevée avec ses indices ; le client normal non', async () => {
    const r = await viewer.get('/api/filter/tunnel?hours=24')
    expect(r.status, r.text).toBe(200)
    const t = r.json.items.find((x: any) => x.domain === 'evil-tunnel.com')
    expect(t).toMatchObject({ client: '10.50.0.5', severity: 'high', subs: 120 })
    expect(t.reasons).toEqual(expect.arrayContaining(['many_subdomains', 'long_names', 'high_entropy', 'rare_types']))
    expect(r.json.items.some((x: any) => x.client === '10.50.0.6')).toBe(false)
  })
  it('un domaine autorisé par une règle est ignoré', async () => {
    expect((await viewer.get('/api/filter/tunnel')).json.items.some((x: any) => x.domain === 'cdn-legit.net')).toBe(true)
    expect((await admin.post('/api/filter/rules', { domain: 'cdn-legit.net', action: 'allow' })).status).toBe(200)
    const r = await viewer.get('/api/filter/tunnel')
    expect(r.json.items.some((x: any) => x.domain === 'cdn-legit.net')).toBe(false)
    expect(r.json.items.some((x: any) => x.domain === 'evil-tunnel.com')).toBe(true)
  })
  it('fenêtre : hors fenêtre rien ; paramètres invalides refusés', async () => {
    await db.query("update dns_queries set at = now() - interval '3 days'")
    expect((await viewer.get('/api/filter/tunnel?hours=24')).json.items).toEqual([])
    expect((await viewer.get('/api/filter/tunnel?hours=168')).json.items.some((x: any) => x.domain === 'evil-tunnel.com')).toBe(true)
    code(await viewer.get('/api/filter/tunnel?hours=x'), 400, 'invalid_query')
    expect((await anon.get('/api/filter/tunnel')).status).toBe(401)
  })
  it('injection dans le domaine ou le client : paramètres liés, aucun effet', async () => {
    await db.query("insert into dns_queries (at, client, domain, qtype, status) select now(), $1, 'x' || g || '.%_\\\\.evil.com', 'A', 'allowed' from generate_series(1,30) g", ["10.1.1.1'; drop table users;--"])
    const r = await viewer.get('/api/filter/tunnel?hours=1')
    expect(r.status, r.text).toBe(200)
    expect((await db.query("select count(*)::int n from users")).rows[0].n).toBeGreaterThan(0)
  })
})
