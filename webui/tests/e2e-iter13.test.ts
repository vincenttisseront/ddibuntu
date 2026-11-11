// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : vues DNS 0.9.8 — création, ordre, copie, suppression, rendu déployé, couverture locale, restauration.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3402, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s13-')); mkdirSync(join(TMP, 'gen'))
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


const GEN = join(TMP, 'gen')
const zone = (o: Record<string, unknown>) => ({ type: 'primary', soa_mname: 'ns1.example.test.', soa_rname: 'hostmaster.example.test.', ...o })
const view = (o: Record<string, unknown>) => ({ name: 'interne', match_clients: ['10.0.0.0/8', 'localhost'], match_destinations: [], recursion: true, ...o })
const zones = () => readFileSync(join(GEN, 'named.conf.zones'), 'utf8')
const apply = async () => (await admin.post('/api/system/apply', { deploy: true })).json
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const addNs = (id: number) => admin.post('/api/dns/records', { zone_id: id, name: '@', type: 'NS', rdata: 'ns.elsewhere.example.' })
let interne = 0, externe = 0, zInt = 0, zExt = 0

describe('vues DNS', () => {
  it('droits : lecture pour tous, écriture réservée à l\'administrateur', async () => {
    expect((await viewer.get('/api/dns/views')).json).toMatchObject({ items: [], uncovered: [], max: 16 })
    code(await viewer.post('/api/dns/views', view({})), 403, 'forbidden')
    code(await anon.get('/api/dns/views'), 401, 'unauthenticated')
  })
  it('validation : nom, listes de clients, injection refusés', async () => {
    for (const bad of [{ name: 'Mauvais Nom' }, { name: '1abc' }, { name: 'a.b' }, { name: '' }, { match_clients: [] }, { match_clients: ['oups'] }, { match_clients: ['10.0.0.0/8; };'] }, { match_clients: ['!any'] },
      { match_destinations: ['pas-une-ip'] }, { match_clients: Array.from({ length: 51 }, () => 'any') }]) {
      const r = await admin.post('/api/dns/views', view(bad)); expect([400], JSON.stringify(bad)).toContain(r.status)
    }
    expect((await rows('select count(*)::int c from dns_views'))[0].c).toBe(0)
  })
  it('première vue avec des zones existantes : refusée sans adoption explicite, puis les zones y entrent', async () => {
    zInt = (await admin.post('/api/dns/zones', zone({ name: 'example.test' }))).json.id; expect(zInt).toBeTruthy(); await addNs(zInt)
    const loose = (await admin.post('/api/dns/zones', zone({ name: 'autre.test' }))).json.id; await addNs(loose)
    const r = await admin.post('/api/dns/views', view({})); code(r, 409, 'zones_need_view'); expect(r.json.data.zones).toBe(2)
    expect((await rows('select count(*)::int c from dns_views'))[0].c).toBe(0)
    const ok = await admin.post('/api/dns/views', view({ adopt_zones: true })); expect(ok.status, ok.text).toBe(200); interne = ok.json.id
    expect((await rows('select count(*)::int c from dns_zones where view_id = $1', [interne]))[0].c).toBe(2)
    code(await admin.post('/api/dns/views', view({})), 409, 'duplicate')   // nom unique
  })
  it('une zone doit appartenir à une vue (et la vue doit exister)', async () => {
    code(await admin.post('/api/dns/zones', zone({ name: 'sans-vue.test' })), 400, 'view_required')
    code(await admin.post('/api/dns/zones', zone({ name: 'x.test', view_id: 99999 })), 400, 'view_not_found')
    const z = await admin.post('/api/dns/zones', zone({ name: 'ok.test', view_id: interne })); expect(z.status, z.text).toBe(200); await addNs(z.json.id)
    expect((await admin.get(`/api/dns/zones/${z.json.id}`)).json).toMatchObject({ view_id: interne, view: 'interne' })
    // une modification sans view_id ne déplace pas la zone
    expect((await admin.put(`/api/dns/zones/${z.json.id}`, zone({ name: 'ok.test', comment: 'maj' }))).status).toBe(200)
    expect((await admin.get(`/api/dns/zones/${z.json.id}`)).json.view_id).toBe(interne)
    expect((await admin.delete(`/api/dns/zones/${z.json.id}?force=1`)).status).toBe(200)
  })
  it('seconde vue, copie d\'une zone : même nom dans deux vues, enregistrements copiés', async () => {
    externe = (await admin.post('/api/dns/views', view({ name: 'externe', match_clients: ['any'], recursion: false }))).json.id; expect(externe).toBeTruthy()
    await admin.post('/api/dns/records', { zone_id: zInt, name: 'www', type: 'A', rdata: '10.0.0.80' })
    const c = await admin.post(`/api/dns/zones/${zInt}/copy`, { view_id: externe }); expect(c.status, c.text).toBe(200); zExt = c.json.id
    expect(c.json.records).toBe(2)   // NS + www
    code(await admin.post(`/api/dns/zones/${zInt}/copy`, { view_id: externe }), 409, 'zone_exists')   // déjà présente
    code(await admin.post(`/api/dns/zones/${zInt}/copy`, { view_id: interne }), 409, 'zone_exists')   // même vue
    code(await admin.post(`/api/dns/zones/${zInt}/copy`, { view_id: 99999 }), 400, 'view_not_found')
    await admin.put(`/api/dns/records/${(await rows("select id from dns_records where zone_id = $1 and name = 'www'", [zExt]))[0].id}`, { zone_id: zExt, name: 'www', type: 'A', rdata: '203.0.113.80' })
    const recs = (await admin.get('/api/dns/records?q=www')).json.items.filter((r: any) => r.name === 'www')
    expect(recs.map((r: any) => `${r.view}:${r.rdata}`).sort()).toEqual(['externe:203.0.113.80', 'interne:10.0.0.80'])
  })
  it('ordre : liste complète exigée ; l\'ordre décide de la première vue', async () => {
    code(await admin.post('/api/dns/views/order', { ids: [externe] }), 400, 'view_order')
    code(await admin.post('/api/dns/views/order', { ids: [externe, externe] }), 400, 'view_order')
    expect((await admin.post('/api/dns/views/order', { ids: [externe, interne] })).status).toBe(200)
    const l = (await admin.get('/api/dns/views')).json
    expect(l.items.map((v: any) => v.name)).toEqual(['externe', 'interne'])
    expect(l.shadowed).toEqual(['interne'])   // « externe » répond à tout le monde et passe en premier
    expect((await admin.post('/api/dns/views/order', { ids: [interne, externe] })).status).toBe(200)
    expect((await admin.get('/api/dns/views')).json.shadowed).toEqual([])
  })
  it('déploiement : un bloc par vue, un fichier de zone et de RPZ par vue', async () => {
    await admin.put('/api/dns/settings', { ...(await admin.get('/api/dns/settings')).json, rpzEnabled: true })
    const d = await apply(); expect(d, JSON.stringify(d)).toMatchObject({ ok: true, deployed: true })
    const z = zones(), lines = z.split('\n')
    expect(lines.indexOf('view "interne" {')).toBeGreaterThan(-1); expect(lines.indexOf('view "externe" {')).toBeGreaterThan(lines.indexOf('view "interne" {'))
    expect(z).toContain('match-clients { 10.0.0.0/8; localhost; };'); expect(z).toContain('match-clients { any; };')
    expect(z).toMatch(/zone "example\.test" [^\n]*db\.interne\.example\.test/); expect(z).toMatch(/zone "example\.test" [^\n]*db\.externe\.example\.test/)
    expect(z).toContain('db.rpz-interne'); expect(z).toContain('db.rpz-externe'); expect(z).not.toMatch(/db\.rpz"/)
    for (const f of ['db.interne.example.test', 'db.externe.example.test', 'db.rpz-interne', 'db.rpz-externe']) expect(existsSync(join(GEN, 'zones', f)), f).toBe(true)
    expect(readFileSync(join(GEN, 'zones', 'db.externe.example.test'), 'utf8')).toContain('203.0.113.80')
    expect(readFileSync(join(GEN, 'zones', 'db.interne.example.test'), 'utf8')).toContain('10.0.0.80')
    expect(existsSync(join(GEN, 'zones', 'db.example.test'))).toBe(false)
  })
  it('le serveur doit se couvrir lui-même : sans vue pour 127.0.0.1 / ::1, le déploiement est refusé', async () => {
    expect((await admin.put(`/api/dns/views/${interne}`, view({ match_clients: ['10.0.0.0/8'] }))).status).toBe(200)
    expect((await admin.put(`/api/dns/views/${externe}`, view({ name: 'externe', match_clients: ['192.0.2.0/24'], recursion: false }))).status).toBe(200)
    const l = (await admin.get('/api/dns/views')).json; expect(l.uncovered).toEqual(['127.0.0.1', '::1'])
    const d = await apply(); expect(d.ok).toBe(false); expect(d.deployed).toBe(false)
    expect(JSON.stringify(d.results)).toContain('couverture locale')
    expect((await admin.put(`/api/dns/views/${interne}`, view({}))).status).toBe(200)   // « localhost » rétabli
    expect((await admin.get('/api/dns/views')).json.uncovered).toEqual([])
    expect(await apply()).toMatchObject({ ok: true, deployed: true })
  })
  it('suppression : une vue non vide est refusée tant qu\'il en reste une autre ; la dernière rend ses zones ordinaires', async () => {
    const r = await admin.delete(`/api/dns/views/${externe}`); code(r, 409, 'view_not_empty'); expect(r.json.data.zones).toBe(1)
    await admin.delete(`/api/dns/zones/${zExt}?force=1`)
    expect((await admin.delete(`/api/dns/views/${externe}`)).status).toBe(200)
    const last = await admin.delete(`/api/dns/views/${interne}`); code(last, 409, 'view_last_with_zones')
    expect((await rows('select count(*)::int c from dns_views'))[0].c).toBe(1)
    expect((await admin.delete(`/api/dns/views/${interne}?force=1`)).status).toBe(200)
    expect((await rows('select count(*)::int c from dns_zones where view_id is not null'))[0].c).toBe(0)
    const d = await apply(); expect(d, JSON.stringify(d)).toMatchObject({ ok: true, deployed: true })
    expect(zones()).not.toContain('view "'); expect(zones()).toMatch(/zone "example\.test" [^\n]*db\.example\.test/); expect(zones()).toContain('db.rpz"')
  })
  it('garde-fou du rendu : des zones hors vue alors qu\'une vue existe (base modifiée à la main) bloquent le déploiement', async () => {
    const v = (await admin.post('/api/dns/views', view({ adopt_zones: true }))).json.id; expect(v).toBeTruthy()
    await db.query('update dns_zones set view_id = null')
    const r = await admin.post('/api/system/apply', { deploy: true }); code(r, 409, 'zones_without_view')
    await db.query('update dns_zones set view_id = $1', [v])
  })
  it('points de restauration : les vues et l\'appartenance des zones reviennent', async () => {
    const snap = (await admin.post('/api/snapshots', { label: 'avec vue' })).json.id; expect(snap).toBeGreaterThan(0)
    expect((await rows('select data from config_snapshots where id = $1', [snap]))[0].data.dns_views).toHaveLength(1)
    await admin.post('/api/dns/views', view({ name: 'tiers', match_clients: ['192.0.2.0/24'] }))
    expect((await admin.post(`/api/snapshots/${snap}/restore`, {})).status).toBe(200)
    expect((await rows('select name from dns_views order by position')).map((r) => r.name)).toEqual(['interne'])
    expect((await rows('select count(*)::int c from dns_zones where view_id is null'))[0].c).toBe(0)
    const d = await apply(); expect(d, JSON.stringify(d)).toMatchObject({ ok: true, deployed: true })
  })
})
