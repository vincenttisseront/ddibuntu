// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.6 — plan de bascule et retour arrière.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3429, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s28-')); mkdirSync(join(TMP, 'gen'))
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
const step = (r: any, id: string) => r.json.steps.find((s: any) => s.id === id)
const item = (r: any, id: string) => r.json.items.find((i: any) => i.id === id)

describe('plan de bascule', () => {
  it('avant le démarrage : check-list ordonnée, points automatiques déduits, rien de démarré', async () => {
    const r = await viewer.get('/api/migration/cutover'); expect(r.status, r.text).toBe(200)
    expect(r.json.started).toBeNull(); expect(r.json.items.map((i: any) => i.id)).toEqual(['ttl', 'verify', 'leases', 'relay', 'stop_windows', 'promote', 'clients_dns'])
    expect(item(r, 'promote').done).toBe(true); expect(item(r, 'verify').done).toBe(false)
    code(await oper.post('/api/migration/cutover/finish'), 403, 'forbidden'); code(await admin.post('/api/migration/cutover/finish'), 409, 'cutover_not_started'); code(await admin.post('/api/migration/cutover/rollback'), 409, 'cutover_not_started')
  })
  it('démarrage : administrateur, point de restauration pris, une seule fois', async () => {
    code(await oper.post('/api/migration/cutover/start'), 403, 'forbidden')
    const r = await admin.post('/api/migration/cutover/start'); expect(r.status, r.text).toBe(200); expect(r.json.started.snapshotId).toBeGreaterThan(0)
    expect((await rows('select count(*)::int n from config_snapshots where id = $1', [r.json.started.snapshotId]))[0].n).toBe(1)
    code(await admin.post('/api/migration/cutover/start'), 409, 'cutover_started')
  })
  it('points manuels cochables par un opérateur ; points automatiques refusés ; bascule refusée tant que tout n\'est pas fait', async () => {
    code(await oper.put('/api/migration/cutover/item', { id: 'verify', done: true }), 400, 'cutover_item_auto')
    code(await viewer.put('/api/migration/cutover/item', { id: 'ttl', done: true }), 403, 'forbidden')
    for (const id of ['ttl', 'relay']) expect(item(await oper.put('/api/migration/cutover/item', { id, done: true }), id).done).toBe(true)
    const r = await admin.post('/api/migration/cutover/finish'); code(r, 409, 'cutover_incomplete'); expect(r.json.data.pending).toEqual(['verify', 'leases', 'stop_windows', 'clients_dns'])
  })
  it('tout fait : bascule terminée, étape du parcours cochée, plus de modification', async () => {
    await admin.put('/api/migration', { step: 'review', done: true })
    await db.query("insert into settings (key, value) values ('migration_leases', $1) on conflict (key) do update set value = excluded.value", [JSON.stringify({ at: new Date().toISOString(), imported: 1, total: 1 })])
    for (const id of ['stop_windows', 'clients_dns']) await oper.put('/api/migration/cutover/item', { id, done: true })
    const r = await admin.post('/api/migration/cutover/finish'); expect(r.status, r.text).toBe(200); expect(r.json.finishedAt).toBeTruthy(); expect(r.json.pending).toEqual([])
    expect(step(await admin.get('/api/migration'), 'cutover').manual).toBe(true)
    code(await oper.put('/api/migration/cutover/item', { id: 'ttl', done: false }), 409, 'cutover_done'); code(await admin.post('/api/migration/cutover/finish'), 409, 'cutover_done')
  })
  it('retour arrière : les données reviennent au point de départ, la bascule repart de zéro, tout est journalisé', async () => {
    await db.query("insert into dns_zones (name, type) values ('apres.test', 'primary')")
    const r = await admin.post('/api/migration/cutover/rollback'); expect(r.status, r.text).toBe(200); expect(r.json.started).toBeNull(); expect(r.json.preSnapshot).toBeGreaterThan(0)
    expect((await rows("select count(*)::int n from dns_zones where name = 'apres.test'"))[0].n).toBe(0)
    expect(step(await admin.get('/api/migration'), 'cutover').manual).toBe(false)
    expect((await rows("select action from audit_log where action like 'migration_cutover%' order by id")).map((x: any) => x.action)).toEqual(
      ['migration_cutover_start', 'migration_cutover_item', 'migration_cutover_item', 'migration_cutover_item', 'migration_cutover_item', 'migration_cutover_finish', 'migration_cutover_rollback'])
    expect((await admin.post('/api/migration/cutover/start')).status).toBe(200)
  })
})
