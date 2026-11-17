// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.13.6 — « à déployer » ne reste plus affiché quand rien n'a changé (écritures sans effet, déclencheurs par instruction)
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3445, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s44-')); mkdirSync(join(TMP, 'gen'))
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


afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })


describe('0.13.6 — état « à déployer » fondé sur le contenu', () => {
  const st = async () => (await admin.get('/api/system/config-generation')).json
  it('après déploiement : aucune modification en attente ; une écriture sans effet n\'en crée pas ; une vraie modification, si', async () => {
    const z = await admin.post('/api/dns/zones', { name: 'etat.test', type: 'primary' })
    expect(z.status, z.text).toBe(200)
    for (const x of [{ name: '@', type: 'NS', rdata: 'ns.etat.test.' }, { name: 'ns', type: 'A', rdata: '10.1.1.53' }]) expect((await admin.post('/api/dns/records', { zone_id: z.json.id, ...x })).status).toBe(200)
    const r = await admin.post('/api/dns/records', { zone_id: z.json.id, name: 'www', type: 'A', rdata: '10.1.1.1' })
    expect(r.status, r.text).toBe(200)
    expect((await st()).pending).toBe(true)
    const dep = (await admin.post('/api/system/apply', { deploy: true })).json
    expect(dep, JSON.stringify(dep)).toMatchObject({ ok: true, deployed: true })
    const s0 = await st(); expect(s0.pending).toBe(false)
    // écriture sans effet : l'insertion est ignorée (conflit) mais le déclencheur par instruction incrémente quand même la génération
    await db.query("insert into dns_records (zone_id, name, type, rdata) values ($1,'www','A','10.1.1.1') on conflict do nothing", [z.json.id])
    await db.query('update config_generation set generation = generation + 5 where id = 1')
    const s1 = await st(); expect(s1.generation).toBeGreaterThan(s0.generation); expect(s1.pending).toBe(false)
    // vraie modification
    expect((await admin.post('/api/dns/records', { zone_id: z.json.id, name: 'ftp', type: 'A', rdata: '10.1.1.2' })).status).toBe(200)
    expect((await st()).pending).toBe(true)
    expect((await admin.post('/api/system/apply', { deploy: true })).json).toMatchObject({ deployed: true })
    expect((await st()).pending).toBe(false)
    // le filtrage (zone RPZ horodatée) ne doit pas non plus donner de fausse alerte
    expect((await admin.put('/api/filter/settings', { rpzEnabled: true, rpzAction: 'nxdomain', sinkhole4: '0.0.0.0', sinkhole6: '::' })).status).toBe(200)
    expect((await admin.post('/api/system/apply', { deploy: true })).json).toMatchObject({ deployed: true })
    expect((await admin.post('/api/filter/rules', { domain: 'pub.example.com', action: 'block' })).status).toBe(200)
    expect((await st()).pending).toBe(true)
    expect((await admin.post('/api/system/apply', { deploy: true })).json).toMatchObject({ deployed: true })
    await new Promise((r) => setTimeout(r, 1100))
    await db.query('update config_generation set generation = generation + 1 where id = 1')
    expect((await st()).pending).toBe(false)
  })
})
