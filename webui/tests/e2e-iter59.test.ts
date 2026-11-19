// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.15.0 — RADIUS actif / passif dans le cluster. Un faux « root » répond aux demandes de la console.
// « Déployer » mémorise (chiffré) ce que root a ACCEPTÉ ; le nouveau leader, quand RADIUS ne tourne pas, rejoue ce déploiement ; sur un secondaire, un arbitre, hors cluster
// ou après un arrêt voulu, rien n'est rejoué. Le côté root (align, refus hors leader) est vérifié contre un vrai FreeRADIUS par tests/b28.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3487, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s59-')), GEN = join(TMP, 'gen'), CL = join(TMP, 'cluster-status.json'), ST = join(TMP, 'radius-status.json'), RES = join(TMP, 'radius-result.json'), REQ = join(GEN, '.radius-request')
let srv: ChildProcess, db: pg.Client, srvLog = ''

class Client {
  cookie = ''; csrf = ''
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { cookie: this.cookie }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* texte */ }
    return { status: r.status, json, text, headers: r.headers }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); del = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), oper = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 200)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows

const NOW = () => Math.floor(Date.now() / 1000)
const doc = (o: { node?: string; role?: string; leader?: string } = {}) => ({
  cluster: 'lab', node: o.node ?? 'n1', role: o.role ?? 'data', local_role: (o.leader ?? 'n1') === (o.node ?? 'n1') ? 'leader' : 'replica', at: NOW() - 3, bind: 'primary',
  etcd: { healthy: true, members: 3 }, peers: [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }],
  patroni: { members: [{ name: 'n1', role: (o.leader ?? 'n1') === 'n1' ? 'leader' : 'replica', state: 'running' }, { name: 'n2', role: (o.leader ?? 'n1') === 'n2' ? 'leader' : 'replica', state: 'streaming', lag: 0 }] },
  vip: { address: '192.0.2.10/24', iface: 'ens192', held: (o.leader ?? 'n1') === (o.node ?? 'n1') } })
const setCluster = (o?: Parameters<typeof doc>[0]) => writeFileSync(CL, JSON.stringify(doc(o)))
const setStatus = (active: boolean) => writeFileSync(ST, JSON.stringify({ at: NOW(), installed: true, version: '3.2.5', configured: true, active, enabled: active, clients: 1, ports: [1812, 1813], eap: { enabled: false }, authz: { enabled: false }, ldap_module: true }))
const sent = () => (existsSync(REQ) ? JSON.parse(readFileSync(REQ, 'utf8')) : null)
/** Le faux root : consomme la demande en attente et répond (ok ou refus). */
const rootAnswers = (ok: boolean, message = ok ? 'Service RADIUS démarré (1 client(s)).' : 'configuration refusée par freeradius') => {
  const rq = sent(); expect(rq, 'une demande était attendue').not.toBeNull()
  rmSync(REQ, { force: true })
  writeFileSync(RES, JSON.stringify({ at: NOW() + 1, action: rq.action, ok, message }))
  return rq
}
const snap = async () => (await db.query("select value from settings where key = 'radius_snapshot'")).rows[0]?.value ?? null
const radius = async () => { const r = await viewer.get('/api/radius'); expect(r.status, r.text).toBe(200); return r.json.data ?? r.json }
const noRequestFor = async (ms: number) => { await new Promise((r) => setTimeout(r, ms)); expect(sent()).toBeNull() }

beforeAll(async () => {
  mkdirSync(GEN, { recursive: true })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_CLUSTER_STATUS: CL, DDI_RADIUS_STATUS: ST, DDI_RADIUS_RESULT: RES, DDI_RADIUS_FOLLOW_MS: '1000', DDI_RADIUS_CRL_MS: '3600000' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  for (const [u, ro, c] of [['lect', 'viewer', viewer]] as const) { expect((await admin.post('/api/users', { username: u, role: ro, password: PW })).status).toBe(200); expect((await c.login(u, PW)).status).toBe(200) }
}, 300000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })


describe('RADIUS actif / passif', () => {
  it('hors cluster : aucun bloc cluster, « Déployer » accepté, rien n\'est rejoué', async () => {
    expect((await radius()).cluster).toBeNull()
    setStatus(false)
    expect((await admin.post('/api/radius/apply')).status).toBe(200)
    rootAnswers(true)
    await radius()
    const s = await snap(); expect(s.deployed, JSON.stringify(s)).toMatch(/^v1:/); expect(s.pending).toBeNull()
    await noRequestFor(2500)   // service « arrêté » mais hors cluster : on ne rejoue rien
  })
  it('l\'instantané est chiffré : aucun texte de la configuration dans la base', async () => {
    const raw = JSON.stringify(await snap())
    expect(raw).not.toContain('ddi-selftest'); expect(raw).not.toContain('client "')
  })
  it('un déploiement refusé par root ne remplace pas le dernier déploiement', async () => {
    const before = (await snap()).deployed
    expect((await admin.post('/api/radius/apply')).status).toBe(200)
    rootAnswers(false)
    await radius()
    const s = await snap(); expect(s.deployed).toBe(before); expect(s.pending).toBeNull()
  })
  it('secondaire : le bloc cluster le dit et rien n\'est rejoué', async () => {
    setCluster({ node: 'n2', leader: 'n1' }); setStatus(false)
    expect((await radius()).cluster).toMatchObject({ node: 'n2', role: 'replica', leader: 'n1', deployed: true, vip: { address: '192.0.2.10/24', held: false } })
    await noRequestFor(2500)
  })
  it('arbitre : rien n\'est rejoué, pas de bloc cluster', async () => {
    setCluster({ node: 'n3', role: 'witness', leader: 'n1' }); setStatus(false)
    expect((await radius()).cluster).toBeNull()
    await noRequestFor(2500)
  })
  it('leader dont le service tourne : rien n\'est rejoué', async () => {
    setCluster({ node: 'n1', leader: 'n1' }); setStatus(true)
    expect((await radius()).cluster).toMatchObject({ node: 'n1', role: 'leader', deployed: true, follow: null })
    await noRequestFor(2500)
  })
  it('nouveau leader dont le service ne tourne pas : le dernier déploiement est rejoué, puis le résultat est affiché', async () => {
    setCluster({ node: 'n1', leader: 'n1' }); setStatus(false)
    await until(async () => sent() !== null, 15000)
    expect(sent()).toEqual({ action: 'apply' })
    expect(readFileSync(join(GEN, 'radius-clients.conf'), 'utf8')).toContain('ddi-selftest')
    rootAnswers(true)
    await until(async () => (await radius()).cluster.follow?.ok === true, 15000)
    expect((await radius()).cluster.follow).toMatchObject({ ok: true, message: expect.stringContaining('démarré') })
  })
  it('au plus une reprise toutes les 5 minutes, même si le service ne tourne toujours pas', async () => {
    await noRequestFor(3000)
  })
  it('« Arrêter » voulu : plus aucun leader ne redémarre le service', async () => {
    expect((await admin.post('/api/radius/stop')).status).toBe(200)
    rootAnswers(true, 'Service RADIUS arrêté.')
    await radius()
    expect((await snap()).deployed).toBeNull()
    setStatus(false)
    await noRequestFor(2500)
  })
  it('accès : lecture authentifiée, écriture réservée à l\'administrateur', async () => {
    code(await anon.get('/api/radius'), 401, 'unauthenticated')
    code(await viewer.post('/api/radius/apply'), 403, 'forbidden')
    code(await viewer.post('/api/radius/stop'), 403, 'forbidden')
  })
})
