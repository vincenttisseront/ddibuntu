// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : test de bascule guidé 0.9.3 — rapports, pré-contrôles, avancement, demandes, refus pendant un test.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3401, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s12-')); mkdirSync(join(TMP, 'gen'))
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

const GEN = join(TMP, 'gen'), CL = join(TMP, 'cl.json'), ACT = join(GEN, '.cluster-action')
const DRILLS = join(TMP, 'cluster-drills.json'), CHECK = join(TMP, 'cluster-drill-check.json'), LIVE = join(TMP, 'cluster-drill-live.json')
const nowS = () => Math.floor(Date.now() / 1000)
const member = (name: string, ok = true, over: Record<string, unknown> = {}) => ({ name, ip: '10.9.0.' + name.slice(1), role: name === 'n3' ? 'witness' : 'data', reachable: ok, healthy: ok, learner: false, isLeader: false, version: '3.4.30', raftIndex: 120, raftTerm: 4, dbSize: 40960, latencyMs: 3, ...over })
const quorum = (over: Record<string, unknown> = {}) => ({ voters: 3, needed: 2, healthy: 3, hasQuorum: true, tolerance: 1, leader: 'n1', members: [member('n1', true, { isLeader: true }), member('n2'), member('n3')], unknownToEtcd: [], ...over })
const state = (over: Record<string, unknown> = {}) => ({
  cluster: 'lab', node: 'n2', role: 'data', local_role: 'replica', at: nowS(), bind: 'secondary', etcd: { healthy: true, members: 3, quorum: quorum() },
  ca: { node: false, owner: 'n1', escrow: true },
  peers: [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }],
  patroni: { members: [{ name: 'n1', role: 'leader', state: 'running' }, { name: 'n2', role: 'replica', state: 'streaming', lag: 0 }] }, kea: null, vip: null,
  settings: { published: { rev: 1, vip: null, vrid: 51, iface: null, net: '10.9.0.0/24' }, applied: { rev: 1, vip: null, vrid: 51, iface: null, net: '10.9.0.0/24' } }, ...over })
const publish = (o?: Record<string, unknown>) => writeFileSync(CL, JSON.stringify(state(o)))
const clear = () => rmSync(ACT, { force: true })
const sent = () => JSON.parse(readFileSync(ACT, 'utf8'))
const post = (b: unknown) => admin.post('/api/cluster/action', b)

const metrics = { noPrimaryMs: 3003, resolutionMs: 507, promotionMs: 3450, demotionMs: 949, rejoinMs: 5450, catchUpMs: 2000, timeline: [2, 3], lagMaxBytes: 0, lsnContinuity: true, settleMs: 6175 }
const phase = (name: string, from: string, to: string) => ({ name, from, to, cmdRc: 0, cmdMs: 3673, output: 'Successfully switched over', metrics, verdicts: { noPrimary: 'ok', promotion: 'ok', rejoin: 'ok', catchUp: 'ok', timeline: 'ok', lsn: 'ok' }, post: [{ id: 'leader', status: 'ok', detail: 'primaire : ' + to }], ok: true })
const report = (id = '20261111T163812Z', over: Record<string, unknown> = {}) => ({
  v: 1, id, cluster: 'lab', node: 'n1', by: 'console', startedAt: nowS() - 600, back: true, from: 'n1', to: 'n2', pre: { ok: true, checks: [{ id: 'topology', status: 'ok', detail: 'primaire : n1' }], candidates: [{ name: 'n2', ok: true, lagBytes: 0, issues: [] }] },
  phases: [phase('switch', 'n1', 'n2'), phase('back', 'n2', 'n1')], events: [{ t: 396, kind: 'step', node: 'n1', detail: 'commande de bascule vers n2' }], resolutionMs: 507, outcome: 'success', finishedAt: nowS() - 580, durationMs: 19503,
  thresholds: { noPrimaryMs: [15000, 30000], promotionMs: [30000, 60000], rejoinMs: [90000, 150000], catchUpLagBytes: 16384, maxLagBytes: 1048576 }, ...over })
const drills = (o: Record<string, unknown> = {}) => writeFileSync(DRILLS, JSON.stringify({ at: nowS(), active: null, reports: [report()], ...o }))
const live = (o: Record<string, unknown> = {}) => writeFileSync(LIVE, JSON.stringify({ type: 'live', id: '20261111T170000Z', node: 'n1', phase: 'switch', startedAt: nowS() - 10, at: nowS(), elapsedMs: 10000, steps: [{ t: 0, text: 'pré-contrôles' }], ...o }))
const reset = () => { clear(); for (const f of [DRILLS, CHECK, LIVE]) rmSync(f, { force: true }); publish() }

describe('lecture : rapports, pré-contrôles, avancement', () => {
  it('droits : lisible par un lecteur, pas sans session', async () => {
    reset(); drills()
    expect((await anon.get('/api/cluster/drills')).status).toBe(401)
    const r = await viewer.get('/api/cluster/drills'); expect(r.status).toBe(200)
    expect(r.json.drills.reports.map((x: any) => x.id)).toEqual(['20261111T163812Z']); expect(r.json.busy).toBe(false)
  })
  it('rien de publié : valeurs nulles, la page reste utilisable', async () => {
    reset(); expect((await viewer.get('/api/cluster/drills')).json).toEqual({ drills: null, check: null, live: null, busy: false })
  })
  it('fichiers mal formés ou hostiles : ignorés ; champs inconnus jamais relayés', async () => {
    reset(); writeFileSync(DRILLS, 'pas du json'); writeFileSync(CHECK, '[]'); writeFileSync(LIVE, '{"type":"autre"}')
    expect((await viewer.get('/api/cluster/drills')).json).toEqual({ drills: null, check: null, live: null, busy: false })
    drills({ secret: 'topsecret', reports: [{ ...report(), secret: 'topsecret' }, { v: 1, id: '../../etc/passwd', outcome: 'success' }] })
    const r = (await viewer.get('/api/cluster/drills')).json
    expect(r.drills.reports).toHaveLength(1); expect(JSON.stringify(r)).not.toContain('topsecret')
  })
  it('test en cours : marque etcd valable ou avancement vivant ; périmés = ignorés', async () => {
    reset(); drills({ active: { id: '20261111T170000Z', node: 'n1', at: nowS() - 5, phase: 'switch' } })
    let r = (await viewer.get('/api/cluster/drills')).json; expect([r.busy, r.drills.active.node, r.drills.active.phase]).toEqual([true, 'n1', 'switch'])
    reset(); drills({ active: { id: '20261111T170000Z', node: 'n1', at: nowS() - 4000, phase: 'switch' } })
    r = (await viewer.get('/api/cluster/drills')).json; expect([r.busy, r.drills.active]).toEqual([false, null])
    reset(); drills(); live()
    r = (await viewer.get('/api/cluster/drills')).json; expect([r.busy, r.live.running, r.live.steps[0].text]).toEqual([true, true, 'pré-contrôles'])
    live({ at: nowS() - 120 }); r = (await viewer.get('/api/cluster/drills')).json; expect([r.busy, r.live.running]).toEqual([false, false])
  })
  it('rapport téléchargeable : seulement un identifiant publié', async () => {
    reset(); drills({ reports: [report('20261111T163812Z'), report('20261110T080000Z', { outcome: 'failed' })] })
    const ok = await fetch(BASE + '/api/cluster/drills/20261110T080000Z', { headers: { cookie: viewer.cookie } })
    expect(ok.status).toBe(200); expect(ok.headers.get('content-disposition')).toContain('ddibuntu-drill-20261110T080000Z.json')
    expect((await ok.json()).outcome).toBe('failed')
    code(await viewer.get('/api/cluster/drills/20250101T000000Z'), 404, 'not_found')
    for (const bad of ['..%2Fetc%2Fpasswd', 'x', '20261110T080000Z%00', '2026111T163812Z']) expect((await viewer.get('/api/cluster/drills/' + bad)).status).toBe(404)
    expect((await anon.get('/api/cluster/drills/20261111T163812Z')).status).toBe(401)
  })
})

describe('demandes de pré-contrôles', () => {
  it('droits et validation stricte', async () => {
    reset()
    code(await viewer.post('/api/cluster/action', { action: 'drill-check' }), 403, 'forbidden'); code(await anon.post('/api/cluster/action', { action: 'drill-check' }), 401, 'unauthenticated')
    for (const bad of [{ action: 'drill-check', extra: 1 }, { action: 'drill-check', node: 'N 1' }, { action: 'drill-check', node: 'n1; reboot' }, { action: 'drill-check', node: 5 }, { action: 'drill-check', confirm: 'lab' }, { action: 'drill-check', back: true }])
      code(await post(bad), 400, 'validation')
    expect(existsSync(ACT)).toBe(false)
  })
  it('refus : état périmé, nœud arbitre, pas de cluster ; permis pendant un test', async () => {
    reset(); publish({ at: nowS() - 900 }); code(await post({ action: 'drill-check' }), 409, 'cluster_state_stale')
    publish({ role: 'witness' }); code(await post({ action: 'drill-check' }), 409, 'action_data_node_only')
    rmSync(CL, { force: true }); code(await post({ action: 'drill-check' }), 409, 'not_clustered')
    reset(); live(); expect((await post({ action: 'drill-check' })).status).toBe(200); clear()
  })
  it('demande déposée telle que validée, une seule à la fois', async () => {
    reset(); expect((await post({ action: 'drill-check' })).json).toEqual({ accepted: true }); expect(sent()).toEqual({ action: 'drill-check' })
    code(await post({ action: 'drill-check' }), 409, 'action_pending'); clear()
    expect((await post({ action: 'drill-check', node: 'n2' })).status).toBe(200); expect(sent()).toEqual({ action: 'drill-check', node: 'n2' }); clear()
  })
})

describe('demande de test de bascule', () => {
  const drill = (o: Record<string, unknown> = {}) => ({ action: 'drill', confirm: 'lab', back: true, ...o })
  it('validation stricte', async () => {
    reset()
    code(await viewer.post('/api/cluster/action', drill()), 403, 'forbidden')
    for (const bad of [{ action: 'drill' }, drill({ confirm: undefined }), drill({ back: 'oui' }), drill({ back: 1 }), drill({ node: 'N 1' }), drill({ node: 'n2; x' }), drill({ extra: 1 }), drill({ confirm: 'x'.repeat(65) }), drill({ node: 7 })])
      code(await post(bad), 400, 'validation')
    expect(existsSync(ACT)).toBe(false)
  })
  it('refus : confirmation, candidat, quorum, état périmé, nœud arbitre', async () => {
    reset()
    code(await post(drill({ confirm: 'n2' })), 409, 'confirm_mismatch'); code(await post(drill({ confirm: '' })), 409, 'confirm_mismatch')
    code(await post(drill({ node: 'n1' })), 409, 'invalid_candidate'); code(await post(drill({ node: 'n3' })), 409, 'invalid_candidate'); code(await post(drill({ node: 'n9' })), 409, 'invalid_candidate')
    publish({ patroni: { members: [{ name: 'n1', role: 'leader', state: 'running' }, { name: 'n2', role: 'replica', state: 'starting' }] } }); code(await post(drill()), 409, 'invalid_candidate')
    publish({ etcd: { healthy: false, members: 3, quorum: quorum({ hasQuorum: false, healthy: 1, tolerance: -1 }) } }); code(await post(drill()), 409, 'quorum_required')
    publish({ at: nowS() - 900 }); code(await post(drill()), 409, 'cluster_state_stale')
    publish({ role: 'witness' }); code(await post(drill()), 409, 'action_data_node_only')
    expect(existsSync(ACT)).toBe(false)
  })
  it('un test déjà en cours (marque ou avancement) interdit d\'en lancer un autre', async () => {
    reset(); drills({ active: { id: '20261111T170000Z', node: 'n1', at: nowS() - 5, phase: 'back' } }); code(await post(drill()), 409, 'drill_active')
    reset(); live(); code(await post(drill()), 409, 'drill_active')
    reset(); live({ at: nowS() - 300 }); expect((await post(drill())).status).toBe(200); clear()   // avancement abandonné : plus bloquant
    expect(existsSync(ACT)).toBe(false)
  })
  it('demande déposée telle que validée (candidat et retour facultatifs), auditée', async () => {
    const n0 = Number((await db.query("select count(*)::int c from audit_log where action = 'cluster.drill'")).rows[0].c)
    reset(); expect((await post(drill())).json).toEqual({ accepted: true }); expect(sent()).toEqual({ action: 'drill', confirm: 'lab', back: true })
    code(await post(drill()), 409, 'action_pending'); clear()
    expect((await post({ action: 'drill', confirm: 'lab' })).status).toBe(200); expect(sent()).toEqual({ action: 'drill', confirm: 'lab' }); clear()
    expect((await post(drill({ node: 'n2', back: false }))).status).toBe(200); expect(sent()).toEqual({ action: 'drill', node: 'n2', back: false, confirm: 'lab' }); clear()
    const a = await db.query("select action, entity, entity_id, username from audit_log where action = 'cluster.drill' order by id offset $1", [n0])
    expect(a.rows.map((x: any) => `${x.action}|${x.entity_id}`)).toEqual(['cluster.drill|', 'cluster.drill|', 'cluster.drill|n2'])
    expect(new Set(a.rows.map((x: any) => x.username))).toEqual(new Set(['admin']))
  })
})

describe('pendant un test, la topologie ne bouge pas', () => {
  it('les opérations qui changent le cluster sont refusées, pas le certificat ni la reprise', async () => {
    reset(); drills({ active: { id: '20261111T170000Z', node: 'n1', at: nowS() - 5, phase: 'switch' } })
    const lab = 'lab'
    for (const a of [{ action: 'remove-node', node: 'n3', confirm: 'n3' }, { action: 'take-ca', confirm: 'n2' }, { action: 'set-vip', vip: '192.0.2.50/24', iface: 'lo', confirm: lab }, { action: 'clear-vip', confirm: lab },
      { action: 'set-net', net: '10.9.0.0/16', confirm: lab }, { action: 'change-ip', ip: '127.0.0.1', confirm: 'n2' }])
      code(await post(a), 409, 'drill_active')
    code(await admin.post('/api/cluster/switchover', { candidate: 'n2' }), 409, 'drill_active')
    expect(existsSync(ACT)).toBe(false); expect(existsSync(join(GEN, '.cluster-switchover'))).toBe(false)
    expect((await post({ action: 'renew-cert' })).status).toBe(200); expect(sent()).toEqual({ action: 'renew-cert' }); clear()
  })
  it('sans test en cours, la bascule manuelle reste possible', async () => {
    reset(); expect((await admin.post('/api/cluster/switchover', { candidate: 'n2' })).status).toBe(200)
    expect(readFileSync(join(GEN, '.cluster-switchover'), 'utf8').trim()).toBe('n2'); rmSync(join(GEN, '.cluster-switchover'), { force: true })
  })
})
