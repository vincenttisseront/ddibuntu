// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : exploitation du cluster (quorum en direct, retrait de nœud, reprise, autorité).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3396, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s9-')); mkdirSync(join(TMP, 'gen'))
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
const member = (name: string, ok = true, over: Record<string, unknown> = {}) => ({ name, ip: '10.9.0.' + name.slice(1), role: name === 'n3' ? 'witness' : 'data', reachable: ok, healthy: ok, learner: false, isLeader: false, version: '3.4.30', raftIndex: 120, raftTerm: 4, dbSize: 40960, latencyMs: 3, ...over })
const quorum = (over: Record<string, unknown> = {}) => ({ voters: 3, needed: 2, healthy: 3, hasQuorum: true, tolerance: 1, leader: 'n1', members: [member('n1', true, { isLeader: true }), member('n2'), member('n3')], unknownToEtcd: [], ...over })
const state = (over: Record<string, unknown> = {}) => ({
  cluster: 'lab', node: 'n2', role: 'data', local_role: 'replica', at: Math.floor(Date.now() / 1000), bind: 'secondary', etcd: { healthy: true, members: 3, quorum: quorum() },
  ca: { node: false, owner: 'n1', escrow: true },
  peers: [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }],
  patroni: { members: [{ name: 'n1', role: 'leader', state: 'running' }, { name: 'n2', role: 'replica', state: 'streaming', lag: 0 }] }, kea: null, vip: null, ...over })
const publish = (o?: Record<string, unknown>) => writeFileSync(CL, JSON.stringify(state(o)))
const clear = () => rmSync(ACT, { force: true })
const sent = () => JSON.parse(readFileSync(ACT, 'utf8'))

describe('quorum en direct', () => {
  it('le quorum mesuré par root est relayé, assaini et lisible par un lecteur', async () => {
    publish(); const r = (await viewer.get('/api/cluster/status')).json
    expect(r.state.etcd.quorum).toMatchObject({ voters: 3, needed: 2, healthy: 3, hasQuorum: true, tolerance: 1, leader: 'n1' })
    expect(r.state.etcd.quorum.members).toHaveLength(3); expect(r.state.etcd.quorum.members[0]).toMatchObject({ name: 'n1', isLeader: true, latencyMs: 3, raftIndex: 120 })
    expect(r.state.ca).toEqual({ node: false, owner: 'n1', escrow: true })
  })
  it('champs inconnus ignorés, valeurs hors bornes écartées', async () => {
    publish({ etcd: { healthy: true, members: 3, quorum: { ...quorum(), secret: 'x', members: [{ ...member('n1'), name: 'n'.repeat(300), latencyMs: 'abc', extra: 1 }] } } })
    const q = (await viewer.get('/api/cluster/status')).json.state.etcd.quorum
    expect(JSON.stringify(q)).not.toMatch(/secret|extra/); expect(q.members[0].name.length).toBe(63); expect(q.members[0].latencyMs).toBeNull()
  })
  it('actualisation : opérateur oui, lecteur non, une seule demande en attente', async () => {
    clear(); publish()
    code(await viewer.post('/api/cluster/refresh', {}), 403, 'forbidden'); code(await anon.post('/api/cluster/refresh', {}), 401, 'unauthenticated')
    expect((await admin.post('/api/cluster/refresh', {})).json).toEqual({ accepted: true }); expect(sent()).toEqual({ action: 'refresh' })
    code(await admin.post('/api/cluster/refresh', {}), 409, 'action_pending')   // la précédente n'est pas encore consommée par root
    clear()
  })
})

describe('retrait d\'un nœud perdu', () => {
  it('droits et validation', async () => {
    clear(); publish()
    code(await viewer.post('/api/cluster/action', { action: 'remove-node', node: 'n1', confirm: 'n1' }), 403, 'forbidden'); code(await anon.post('/api/cluster/action', { action: 'recover', confirm: 'lab' }), 401, 'unauthenticated')
    for (const bad of [{}, { action: 'format' }, { action: 'remove-node' }, { action: 'remove-node', node: 'N1', confirm: 'N1' }, { action: 'remove-node', node: 'n1; rm', confirm: 'n1; rm' }, { action: 'remove-node', node: '../x', confirm: '../x' },
      { action: 'remove-node', node: 'n1', confirm: 'n1', extra: 1 }, { action: 'recover', confirm: 'lab', node: 'n1' }, { action: 'take-ca', confirm: 'n2', node: 'n1' }, { action: 'refresh' }])
      code(await admin.post('/api/cluster/action', bad), 400, 'validation')
    expect(existsSync(ACT)).toBe(false)
  })
  it('refus : confirmation, soi-même, nœud inconnu, quorum', async () => {
    publish()
    code(await admin.post('/api/cluster/action', { action: 'remove-node', node: 'n1', confirm: 'n3' }), 409, 'confirm_mismatch')
    code(await admin.post('/api/cluster/action', { action: 'remove-node', node: 'n2', confirm: 'n2' }), 409, 'cannot_remove_self')
    code(await admin.post('/api/cluster/action', { action: 'remove-node', node: 'n9', confirm: 'n9' }), 409, 'unknown_node')
    publish({ at: Math.floor(Date.now() / 1000) - 900 }); code(await admin.post('/api/cluster/action', { action: 'remove-node', node: 'n1', confirm: 'n1' }), 409, 'quorum_required')
    publish({ etcd: { healthy: false, members: 3, quorum: quorum({ hasQuorum: false, healthy: 1, tolerance: -1 }) } }); code(await admin.post('/api/cluster/action', { action: 'remove-node', node: 'n1', confirm: 'n1' }), 409, 'quorum_required')
    publish({ role: 'witness' }); code(await admin.post('/api/cluster/action', { action: 'remove-node', node: 'n1', confirm: 'n1' }), 409, 'action_data_node_only')
    expect(existsSync(ACT)).toBe(false)
  })
  it('accepté : demande déposée pour root, auditée', async () => {
    publish(); const r = await admin.post('/api/cluster/action', { action: 'remove-node', node: 'n1', confirm: 'n1' })
    expect(r.json).toEqual({ accepted: true }); expect(sent()).toEqual({ action: 'remove-node', node: 'n1', confirm: 'n1' })
    code(await admin.post('/api/cluster/action', { action: 'remove-node', node: 'n3', confirm: 'n3' }), 409, 'action_pending')
    expect((await db.query("select username, entity_id from audit_log where action = 'cluster.remove-node'")).rows).toEqual([{ username: 'admin', entity_id: 'n1' }])
    clear()
  })
})

describe('reprise de l\'autorité et reconstruction', () => {
  it('take-ca : seulement si un autre nœud la porte et qu\'une copie existe', async () => {
    clear(); publish()
    code(await admin.post('/api/cluster/action', { action: 'take-ca', confirm: 'n1' }), 409, 'confirm_mismatch')
    publish({ ca: { node: true, owner: 'n2', escrow: true } }); code(await admin.post('/api/cluster/action', { action: 'take-ca', confirm: 'n2' }), 409, 'already_ca')
    publish({ ca: { node: false, owner: 'n1', escrow: false } }); code(await admin.post('/api/cluster/action', { action: 'take-ca', confirm: 'n2' }), 409, 'no_escrow')
    publish(); expect((await admin.post('/api/cluster/action', { action: 'take-ca', confirm: 'n2' })).json).toEqual({ accepted: true }); expect(sent()).toEqual({ action: 'take-ca', confirm: 'n2' }); clear()
  })
  it('recover : seulement sans quorum, avec le nom du cluster', async () => {
    publish(); code(await admin.post('/api/cluster/action', { action: 'recover', confirm: 'lab' }), 409, 'quorum_present')
    publish({ etcd: { healthy: false, members: 3, quorum: quorum({ hasQuorum: false, healthy: 1, tolerance: -1 }) } })
    code(await admin.post('/api/cluster/action', { action: 'recover', confirm: 'n2' }), 409, 'confirm_mismatch')
    expect((await admin.post('/api/cluster/action', { action: 'recover', confirm: 'lab' })).json).toEqual({ accepted: true }); expect(sent()).toEqual({ action: 'recover', confirm: 'lab' }); clear()
  })
  it('hors cluster : refusé', async () => { rmSync(CL, { force: true }); code(await admin.post('/api/cluster/action', { action: 'recover', confirm: 'lab' }), 409, 'not_clustered') })
  it('le résultat de root (avec son action) est relayé', async () => {
    publish(); writeFileSync(join(TMP, 'cluster-result.json'), JSON.stringify({ at: 99, action: 'remove-node', candidate: 'n1', ok: true, message: 'nœud retiré' }))
    expect((await admin.get('/api/cluster/status')).json.result).toEqual({ at: 99, action: 'remove-node', candidate: 'n1', ok: true, message: 'nœud retiré' })
  })
  it('chaque code d\'erreur a sa traduction FR et EN', async () => {
    const fr = (await import('../app/i18n/fr')).default as any, en = (await import('../app/i18n/en')).default as any
    for (const c of ['action_pending', 'action_data_node_only', 'confirm_mismatch', 'cannot_remove_self', 'unknown_node', 'quorum_required', 'already_ca', 'no_escrow', 'quorum_present']) { expect(fr[`err.${c}`], c).toBeTruthy(); expect(en[`err.${c}`], c).toBeTruthy() }
  })
})
