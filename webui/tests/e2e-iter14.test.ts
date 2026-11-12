// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.9.11 — icône de l'onglet, nœud préféré du primaire (API + demande déposée pour root), jetons de session signés.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { signReplicaSession } from '../server/utils/auth'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3403, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s14-')); mkdirSync(join(TMP, 'gen'))
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

const CL = join(TMP, 'cl.json'), ACT = join(TMP, 'gen', '.cluster-action')
const NOW = () => Math.floor(Date.now() / 1000)
const state = (over: Record<string, unknown> = {}) => JSON.stringify({
  cluster: 'lab', node: 'n1', role: 'data', local_role: 'leader', at: NOW(), bind: 'primary',
  etcd: { healthy: true, members: 3, quorum: { voters: 3, needed: 2, healthy: 3, hasQuorum: true, tolerance: 1, leader: 'n1', members: [
    { name: 'n1', ip: '10.9.0.1', role: 'data', reachable: true, healthy: true, learner: false, isLeader: true, version: '3.4.30', raftIndex: 9, raftTerm: 2, dbSize: 1, latencyMs: 3 },
    { name: 'n2', ip: '10.9.0.2', role: 'data', reachable: true, healthy: true, learner: false, isLeader: false, version: '3.4.30', raftIndex: 9, raftTerm: 2, dbSize: 1, latencyMs: 4 },
    { name: 'n3', ip: '10.9.0.3', role: 'witness', reachable: true, healthy: true, learner: false, isLeader: false, version: '3.4.30', raftIndex: 9, raftTerm: 2, dbSize: 1, latencyMs: 5 }], unknownToEtcd: [] } },
  peers: [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }],
  patroni: { members: [{ name: 'n1', role: 'leader', state: 'running', host: '10.9.0.1', timeline: 3 }, { name: 'n2', role: 'replica', state: 'streaming', lag: 0, timeline: 3 }] },
  vip: { address: '192.0.2.10/24', iface: 'ens18', held: true }, ...over,
})

describe('icône de l\'onglet', () => {
  it('servie sans connexion, en SVG, et annoncée dans la page', async () => {
    const r = await fetch(BASE + '/favicon.svg')
    expect(r.status).toBe(200); expect(r.headers.get('content-type')).toContain('svg')
    expect(await r.text()).toContain('<svg')
    const html = await (await fetch(BASE + '/login')).text()
    expect(html).toMatch(/<link[^>]+rel="icon"[^>]+href="\/favicon\.svg"|<link[^>]+href="\/favicon\.svg"[^>]+rel="icon"/)
  })
})

describe('nœud préféré du primaire', () => {
  const set = { action: 'set-preferred', node: 'n2', confirm: 'lab' }
  it('hors cluster : refusé', async () => { code(await admin.post('/api/cluster/action', set), 409, 'not_clustered') })
  it('état publié → consigne lue et exposée', async () => {
    writeFileSync(CL, state({ preferred: { node: 'n2', at: 1700000000, by: 'n1' } }))
    const r = await viewer.get('/api/cluster/status')
    expect(r.status).toBe(200); expect(r.json.state.preferred).toEqual({ node: 'n2', at: 1700000000, by: 'n1' })
    writeFileSync(CL, state({ preferred: { node: 'n3', at: 1, by: 'n1' } }))   // arbitre : consigne ignorée
    expect((await viewer.get('/api/cluster/status')).json.state.preferred).toBeNull()
    writeFileSync(CL, state())
  })
  it('droits et validation', async () => {
    code(await viewer.post('/api/cluster/action', set), 403, 'forbidden')
    code(await admin.post('/api/cluster/action', { ...set, extra: 1 }), 400, 'validation')
    code(await admin.post('/api/cluster/action', { action: 'set-preferred', node: 'N2!', confirm: 'lab' }), 400, 'validation')
    code(await admin.post('/api/cluster/action', { ...set, confirm: 'autre' }), 409, 'confirm_mismatch')
    code(await admin.post('/api/cluster/action', { ...set, node: 'n3' }), 409, 'invalid_node')
    code(await admin.post('/api/cluster/action', { action: 'clear-preferred', confirm: 'lab' }), 409, 'no_preferred')
    expect(existsSync(ACT)).toBe(false)
  })
  it('quorum perdu : refusé ; sinon demande déposée pour root (jeu de clés exact), une seule à la fois', async () => {
    writeFileSync(CL, state({ etcd: { healthy: false, members: 3, quorum: { voters: 3, needed: 2, healthy: 1, hasQuorum: false, tolerance: 0, leader: null, members: [], unknownToEtcd: [] } } }))
    code(await admin.post('/api/cluster/action', set), 409, 'quorum_required')
    writeFileSync(CL, state())
    const ok = await admin.post('/api/cluster/action', set)
    expect(ok.status, ok.text).toBe(200)
    expect(JSON.parse(readFileSync(ACT, 'utf8'))).toEqual(set)
    code(await admin.post('/api/cluster/action', { ...set, node: 'n1' }), 409, 'action_pending')
    rmSync(ACT)
    writeFileSync(CL, state({ preferred: { node: 'n2', at: 1, by: 'n1' } }))
    expect((await admin.post('/api/cluster/action', { action: 'clear-preferred', confirm: 'lab' })).status).toBe(200)
    expect(JSON.parse(readFileSync(ACT, 'utf8'))).toEqual({ action: 'clear-preferred', confirm: 'lab' })
    rmSync(ACT)
    const au = await db.query("select action, entity_id from audit_log where action like 'cluster.%' order by id desc limit 2")
    expect(au.rows.map((x) => x.action)).toEqual(['cluster.clear-preferred', 'cluster.set-preferred'])
  })
})

describe('jeton de session signé (secondaire → primaire après bascule)', () => {
  let lect: { id: number; password_hash: string; source: string }
  beforeAll(async () => { lect = (await db.query("select id, password_hash, source from users where username = 'lect'")).rows[0] })
  const with_ = (token: string) => { const c = new Client(); c.cookie = 'ddi_session=' + token; return c }
  it('un jeton valide ouvre la session (lecture), mêmes droits que le compte', async () => {
    const s = signReplicaSession(lect)
    const c = with_(s.token)
    const me = await c.get('/api/auth/me')
    expect(me.json.user.username).toBe('lect'); expect(me.json.csrf).toBe(s.csrf)
    expect((await c.get('/api/cluster/status')).status).toBe(200)
    c.csrf = s.csrf
    code(await c.post('/api/users', { username: 'x', role: 'viewer', password: PW }), 403, 'forbidden')   // viewer : aucune écriture d'administration
  })
  it('jeton altéré ou signé avec une autre clé : session absente', async () => {
    const s = signReplicaSession(lect)
    expect((await with_(s.token.slice(0, -3) + 'AAA').get('/api/auth/me')).json.user).toBeNull()
    expect((await with_('r1.' + Buffer.from('{"u":1,"e":9999999999,"v":"x"}').toString('base64url') + '.AAAA').get('/api/auth/me')).json.user).toBeNull()
  })
  it('mot de passe changé ou compte désactivé : jeton révoqué', async () => {
    const s = signReplicaSession(lect)
    expect((await with_(s.token).get('/api/auth/me')).json.user?.username).toBe('lect')
    await db.query("update users set password_hash = password_hash || 'x' where id = $1", [lect.id])
    expect((await with_(s.token).get('/api/auth/me')).json.user).toBeNull()
    await db.query("update users set password_hash = $2 where id = $1", [lect.id, lect.password_hash])
    expect((await with_(s.token).get('/api/auth/me')).json.user?.username).toBe('lect')
    await db.query('update users set disabled = true where id = $1', [lect.id])
    expect((await with_(s.token).get('/api/auth/me')).json.user).toBeNull()
    await db.query('update users set disabled = false where id = $1', [lect.id])
  })
  it('déconnexion avec un jeton signé : cookie effacé, aucune erreur', async () => {
    const s = signReplicaSession(lect); const c = with_(s.token); c.csrf = s.csrf
    const r = await c.post('/api/auth/logout')
    expect(r.status).toBe(200)
  })
})

describe('mise à jour du cluster, nœud par nœud (demandes)', () => {
  const upd = (o: Record<string, unknown> = {}) => ({ order: null, versions: { n1: '0.9.12', n2: '0.9.12', n3: '0.9.12' }, states: {}, ...o })
  const go = { action: 'update-start', version: '0.9.13', confirm: 'lab' }
  it('état publié exposé, droits et validation', async () => {
    writeFileSync(CL, state({ update: upd() }))
    expect((await viewer.get('/api/cluster/status')).json.state.update.versions).toEqual({ n1: '0.9.12', n2: '0.9.12', n3: '0.9.12' })
    code(await viewer.post('/api/cluster/action', go), 403, 'forbidden')
    code(await admin.post('/api/cluster/action', { ...go, version: 'latest' }), 400, 'validation')
    code(await admin.post('/api/cluster/action', { ...go, extra: 1 }), 400, 'validation')
    code(await admin.post('/api/cluster/action', { action: 'update-start', version: '0.9.13' }), 400, 'validation')
    code(await admin.post('/api/cluster/action', { ...go, confirm: 'x' }), 409, 'confirm_mismatch')
    code(await admin.post('/api/cluster/action', { ...go, version: '0.9.12' }), 409, 'already_at_target')
    code(await admin.post('/api/cluster/action', { action: 'update-cancel', confirm: 'lab' }), 409, 'no_update')
    expect(existsSync(ACT)).toBe(false)
  })
  it('ordre déposé pour root (jeu de clés exact), puis annulation', async () => {
    const r = await admin.post('/api/cluster/action', go); expect(r.status, r.text).toBe(200)
    expect(JSON.parse(readFileSync(ACT, 'utf8'))).toEqual(go); rmSync(ACT)
    writeFileSync(CL, state({ update: upd({ order: { target: '0.9.13', at: 1, by: 'n1' } }) }))
    code(await admin.post('/api/cluster/action', go), 409, 'update_running')
    expect((await admin.post('/api/cluster/action', { action: 'update-cancel', confirm: 'lab' })).status).toBe(200)
    expect(JSON.parse(readFileSync(ACT, 'utf8'))).toEqual({ action: 'update-cancel', confirm: 'lab' }); rmSync(ACT)
    writeFileSync(CL, state())
  })
})

describe('0.9.14 — réglages de session communs', () => {
  const loginMaxAge = async () => {
    const r = await fetch(BASE + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: PW }) })
    const c = (r.headers.getSetCookie?.() ?? []).find((x) => x.startsWith('ddi_session=')) ?? ''
    return Number(/Max-Age=(\d+)/i.exec(c)?.[1] ?? 0)
  }
  it('nœud hors cluster : l\'état annonce les composants manquants (vide en mode test)', async () => {
    const r = await admin.get('/api/cluster/status'); expect(r.status).toBe(200)
    if (r.json.setup) { expect(r.json.setup.missing).toEqual([]); expect(r.json.setup.install).toContain('apt install') }
  })
  it('réservé aux administrateurs', async () => {
    expect((await viewer.get('/api/system/session')).status).toBe(403)
    expect((await viewer.put('/api/system/session', { hours: 4, idleMinutes: 20 })).status).toBe(403)
    expect((await anon.get('/api/system/session')).status).toBe(401)
  })
  it('valeurs par défaut du nœud tant que rien n\'est enregistré', async () => {
    const r = await admin.get('/api/system/session'); expect(r.status).toBe(200)
    expect(r.json.stored).toBe(false); expect(r.json.hours).toBe(r.json.defaults.hours); expect(r.json.limits.hours.max).toBe(72)
  })
  it('refus : hors bornes, flottant, champ inconnu, champ manquant', async () => {
    for (const b of [{ hours: 0, idleMinutes: 30 }, { hours: 73, idleMinutes: 30 }, { hours: 8, idleMinutes: 4 }, { hours: 8, idleMinutes: 1441 }, { hours: 1.5, idleMinutes: 30 }, { hours: 8, idleMinutes: 30, x: 1 }, { hours: 8 }])
      code(await admin.put('/api/system/session', b), 400, 'validation')
  })
  it('enregistrement : stocké en base, durée appliquée aux nouvelles connexions, audité', async () => {
    const r = await admin.put('/api/system/session', { hours: 3, idleMinutes: 45 }); expect(r.status, r.text).toBe(200)
    expect([r.json.hours, r.json.idleMinutes, r.json.stored]).toEqual([3, 45, true])
    expect((await db.query("select value from settings where key = 'session'")).rows[0].value).toEqual({ hours: 3, idleMinutes: 45 })
    expect(await loginMaxAge()).toBe(3 * 3600)
    expect((await db.query("select 1 from audit_log where action = 'session_settings'")).rowCount).toBeGreaterThan(0)
  })
  it('valeur corrompue en base : retour au défaut, la connexion reste possible', async () => {
    await db.query("update settings set value = '{\"hours\":99999,\"idleMinutes\":\"x\"}'::jsonb where key = 'session'")
    await new Promise((r) => setTimeout(r, 16000))
    expect((await admin.get('/api/system/session')).json.hours).toBe((await admin.get('/api/system/session')).json.defaults.hours)
  }, 30000)
  it('retour aux valeurs par défaut', async () => {
    const r = await admin.delete('/api/system/session'); expect(r.status).toBe(200); expect(r.json.stored).toBe(false)
    expect((await db.query("select 1 from settings where key = 'session'")).rowCount).toBe(0)
  })
})
