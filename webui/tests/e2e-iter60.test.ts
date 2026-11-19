// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.16.0 — identifiant et mot de passe (PEAP-MSCHAPv2, EAP-TTLS). Réglages, dépôts pour root (auth.json, jonction au domaine),
// secrets jamais conservés ni journalisés, refus de déployer sans règle. Un faux « root » répond. Le côté root est vérifié contre un vrai FreeRADIUS et un vrai Samba AD par tests/b40.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3488, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s60-')), GEN = join(TMP, 'gen'), CL = join(TMP, 'cluster-status.json'), ST = join(TMP, 'radius-status.json'), RES = join(TMP, 'radius-result.json'), REQ = join(GEN, '.radius-request')
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



const body = (r: { json: any }) => r.json?.data ?? r.json
const JOIN_PW = 'Join-Secret-Pw-7788', JOIN_USER = 'Administrator'
const joinDir = () => join(GEN, 'radius-join')

describe('identifiant et mot de passe', () => {
  it('réglages : désactivés par défaut, réservés à l\'administrateur', async () => {
    const r = await admin.get('/api/radius/auth'); expect(r.status, r.text).toBe(200)
    expect(body(r)).toMatchObject({ peap: false, ttls: false, netbios: '' })
    expect((await viewer.get('/api/radius/auth')).status).toBe(403)
    expect((await viewer.req('PUT', '/api/radius/auth', { peap: true, ttls: false, netbios: 'LAB' })).status).toBe(403)
  })
  it('réglages : enregistrement, relecture, NetBIOS invalide et champ inconnu refusés', async () => {
    expect((await admin.req('PUT', '/api/radius/auth', { peap: true, ttls: true, netbios: 'LAB' })).status).toBe(200)
    expect(body(await admin.get('/api/radius/auth'))).toMatchObject({ peap: true, ttls: true, netbios: 'LAB' })
    expect((await radius()).auth).toMatchObject({ peap: true, ttls: true, netbios: 'LAB' })
    expect((await admin.req('PUT', '/api/radius/auth', { peap: true, ttls: false, netbios: 'A B' })).status).toBe(400)
    expect((await admin.req('PUT', '/api/radius/auth', { peap: true, ttls: false, netbios: 'LAB', x: 1 })).status).toBe(400)
  })
  it('déployer avec une méthode par mot de passe mais sans règle : refusé, rien n\'est déposé', async () => {
    const r = await admin.post('/api/radius/apply'); code(r, 409, 'radius_authz_not_ready')
    expect(body(r).problems).toEqual(['auth_needs_rules']); expect(sent()).toBeNull()
  })
  it('sans méthode par mot de passe, « Déployer » redevient possible (comportement de la 0.15)', async () => {
    expect((await admin.req('PUT', '/api/radius/auth', { peap: false, ttls: false, netbios: '' })).status).toBe(200)
    setStatus(false); expect((await admin.post('/api/radius/apply')).status).toBe(200); rootAnswers(true); await radius()   // le déploiement accepté est pris en compte avant la jonction
  })
  it('jonction : dépôt 0600 pour root, demande « join », mot de passe absent de la base et du journal d\'audit', async () => {
    const r = await admin.post('/api/radius/join', { realm: 'lab.test', netbios: 'LAB', servers: ['dc1.lab.test'], user: JOIN_USER, password: JOIN_PW })
    expect(r.status, r.text).toBe(200)
    const dep = JSON.parse(readFileSync(join(joinDir(), 'join.json'), 'utf8'))
    expect(dep).toEqual({ realm: 'lab.test', netbios: 'LAB', servers: ['dc1.lab.test'], user: JOIN_USER, password: JOIN_PW })
    expect(statSync(join(joinDir(), 'join.json')).mode & 0o777).toBe(0o600)
    expect(sent()).toEqual({ action: 'join' })
    expect(JSON.stringify(await rows('select detail from audit_log'))).not.toContain(JOIN_PW)
    expect(JSON.stringify(await rows('select key, value from settings'))).not.toContain(JOIN_PW)
    expect(JSON.stringify(await rows("select detail from audit_log where action = 'radius.join'"))).toContain(JOIN_USER)
    expect(srvLog).not.toContain(JOIN_PW)
    expect(body(await admin.get('/api/radius/auth')).netbios).toBe('LAB')   // le nom du domaine est mémorisé pour les identifiants « DOMAINE\compte »
  })
  it('jonction : une seconde demande est refusée tant que root n\'a pas répondu', async () => {
    code(await admin.post('/api/radius/join', { realm: 'lab.test', netbios: 'LAB', servers: ['dc1.lab.test'], user: JOIN_USER, password: JOIN_PW }), 409, 'request_pending')
  })
  it('jonction : la réponse de root est publiée, l\'état « joint » est relayé sans secret', async () => {
    rmSync(REQ, { force: true })
    writeFileSync(RES, JSON.stringify({ at: NOW() + 2, action: 'join', ok: true, message: 'Appliance jointe au domaine lab.test (compte machine RAD-vmtools-d).' }))
    writeFileSync(ST, JSON.stringify({ at: NOW(), installed: true, version: '3.2.5', configured: true, active: false, enabled: false, clients: 1, ports: [1812, 1813], eap: { enabled: false },
      winbind: { joined: true, realm: 'LAB.TEST', netbios: 'LAB', computer: 'RAD-vmtools-d', at: NOW(), active: true, trust: true, password: 'ne-doit-pas-passer' } }))
    const r = await radius()
    expect(r.result).toMatchObject({ action: 'join', ok: true }); expect(r.status.winbind).toEqual({ joined: true, realm: 'LAB.TEST', netbios: 'LAB', computer: 'RAD-vmtools-d', at: r.status.winbind.at, active: true, trust: true })
    expect(JSON.stringify(r)).not.toContain('ne-doit-pas-passer')
  })
  it('jonction : champs invalides refusés (domaine, NetBIOS, serveur, caractères de contrôle, champ inconnu), lecteur refusé', async () => {
    const ok = { realm: 'lab.test', netbios: 'LAB', servers: ['dc1.lab.test'], user: JOIN_USER, password: JOIN_PW }
    for (const bad of [{ realm: 'labtest' }, { realm: 'lab.test;x' }, { netbios: 'L B' }, { servers: ['dc1 lab'] }, { servers: [] }, { user: 'a\nb' }, { password: 'a\nb' }, { user: '' }, { extra: 1 }]) expect((await admin.post('/api/radius/join', { ...ok, ...bad })).status, JSON.stringify(bad)).toBe(400)
    expect((await viewer.post('/api/radius/join', ok)).status).toBe(403)
    expect(sent()).toBeNull()
  })
  it('départ : sans compte, aucun dépôt de jonction ; avec un compte, il est déposé en 0600 ; moitié de compte refusée', async () => {
    expect((await admin.post('/api/radius/leave', {})).status).toBe(200)
    expect(sent()).toEqual({ action: 'leave' }); expect(existsSync(joinDir())).toBe(false)
    rootAnswers(true, 'Appliance retirée du domaine.')
    code(await admin.post('/api/radius/leave', { user: JOIN_USER }), 400, 'radius_leave_creds')
    expect((await admin.post('/api/radius/leave', { user: JOIN_USER, password: JOIN_PW, realm: 'lab.test', netbios: 'LAB', servers: ['dc1.lab.test'] })).status).toBe(200)
    expect(JSON.parse(readFileSync(join(joinDir(), 'join.json'), 'utf8'))).toMatchObject({ user: JOIN_USER, password: JOIN_PW })
    expect(sent()).toEqual({ action: 'leave' })
    expect(JSON.stringify(await rows('select detail from audit_log'))).not.toContain(JOIN_PW)
    rootAnswers(true, 'Appliance retirée du domaine.')
  })
  it('jonction sans serveur donné ni annuaire : refusée avec un message clair', async () => {
    code(await admin.post('/api/radius/join', { realm: 'lab.test', netbios: 'LAB', user: JOIN_USER, password: JOIN_PW }), 400, 'radius_join_servers')
  })
})
