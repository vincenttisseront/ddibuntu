// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.9 — la PKI dans le cluster. La console ne décide rien : elle relit deux fichiers que root publie (le statut du cluster, avec son
// bloc « ejbca », et pki-cluster.json de ce nœud) et les met en forme dans GET /api/pki (« cluster »). Ici on vérifie les droits, la forme rendue pour un leader, un secondaire, l'arbitre,
// un statut périmé et l'absence de cluster, la suggestion DNS (l'adresse virtuelle d'abord), les blocages (mise à jour interrompue, etcd injoignable), la lecture bornée d'un fichier
// hostile (jamais de contenu chiffré ni de secret relayé) et le refus des écritures sur un secondaire (root le refuse aussi : tests/b40-pki-cluster-live.sh).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3485, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s57-')), GEN = join(TMP, 'gen'), REQ = join(GEN, '.pki-request')
const STATUS = join(TMP, 'ps.json'), RESULT = join(TMP, 'pr.json'), CL = join(TMP, 'cluster-status.json'), PCL = join(TMP, 'pki-cluster.json')
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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 200)) } throw new Error('délai dépassé') }
const NOW = () => Math.floor(Date.now() / 1000)
const SHA = 'a1b2c3d4e5f6'

const setStatus = (o: Record<string, unknown> = {}) => writeFileSync(STATUS, JSON.stringify({ at: NOW(), podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', digest: 'sha256:' + 'a'.repeat(64), nets: [],
  health: 'ALLOK', port: 8080, dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab.test', casCount: 1, resetAllowed: false, recovery: null, ...o }))
const ready = (over: Record<string, unknown> = {}) => ({ role: 'replica', installed: true, unit: 'inactive', image: 'ready', version: '9.6.3', desired: 'running', synced: SHA, blocked: null, at: NOW() - 20, ...over })
const ejbca = (over: Record<string, unknown> = {}) => ({ enabled: true, state: { sha: SHA, by: 'n1', at: NOW() - 60 }, nodes: { n1: ready({ role: 'leader', unit: 'active' }), n2: ready() },
  mark: null, sync: { at: NOW() - 10, state: 'synced', message: 'à jour', hash: SHA }, ...over })
const clusterDoc = (o: { node?: string; role?: string; leader?: string; at?: number; ejbca?: unknown; vip?: unknown } = {}) => ({
  cluster: 'lab', node: o.node ?? 'n1', role: o.role ?? 'data', local_role: (o.leader ?? 'n1') === (o.node ?? 'n1') ? 'leader' : 'replica', at: o.at ?? NOW() - 3, bind: 'primary',
  etcd: { healthy: true, members: 3 },
  peers: [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }],
  patroni: { members: [{ name: 'n1', role: (o.leader ?? 'n1') === 'n1' ? 'leader' : 'replica', state: 'running' }, { name: 'n2', role: (o.leader ?? 'n1') === 'n2' ? 'leader' : 'replica', state: 'streaming', lag: 0 }] },
  vip: o.vip === undefined ? { address: '192.0.2.10/24', iface: 'ens192', held: (o.leader ?? 'n1') === (o.node ?? 'n1') } : o.vip, ejbca: o.ejbca === undefined ? ejbca() : o.ejbca })
const setCluster = (o?: Parameters<typeof clusterDoc>[0]) => writeFileSync(CL, JSON.stringify(clusterDoc(o)))
const setLocal = (o: Record<string, unknown> = {}) => writeFileSync(PCL, JSON.stringify({ at: NOW(), role: 'leader', installed: true, unit: 'active', image: 'ready', desired: 'running', version: '9.6.3', blocked: null, ...o }))
const noCluster = () => { rmSync(CL, { force: true }); rmSync(PCL, { force: true }) }
const sent = () => (existsSync(REQ) ? readFileSync(REQ, 'utf8') : null)
const pki = async () => { const r = await admin.get('/api/pki'); expect(r.status, r.text).toBe(200); return r.json.data ?? r.json }

beforeAll(async () => {
  mkdirSync(GEN, { recursive: true })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT,
    DDI_CLUSTER_STATUS: CL, DDI_PKI_CLUSTER: PCL } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200); expect((await viewer.login('lect', PW)).status).toBe(200)
  setStatus()
}, 300000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('droits', () => {
  it('la page PKI, bloc cluster compris, reste réservée à l\'administrateur', async () => {
    setCluster(); setLocal()
    code(await anon.get('/api/pki'), 401, 'unauthenticated')
    code(await viewer.get('/api/pki'), 403, 'forbidden')
  })
})

describe('hors cluster', () => {
  it('aucun fichier de cluster : « cluster » est nul, la page est celle d\'un nœud seul', async () => {
    noCluster()
    const j = await pki()
    expect(j.cluster).toBeNull()
    expect(j.status.installed).toBe(true)
  })
  it('un fichier pki-cluster.json sans statut de cluster est ignoré (pas de cluster)', async () => {
    noCluster(); setLocal()
    expect((await pki()).cluster).toBeNull()
  })
})

describe('leader', () => {
  it('rend le rôle, l\'état local, les nœuds prêts et l\'adresse virtuelle sans son préfixe', async () => {
    setCluster(); setLocal()
    const c = (await pki()).cluster
    expect(c).toMatchObject({ clustered: true, node: 'n1', nodeRole: 'data', leader: 'n1', vip: { address: '192.0.2.10', held: true } })
    expect(c.stale).toBeUndefined()
    expect(c.local).toMatchObject({ role: 'leader', installed: true, unit: 'active', image: 'ready', desired: 'running', version: '9.6.3', blocked: null, stale: false })
    expect(c.ejbca.enabled).toBe(true)
    expect(c.ejbca.state).toEqual({ sha: SHA, by: 'n1', at: expect.any(Number) })
    expect(Object.keys(c.ejbca.nodes).sort()).toEqual(['n1', 'n2'])
    expect(c.ejbca.nodes.n2).toMatchObject({ role: 'replica', unit: 'inactive', image: 'ready', synced: SHA })
    expect(c.ejbca.sync).toMatchObject({ state: 'synced', hash: SHA })
    expect(c.ejbca.mark).toBeNull()
  })
  it('la suggestion DNS commence par l\'adresse virtuelle (elle suit le leader)', async () => {
    setCluster(); setLocal()
    const d = (await pki()).dns
    expect(d.suggested[0]).toBe('192.0.2.10')
    expect(new Set(d.suggested).size).toBe(d.suggested.length)
  })
  it('sans adresse virtuelle : pas de suggestion forcée, « vip » nul', async () => {
    setCluster({ vip: null }); setLocal()
    const j = await pki()
    expect(j.cluster.vip).toBeNull()
    expect(j.dns.suggested).not.toContain('192.0.2.10')
  })
})

describe('secondaire et arbitre', () => {
  it('un secondaire dit où la PKI tourne et qu\'il est prêt à la reprendre', async () => {
    setCluster({ node: 'n2', leader: 'n1' }); setLocal({ role: 'replica', unit: 'inactive' })
    const c = (await pki()).cluster
    expect(c).toMatchObject({ clustered: true, node: 'n2', nodeRole: 'data', leader: 'n1', vip: { address: '192.0.2.10', held: false } })
    expect(c.local).toMatchObject({ role: 'replica', unit: 'inactive', image: 'ready' })
    expect(c.ejbca.nodes.n2.synced).toBe(SHA)
  })
  it('l\'arbitre n\'a pas de PKI : bloc ejbca nul', async () => {
    setCluster({ node: 'n3', role: 'witness', leader: 'n1', ejbca: null }); rmSync(PCL, { force: true })
    const c = (await pki()).cluster
    expect(c).toMatchObject({ clustered: true, node: 'n3', nodeRole: 'witness', ejbca: null })
  })
})

describe('blocages et périmé', () => {
  it('mise à jour interrompue : la marque est rendue (nœud, versions) et le blocage local aussi', async () => {
    setCluster({ ejbca: ejbca({ mark: { node: 'n1', at: NOW() - 300, from: '9.6.3', to: '9.6.4' } }) })
    setLocal({ blocked: { reason: 'update-interrupted', node: 'n1', at: NOW() - 300, from: '9.6.3', to: '9.6.4' } })
    const c = (await pki()).cluster
    expect(c.ejbca.mark).toEqual({ node: 'n1', at: expect.any(Number), from: '9.6.3', to: '9.6.4' })
    expect(c.local.blocked).toEqual({ reason: 'update-interrupted', node: 'n1', at: expect.any(Number), from: '9.6.3', to: '9.6.4' })
  })
  it('etcd injoignable : « cluster-unreachable »', async () => {
    setCluster(); setLocal({ blocked: { reason: 'cluster-unreachable' } })
    expect((await pki()).cluster.local.blocked).toEqual({ reason: 'cluster-unreachable' })
  })
  it('synchronisation en conflit ou en échec : rendue telle quelle (état, message borné)', async () => {
    setCluster({ ejbca: ejbca({ sync: { at: NOW() - 5, state: 'conflict', message: 'x'.repeat(5000), hash: '' } }) }); setLocal()
    const s = (await pki()).cluster.ejbca.sync
    expect(s.state).toBe('conflict'); expect(s.message.length).toBeLessThanOrEqual(200)
  })
  it('statut du cluster périmé (root ne publie plus) : variante « stale », sans état de PKI', async () => {
    setCluster({ at: NOW() - 3600 }); setLocal()
    const c = (await pki()).cluster
    expect(c).toMatchObject({ clustered: true, stale: true, node: 'n1', leader: null, local: null, ejbca: null, vip: null })
  })
  it('pki-cluster.json périmé (plus de 3 minutes) : marqué « stale » (la page prévient)', async () => {
    setCluster(); setLocal({ at: NOW() - 1000 })
    expect((await pki()).cluster.local.stale).toBe(true)
  })
})

describe('fichiers hostiles', () => {
  it('valeurs piégées : aucune balise, aucun contenu chiffré ni secret ne ressort', async () => {
    setCluster({ ejbca: ejbca({ state: { sha: SHA, by: '<img src=x onerror=1>', at: 'x' }, nodes: { n1: ready({ role: '<script>', unit: 'rm -rf /', synced: 'zz;id' }), evil: ready(), '../x': ready() },
      blob: 'BLOBSECRET', secret: 'topsecret', passphrase: 'phrase' }) })
    setLocal({ role: '<b>', blocked: { reason: 'x; id' }, password: 'topsecret' })
    const r = await admin.get('/api/pki')
    expect(r.status).toBe(200)
    expect(r.text).not.toMatch(/BLOBSECRET|topsecret|phrase|<script|<img|evil|\.\.\/x/)
    const c = (r.json.data ?? r.json).cluster
    expect(Object.keys(c.ejbca.nodes)).toEqual(['n1'])
    expect(c.ejbca.nodes.n1).toMatchObject({ role: 'unknown', unit: 'inactive', synced: '' })
    expect(c.local).toMatchObject({ role: 'unknown', blocked: null })
  })
  it('fichiers énormes ou illisibles : ignorés sans erreur', async () => {
    writeFileSync(CL, 'x'.repeat(300 * 1024)); writeFileSync(PCL, 'pas du json')
    expect((await pki()).cluster).toBeNull()
    writeFileSync(CL, JSON.stringify(clusterDoc())); writeFileSync(PCL, '[]')
    const c = (await pki()).cluster
    expect(c.clustered).toBe(true); expect(c.local).toBeNull()
  })
})

describe('écritures', () => {
  it('la console dépose la demande telle quelle sur un secondaire aussi (c\'est root qui la refuse : tests/b40-pki-cluster-live.sh) et n\'écrit aucun fichier de cluster', async () => {
    setCluster({ node: 'n2', leader: 'n1' }); setLocal({ role: 'replica' })
    const before = readFileSync(PCL, 'utf8'), beforeCl = readFileSync(CL, 'utf8')
    rmSync(REQ, { force: true }); rmSync(RESULT, { force: true })
    const r = await admin.post('/api/pki/stop', {})
    expect(r.status, r.text).toBe(200)
    expect(JSON.parse(sent() ?? '{}')).toEqual({ action: 'stop' })
    expect(readFileSync(PCL, 'utf8')).toBe(before); expect(readFileSync(CL, 'utf8')).toBe(beforeCl)
    rmSync(REQ, { force: true })
    expect(srvLog).not.toMatch(/TypeError|Unhandled|unhandledRejection/)
  })
})
