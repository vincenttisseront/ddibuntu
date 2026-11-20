// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.17.0 — second facteur (MFA) des clients RADIUS : réglages du fournisseur, drapeau « MFA » des clients, longueur du secret,
// refus de déployer sans règle ni fournisseur, test de joignabilité, secrets jamais renvoyés ni journalisés. Le côté root est vérifié contre un vrai FreeRADIUS par tests/b42.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3489, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s61-')), GEN = join(TMP, 'gen'), CL = join(TMP, 'cluster-status.json'), ST = join(TMP, 'radius-status.json'), RES = join(TMP, 'radius-result.json'), REQ = join(GEN, '.radius-request')
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
const SECRET = 'Provider-Secret_0123.~abc'
const prov = (over: Record<string, unknown> = {}) => ({ type: 'oauth2_password', tokenUrl: 'https://127.0.0.1:9/realms/corp/protocol/openid-connect/token', clientId: 'ddi-radius', clientSecret: SECRET,
  fields: { identity: 'username', password: 'password', otp: 'totp' }, identity: 'typed', otpDigits: 6, extra: [], timeoutSec: 2, tlsVerify: true, caPem: '', ...over })
const put = (b: unknown, c = admin) => c.req('PUT', '/api/radius/mfa', b)
const client = (over: Record<string, unknown> = {}) => ({ name: 'fw-vpn', address: '10.20.0.2', usage: 'vpn', enabled: true, mfa: true, ...over })

describe('second facteur — fournisseur', () => {
  it('par défaut : aucun fournisseur, aucun client MFA ; réservé à l\'administrateur', async () => {
    const r = await admin.get('/api/radius/mfa'); expect(r.status, r.text).toBe(200)
    expect(body(r)).toMatchObject({ type: 'oauth2_password', tokenUrl: '', clientId: '', clientSecretSet: false, otpDigits: 6, tlsVerify: true, clients: [] })
    expect((await viewer.get('/api/radius/mfa')).status).toBe(403); expect((await put(prov(), viewer)).status).toBe(403); expect((await viewer.post('/api/radius/mfa/test')).status).toBe(403)
  })
  it('enregistrement : relu sans le secret, secret chiffré en base, absent du journal d\'audit', async () => {
    expect((await put(prov())).status).toBe(200)
    const r = body(await admin.get('/api/radius/mfa'))
    expect(r).toMatchObject({ clientId: 'ddi-radius', clientSecretSet: true, fields: { identity: 'username', password: 'password', otp: 'totp' } })
    expect(JSON.stringify(r)).not.toContain(SECRET)
    expect(JSON.stringify(await rows("select value from settings where key = 'radius_mfa'"))).not.toContain(SECRET)
    expect(JSON.stringify(await rows('select detail from audit_log'))).not.toContain(SECRET)
    expect(srvLog).not.toContain(SECRET)
  })
  it('secret absent = conservé ; chaîne vide = supprimé ; nouveau = remplacé', async () => {
    const { clientSecret: _s, ...sans } = prov({ clientId: 'ddi-radius2' }); expect((await put(sans)).status).toBe(200)
    expect(body(await admin.get('/api/radius/mfa'))).toMatchObject({ clientId: 'ddi-radius2', clientSecretSet: true })
    expect((await put(prov({ clientSecret: '' }))).status).toBe(200); expect(body(await admin.get('/api/radius/mfa')).clientSecretSet).toBe(false)
    expect((await put(prov())).status).toBe(200); expect(body(await admin.get('/api/radius/mfa')).clientSecretSet).toBe(true)
  })
  it('refus : HTTP clair, champs en double ou réservés, paramètre réservé, chiffres du code, délai, champ inconnu', async () => {
    for (const bad of [{ tokenUrl: 'http://sso.example.local/t' }, { fields: { identity: 'u', password: 'u', otp: 't' } }, { fields: { identity: 'client_secret', password: 'p', otp: 't' } },
      { extra: [{ name: 'grant_type', value: 'x' }] }, { extra: [{ name: 'a', value: '%{x}' }] }, { otpDigits: 5 }, { timeoutSec: 60 }, { clientId: 'a b' }, { x: 1 }])
      expect((await put(prov(bad))).status, JSON.stringify(bad)).toBe(400)
  })
  it('test de joignabilité : non configuré, puis injoignable (aucun compte réel utilisé)', async () => {
    expect((await put(prov({ tokenUrl: '', clientId: '', clientSecret: '' }))).status).toBe(200)
    expect(body(await admin.post('/api/radius/mfa/test'))).toMatchObject({ ok: false, reason: 'not_configured' })
    expect((await put(prov())).status).toBe(200)
    expect(body(await admin.post('/api/radius/mfa/test'))).toMatchObject({ ok: false, reason: expect.stringMatching(/^(unreachable|timeout)$/) })
    expect(JSON.stringify(await rows("select detail from audit_log where action = 'radius.mfa_test'"))).not.toContain(SECRET)
  })
})

describe('second facteur — clients', () => {
  it('un client MFA sans secret en reçoit un de 40 caractères ; un secret trop court est refusé', async () => {
    code(await admin.post('/api/radius/clients', client({ secret: 'x'.repeat(31) })), 400, 'radius_mfa_secret_short')
    const r = await admin.post('/api/radius/clients', client()); expect(r.status, r.text).toBe(200)
    expect(String(r.json.secret ?? r.json.data?.secret)).toHaveLength(40)
    const list = await admin.get('/api/radius/clients'); const row = (list.json.items ?? body(list).items).find((c: any) => c.name === 'fw-vpn'); expect(row.mfa).toBe(true)
  })
  it('un client sans MFA garde un secret de 32 caractères ; le drapeau est faux par défaut', async () => {
    const r = await admin.post('/api/radius/clients', { name: 'wifi', address: '10.20.0.3', usage: 'wifi', enabled: true }); expect(r.status, r.text).toBe(200)
    expect(String(r.json.secret ?? r.json.data?.secret)).toHaveLength(32)
    expect((await rows("select mfa from radius_clients where name = 'wifi'"))[0].mfa).toBe(false)
  })
  it('modification : activer MFA exige un secret d\'au moins 32 caractères (le secret actuel compte)', async () => {
    const id = (await rows("select id from radius_clients where name = 'wifi'"))[0].id
    await db.query('update radius_clients set secret_enc = $1 where id = $2', [(await rows("select secret_enc from radius_clients where name = 'wifi'"))[0].secret_enc, id])
    const short = await admin.req('PUT', `/api/radius/clients/${id}`, { name: 'wifi', address: '10.20.0.3', usage: 'wifi', enabled: true, mfa: true, secret: 'courtcourtcourt1' }); code(short, 400, 'radius_mfa_secret_short')
    expect((await rows("select mfa from radius_clients where name = 'wifi'"))[0].mfa).toBe(false)
    expect((await admin.req('PUT', `/api/radius/clients/${id}`, { name: 'wifi', address: '10.20.0.3', usage: 'wifi', enabled: true, mfa: true, secret: 'L'.repeat(40) })).status).toBe(200)
    expect((await admin.req('PUT', `/api/radius/clients/${id}`, { name: 'wifi', address: '10.20.0.3', usage: 'wifi', enabled: true, mfa: false })).status).toBe(200)
  })
  it('la lecture publique de l\'état compte les clients MFA et la liste du réglage les nomme', async () => {
    expect(body(await admin.get('/api/radius/mfa')).clients).toEqual(['fw-vpn'])
  })
})

describe('second facteur — déploiement', () => {
  it('client MFA actif mais aucune règle d\'accès : refusé, rien n\'est déposé', async () => {
    setStatus(false)
    const r = await admin.post('/api/radius/apply'); code(r, 409, 'radius_authz_not_ready')
    expect(body(r).problems).toEqual(['mfa_needs_rules']); expect(sent()).toBeNull()
  })
  it('sans client MFA actif, « Déployer » redevient possible et le service garde son comportement', async () => {
    await db.query("update radius_clients set enabled = false where name = 'fw-vpn'")
    expect((await admin.post('/api/radius/apply')).status).toBe(200); rootAnswers(true)
    expect(existsSync(join(GEN, 'radius-authz', 'mfa.json'))).toBe(false)
    expect(readFileSync(join(GEN, 'radius-clients.conf'), 'utf8')).not.toContain('virtual_server')
  })
})

describe('ce qui attend un déploiement', () => {
  const deploy = async () => (await radius()).deploy
  const rootDone = async () => { rootAnswers(true); await new Promise((r) => setTimeout(r, 1300)) }   // la réponse de root est datée une seconde plus tard : on attend qu'elle soit passée
  it('juste après un déploiement : rien en attente', async () => {
    expect(await deploy()).toEqual({ pending: false, parts: [], never: false })
  })
  it('un client ajouté, modifié ou supprimé est « à déployer » ; revenir à l\'état déployé efface l\'attente', async () => {
    const r = await admin.post('/api/radius/clients', { name: 'sw1', address: '10.20.0.9', usage: 'switch', enabled: true }); expect(r.status, r.text).toBe(200)
    expect(await deploy()).toEqual({ pending: true, parts: ['clients'], never: false })
    const id = (await rows("select id from radius_clients where name = 'sw1'"))[0].id
    expect((await admin.del(`/api/radius/clients/${id}`)).status).toBe(200)
    expect(await deploy()).toEqual({ pending: false, parts: [], never: false })   // supprimé : l'état redevient celui qui tourne
  })
  it('un commentaire ne change rien ; désactiver, l\'adresse ou le secret oui', async () => {
    await new Promise((r) => setTimeout(r, 1300))   // la réponse précédente de root est datée de la seconde en cours : une réponse identique ne serait pas distinguée de l'ancienne
    const c = await admin.post('/api/radius/clients', { name: 'sw2', address: '10.20.0.10', usage: 'switch', enabled: true }); expect(c.status).toBe(200)
    expect((await admin.post('/api/radius/apply')).status).toBe(200); await rootDone(); expect((await deploy()).pending).toBe(false)
    const id = (await rows("select id from radius_clients where name = 'sw2'"))[0].id
    const put = (over: Record<string, unknown>) => admin.req('PUT', `/api/radius/clients/${id}`, { name: 'sw2', address: '10.20.0.10', usage: 'switch', enabled: true, mfa: false, ...over })
    expect((await put({ comment: 'sans effet sur le service' })).status).toBe(200); expect((await deploy()).pending).toBe(false)
    expect((await put({ enabled: false })).status).toBe(200); expect((await deploy()).parts).toEqual(['clients'])
    expect((await put({ enabled: true })).status).toBe(200); expect((await deploy()).pending).toBe(false)
    expect((await put({ address: '10.20.0.11' })).status).toBe(200); expect((await deploy()).parts).toEqual(['clients'])
    expect((await put({ address: '10.20.0.10' })).status).toBe(200); expect((await deploy()).pending).toBe(false)
    expect((await admin.post(`/api/radius/clients/${id}/secret`, {})).status).toBe(200); expect((await deploy()).parts).toEqual(['clients'])
  })
  it('« Déployer » accepté par root : plus rien en attente ; le résumé ne contient aucun secret', async () => {
    const ap = await admin.post('/api/radius/apply'); expect([ap.status, ap.json?.data?.code], ap.text).toEqual([200, undefined]); await rootDone()
    expect(await deploy()).toEqual({ pending: false, parts: [], never: false })
    expect(JSON.stringify(await rows("select value from settings where key = 'radius_deploy_pushed'"))).toMatch(/[0-9a-f]{64}/)
  })
  it('lecture seule : un lecteur voit l\'état (la bannière est la même), sans pouvoir déployer', async () => {
    expect((await viewer.get('/api/radius')).status).toBe(200); expect((await viewer.post('/api/radius/apply')).status).toBe(403)
  })
})
