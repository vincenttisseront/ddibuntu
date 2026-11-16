// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.13.0 — accès réseau RADIUS (itération 1) : clients (secret chiffré, montré une seule fois),
// demande déposée pour root (fichier de clients + déclencheur), état publié par root, test d'Access-Request contre un serveur de référence.
import { createHash, createHmac } from 'node:crypto'
import { createSocket, type Socket } from 'node:dgram'
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { selftestSecret } from '../server/utils/radius'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3439, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s38-')); mkdirSync(join(TMP, 'gen'))
const GEN = join(TMP, 'gen'), REQ = join(GEN, '.radius-request'), CONF = join(GEN, 'radius-clients.conf'), STATUS = join(TMP, 'rs.json'), RESULT = join(TMP, 'rr.json')
let srv: ChildProcess, db: pg.Client, srvLog = '', fake: Socket, fakePort = 0, fakeMode: 'reject' | 'silent' = 'reject'

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

// serveur RADIUS de référence : ne répond (Access-Reject authentique, RFC 2865 / 3579) que si le Message-Authenticator est signé avec le secret du client d'essai
function startFake() {
  return new Promise<void>((resolve) => {
    fake = createSocket('udp4')
    fake.on('message', (m, r) => {
      if (fakeMode === 'silent') return
      const secret = selftestSecret()
      const tmp = Buffer.from(m); tmp.fill(0, m.length - 16)
      if (!createHmac('md5', secret).update(tmp).digest().equals(m.subarray(m.length - 16))) return
      const body = Buffer.concat([Buffer.from([80, 18]), Buffer.alloc(16)])
      const head = Buffer.alloc(20); head[0] = 3; head[1] = m[1]!; head.writeUInt16BE(20 + body.length, 2); m.subarray(4, 20).copy(head, 4)
      createHmac('md5', secret).update(Buffer.concat([head, body])).digest().copy(body, 2)
      const pkt = Buffer.concat([head, body])
      createHash('md5').update(Buffer.concat([pkt.subarray(0, 4), m.subarray(4, 20), pkt.subarray(20), Buffer.from(secret)])).digest().copy(pkt, 4)
      fake.send(pkt, r.port, r.address)
    })
    fake.bind(0, '127.0.0.1', () => { fakePort = fake.address().port; resolve() })
  })
}

beforeAll(async () => {
  await startFake()
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_RADIUS_STATUS: STATUS, DDI_RADIUS_RESULT: RESULT, DDI_RADIUS_PORT: String(fakePort) } })
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
afterAll(async () => { srv?.kill('SIGTERM'); fake?.close(); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
let wifiId = 0, wifiSecret = ''

describe('RADIUS — clients', () => {
  it('lecture ouverte à tous les rôles connectés, écriture réservée à l\'administrateur', async () => {
    code(await anon.get('/api/radius'), 401, 'unauthenticated')
    const r = await viewer.get('/api/radius'); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ status: null, result: null, requestPending: false, clients: 0, enabledClients: 0 })
    expect((await viewer.get('/api/radius/clients')).status).toBe(200)
    for (const c of [viewer, oper]) {
      code(await c.post('/api/radius/clients', { name: 'x1', address: '10.1.0.1' }), 403, 'forbidden')
      code(await c.post('/api/radius/apply'), 403, 'forbidden'); code(await c.post('/api/radius/stop'), 403, 'forbidden'); code(await c.post('/api/radius/test'), 403, 'forbidden')
    }
  })
  it('validation : nom réservé ou invalide, adresse refusée, secret hors alphabet ou trop court, champ inconnu', async () => {
    const ok = { name: 'wlc-01', address: '10.10.0.0/24', usage: 'wifi' }
    for (const bad of [{ name: 'ddi-selftest' }, { name: '1abc' }, { name: 'a b' }, { name: '' }, { address: '127.0.0.1' }, { address: '10.0.0.0/8' }, { address: '169.254.1.1' }, { address: '224.0.0.1' }, { address: '::1' }, { address: 'fe80::1' }, { address: 'pas-une-adresse' }, { address: '2001:db8::/32' },
      { usage: 'telnet' }, { secret: 'trop-court' }, { secret: 'a'.repeat(129) }, { secret: 'avec "guillemets" dans le secret 123' }, { secret: 'avec\nsaut-de-ligne-1234567' }, { extra: 1 }]) {
      const r = await admin.post('/api/radius/clients', { ...ok, ...bad }); expect([r.status, JSON.stringify(bad)], r.text).toEqual([400, JSON.stringify(bad)])
    }
    expect(await rows('select count(*)::int as n from radius_clients')).toEqual([{ n: 0 }])
  })
  it('création : secret généré montré une seule fois, chiffré en base, jamais renvoyé ensuite', async () => {
    const r = await admin.post('/api/radius/clients', { name: 'WLC-01', address: '10.10.0.0/24', usage: 'wifi', comment: 'contrôleur Wi-Fi' }); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ name: 'wlc-01' }); wifiId = r.json.id; wifiSecret = r.json.secret
    expect(wifiSecret).toMatch(/^[A-Za-z0-9]{32}$/)
    const [row] = await rows('select address::text as address, secret_enc, usage, enabled from radius_clients where id=$1', [wifiId])
    expect(row).toMatchObject({ address: '10.10.0.0/24', usage: 'wifi', enabled: true })
    expect(row.secret_enc).not.toContain(wifiSecret)
    for (const path of ['/api/radius/clients', '/api/radius']) expect((await admin.get(path)).text, path).not.toContain(wifiSecret)
    const list = (await viewer.get('/api/radius/clients')).json.items; expect(list).toHaveLength(1)
    expect(Object.keys(list[0]).sort()).toEqual(['address', 'comment', 'created_at', 'enabled', 'id', 'name', 'updated_at', 'usage'])
    const aud = await rows("select detail from audit_log where action='radius_client_create'"); expect(JSON.stringify(aud)).not.toContain(wifiSecret)
  })
  it('création avec un secret choisi : il n\'est pas renvoyé ; adresse seule normalisée ; doublons refusés', async () => {
    const mine = 'MonSecretPartage-2024.xyz'
    const r = await admin.post('/api/radius/clients', { name: 'vpn-gw', address: '192.0.2.7', usage: 'vpn', secret: mine }); expect(r.status, r.text).toBe(200)
    expect(r.json.secret).toBeNull()
    expect((await rows('select address::text as a from radius_clients where name=$1', ['vpn-gw']))[0].a).toBe('192.0.2.7/32')
    expect((await admin.post('/api/radius/clients', { name: 'vpn-gw', address: '192.0.2.8' })).status).toBeGreaterThanOrEqual(409)
    expect((await admin.post('/api/radius/clients', { name: 'autre', address: '192.0.2.7/32' })).status).toBeGreaterThanOrEqual(409)
    expect((await rows('select count(*)::int as n from radius_clients'))[0].n).toBe(2)
  })
  it('modification : le secret est conservé s\'il n\'est pas fourni, remplacé sinon ; régénération', async () => {
    const before = (await rows('select secret_enc from radius_clients where id=$1', [wifiId]))[0].secret_enc
    expect((await admin.put(`/api/radius/clients/${wifiId}`, { name: 'wlc-01', address: '10.10.0.0/24', usage: 'wifi', enabled: true, comment: 'modifié' })).status).toBe(200)
    expect((await rows('select secret_enc, comment from radius_clients where id=$1', [wifiId]))[0]).toEqual({ secret_enc: before, comment: 'modifié' })
    expect((await admin.put(`/api/radius/clients/${wifiId}`, { name: 'wlc-01', address: '10.10.0.0/24', usage: 'wifi', secret: 'NouveauSecret-Choisi-123' })).status).toBe(200)
    const mid = (await rows('select secret_enc from radius_clients where id=$1', [wifiId]))[0].secret_enc; expect(mid).not.toBe(before)
    const g = await admin.post(`/api/radius/clients/${wifiId}/secret`); expect(g.status, g.text).toBe(200)
    expect(g.json.secret).toMatch(/^[A-Za-z0-9]{32}$/); wifiSecret = g.json.secret
    expect((await rows('select secret_enc from radius_clients where id=$1', [wifiId]))[0].secret_enc).not.toBe(mid)
    code(await admin.post('/api/radius/clients/99999/secret'), 404, 'not_found'); code(await admin.put('/api/radius/clients/99999', { name: 'zz', address: '10.9.0.1' }), 404, 'not_found')
    code(await admin.delete('/api/radius/clients/99999'), 404, 'not_found')
  })
})

describe('RADIUS — demande pour root', () => {
  it('déploiement : fichier de clients (client d\'essai + clients actifs) puis déclencheur ; une seule demande à la fois', async () => {
    const dis = await admin.post('/api/radius/clients', { name: 'sw-coeur', address: '10.50.0.1', usage: 'switch', enabled: false }); expect(dis.status).toBe(200)
    const r = await admin.post('/api/radius/apply'); expect(r.status, r.text).toBe(200); expect(r.json.accepted).toBe(true)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'apply' })
    expect(statSync(CONF).mode & 0o777).toBe(0o640)
    const conf = readFileSync(CONF, 'utf8')
    expect(conf).toContain('client "ddi-selftest"'); expect(conf).toContain(`secret = "${selftestSecret()}"`)
    expect(conf).toContain('client "wlc-01"'); expect(conf).toContain('ipaddr = 10.10.0.0/24'); expect(conf).toContain(`secret = "${wifiSecret}"`)
    expect(conf).toContain('client "vpn-gw"'); expect(conf).toContain('ipaddr = 192.0.2.7\n'); expect(conf).toContain('secret = "MonSecretPartage-2024.xyz"')
    expect(conf).not.toContain('sw-coeur')
    expect(conf.match(/^client "/gm)).toHaveLength(3)
    expect((await admin.get('/api/radius')).json).toMatchObject({ requestPending: true, clients: 3, enabledClients: 2 })
    code(await admin.post('/api/radius/apply'), 409, 'request_pending'); code(await admin.post('/api/radius/stop'), 409, 'request_pending')
    rmSync(REQ); rmSync(CONF)   // root a traité la demande
    expect((await admin.get('/api/radius')).json.requestPending).toBe(false)
  })
  it('arrêt : demande sans fichier de clients', async () => {
    const r = await admin.post('/api/radius/stop'); expect(r.status, r.text).toBe(200)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'stop' }); expect(existsSync(CONF)).toBe(false); rmSync(REQ)
  })
  it('l\'état et le résultat publiés par root sont relayés tels quels', async () => {
    writeFileSync(STATUS, JSON.stringify({ at: 1700000000, installed: true, version: '3.2.5', configured: true, active: true, enabled: true, clients: 2, ports: [1812, 1813] }))
    writeFileSync(RESULT, JSON.stringify({ at: 1700000001, action: 'apply', ok: true, message: 'service démarré (2 clients)' }))
    const r = (await viewer.get('/api/radius')).json
    expect(r.status).toMatchObject({ installed: true, version: '3.2.5', active: true, clients: 2 }); expect(r.result).toMatchObject({ ok: true, action: 'apply' })
    writeFileSync(STATUS, 'pas du json'); expect((await viewer.get('/api/radius')).json.status).toBeNull()
  })
})

describe('RADIUS — test d\'Access-Request', () => {
  it('service non démarré : refusé sans émettre de paquet', async () => {
    writeFileSync(STATUS, JSON.stringify({ at: 1700000000, installed: true, version: '3.2.5', configured: true, active: false, enabled: true, clients: 2 }))
    code(await admin.post('/api/radius/test'), 409, 'radius_not_running')
  })
  it('service actif : refus authentique reconnu ; serveur muet : délai dépassé', async () => {
    writeFileSync(STATUS, JSON.stringify({ at: 1700000000, installed: true, version: '3.2.5', configured: true, active: true, enabled: true, clients: 2 }))
    fakeMode = 'reject'
    const r = await admin.post('/api/radius/test'); expect(r.status, r.text).toBe(200); expect(r.json).toMatchObject({ ok: true, reply: 'reject' })
    fakeMode = 'silent'
    const t = await admin.post('/api/radius/test'); expect(t.status, t.text).toBe(200); expect(t.json).toMatchObject({ ok: false, error: 'timeout' })
    fakeMode = 'reject'
    const aud = await rows("select detail from audit_log where action='radius.test' order by id"); expect(aud).toHaveLength(2)
  }, 30000)
})

describe('RADIUS — suppression et traçabilité', () => {
  it('suppression ; chaque action est journalisée sans secret', async () => {
    expect((await admin.delete(`/api/radius/clients/${wifiId}`)).status).toBe(200)
    expect((await rows('select count(*)::int as n from radius_clients where id=$1', [wifiId]))[0].n).toBe(0)
    const actions = (await rows("select action from audit_log where action like 'radius%' order by id")).map((r) => r.action)
    for (const a of ['radius_client_create', 'radius_client_update', 'radius_client_secret', 'radius_client_delete', 'radius.apply', 'radius.stop', 'radius.test']) expect(actions, a).toContain(a)
    const all = JSON.stringify(await rows("select detail from audit_log where action like 'radius%'"))
    for (const s of [wifiSecret, 'MonSecretPartage-2024.xyz', 'NouveauSecret-Choisi-123', selftestSecret()]) expect(all).not.toContain(s)
  })
})
