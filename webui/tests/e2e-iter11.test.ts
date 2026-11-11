// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : réglages du cluster 0.9.2 — adresse virtuelle, réseau dédié, certificat, adresse du nœud.
import { spawn, type ChildProcess } from 'node:child_process'
import { hostname } from 'node:os'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3400, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s11-')); mkdirSync(join(TMP, 'gen'))
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

const settings = (over: Record<string, unknown> = {}) => ({ published: { rev: 3, vip: '192.0.2.10/24', vrid: 77, iface: 'lo', net: '10.9.0.0/24' }, applied: { rev: 3, vip: '192.0.2.10/24', vrid: 77, iface: 'lo', net: '10.9.0.0/24' }, ...over })
const pki = (over: Record<string, unknown> = {}) => ({ node: { notAfter: 1_900_000_000, daysLeft: 400, serial: 'AB12CD' }, ca: { notAfter: 2_100_000_000, daysLeft: 3000 }, renewDays: 60, pending: false, ...over })
const withSettings = (o: Record<string, unknown> = {}) => publish({ settings: settings(), pki: pki(), vip: { address: '192.0.2.10/24', iface: 'lo', held: false }, ...o })
const post = (b: unknown) => admin.post('/api/cluster/action', b)

describe('état : réglages communs et certificat', () => {
  it('relayés, assainis, lisibles par un lecteur ; interfaces de ce serveur fournies aux formulaires', async () => {
    withSettings(); const r = (await viewer.get('/api/cluster/status')).json
    expect(r.state.settings.applied).toMatchObject({ rev: 3, vip: '192.0.2.10/24', vrid: 77, iface: 'lo', net: '10.9.0.0/24' })
    expect(r.state.pki).toMatchObject({ node: { daysLeft: 400, serial: 'AB12CD' }, ca: { daysLeft: 3000 }, renewDays: 60, pending: false })
    expect(r.local.addresses.some((a: any) => a.iface === 'lo' && a.address === '127.0.0.1')).toBe(true)
    publish({ settings: { applied: { rev: 'x', vrid: 9999, vip: 5 }, secret: 'zz' }, pki: { node: { daysLeft: 'beaucoup' }, ca: {} } })
    const h = (await viewer.get('/api/cluster/status')).json.state
    expect(JSON.stringify(h)).not.toContain('zz'); expect(h.settings.applied).toMatchObject({ rev: 0, vrid: 51, vip: null })
  })
  it('ancien nœud sans ces blocs : null, la page reste utilisable', async () => {
    publish(); const r = (await viewer.get('/api/cluster/status')).json
    expect([r.state.settings, r.state.pki]).toEqual([null, null])
  })
})

describe('adresse virtuelle', () => {
  const vip = (o: Record<string, unknown> = {}) => ({ action: 'set-vip', vip: '192.0.2.50/24', iface: 'lo', confirm: 'lab', ...o })
  it('droits et validation stricte', async () => {
    clear(); withSettings()
    code(await viewer.post('/api/cluster/action', vip()), 403, 'forbidden'); code(await anon.post('/api/cluster/action', vip()), 401, 'unauthenticated')
    for (const bad of [vip({ vip: '192.0.2.50' }), vip({ vip: '192.0.2.50/33' }), vip({ vip: '999.0.2.50/24' }), vip({ vip: '192.0.2.50/24; reboot' }), vip({ iface: 'ens18; x' }), vip({ iface: 'Eth0' }), vip({ vrid: 0 }), vip({ vrid: 256 }), vip({ vrid: '5' }), vip({ vrid: 1.5 }),
      vip({ extra: 1 }), { action: 'set-vip', iface: 'lo', confirm: 'lab' }, { action: 'set-vip', vip: '192.0.2.50/24', confirm: 'lab' }, { action: 'clear-vip' }, { action: 'clear-vip', confirm: 'lab', vip: '1.2.3.4/24' }, { action: 'vip-iface' }, { action: 'vip-iface', iface: 'lo', confirm: 'lab' }])
      code(await post(bad), 400, 'validation')
    expect(existsSync(ACT)).toBe(false)
  })
  it('refus : confirmation, adresse d\'un nœud, quorum, état périmé, nœud arbitre, interface inconnue', async () => {
    withSettings()
    code(await post(vip({ confirm: 'autre' })), 409, 'confirm_mismatch')
    code(await post(vip({ vip: '10.9.0.3/24' })), 409, 'vip_is_node')
    code(await post(vip({ iface: 'ens999' })), 409, 'iface_unknown')
    withSettings({ at: Math.floor(Date.now() / 1000) - 900 }); code(await post(vip()), 409, 'quorum_required')
    withSettings({ etcd: { healthy: false, members: 3, quorum: quorum({ hasQuorum: false, healthy: 1, tolerance: -1 }) } }); code(await post(vip()), 409, 'quorum_required')
    withSettings({ role: 'witness' }); code(await post(vip()), 409, 'action_data_node_only')
    expect(existsSync(ACT)).toBe(false)
  })
  it('demande déposée telle que validée (VRID facultatif), une seule à la fois', async () => {
    clear(); withSettings()
    expect((await post(vip({ vrid: 77 }))).json).toEqual({ accepted: true })
    expect(sent()).toEqual({ action: 'set-vip', vip: '192.0.2.50/24', iface: 'lo', vrid: 77, confirm: 'lab' })
    code(await post(vip()), 409, 'action_pending'); clear()
    expect((await post(vip())).status).toBe(200); expect(sent()).toEqual({ action: 'set-vip', vip: '192.0.2.50/24', iface: 'lo', confirm: 'lab' }); clear()
  })
  it('retrait de l\'adresse et interface de ce nœud', async () => {
    clear(); withSettings({ vip: null })
    code(await post({ action: 'clear-vip', confirm: 'lab' }), 409, 'no_vip'); code(await post({ action: 'vip-iface', iface: 'lo' }), 409, 'no_vip')
    withSettings()
    code(await post({ action: 'clear-vip', confirm: 'x' }), 409, 'confirm_mismatch'); code(await post({ action: 'vip-iface', iface: 'ens999' }), 409, 'iface_unknown')
    expect((await post({ action: 'vip-iface', iface: 'lo' })).status).toBe(200); expect(sent()).toEqual({ action: 'vip-iface', iface: 'lo' }); clear()
    expect((await post({ action: 'clear-vip', confirm: 'lab' })).status).toBe(200); expect(sent()).toEqual({ action: 'clear-vip', confirm: 'lab' }); clear()
  })
})

describe('réseau dédié', () => {
  const net = (o: Record<string, unknown> = {}) => ({ action: 'set-net', net: '10.9.0.0/16', confirm: 'lab', ...o })
  it('validation et refus : le réseau doit englober tous les nœuds', async () => {
    clear(); withSettings()
    for (const bad of [net({ net: '10.9.0.0' }), net({ net: '10.9.0.0/33' }), net({ net: '10.9.0.0/16;x' }), net({ extra: 1 }), { action: 'set-net', confirm: 'lab' }]) code(await post(bad), 400, 'validation')
    code(await post(net({ confirm: 'x' })), 409, 'confirm_mismatch')
    code(await post(net({ net: '10.8.0.0/16' })), 409, 'nodes_outside_net')
    code(await post(net({ net: '10.9.0.0/31' })), 409, 'nodes_outside_net')
    withSettings({ at: Math.floor(Date.now() / 1000) - 900 }); code(await post(net()), 409, 'quorum_required')
    expect(existsSync(ACT)).toBe(false)
  })
  it('demande déposée', async () => {
    clear(); withSettings(); expect((await post(net())).status).toBe(200); expect(sent()).toEqual({ action: 'set-net', net: '10.9.0.0/16', confirm: 'lab' }); clear()
  })
})

describe('renouvellement du certificat', () => {
  it('droits, demande unique, refus tant qu\'une demande est en cours', async () => {
    clear(); withSettings()
    code(await viewer.post('/api/cluster/action', { action: 'renew-cert' }), 403, 'forbidden')
    code(await post({ action: 'renew-cert', confirm: 'lab' }), 400, 'validation')
    expect((await post({ action: 'renew-cert' })).status).toBe(200); expect(sent()).toEqual({ action: 'renew-cert' }); clear()
    withSettings({ pki: pki({ pending: true }) }); code(await post({ action: 'renew-cert' }), 409, 'renew_pending')
    expect(existsSync(ACT)).toBe(false)
  })
})

describe('adresse du nœud', () => {
  const ip = (o: Record<string, unknown> = {}) => ({ action: 'change-ip', ip: '127.0.0.1', confirm: 'n2', ...o })
  const inLo = (o: Record<string, unknown> = {}) => withSettings({ settings: settings({ applied: { rev: 3, vip: null, vrid: 51, iface: null, net: '127.0.0.0/8' } }), ...o })
  it('validation stricte', async () => {
    clear(); inLo()
    for (const bad of [ip({ ip: '127.0.0' }), ip({ ip: '300.0.0.1' }), ip({ ip: '127.0.0.1;reboot' }), ip({ ip: '10.9.0.2/24' }), ip({ extra: 1 }), { action: 'change-ip', confirm: 'n2' }, { action: 'change-ip', ip: '127.0.0.1' }]) code(await post(bad), 400, 'validation')
    code(await viewer.post('/api/cluster/action', ip()), 403, 'forbidden')
    expect(existsSync(ACT)).toBe(false)
  })
  it('refus : confirmation, même adresse, adresse prise, hors réseau, primaire, quorum sans marge, adresse non portée', async () => {
    inLo()
    code(await post(ip({ confirm: 'n1' })), 409, 'confirm_mismatch')
    code(await post(ip({ ip: '10.9.0.2' })), 409, 'same_ip')
    code(await post(ip({ ip: '10.9.0.1' })), 409, 'node_ip_taken')
    code(await post(ip({ ip: '10.5.5.5' })), 409, 'ip_outside_net')
    code(await post(ip({ ip: '127.9.9.9' })), 409, 'ip_not_local')
    inLo({ local_role: 'leader' }); code(await post(ip()), 409, 'is_leader')
    inLo({ etcd: { healthy: true, members: 3, quorum: quorum({ healthy: 2, members: [member('n1', true, { isLeader: true }), member('n2'), member('n3', false)] }) } }); code(await post(ip()), 409, 'quorum_margin_required')
    inLo({ etcd: { healthy: false, members: 3, quorum: quorum({ hasQuorum: false, healthy: 1, tolerance: -1 }) } }); code(await post(ip()), 409, 'quorum_required')
    inLo({ role: 'witness' }); code(await post(ip()), 409, 'action_data_node_only')
    expect(existsSync(ACT)).toBe(false)
  })
  it('demande déposée et journalisée', async () => {
    clear(); inLo(); expect((await post(ip())).json).toEqual({ accepted: true }); expect(sent()).toEqual({ action: 'change-ip', ip: '127.0.0.1', confirm: 'n2' }); clear()
    const rows = await db.query("select distinct action from audit_log where action like 'cluster.%'")
    expect(rows.rows.map((x: any) => x.action)).toEqual(expect.arrayContaining(['cluster.change-ip', 'cluster.set-vip', 'cluster.set-net', 'cluster.renew-cert']))
  })
  it('chaque nouveau code d\'erreur et chaque texte de l\'écran a sa traduction FR et EN', async () => {
    const fr = (await import('../app/i18n/fr')).default as any, en = (await import('../app/i18n/en')).default as any
    for (const c of ['vip_is_node', 'no_vip', 'nodes_outside_net', 'renew_pending', 'same_ip', 'ip_outside_net', 'is_leader', 'quorum_margin_required', 'iface_unknown', 'ip_not_local', 'node_ip_taken']) { expect(fr[`err.${c}`], c).toBeTruthy(); expect(en[`err.${c}`], c).toBeTruthy() }
    const keys = Object.keys(fr).filter((k) => /^cluster\.(set|pki|ip)\./.test(k)); expect(keys.length).toBeGreaterThan(40)
    for (const k of keys) expect(en[k], k).toBeTruthy()
    for (const k of Object.keys(en).filter((x) => /^cluster\.(set|pki|ip)\./.test(x))) expect(fr[k], k).toBeTruthy()
  })
})
