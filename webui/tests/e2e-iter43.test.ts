// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.13.5 — labels IPAM (espaces, réseaux, adresses, VLAN) : pose, filtre, catalogue, renommage, suppression, masse ; 0.22.0 — passerelles dans la liste des adresses, journal d'audit des échecs de connexion
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'; process.env.DDI_ALLOW_UNVERIFIED_AUTH = '1'

const PORT = 3444, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s43-')); mkdirSync(join(TMP, 'gen'))
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


describe('0.13.5 — labels IPAM', () => {
  let netId = 0, a1 = 0, a2 = 0, vlanId = 0, spaceId = 0
  it('pose à la création/modification, normalisation et catalogue automatique', async () => {
    const n = await admin.post('/api/ipam/subnets', { cidr: '10.77.0.0/24', name: 'Prod', tags: ['Env:Prod', ' env:prod ', 'DMZ'] })
    expect(n.status, n.text).toBe(200); netId = n.json.id
    const list = (await viewer.get('/api/ipam/subnets')).json.items.find((x: any) => x.id === netId)
    expect(list.tags).toEqual(['env:prod', 'dmz'])
    const x1 = await admin.post(`/api/ipam/subnets/${netId}/addresses`, { ip: '10.77.0.10', hostname: 'srv-a', tags: ['env:prod', 'role:web'] }); a1 = x1.json.id
    const x2 = await admin.post(`/api/ipam/subnets/${netId}/addresses`, { ip: '10.77.0.11', hostname: 'srv-b', tags: ['env:test'] }); a2 = x2.json.id
    expect([x1.status, x2.status]).toEqual([200, 200])
    const v = await admin.post('/api/ipam/vlans', { vlan_id: 770, name: 'Prod', tags: ['env:prod'] }); vlanId = v.json.id
    const sp = await admin.post('/api/ipam/spaces', { name: 'Labo', tags: ['lab'] }); spaceId = sp.json.id
    expect([v.status, sp.status]).toEqual([200, 200])
    expect((await viewer.get('/api/ipam/vlans')).json.items.find((x: any) => x.id === vlanId).tags).toEqual(['env:prod'])
    expect((await viewer.get('/api/ipam/spaces')).json.items.find((x: any) => x.id === spaceId).tags).toEqual(['lab'])
    code(await admin.post('/api/ipam/subnets/' + netId + '/addresses', { ip: '10.77.0.12', tags: ['bad;label'] }), 400, 'validation')
    const cat = (await viewer.get('/api/ipam/labels')).json.items as any[]
    const prod = cat.find((l) => l.name === 'env:prod')
    expect(prod).toMatchObject({ subnets: 1, addresses: 1, vlans: 1, spaces: 0, total: 3 })
    expect(cat.map((l) => l.name)).toEqual(expect.arrayContaining(['dmz', 'role:web', 'env:test', 'lab']))
  })
  it('filtre des adresses par label (ET), recherche et export', async () => {
    const f = async (q: string) => ((await viewer.get('/api/ipam/addresses?' + q)).json.items as any[]).filter((i) => i.cidr === '10.77.0.0/24' && i.hostname).map((i) => i.hostname).sort()
    expect(await f('label=env:prod')).toEqual(['srv-a'])
    expect(await f('label=env:prod,role:web')).toEqual(['srv-a'])
    expect(await f('label=env:prod,env:test')).toEqual([])
    expect(await f('q=role:web')).toEqual(['srv-a'])
    const sub = (await viewer.get(`/api/ipam/subnets/${netId}/addresses?label=env:test`)).json.items
    expect(sub.map((i: any) => i.hostname)).toEqual(['srv-b'])
    expect((await viewer.get('/api/ipam/export/addresses')).text).toContain('srv-a,,,"env:prod;role:web"')
  })
  it('catalogue : couleur, description, renommage propagé, doublon refusé', async () => {
    const cat = (await viewer.get('/api/ipam/labels')).json.items as any[]
    const prod = cat.find((l) => l.name === 'env:prod'), test = cat.find((l) => l.name === 'env:test')
    expect((await admin.put(`/api/ipam/labels/${prod.id}`, { color: '#ff0000', description: 'Production' })).status).toBe(200)
    code(await admin.put(`/api/ipam/labels/${prod.id}`, { color: 'rouge' }), 400, 'validation')
    code(await admin.put(`/api/ipam/labels/${prod.id}`, { name: 'env:test' }), 409, 'label_exists')
    expect((await admin.put(`/api/ipam/labels/${prod.id}`, { name: 'prod' })).status).toBe(200)
    const l2 = ((await viewer.get('/api/ipam/labels')).json.items as any[]).find((l) => l.name === 'prod')
    expect(l2).toMatchObject({ color: '#ff0000', description: 'Production', total: 3 })
    expect((await viewer.get(`/api/ipam/subnets/${netId}/addresses?label=prod`)).json.items.map((i: any) => i.hostname)).toEqual(['srv-a'])
    expect((await viewer.get('/api/ipam/vlans')).json.items.find((x: any) => x.id === vlanId).tags).toEqual(['prod'])
    code(await admin.post('/api/ipam/labels', { name: 'PROD' }), 409, 'label_exists')
    expect((await admin.post('/api/ipam/labels', { name: 'Nouveau', color: '#00ff00' })).status).toBe(200)
    void test
  })
  it('pose et retrait en masse, droits', async () => {
    const r = await admin.post('/api/ipam/labels/assign', { kind: 'address', ids: [a1, a2], add: ['Audit'], remove: ['role:web', 'inexistant'] })
    expect(r.json).toEqual({ updated: 2 })
    const items = (await viewer.get(`/api/ipam/subnets/${netId}/addresses`)).json.items as any[]
    expect(items.find((i) => i.id === a1).tags).toEqual(['prod', 'audit'])
    expect(items.find((i) => i.id === a2).tags).toEqual(['env:test', 'audit'])
    code(await admin.post('/api/ipam/labels/assign', { kind: 'address', ids: [a1] }), 400, 'nothing_to_do')
    expect((await oper.post('/api/ipam/labels/assign', { kind: 'vlan', ids: [vlanId], add: ['x1'] })).status).toBe(200)
    expect((await viewer.post('/api/ipam/labels/assign', { kind: 'vlan', ids: [vlanId], add: ['x2'] })).status).toBe(403)
    expect((await viewer.post('/api/ipam/labels', { name: 'vue' })).status).toBe(403)
    expect((await anon.get('/api/ipam/labels')).status).toBe(401)
  })
  it('suppression : le label disparaît partout', async () => {
    const l = ((await viewer.get('/api/ipam/labels')).json.items as any[]).find((x) => x.name === 'audit')
    expect((await admin.delete(`/api/ipam/labels/${l.id}`)).status).toBe(200)
    const items = (await viewer.get(`/api/ipam/subnets/${netId}/addresses`)).json.items as any[]
    expect(items.find((i) => i.id === a1).tags).toEqual(['prod'])
    expect(((await viewer.get('/api/ipam/labels')).json.items as any[]).some((x) => x.name === 'audit')).toBe(false)
    expect((await admin.delete(`/api/ipam/labels/999999`)).status).toBe(404)
  })
})

const rowsOf = async (netId: number, q = '') => (await viewer.get(`/api/ipam/addresses?subnet_id=${netId}&limit=500${q}`)).json.items as any[]
const find = (items: any[], ip: string) => items.filter((i) => i.ip === ip)

describe('0.22.0 — passerelles dans la liste des adresses', () => {
  let net = 0, scope = 0
  it('un routeur d\'une étendue DHCP apparaît seul, en lecture seule ; une IP hors du réseau est ignorée', async () => {
    const n = await admin.post('/api/ipam/subnets', { cidr: '10.88.1.0/24', name: 'Postes' }); expect(n.status, n.text).toBe(200); net = n.json.id
    const sc = await admin.post('/api/dhcp/scopes', { subnet_id: net, options: { routers: ['10.88.1.1', '10.99.9.9'] } }); expect(sc.status, sc.text).toBe(200); scope = sc.json.id
    const items = await rowsOf(net)
    expect(find(items, '10.88.1.1')).toEqual([expect.objectContaining({ id: null, status: 'gateway', gw: 'dhcp', is_gateway: false, hostname: null })])
    expect(find(items, '10.99.9.9')).toEqual([])
    const per = (await viewer.get(`/api/ipam/subnets/${net}/addresses`)).json.items
    expect(find(per, '10.88.1.1')).toEqual([expect.objectContaining({ id: null, status: 'gateway', gw: 'dhcp' })])
    expect(find(per, '10.99.9.9')).toEqual([])
  })
  it('déclarée dans l\'IPAM, la ligne reste unique et garde l\'origine automatique, sans poser le drapeau', async () => {
    const a = await admin.post(`/api/ipam/subnets/${net}/addresses`, { ip: '10.88.1.1', hostname: 'fw-lan' }); expect(a.status, a.text).toBe(200)
    const items = await rowsOf(net), r = find(items, '10.88.1.1')
    expect(r).toHaveLength(1); expect(r[0]).toMatchObject({ id: a.json.id, status: 'used', hostname: 'fw-lan', gw: 'dhcp', is_gateway: false })
    expect(find((await viewer.get(`/api/ipam/subnets/${net}/addresses`)).json.items, '10.88.1.1')).toHaveLength(1)
  })
  it('le drapeau manuel : posé à la création, retiré, posé par le statut passerelle, retiré par un autre statut', async () => {
    const a = await admin.post(`/api/ipam/subnets/${net}/addresses`, { ip: '10.88.1.2', hostname: 'rtr-b', is_gateway: true }); expect(a.status, a.text).toBe(200)
    const state = async () => find(await rowsOf(net), '10.88.1.2')[0]
    expect(await state()).toMatchObject({ gw: 'flag', is_gateway: true, status: 'used' })
    expect((await admin.put(`/api/ipam/addresses/${a.json.id}`, { is_gateway: false })).status).toBe(200)
    expect(await state()).toMatchObject({ gw: null, is_gateway: false })
    expect((await admin.put(`/api/ipam/addresses/${a.json.id}`, { status: 'gateway' })).status).toBe(200)
    expect(await state()).toMatchObject({ gw: 'flag', is_gateway: true, status: 'gateway' })
    expect((await admin.put(`/api/ipam/addresses/${a.json.id}`, { is_gateway: false })).status).toBe(200)   // le statut passerelle l'emporte
    expect(await state()).toMatchObject({ gw: 'flag', is_gateway: true })
    expect((await admin.put(`/api/ipam/addresses/${a.json.id}`, { status: 'infra' })).status).toBe(200)
    expect(await state()).toMatchObject({ gw: null, is_gateway: false, status: 'infra' })
    code(await admin.put(`/api/ipam/addresses/${a.json.id}`, { is_gateway: 'oui' }), 400, 'validation')
  })
  it('la passerelle déclarée sur le réseau est automatique ; sans ligne dans l\'IPAM elle s\'affiche aussi', async () => {
    const n2 = await admin.post('/api/ipam/subnets', { cidr: '10.88.2.0/24', name: 'Serveurs', gateway: '10.88.2.254' }); expect(n2.status, n2.text).toBe(200)
    expect(find(await rowsOf(n2.json.id), '10.88.2.254')).toEqual([expect.objectContaining({ id: expect.any(Number), status: 'gateway', gw: 'subnet', is_gateway: true })])
    const n3 = await admin.post('/api/ipam/subnets', { cidr: '10.88.3.0/24', name: 'Vide' }); expect(n3.status).toBe(200)
    expect(await rowsOf(n3.json.id)).toEqual([])
    expect((await admin.put(`/api/ipam/subnets/${n3.json.id}`, { gateway: '10.88.3.1' })).status).toBe(200)
    expect(find(await rowsOf(n3.json.id), '10.88.3.1')).toEqual([expect.objectContaining({ id: null, status: 'gateway', gw: 'subnet' })])
  })
  it('le filtre « gw » ne garde que les passerelles (toutes origines) ; le filtre de statut ordinaire est inchangé', async () => {
    expect((await rowsOf(net, '&status=gw')).map((i) => i.ip).sort()).toEqual(['10.88.1.1'])
    const used = await rowsOf(net, '&status=used'); expect(used.map((i) => i.ip)).toEqual(['10.88.1.1'])   // 10.88.1.1 a le statut « used » : le filtre porte sur le statut
    expect((await viewer.get(`/api/ipam/subnets/${net}/addresses?status=gw`)).json.items.map((i: any) => i.ip)).toEqual(['10.88.1.1'])
  })
  it('« prochaine adresse libre » ne propose jamais un routeur DHCP', async () => {
    const n4 = await admin.post('/api/ipam/subnets', { cidr: '10.88.4.0/29', name: 'Petit' }); expect(n4.status).toBe(200)
    expect((await admin.post('/api/dhcp/scopes', { subnet_id: n4.json.id, options: { routers: ['10.88.4.1'] } })).status).toBe(200)
    const nx = await admin.post(`/api/ipam/subnets/${n4.json.id}/next`, { hostname: 'h1' }); expect(nx.status, nx.text).toBe(200)
    expect(nx.json.ip).toBe('10.88.4.2')
  })
  it('un routeur retiré de l\'étendue disparaît de la liste', async () => {
    const n5 = await admin.post('/api/ipam/subnets', { cidr: '10.88.5.0/24', name: 'Temp' }); const sc = await admin.post('/api/dhcp/scopes', { subnet_id: n5.json.id, options: { routers: ['10.88.5.1'] } })
    expect(find(await rowsOf(n5.json.id), '10.88.5.1')).toHaveLength(1)
    expect((await admin.put(`/api/dhcp/scopes/${sc.json.id}`, { subnet_id: n5.json.id, options: {} })).status).toBe(200)
    expect(find(await rowsOf(n5.json.id), '10.88.5.1')).toHaveLength(0)
  })
})

const cfgBody = (o: any = {}) => ({ enabled: true, urls: ['ldaps://127.0.0.1:1'], baseDn: 'ou=people,dc=x', bindDn: 'cn=svc,dc=x', bindPassword: 'mdp-de-liaison-secret', userFilter: '(&(objectClass=inetOrgPerson)(uid={u}))', userAttr: 'uid', displayAttr: 'cn',
  groupMode: 'memberOf', groupBaseDn: '', groupFilter: '(member={dn})', groupMap: [{ groupDn: 'cn=admins,ou=groups,dc=x', role: 'admin' }], tlsRejectUnauthorized: true, ...o })
const lastFailed = async (name: string) => ((await admin.get('/api/audit?limit=50&q=login_failed')).json.items as any[]).find((i) => i.detail?.username === name)

describe('0.22.0 — journal d\'audit : échecs de connexion détaillés', () => {
  it('mot de passe incorrect d\'un compte local : motif, méthode essayée, utilisateur dans la ligne', async () => {
    const r = await new Client().login('admin', 'mauvais-mot-de-passe-1'); expect(r.status).toBe(401)
    const l = await lastFailed('admin'); expect(l).toBeTruthy()
    expect(l.username).toBe('admin'); expect(l.action).toBe('login_failed'); expect(l.ip).toBeTruthy()
    expect(l.detail).toMatchObject({ username: 'admin', reason: 'bad_password', source: 'local', tried: [{ via: 'local', result: 'bad_password' }] })
    expect(JSON.stringify(l.detail)).not.toContain('mauvais-mot-de-passe')   // jamais de mot de passe dans le journal
  })
  it('compte inconnu sans annuaire : motif « unknown_user » ; la réponse au client reste « bad_credentials »', async () => {
    const r = await new Client().login('fantome', 'x-y-z-0123456'); code(r, 401, 'bad_credentials')
    expect((await lastFailed('fantome')).detail).toMatchObject({ reason: 'unknown_user', source: null, tried: [] })
  })
  it('compte désactivé', async () => {
    const u = await admin.post('/api/users', { username: 'coupe', role: 'viewer', password: PW }); expect(u.status, u.text).toBe(200)
    expect((await admin.put(`/api/users/${u.json.id}`, { disabled: true })).status).toBe(200)
    expect((await new Client().login('coupe', PW)).status).toBe(401)
    expect((await lastFailed('coupe')).detail).toMatchObject({ reason: 'account_disabled', source: 'local' })
  })
  it('annuaire LDAP injoignable : le motif nomme l\'annuaire (et non une liaison refusée)', async () => {
    expect((await admin.put('/api/ldap/settings', cfgBody())).status).toBe(200)
    expect((await new Client().login('jdupont', 'mdp-ldap-0123456')).status).toBe(401)
    const l = await lastFailed('jdupont'); expect(l.detail.reason).toBe('unreachable'); expect(l.detail.tried).toEqual([{ via: 'ldap', result: 'unreachable' }])
    expect((await admin.put('/api/ldap/settings', cfgBody({ enabled: false }))).status).toBe(200)
  })
  it('recherche par motif et par IP ; une connexion réussie note son origine', async () => {
    const byReason = (await admin.get('/api/audit?q=account_disabled')).json.items as any[]
    expect(byReason.length).toBeGreaterThan(0); expect(byReason.every((i) => i.detail?.reason === 'account_disabled')).toBe(true)
    expect(((await admin.get('/api/audit?q=127.0.0.1')).json.items as any[]).length).toBeGreaterThan(0)
    const ok = ((await admin.get('/api/audit?q=login')).json.items as any[]).find((i) => i.action === 'login' && i.username === 'admin')
    expect(ok.detail).toMatchObject({ source: 'local' })
  })
})
