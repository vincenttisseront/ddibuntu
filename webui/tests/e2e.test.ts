// Bout en bout : le serveur CONSTRUIT (.output) est lancé tel quel, contre PostgreSQL, avec les outils BIND/Kea réels.
import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtempSync, existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import http from 'node:http'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3399, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef'
const GEN = mkdtempSync(join(tmpdir(), 'ddi-gen-'))
let srv: ChildProcess, db: pg.Client, srvLog = ''

class Client {
  cookie = ''; csrf = ''
  constructor(public lang = 'fr') {}
  async req(method: string, path: string, body?: unknown, o: { headers?: Record<string, string>; noCsrf?: boolean } = {}) {
    const headers: Record<string, string> = { ...(o.headers ?? {}) }
    if (this.cookie) headers.cookie = this.cookie + (this.lang ? `; ddi_lang=${this.lang}` : '')
    else if (this.lang) headers.cookie = `ddi_lang=${this.lang}`
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf && !o.noCsrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = /=$/.test(kv) ? '' : kv }
    const text = await r.text()
    let json: any = null
    try { json = JSON.parse(text) } catch { /* HTML ou CSV */ }
    return { status: r.status, json, text, headers: r.headers }
  }
  get = (p: string) => this.req('GET', p)
  post = (p: string, b: unknown = {}) => this.req('POST', p, b)
  put = (p: string, b: unknown) => this.req('PUT', p, b)
  del = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const err = (r: { status: number; json: any }, status: number, code: string) => { expect([r.status, r.json?.data?.code]).toEqual([status, code]) }

const admin = new Client(), operator = new Client(), viewer = new Client(), anon = new Client()
const PW = 'Correct-Horse-Battery-9'

async function until(fn: () => Promise<boolean>, ms = 30000) { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }

beforeAll(async () => {
  expect(existsSync('.output/server/index.mjs'), 'lancer « nuxt build » avant les tests').toBe(true)
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_ALLOW_PRIVATE_FETCH: '1' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })

describe('sécurité : accès, session, CSRF, rôles', () => {
  it('santé publique ; routes protégées refusées sans session ; route inconnue', async () => {
    expect((await anon.get('/api/health')).json.status).toBe('ok')
    for (const p of ['/api/ipam/subnets', '/api/dns/zones', '/api/dhcp/scopes', '/api/filter/lists', '/api/users', '/api/dashboard', '/api/audit']) err(await anon.get(p), 401, 'unauthenticated')
    err(await anon.get('/api/nexiste/pas'), 404, 'not_found')
  })
  it('en-têtes de sécurité sur l’API et sur les pages', async () => {
    for (const p of ['/api/health', '/login']) {
      const h = (await anon.get(p)).headers
      expect(h.get('content-security-policy')).toContain("frame-ancestors 'none'"); expect(h.get('content-security-policy')).toContain("object-src 'none'")
      expect(h.get('x-content-type-options')).toBe('nosniff'); expect(h.get('x-frame-options')).toBe('DENY'); expect(h.get('referrer-policy')).toBe('no-referrer')
    }
    expect((await anon.get('/api/health')).headers.get('cache-control')).toBe('no-store')
  })
  it('première configuration : jeton exigé, une seule fois, mot de passe contrôlé', async () => {
    err(await anon.post('/api/setup/admin', { token: 'mauvais', username: 'admin', password: PW }), 403, 'bad_setup_token')
    err(await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: 'court' }), 400, 'password_short')
    err(await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: 'xxadminxxxxxxx' }), 400, 'password_contains_username')
    expect((await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })).status).toBe(200)
    err(await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'autre', password: PW }), 409, 'already_configured')
  })
  it('connexion : cookie HttpOnly SameSite=Lax, jeton CSRF, identifiants erronés refusés', async () => {
    err(await admin.login('admin', 'faux-faux-faux-1'), 401, 'bad_credentials')
    err(await admin.login('inconnu', PW), 401, 'bad_credentials')
    const r = await admin.post('/api/auth/login', { username: 'ADMIN', password: PW })   // insensible à la casse
    expect(r.status).toBe(200); admin.csrf = r.json.csrf
    const sc = r.headers.getSetCookie().find((c) => c.startsWith('ddi_session='))!
    expect(sc).toMatch(/HttpOnly/i); expect(sc).toMatch(/SameSite=Lax/i); expect(sc).toMatch(/Path=\//)
    expect(JSON.stringify(r.json)).not.toMatch(/password|hash/i)
    expect((await admin.get('/api/auth/me')).json.user.username).toBe('admin')
  })
  it('CSRF et origine : requêtes d’écriture refusées sans jeton valide ou depuis une autre origine', async () => {
    err(await admin.req('POST', '/api/ipam/vlans', { vlan_id: 10, name: 'x' }, { noCsrf: true }), 403, 'csrf')
    err(await admin.req('POST', '/api/ipam/vlans', { vlan_id: 10, name: 'x' }, { headers: { 'x-csrf-token': 'faux' }, noCsrf: true }), 403, 'csrf')
    err(await admin.req('POST', '/api/ipam/vlans', { vlan_id: 10, name: 'x' }, { headers: { origin: 'http://evil.example' } }), 403, 'bad_origin')
    err(await anon.req('POST', '/api/auth/login', { username: 'admin', password: PW }, { headers: { origin: 'http://evil.example' } }), 403, 'bad_origin')
  })
  it('rôles : administrateur crée opérateur et lecteur ; chacun limité à ses droits', async () => {
    expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
    expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
    err(await admin.post('/api/users', { username: 'oper', role: 'viewer', password: PW }), 409, 'duplicate')
    expect((await operator.login('oper', PW)).status).toBe(200); expect((await viewer.login('lect', PW)).status).toBe(200)
    err(await viewer.post('/api/ipam/vlans', { vlan_id: 10, name: 'x' }), 403, 'forbidden')
    expect((await viewer.get('/api/ipam/subnets')).status).toBe(200)
    err(await operator.get('/api/users'), 403, 'forbidden'); err(await operator.get('/api/audit'), 403, 'forbidden'); err(await operator.post('/api/system/apply', { deploy: false }), 403, 'forbidden')
    err(await operator.put('/api/dns/settings', {}), 403, 'forbidden'); err(await viewer.get('/api/system/info'), 403, 'forbidden')
    expect((await operator.post('/api/ipam/vlans', { vlan_id: 99, name: 'op-vlan' })).status).toBe(200)
  })
  it('anti-force brute : verrouillage après 5 échecs, message identique, réussite impossible pendant le verrouillage', async () => {
    await admin.post('/api/users', { username: 'cible', role: 'viewer', password: PW })
    const c = new Client()
    for (let i = 0; i < 5; i++) err(await c.login('cible', 'mauvais-mot-de-passe-1'), 401, 'bad_credentials')
    err(await c.login('cible', 'mauvais-mot-de-passe-1'), 429, 'too_many_attempts')
    err(await c.login('cible', PW), 429, 'too_many_attempts')
  })
  it('changement de mot de passe : ancien refusé, politique, autres sessions fermées', async () => {
    const c = new Client(); await c.login('lect', PW); const c2 = new Client(); await c2.login('lect', PW)
    err(await c.post('/api/auth/password', { current: 'faux', next: 'Nouveau-Mot-De-Passe-1' }), 403, 'bad_credentials')
    err(await c.post('/api/auth/password', { current: PW, next: 'court' }), 400, 'password_short')
    expect((await c.post('/api/auth/password', { current: PW, next: 'Nouveau-Mot-De-Passe-1' })).status).toBe(200)
    err(await c2.get('/api/auth/me').then((r) => ({ status: r.json.user ? 200 : 401, json: { data: { code: 'unauthenticated' } } })), 401, 'unauthenticated')
    expect((await c.get('/api/auth/me')).json.user.username).toBe('lect')
    expect((await new Client().login('lect', 'Nouveau-Mot-De-Passe-1')).status).toBe(200)
    await admin.put(`/api/users/${(await admin.get('/api/users')).json.items.find((u: any) => u.username === 'lect').id}`, { password: PW })
    expect((await viewer.login('lect', PW)).status).toBe(200)   // ses sessions ont été fermées par le changement de mot de passe
  })
  it('désactivation : la session est fermée et la connexion refusée ; dernier administrateur protégé', async () => {
    const users = (await admin.get('/api/users')).json.items
    const id = users.find((u: any) => u.username === 'oper').id
    const c = new Client(); await c.login('oper', PW)
    expect((await admin.put(`/api/users/${id}`, { disabled: true })).status).toBe(200)
    expect((await c.get('/api/auth/me')).json.user).toBeNull(); err(await new Client().login('oper', PW), 401, 'bad_credentials')
    await admin.put(`/api/users/${id}`, { disabled: false })
    const aid = users.find((u: any) => u.username === 'admin').id
    err(await admin.put(`/api/users/${aid}`, { role: 'viewer' }), 409, 'last_admin'); err(await admin.put(`/api/users/${aid}`, { disabled: true }), 409, 'last_admin')
    err(await admin.del(`/api/users/${aid}`), 409, 'self_delete')
    expect((await operator.login('oper', PW)).status).toBe(200)
  })
  it('mots de passe : jamais en clair en base ; empreinte PBKDF2', async () => {
    const r = await db.query('select username, password_hash from users where password_hash is not null')
    for (const u of r.rows) { expect(u.password_hash).toMatch(/^pbkdf2\$sha256\$\d+\$/); expect(u.password_hash).not.toContain(PW) }
    const s = await db.query("select count(*)::int n from sessions where token_hash ~ '^[0-9a-f]{64}$'"); expect(s.rows[0].n).toBeGreaterThan(0)
  })
  it('déconnexion : la session est détruite côté serveur', async () => {
    const c = new Client(); await c.login('lect', PW); const cookie = c.cookie
    expect((await c.post('/api/auth/logout')).status).toBe(200)
    const again = new Client(); again.cookie = cookie
    expect((await again.get('/api/auth/me')).json.user).toBeNull()
  })
})

describe('IPAM', () => {
  let subnetId = 0, vlanId = 0
  it('VLAN : création, doublon, bornes', async () => {
    const r = await admin.post('/api/ipam/vlans', { vlan_id: 20, name: 'Serveurs' }); expect(r.status).toBe(200); vlanId = r.json.id
    err(await admin.post('/api/ipam/vlans', { vlan_id: 20, name: 'bis' }), 409, 'duplicate')
    err(await admin.post('/api/ipam/vlans', { vlan_id: 5000, name: 'x' }), 400, 'validation')
    expect((await admin.get('/api/ipam/vlans')).json.items.length).toBe(2)
  })
  it('sous-réseau : bits hôte normalisés, passerelle créée, doublon, validations', async () => {
    const r = await admin.post('/api/ipam/subnets', { cidr: '10.20.30.77/24', name: 'Serveurs', vlan_id: vlanId, site: 'Paris', gateway: '10.20.30.1', tags: ['prod'] }); expect(r.status).toBe(200); subnetId = r.json.id
    err(await admin.post('/api/ipam/subnets', { cidr: '10.20.30.0/24', name: 'bis' }), 409, 'duplicate')
    err(await admin.post('/api/ipam/subnets', { cidr: '10.20.40.0/24', name: 'x', gateway: '10.99.0.1' }), 400, 'gateway_outside')
    err(await admin.post('/api/ipam/subnets', { cidr: 'abc', name: 'x' }), 400, 'validation')
    err(await admin.post('/api/ipam/subnets', { cidr: '10.0.0.0/33', name: 'x' }), 400, 'validation')
    expect((await admin.post('/api/ipam/subnets', { cidr: '10.20.0.0/16', name: 'Parent' })).status).toBe(200)
    expect((await admin.post('/api/ipam/subnets', { cidr: '2001:db8:1::/64', name: 'v6' })).status).toBe(200)
    const list = (await admin.get('/api/ipam/subnets')).json.items
    const s = list.find((x: any) => x.cidr === '10.20.30.0/24')
    expect(s).toMatchObject({ gateway: '10.20.30.1', site: 'Paris', vlan: 20, used: 1, capacity: 254, family: 4 })
    expect(s.parent_id).toBe(list.find((x: any) => x.cidr === '10.20.0.0/16').id)
    expect(list.find((x: any) => x.cidr === '2001:db8:1::/64').capacity).toBeNull()
    err(await admin.put(`/api/ipam/subnets/${subnetId}`, { cidr: '10.99.0.0/24' }), 400, 'cidr_immutable')
  })
  it('adresses : validation, normalisation MAC, hors sous-réseau refusé, doublon', async () => {
    const a = `/api/ipam/subnets/${subnetId}/addresses`
    const ok = await admin.post(a, { ip: '10.20.30.10', hostname: 'SRV-APP-01', mac: 'AA-BB-CC-DD-EE-01', description: '=HYPERLINK("http://x")' }); expect(ok.status).toBe(200)
    err(await admin.post(a, { ip: '10.20.30.10', hostname: 'bis' }), 409, 'duplicate')
    err(await admin.post(a, { ip: '10.99.0.5' }), 400, 'ip_outside_subnet')
    err(await admin.post(a, { ip: '10.20.30.11', hostname: 'nom_invalide' }), 400, 'validation'); err(await admin.post(a, { ip: '10.20.30.11', mac: 'zz' }), 400, 'validation')
    err(await admin.post(a, { ip: '10.20.30.999' }), 400, 'validation')
    const row = (await admin.get(a)).json.items.find((x: any) => x.ip === '10.20.30.10')
    expect(row).toMatchObject({ hostname: 'srv-app-01', mac: 'aa:bb:cc:dd:ee:01', status: 'used' })
    expect((await admin.put(`/api/ipam/addresses/${row.id}`, { status: 'reserved', owner: 'équipe infra' })).status).toBe(200)
    expect((await admin.get(`${a}?status=reserved`)).json.items.length).toBe(1)
    expect((await admin.get(`${a}?q=srv-app`)).json.items.length).toBe(1)
  })
  it('prochaine adresse libre : saute passerelle, adresses prises et plages DHCP ; sous-réseau plein', async () => {
    const sc = await admin.post('/api/dhcp/scopes', { subnet_id: subnetId, name: 'Serveurs', options: {} }); expect(sc.status).toBe(200)
    expect((await admin.post(`/api/dhcp/scopes/${sc.json.id}/pools`, { start: '10.20.30.2', end: '10.20.30.9' })).status).toBe(200)
    const first = await admin.post(`/api/ipam/subnets/${subnetId}/next`, { hostname: 'auto-01' })
    expect(first.json.ip).toBe('10.20.30.11')   // .1 passerelle, .2-.9 plage DHCP, .10 prise
    expect((await admin.post(`/api/ipam/subnets/${subnetId}/next`, {})).json.ip).toBe('10.20.30.12')
    const tiny = await admin.post('/api/ipam/subnets', { cidr: '192.168.77.0/30', name: 'p2p' })
    expect((await admin.post(`/api/ipam/subnets/${tiny.json.id}/next`, {})).json.ip).toBe('192.168.77.1')
    expect((await admin.post(`/api/ipam/subnets/${tiny.json.id}/next`, {})).json.ip).toBe('192.168.77.2')
    err(await admin.post(`/api/ipam/subnets/${tiny.json.id}/next`, {}), 409, 'subnet_full')
    err(await admin.post(`/api/ipam/subnets/${(await admin.get('/api/ipam/subnets')).json.items.find((x: any) => x.family === 6).id}/next`, {}), 400, 'ipv4_only')
  })
  it('allocations simultanées : jamais deux fois la même adresse', async () => {
    const s = await admin.post('/api/ipam/subnets', { cidr: '10.77.0.0/24', name: 'conc' })
    const rs = await Promise.all(Array.from({ length: 12 }, () => admin.post(`/api/ipam/subnets/${s.json.id}/next`, {})))
    const ips = rs.map((r) => r.json.ip)
    expect(rs.every((r) => r.status === 200)).toBe(true); expect(new Set(ips).size).toBe(12)
  })
  it('recherche, export CSV protégé contre l’injection de formules, suppression avec confirmation', async () => {
    const f = (await admin.get('/api/ipam/search?q=srv-app')).json
    expect(f.addresses.length).toBe(1)
    expect((await admin.get('/api/ipam/search?q=' + encodeURIComponent("' OR 1=1 --"))).status).toBe(200)
    const csv = await admin.get('/api/ipam/export/addresses')
    expect(csv.headers.get('content-type')).toContain('text/csv'); expect(csv.text.split('\n')[0]).toBe('cidr,ip,status,hostname,mac,description')
    expect(csv.text).toContain(`"'=HYPERLINK(""http://x"")"`); expect(csv.text).not.toMatch(/,=HYPERLINK/)
    const s = await admin.post('/api/ipam/subnets', { cidr: '172.20.0.0/24', name: 'tmp' })
    await admin.post(`/api/ipam/subnets/${s.json.id}/addresses`, { ip: '172.20.0.5' }); await admin.post(`/api/ipam/subnets/${s.json.id}/addresses`, { ip: '172.20.0.6' })
    err(await admin.del(`/api/ipam/subnets/${s.json.id}`), 409, 'subnet_not_empty')
    expect((await admin.del(`/api/ipam/subnets/${s.json.id}?force=1`)).status).toBe(200)
  })
})

const WINDOWS_ZONE = `@ IN SOA dc01.ad.corp.local. hostmaster.ad.corp.local. ( 42 900 600 86400 3600 )
@ NS dc01.ad.corp.local.
@ [Aging:3631234] 600 A 10.0.0.10
_msdcs NS dc01.ad.corp.local.
dc01 [Aging:3631200] 1200 A 10.0.0.10
www CNAME dc01
_ldap._tcp 600 SRV 0 100 389 dc01.ad.corp.local.
_kerberos._tcp.Default-First-Site-Name._sites 600 SRV 0 100 88 dc01.ad.corp.local.
gc._msdcs 600 A 10.0.0.10
host.autre.org. A 1.2.3.4
wins 900 WINS 10.0.0.9
bad A 999.0.0.1
`

describe('DNS : tous les types, règles, protection AD, import', () => {
  let zid = 0, rzid = 0
  const rec = (o: any) => admin.post('/api/dns/records', { zone_id: zid, ...o })
  it('zones : primaire, inverse, secondaire (maîtres requis), redirection, validations', async () => {
    const z = await admin.post('/api/dns/zones', { name: 'Example.COM.', type: 'primary', ddns_enabled: true }); expect(z.status).toBe(200); zid = z.json.id
    expect((await admin.get(`/api/dns/zones/${zid}`)).json.name).toBe('example.com')
    rzid = (await admin.post('/api/dns/zones', { name: '30.20.10.in-addr.arpa', type: 'primary' })).json.id
    err(await admin.post('/api/dns/zones', { name: 'example.com', type: 'primary' }), 409, 'duplicate')
    err(await admin.post('/api/dns/zones', { name: 'sec.example.org', type: 'secondary' }), 400, 'masters_required')
    err(await admin.post('/api/dns/zones', { name: 'fwd.example.org', type: 'forward' }), 400, 'forwarders_required')
    err(await admin.post('/api/dns/zones', { name: 'mauvais nom', type: 'primary' }), 400, 'validation')
    err(await admin.post('/api/dns/zones', { name: 'x.org', type: 'secondary', masters: ['pas-une-ip'] }), 400, 'validation')
    expect((await admin.post('/api/dns/zones', { name: 'sec.example.org', type: 'secondary', masters: ['192.0.2.7'] })).status).toBe(200)
    expect((await admin.post('/api/dns/zones', { name: 'fwd.example.org', type: 'forward', forwarders: ['10.0.0.10', '10.0.0.11'] })).status).toBe(200)
    err(await admin.post('/api/dns/records', { zone_id: (await admin.get('/api/dns/zones')).json.items.find((z: any) => z.name === 'sec.example.org').id, name: 'a', type: 'A', rdata: '1.1.1.1' }), 400, 'zone_not_primary')
  })
  it('un enregistrement valide de CHAQUE type est accepté et normalisé', async () => {
    const cases: Array<[string, string, string, string?]> = [
      ['@', 'NS', 'NS1.Example.com', 'ns1.example.com.'], ['ns1', 'A', '192.0.2.1'], ['ns1', 'AAAA', '2001:0DB8::0001', '2001:db8::1'], ['www', 'CNAME', 'ns1'], ['@', 'MX', '10 mail.example.com', '10 mail.example.com.'],
      ['mail', 'A', '192.0.2.25'], ['@', 'TXT', 'v=spf1 mx -all'], ['_sip._tcp', 'SRV', '0 5 5060 sip.example.com', '0 5 5060 sip.example.com.'], ['@', 'CAA', '0 issue "letsencrypt.org"', '0 issue letsencrypt.org'],
      ['tel', 'NAPTR', '100 10 "S" "SIP+D2U" "" _sip._udp.example.com', '100 10 "S" "SIP+D2U" "" _sip._udp.example.com.'], ['ssh', 'SSHFP', '4 2 ' + 'AB'.repeat(32), '4 2 ' + 'ab'.repeat(32)],
      ['_443._tcp.www', 'TLSA', '3 1 1 ' + 'cd'.repeat(32)], ['svc', 'HTTPS', '1 . alpn=h2,h3'], ['svc2', 'SVCB', '1 svc.example.com port=8443', '1 svc.example.com. port=8443'], ['box', 'HINFO', 'AMD64 Linux', '"AMD64" "Linux"'],
      ['resp', 'RP', 'admin.example.com info.example.com', 'admin.example.com. info.example.com.'], ['child', 'NS', 'ns.child.example.com', 'ns.child.example.com.'], ['child', 'DS', '12345 13 2 ' + 'ef'.repeat(32)], ['ns.child', 'A', '192.0.2.50'], ['old', 'DNAME', 'new.example.org', 'new.example.org.'],
      ['alias2', 'PTR', 'h.example.com', 'h.example.com.'],
    ]
    for (const [name, type, rdata, want] of cases) {
      const r = await rec({ name, type, rdata })
      expect([name, type, r.status, r.json?.rdata]).toEqual([name, type, 200, want ?? rdata])
    }
    expect((await admin.get('/api/dns/records?zone_id=' + zid + '&limit=1000')).json.total).toBe(cases.length)
  })
  it('chaque type refuse une valeur invalide (400) sans rien écrire', async () => {
    const bad: Array<[string, string]> = [['A', '2001:db8::1'], ['AAAA', '10.0.0.1'], ['CNAME', 'bad name'], ['MX', 'mail.example.com'], ['TXT', 'a\nb'], ['SRV', '0 5 sip'], ['CAA', 'issue x'], ['NAPTR', '1 2 "x"'],
      ['SSHFP', '4 2 abcd'], ['TLSA', '9 1 1 aa'], ['HTTPS', 'x . alpn=h2'], ['HINFO', 'seul'], ['RP', 'seul'], ['DS', '1 2 3'], ['NS', '10.0.0.1'], ['PTR', 'bad name'], ['DNAME', '--x'], ['SVCB', 'x']]
    const before = (await admin.get(`/api/dns/records?zone_id=${zid}&limit=1000`)).json.total
    for (const [type, rdata] of bad) { const r = await rec({ name: 'zz', type, rdata }); expect([type, r.status, r.json?.data?.code]).toEqual([type, 400, 'rdata_invalid']) }
    err(await rec({ name: 'zz', type: 'SOA', rdata: 'x' }), 400, 'type_unsupported'); err(await rec({ name: 'zz', type: 'A', rdata: '' }), 400, 'validation')
    expect((await admin.get(`/api/dns/records?zone_id=${zid}&limit=1000`)).json.total).toBe(before)
  })
  it('noms : relatifs à la zone, jokers, hors zone refusé ; CNAME exclusif ; doublons', async () => {
    expect((await rec({ name: 'host.example.com.', type: 'A', rdata: '192.0.2.77' })).json.name).toBe('host')
    expect((await rec({ name: '*.apps', type: 'A', rdata: '192.0.2.80' })).status).toBe(200)
    err(await rec({ name: 'host.autre.org.', type: 'A', rdata: '1.2.3.4' }), 400, 'name_invalid'); err(await rec({ name: 'bad name', type: 'A', rdata: '1.2.3.4' }), 400, 'name_invalid')
    err(await rec({ name: 'host', type: 'CNAME', rdata: 'ns1' }), 409, 'cname_conflict'); err(await rec({ name: 'www', type: 'TXT', rdata: 'x' }), 409, 'cname_conflict')
    err(await rec({ name: '@', type: 'CNAME', rdata: 'ns1' }), 409, 'cname_apex')
    err(await rec({ name: 'host', type: 'A', rdata: '192.0.2.77' }), 409, 'duplicate')
    expect((await rec({ name: 'host', type: 'A', rdata: '192.0.2.78' })).status).toBe(200)   // plusieurs A = round-robin
  })
  it('modification : le CNAME existant reste modifiable ; l’opérateur peut écrire', async () => {
    const www = (await admin.get(`/api/dns/records?zone_id=${zid}&q=www`)).json.items.find((r: any) => r.type === 'CNAME')
    expect((await admin.put(`/api/dns/records/${www.id}`, { zone_id: zid, name: 'www', type: 'CNAME', rdata: 'mail', ttl: 600 })).status).toBe(200)
    expect((await operator.post('/api/dns/records', { zone_id: zid, name: 'op', type: 'A', rdata: '192.0.2.99' })).status).toBe(200)
  })
  it('import d’un export de zone Windows : aperçu sans écriture, puis import ; critiques AD protégés', async () => {
    const adz = await admin.post('/api/dns/zones', { name: 'ad.corp.local', type: 'primary' })
    const pre = await admin.post('/api/import/dns/preview', { zone_id: adz.json.id, content: WINDOWS_ZONE })
    expect(pre.json).toMatchObject({ zone: 'ad.corp.local', new: 8, identical: 0, conflicts: 0, adCritical: 4, skipped: 3 })
    expect(pre.json.soa).toMatchObject({ serial: 42 }); expect(pre.json.warnings.map((w: any) => w.code)).toEqual(expect.arrayContaining(['out_of_zone', 'unsupported_type']))
    expect((await admin.get(`/api/dns/records?zone_id=${adz.json.id}`)).json.total).toBe(0)
    const com = await operator.post('/api/import/dns/commit', { zone_id: adz.json.id, content: WINDOWS_ZONE, apply_soa: true }); expect(com.json.inserted).toBe(8)
    expect((await operator.post('/api/import/dns/commit', { zone_id: adz.json.id, content: WINDOWS_ZONE })).json).toMatchObject({ inserted: 0, identical: 8 })
    err(await operator.post('/api/import/dns/commit', { zone_id: adz.json.id, content: WINDOWS_ZONE, mode: 'replace' }), 403, 'forbidden')
    const recs = (await admin.get(`/api/dns/records?zone_id=${adz.json.id}`)).json.items
    const ldap = recs.find((r: any) => r.name === '_ldap._tcp'); expect(ldap.protected).toBe(true)
    expect(recs.find((r: any) => r.name === 'www').rdata).toBe('dc01.ad.corp.local.')
    expect((await admin.get(`/api/dns/zones/${adz.json.id}`)).json).toMatchObject({ ad_integrated: true, soa_refresh: 900 })
    err(await operator.put(`/api/dns/records/${ldap.id}`, { zone_id: adz.json.id, name: '_ldap._tcp', type: 'SRV', rdata: '0 100 389 evil.example.com' }), 403, 'protected_record')
    err(await operator.del(`/api/dns/records/${ldap.id}`), 403, 'protected_record')
    expect((await admin.put(`/api/dns/records/${ldap.id}`, { zone_id: adz.json.id, name: '_ldap._tcp', type: 'SRV', rdata: '0 100 389 dc02.ad.corp.local.' })).status).toBe(200)
    expect((await admin.del(`/api/dns/records/${recs.find((r: any) => r.name === 'gc._msdcs').id}`)).status).toBe(200)
  })
  it('IPAM -> DNS : création de l’enregistrement A et du PTR à l’allocation', async () => {
    const sub = await admin.post('/api/ipam/subnets', { cidr: '10.20.30.0/24x'.replace('x', ''), name: 'dup' }); err(sub, 409, 'duplicate')
    const sid = (await admin.get('/api/ipam/subnets')).json.items.find((s: any) => s.cidr === '10.20.30.0/24').id
    const r = await admin.post(`/api/ipam/subnets/${sid}/addresses`, { ip: '10.20.30.200', hostname: 'syncd', dns_zone_id: zid }); expect(r.status).toBe(200)
    expect((await admin.get(`/api/dns/records?zone_id=${zid}&q=syncd`)).json.items[0]).toMatchObject({ type: 'A', rdata: '10.20.30.200' })
    expect((await admin.get(`/api/dns/records?zone_id=${rzid}`)).json.items[0]).toMatchObject({ name: '200', type: 'PTR', rdata: 'syncd.example.com.' })
  })
  it('export du fichier de zone, suppression avec confirmation', async () => {
    const ex = (await admin.get(`/api/dns/zones/${zid}/export`)).json
    expect(ex.content).toContain('$ORIGIN example.com.'); expect(ex.content).toContain('@ IN SOA')
    err(await admin.del(`/api/dns/zones/${zid}`), 409, 'zone_not_empty')
  })
  it('paramètres DNS : administrateur seulement, valeurs validées', async () => {
    const cur = (await admin.get('/api/dns/settings')).json
    err(await admin.put('/api/dns/settings', { ...cur, forwarders: ['pas-une-ip'] }), 400, 'validation')
    expect((await admin.put('/api/dns/settings', { ...cur, forwarders: ['9.9.9.9'], queryLog: true })).status).toBe(200)
    expect((await viewer.get('/api/dns/settings')).json.forwarders).toEqual(['9.9.9.9'])
  })
})

const DHCP_XML = `<?xml version="1.0"?><DHCPServer><IPv4><OptionValues><OptionValue><OptionId>15</OptionId><Value>corp.local</Value></OptionValue></OptionValues><Scopes>
<Scope><ScopeId>192.168.1.0</ScopeId><Name>LAN Paris</Name><SubnetMask>255.255.255.0</SubnetMask><StartRange>192.168.1.100</StartRange><EndRange>192.168.1.200</EndRange><LeaseDuration>8.00:00:00</LeaseDuration><State>Active</State>
<ExclusionRanges><IPRange><StartRange>192.168.1.120</StartRange><EndRange>192.168.1.130</EndRange></IPRange></ExclusionRanges>
<OptionValues><OptionValue><OptionId>3</OptionId><Value>192.168.1.1</Value></OptionValue><OptionValue><OptionId>6</OptionId><Value>10.0.0.10</Value><Value>10.0.0.11</Value></OptionValue></OptionValues>
<Reservations><Reservation><IPAddress>192.168.1.50</IPAddress><ClientId>AA-BB-CC-DD-EE-01</ClientId><Name>imprimante.corp.local</Name></Reservation></Reservations></Scope></Scopes></IPv4></DHCPServer>`

describe('DHCP', () => {
  let scopeId = 0, subnetId = 0
  it('étendue : seulement IPv4, un seul par sous-réseau, options validées', async () => {
    subnetId = (await admin.post('/api/ipam/subnets', { cidr: '192.168.10.0/24', name: 'LAN', gateway: '192.168.10.1' })).json.id
    const r = await admin.post('/api/dhcp/scopes', { subnet_id: subnetId, name: 'LAN', lease_time: 3600, options: { routers: ['192.168.10.1'], dnsServers: ['192.168.10.2', '192.168.10.3'], domainName: 'corp.local', ntpServers: ['192.168.10.5'], custom: [{ code: 224, name: 'site-code', type: 'string', value: 'PARIS-01' }] } })
    expect(r.status).toBe(200); scopeId = r.json.id
    err(await admin.post('/api/dhcp/scopes', { subnet_id: subnetId }), 409, 'duplicate')
    const v6 = (await admin.get('/api/ipam/subnets')).json.items.find((s: any) => s.family === 6).id
    err(await admin.post('/api/dhcp/scopes', { subnet_id: v6 }), 400, 'ipv4_only')
    const s2 = (await admin.post('/api/ipam/subnets', { cidr: '192.168.11.0/24', name: 'x' })).json.id
    err(await admin.post('/api/dhcp/scopes', { subnet_id: s2, options: { routers: ['pas-une-ip'] } }), 400, 'validation')
    err(await admin.post('/api/dhcp/scopes', { subnet_id: s2, options: { custom: [{ code: 3, name: 'x', type: 'string', value: 'a' }] } }), 400, 'validation')
    err(await admin.post('/api/dhcp/scopes', { subnet_id: s2, options: { inconnue: 1 } }), 400, 'validation')
    err(await admin.post('/api/dhcp/scopes', { subnet_id: s2, lease_time: 5 }), 400, 'validation')
  })
  it('plages : ordre, sous-réseau, chevauchement', async () => {
    const p = `/api/dhcp/scopes/${scopeId}/pools`
    expect((await admin.post(p, { start: '192.168.10.100', end: '192.168.10.150' })).status).toBe(200)
    err(await admin.post(p, { start: '192.168.10.140', end: '192.168.10.160' }), 409, 'pool_overlap'); err(await admin.post(p, { start: '192.168.10.50', end: '192.168.10.40' }), 400, 'pool_order')
    err(await admin.post(p, { start: '192.168.11.1', end: '192.168.11.9' }), 400, 'pool_outside_subnet'); err(await admin.post(p, { start: '::1', end: '::2' }), 400, 'validation')
    expect((await admin.post(p, { start: '192.168.10.200', end: '192.168.10.220' })).status).toBe(200)
  })
  it('réservations : reflétées dans l’IPAM, doublons refusés, hors sous-réseau refusé', async () => {
    const r = `/api/dhcp/scopes/${scopeId}/reservations`
    expect((await admin.post(r, { mac: 'AA:BB:CC:DD:EE:01', ip: '192.168.10.50', hostname: 'printer1' })).status).toBe(200)
    err(await admin.post(r, { mac: 'aa-bb-cc-dd-ee-01', ip: '192.168.10.51' }), 409, 'duplicate'); err(await admin.post(r, { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.10.50' }), 409, 'duplicate')
    err(await admin.post(r, { mac: 'aa:bb:cc:dd:ee:03', ip: '10.9.9.9' }), 400, 'ip_outside_subnet'); err(await admin.post(r, { mac: 'zz', ip: '192.168.10.52' }), 400, 'validation')
    expect((await admin.get(`/api/ipam/subnets/${subnetId}/addresses`)).json.items.find((a: any) => a.ip === '192.168.10.50')).toMatchObject({ status: 'dhcp', mac: 'aa:bb:cc:dd:ee:01', hostname: 'printer1' })
    const sc = (await admin.get(`/api/dhcp/scopes/${scopeId}`)).json
    expect([sc.pools.length, sc.reservations.length]).toEqual([2, 1])
  })
  it('paramètres : le mot de passe de la base est chiffré et n’est jamais renvoyé', async () => {
    const cur = (await admin.get('/api/dhcp/settings')).json
    expect((await admin.put('/api/dhcp/settings', { interfaces: ['*'], ddns: false, lease: { type: 'postgresql', name: 'ddibuntu', user: 'kea', host: '127.0.0.1', password: 'secret-base-kea-123' }, globalOptions: { ntpServers: ['192.168.10.5'] } })).status).toBe(200)
    const g = await admin.get('/api/dhcp/settings')
    expect(g.text).not.toContain('secret-base-kea-123'); expect(g.json.lease.passwordSet).toBe(true); expect(cur.interfaces).toEqual(['*'])
    const raw = (await db.query("select value from settings where key = 'dhcp'")).rows[0].value
    expect(JSON.stringify(raw)).not.toContain('secret-base-kea-123'); expect(raw.lease.passwordEnc).toMatch(/^v1:/)
    err(await operator.put('/api/dhcp/settings', {}), 403, 'forbidden')
  })
  it('baux : indisponibles tant que Kea n’est pas installé', async () => { expect((await admin.get('/api/dhcp/leases')).json).toEqual({ available: false, items: [] }) })
  it('import DHCP Windows : aperçu puis import (plages moins exclusions, options, réservations, IPAM)', async () => {
    const pre = (await admin.post('/api/import/dhcp/preview', { content: DHCP_XML })).json
    expect(pre.totals).toEqual({ scopes: 1, pools: 2, reservations: 1 }); expect(pre.scopes[0]).toMatchObject({ cidr: '192.168.1.0/24', subnetExists: false })
    const done = (await admin.post('/api/import/dhcp/commit', { content: DHCP_XML })).json
    expect(done).toMatchObject({ scopes: 1, subnetsCreated: 1, pools: 2, reservations: 1 })
    expect((await admin.post('/api/import/dhcp/commit', { content: DHCP_XML })).json).toMatchObject({ scopes: 0, scopesSkipped: 1 })
    const sc = (await admin.get('/api/dhcp/scopes')).json.items.find((s: any) => s.cidr === '192.168.1.0/24')
    expect(sc).toMatchObject({ lease_time: 691200, pools: 2, reservations: 1, options: { domainName: 'corp.local', routers: ['192.168.1.1'], dnsServers: ['10.0.0.10', '10.0.0.11'] } })
  })
})

describe('filtrage DNS (RPZ)', () => {
  let srvL: http.Server, port = 0, listId = 0
  beforeAll(async () => {
    srvL = http.createServer((req, res) => { res.end(req.url === '/hosts' ? '# test\n0.0.0.0 pub.example.net\n0.0.0.0 ads.sub.example.net\n127.0.0.1 localhost\n' : 'x'); })
    await new Promise<void>((r) => srvL.listen(0, '127.0.0.1', r)); port = (srvL.address() as any).port
  })
  afterAll(() => { srvL.close() })
  it('listes : création, import par contenu, mise à jour depuis une adresse (action explicite)', async () => {
    const a = await admin.post('/api/filter/lists', { name: 'Adulte', category: 'adult', format: 'domains' }); expect(a.status).toBe(200); listId = a.json.id
    expect((await admin.post(`/api/filter/lists/${listId}/import`, { content: 'adulte1.example.net\n*.adulte2.example.net\nok.example.net\n# x\n' })).json.entries).toBe(3)
    const b = await admin.post('/api/filter/lists', { name: 'Pubs', category: 'ads', format: 'hosts', source_url: `http://127.0.0.1:${port}/hosts` })
    const up = await admin.post(`/api/filter/lists/${b.json.id}/update`); expect(up.json.entries).toBe(2)
    const row = (await admin.get('/api/filter/lists')).json.items.find((l: any) => l.name === 'Pubs'); expect(row.sha256).toMatch(/^[0-9a-f]{64}$/); expect(row.entries).toBe(2)
    err(await admin.post('/api/filter/lists', { name: 'Adulte', category: 'adult' }), 409, 'duplicate'); err(await admin.post('/api/filter/lists', { name: 'x', category: 'inconnue' }), 400, 'validation')
    err(await admin.post('/api/filter/lists', { name: 'y', category: 'ads', source_url: 'ftp://x.example/a' }), 400, 'url_scheme')
    const noUrl = await admin.post(`/api/filter/lists/${listId}/update`); err(noUrl, 400, 'no_source_url')
  })
  it('règles : domaines normalisés, doublons refusés', async () => {
    expect((await admin.post('/api/filter/rules', { domain: 'OK.Example.NET.', action: 'allow', comment: 'faux positif' })).status).toBe(200)
    expect((await admin.post('/api/filter/rules', { domain: 'bloque.example.org', action: 'block' })).status).toBe(200)
    err(await admin.post('/api/filter/rules', { domain: 'ok.example.net', action: 'allow' }), 409, 'duplicate'); err(await admin.post('/api/filter/rules', { domain: 'pas un domaine', action: 'block' }), 400, 'validation')
  })
  it('test d’un domaine : le plus spécifique l’emporte, autoriser prévaut à égalité', async () => {
    const chk = async (d: string) => (await admin.get('/api/filter/check?domain=' + encodeURIComponent(d))).json
    expect(await chk('adulte1.example.net')).toMatchObject({ blocked: true, reason: 'list' })
    expect(await chk('www.adulte2.example.net')).toMatchObject({ blocked: true, reason: 'list' })
    expect(await chk('ok.example.net')).toMatchObject({ blocked: false, reason: 'allow_rule' })
    expect(await chk('bloque.example.org')).toMatchObject({ blocked: true, reason: 'block_rule' })
    expect(await chk('tout-va-bien.example.com')).toMatchObject({ blocked: false, reason: 'no_match' })
    await admin.post('/api/filter/rules', { domain: 'sub.adulte2.example.net', action: 'allow' })
    expect(await chk('x.sub.adulte2.example.net')).toMatchObject({ blocked: false, reason: 'allow_rule' })
    expect(await chk('autre.adulte2.example.net')).toMatchObject({ blocked: true })
    err(await admin.get('/api/filter/check?domain=' + encodeURIComponent('pas un domaine')), 400, 'domain')
  })
  it('paramètres RPZ puis génération : zone RPZ valide pour named-checkzone et named-checkconf', async () => {
    expect((await admin.put('/api/filter/settings', { rpzEnabled: true, rpzAction: 'nxdomain', sinkhole4: '0.0.0.0', sinkhole6: '::' })).status).toBe(200)
    const r = (await admin.get('/api/system/render')).json
    const rpz = r.files.find((f: any) => f.path === 'zones/db.rpz'); expect(rpz.content).toContain('adulte1.example.net IN CNAME .'); expect(rpz.content).toContain('ok.example.net IN CNAME rpz-passthru.')
    expect(rpz.content).not.toContain('ok.example.net IN CNAME .\n'); expect(r.files.find((f: any) => f.path === 'named.conf.options').content).toContain('response-policy')
  })
  it('statistiques : import d’un journal BIND, courbes et catégories', async () => {
    const t = new Date(Date.now() - 120000).toISOString()
    const log = `${t} client @0x7f1 10.0.0.5#43210 (example.com): query: example.com IN A + (10.0.0.1)\n${t} client @0x7f1 10.0.0.5#43211 (b.example.com): query: b.example.com IN A + (10.0.0.1)\n${t} rpz: info: client @0x7f1 10.0.0.5#43212 (adulte1.example.net): rpz QNAME NXDOMAIN rewrite adulte1.example.net/A/IN via adulte1.example.net.rpz.ddibuntu.local\n`
    expect((await operator.post('/api/filter/ingest-log', { content: log })).json.events).toBe(3)
    const s = (await viewer.get('/api/filter/stats?range=15m')).json
    expect(s.series.map((x: any) => `${x.kind}:${x.n}`).sort()).toEqual(['blocked:1', 'query:2']); expect(s.byCategory).toEqual([{ category: 'adult', n: '1' }])
    err(await viewer.get('/api/filter/stats?range=99y'), 400, 'invalid_query')
    expect((await viewer.get('/api/dashboard')).json.day.find((d: any) => d.kind === 'blocked').n).toBe('1')
  })
})

describe('import Active Directory et connexion LDAPS', () => {
  it('sites et sous-réseaux AD : aperçu puis import, site renseigné', async () => {
    const csv = '"Name","Site","Location"\n"10.50.0.0/16","CN=Lyon,CN=Sites,CN=Configuration,DC=corp,DC=local","Agence"\n"10.51.1.7/24","Nantes",""\n"n-importe-quoi","Nantes",""\n'
    const pre = (await admin.post('/api/import/ad-subnets/preview', { content: csv })).json
    expect(pre).toMatchObject({ total: 2, new: 2, existing: 0 }); expect(pre.errors).toEqual([{ line: 4, value: 'n-importe-quoi' }])
    expect((await admin.post('/api/import/ad-subnets/commit', { content: csv })).json).toMatchObject({ created: 2 })
    const l = (await admin.get('/api/ipam/subnets')).json.items
    expect(l.find((s: any) => s.cidr === '10.50.0.0/16')).toMatchObject({ site: 'Lyon' }); expect(l.find((s: any) => s.cidr === '10.51.1.0/24')).toMatchObject({ site: 'Nantes' })
  })
  it('CSV IPAM : sous-réseaux puis adresses, lignes invalides signalées', async () => {
    const r1 = (await admin.post('/api/import/ipam-csv/commit', { kind: 'subnets', content: 'cidr,name,description,site,gateway\n10.60.0.0/24,Test,desc,Brest,10.60.0.1\nbad,x,,,\n10.60.0.0/24,doublon,,,\n' })).json
    expect(r1).toMatchObject({ created: 1, skipped: 1 }); expect(r1.errors).toEqual([{ line: 3, code: 'cidr' }])
    const r2 = (await admin.post('/api/import/ipam-csv/commit', { kind: 'addresses', content: 'ip,hostname,mac,status,description\n10.60.0.5,imp-01,aa:bb:cc:00:00:01,used,x\n10.99.9.9,orphelin,,,\n10.60.0.6,imp-02,zz,,\n' })).json
    expect(r2.created).toBe(1); expect(r2.errors.map((e: any) => e.code).sort()).toEqual(['mac', 'no_subnet'])
    expect((await operator.get('/api/import/runs')).json.items.length).toBeGreaterThanOrEqual(4)
  })
  it('paramètres AD : LDAPS obligatoire, mot de passe chiffré et jamais renvoyé, administrateur seulement', async () => {
    const base = { enabled: true, urls: ['ldaps://dc01.corp.local'], baseDn: 'DC=corp,DC=local', bindDn: 'CN=svc,DC=corp,DC=local', bindPassword: 'mdp-de-liaison-tres-secret', userAttr: 'sAMAccountName', groupMap: [{ groupDn: 'CN=DDI-Admins,DC=corp,DC=local', role: 'admin' }], nestedGroups: true, tlsRejectUnauthorized: true }
    err(await admin.put('/api/ad/settings', { ...base, urls: ['ldap://dc01.corp.local'] }), 400, 'validation')
    err(await admin.put('/api/ad/settings', { ...base, urls: [] }), 400, 'ad_incomplete'); err(await admin.put('/api/ad/settings', { ...base, caPem: 'pas un certificat' }), 400, 'validation')
    expect((await admin.put('/api/ad/settings', base)).status).toBe(200)
    const g = await admin.get('/api/ad/settings'); expect(g.text).not.toContain('mdp-de-liaison'); expect(g.json).toMatchObject({ enabled: true, bindPasswordSet: true }); expect(g.json).not.toHaveProperty('bindPasswordEnc')
    expect(JSON.stringify((await db.query("select value from settings where key = 'ad'")).rows[0].value)).not.toContain('mdp-de-liaison')
    err(await operator.get('/api/ad/settings'), 403, 'forbidden'); err(await operator.post('/api/ad/test', {}), 403, 'forbidden')
  })
  it('test de connexion : un annuaire injoignable est signalé proprement, sans fuite', async () => {
    const r = await admin.post('/api/ad/test', {}); expect(r.status).toBe(200); expect(r.json.ok).toBe(false); expect(JSON.stringify(r.json)).not.toMatch(/ECONN|ENOTFOUND|stack|mdp-de-liaison/)
  })
  it('connexion avec AD activé et annuaire injoignable : refus générique, pas d’erreur serveur', async () => {
    const c = new Client(); const r = await c.login('compte.ad', 'Un-Mot-De-Passe-1'); err(r, 401, 'bad_credentials')
    await admin.put('/api/ad/settings', { enabled: false, urls: [], baseDn: '', bindDn: '', userAttr: 'sAMAccountName', groupMap: [], nestedGroups: true, tlsRejectUnauthorized: true })
  })
})

describe('génération, validation et déploiement', () => {
  it('validation : tous les outils officiels acceptent la configuration complète (zones, RPZ, named.conf, Kea)', async () => {
    // zones primaires sans NS au sommet : on complète pour que named-checkzone accepte
    const zones = (await admin.get('/api/dns/zones')).json.items.filter((z: any) => z.type === 'primary')
    for (const z of zones) if (!(await admin.get(`/api/dns/records?zone_id=${z.id}&type=NS&q=@`)).json.items.some((r: any) => r.name === '@')) await admin.post('/api/dns/records', { zone_id: z.id, name: '@', type: 'NS', rdata: 'ns1.example.com.' })
    const r = (await admin.post('/api/system/apply', { deploy: false })).json
    for (const c of r.results) if (c.ok !== true) console.log('   ', c.name, c.output)
    expect(r.results.every((c: any) => c.ok === true)).toBe(true); expect(r.ok).toBe(true); expect(r.deployed).toBe(false)
    const names = r.results.map((c: any) => c.name)
    expect(names).toEqual(expect.arrayContaining(['named-checkconf', 'kea-dhcp4 -t', 'named-checkzone example.com', 'named-checkzone ad.corp.local', 'named-checkzone rpz.ddibuntu.local']))
    expect(existsSync(join(GEN, 'named.conf.zones'))).toBe(false)   // validé mais pas déployé
  })
  it('déploiement : fichiers écrits, numéros de série incrémentés, zones marquées à jour, secret Kea en 0640', async () => {
    const before = (await admin.get('/api/dns/zones')).json.items.find((z: any) => z.name === 'example.com'); expect(before.dirty).toBe(true)
    const r = (await admin.post('/api/system/apply', { deploy: true })).json; expect(r.deployed).toBe(true)
    for (const f of ['named.conf.options', 'named.conf.zones', 'kea-dhcp4.conf', 'zones/db.example.com', 'zones/db.rpz']) expect(existsSync(join(GEN, f)), f).toBe(true)
    const after = (await admin.get('/api/dns/zones')).json.items.find((z: any) => z.name === 'example.com')
    expect(after.dirty).toBe(false); expect(Number(after.serial)).toBeGreaterThan(Number(before.serial)); expect(readFileSync(join(GEN, 'zones/db.example.com'), 'utf8')).toContain(`( ${after.serial} `)
    expect(readFileSync(join(GEN, 'named.conf.zones'), 'utf8')).toContain(`file "${GEN}/zones/db.example.com"`)
    const kea = JSON.parse(readFileSync(join(GEN, 'kea-dhcp4.conf'), 'utf8')).Dhcp4
    expect(kea.subnet4.length).toBeGreaterThanOrEqual(2); expect(kea['lease-database']).toMatchObject({ type: 'postgresql', password: 'secret-base-kea-123' })
    expect((await import('node:fs')).statSync(join(GEN, 'kea-dhcp4.conf')).mode & 0o777).toBe(0o640)
    expect((await admin.get('/api/system/deployments')).json.items[0]).toMatchObject({ ok: true })
  })
  it('un second déploiement sans changement conserve les numéros de série', async () => {
    const s1 = (await admin.get('/api/dns/zones')).json.items.map((z: any) => z.serial); await admin.post('/api/system/apply', { deploy: true })
    expect((await admin.get('/api/dns/zones')).json.items.map((z: any) => z.serial)).toEqual(s1)
  })
  it('une configuration invalide n’est jamais déployée', async () => {
    await db.query("insert into dns_zones (name, type) values ('casse.test', 'primary')")   // zone sans NS : named-checkzone refuse
    const before = readFileSync(join(GEN, 'named.conf.zones'), 'utf8')
    const r = (await admin.post('/api/system/apply', { deploy: true })).json
    expect(r.ok).toBe(false); expect(r.deployed).toBe(false); expect(r.results.find((c: any) => c.name === 'named-checkzone casse.test').ok).toBe(false)
    expect(readFileSync(join(GEN, 'named.conf.zones'), 'utf8')).toBe(before)
    expect((await admin.get('/api/system/deployments')).json.items[0]).toMatchObject({ ok: false })
    await db.query("delete from dns_zones where name = 'casse.test'")
  })
  it('informations système : binaires de validation détectés', async () => {
    const i = (await operator.get('/api/system/info')).json
    expect(i.binaries.every((b: any) => b.ok)).toBe(true); expect(i.recordTypes.length).toBe(18)
  })
})

describe('robustesse : injections, erreurs assainies, audit', () => {
  it('injection SQL et valeurs hostiles : jamais d’erreur 500 ni de fuite', async () => {
    const evil = ["'; drop table users; --", '" OR "1"="1', '\u0000', '%', '\\', 'a'.repeat(5000)]
    for (const e of evil) {
      for (const p of ['/api/ipam/search?q=', '/api/dns/records?q=', '/api/audit?q=', '/api/filter/check?domain=']) { const r = await admin.get(p + encodeURIComponent(e)); expect(r.status, `${p}${e.slice(0, 10)}`).toBeLessThan(500) }
      const r = await admin.post('/api/ipam/vlans', { vlan_id: 300, name: e }); expect(r.status).toBeLessThan(500)
    }
    expect((await db.query('select count(*)::int n from users')).rows[0].n).toBeGreaterThan(3)
  })
  it('erreurs de la base assainies : ni requête, ni nom de colonne, ni trace', async () => {
    const rs = [await admin.get('/api/ipam/subnets/99999999999/addresses'), await admin.get('/api/dns/zones/abc'), await admin.post('/api/ipam/subnets', { cidr: '10.1.1.0/24', name: 'x', vlan_id: 999999 }),
      await admin.post('/api/dns/records', { zone_id: 99999, name: 'a', type: 'A', rdata: '1.1.1.1' }), await admin.get('/api/dns/records?limit=abc'), await admin.post('/api/auth/login', 'pas du json')]
    for (const r of rs) { expect(r.status).toBeLessThan(500); expect(r.text).not.toMatch(/select |insert |violates|constraint|relation|column|ERROR:|at .*\.mjs|node_modules|pg_/i) }
  })
  it('journal d’audit : actions tracées, aucun mot de passe ni secret dans le détail', async () => {
    const a = (await admin.get('/api/audit?limit=500')).json.items
    const actions = new Set(a.map((x: any) => x.action))
    for (const k of ['login', 'login_failed', 'setup_admin', 'user_create', 'subnet_create', 'zone_create', 'record_create', 'scope_create', 'import_dns', 'config_deploy', 'ad_settings']) expect(actions.has(k), k).toBe(true)
    const blob = JSON.stringify(a)
    for (const secret of [PW, 'secret-base-kea-123', 'mdp-de-liaison-tres-secret', 'Nouveau-Mot-De-Passe-1', SETUP_TOKEN]) expect(blob).not.toContain(secret)
    expect(a.find((x: any) => x.action === 'subnet_create').username).toBe('admin')
  })
  it('journal du serveur : aucun secret', async () => {
    for (const secret of [PW, 'secret-base-kea-123', 'mdp-de-liaison-tres-secret', 'cle-secrete-de-test']) expect(srvLog).not.toContain(secret)
  })
})

describe('pages rendues côté serveur : accès, traductions, accessibilité', () => {
  let frKeys: Record<string, string> = {}
  beforeAll(async () => { frKeys = (await import('../app/i18n/fr')).default })
  const PAGES: Array<[string, string, string]> = [
    ['/', 'Tableau de bord', 'Dashboard'], ['/ipam', 'Réseaux', 'Networks'], ['/dns', 'Zones', 'Zones'], ['/dhcp', 'Étendues', 'Scopes'], ['/filtering', 'Listes', 'Lists'], ['/import', 'Zone DNS', 'DNS zone'], ['/system', 'Utilisateurs', 'Users'],
  ]
  it('sans session : redirection vers la connexion pour chaque page', async () => {
    for (const [p] of PAGES) { const r = await anon.get(p); expect([p, r.status, r.headers.get('location')]).toEqual([p, 302, '/login']) }
  })
  it('connexion : formulaire avec étiquettes associées, titre et langue', async () => {
    const r = await anon.get('/login')
    expect(r.status).toBe(200); expect(r.text).toMatch(/<html\s+lang="fr"/); expect(r.text).toContain('Se connecter')
    // chaque étiquette est reliée à son champ (for = id) : accessibilité WCAG 1.3.1 / 3.3.2
    const html = r.text.replace(/<!--.*?-->/g, '')
    const labels = [...html.matchAll(/<label[^>]*\bfor="([^"]+)"[^>]*>([^<]*)<\/label>/g)].map((m) => [m[1]!, m[2]!.trim()])
    expect(labels.map((l) => l[1])).toEqual(['Identifiant', 'Mot de passe'])
    for (const [id] of labels) expect(html, `champ ${id}`).toMatch(new RegExp(`<input[^>]*\\bid="${id}"`))
    expect(html).toMatch(/<h1[^>]*>DDI-Buntu<\/h1>/)
    const en = await new Client('en').get('/login'); expect(en.text).toMatch(/<html\s+lang="en"/); expect(en.text).toContain('Sign in')
  })
  it.each(PAGES)('page %s : rendue en français puis en anglais, sans clé de traduction brute', async (path, fr, en) => {
    const cfr = new Client('fr'); cfr.cookie = admin.cookie; cfr.csrf = admin.csrf
    const a = await cfr.get(path); expect(a.status, path).toBe(200); expect(a.text).toContain(fr)
    const cen = new Client('en'); cen.cookie = admin.cookie
    const b = await cen.get(path); expect(b.status).toBe(200); expect(b.text).toContain(en)
    for (const html of [a.text, b.text]) {
      for (const key of Object.keys(frKeys)) expect(html.includes(`>${key}<`), `clé brute visible : ${key}`).toBe(false)
      expect(html).toContain('aria-label'); expect(html).not.toContain('v-html')
    }
    expect(a.text).toContain('DDI-Buntu')
  })
  it('un lecteur ne voit pas l’entrée Système et est renvoyé hors de la page', async () => {
    const c = new Client('fr'); await c.login('lect', PW)
    const r = await c.get('/ipam'); expect(r.status).toBe(200); expect(r.text).not.toContain('href="/system"')
    const s = await c.get('/system'); expect([301, 302, 200]).toContain(s.status); if (s.status === 302) expect(s.headers.get('location')).toBe('/')
  })
  it('catalogues : mêmes clés en français et en anglais, aucune clé utilisée sans traduction', async () => {
    const fr = (await import('../app/i18n/fr')).default, en = (await import('../app/i18n/en')).default
    expect(Object.keys(fr).sort()).toEqual(Object.keys(en).sort())
    for (const [k, v] of Object.entries(fr)) { expect(v.length, k).toBeGreaterThan(0); expect(((v as string).match(/\{[a-z]+\}/g) ?? []).sort(), k).toEqual((((en as any)[k] as string).match(/\{[a-z]+\}/g) ?? []).sort()) }
    const { readdirSync, readFileSync: rf, statSync } = await import('node:fs')
    const walk = (d: string): string[] => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : /\.(vue|ts)$/.test(f) && !f.includes('i18n') ? [join(d, f)] : []))
    const used = new Set<string>()
    for (const f of walk('app')) for (const m of rf(f, 'utf8').matchAll(/\bt\('([A-Za-z0-9_.]+)'/g)) used.add(m[1]!)
    expect([...used].filter((k) => !(k in fr))).toEqual([])
  })
})
