// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : recherche globale multi-modules et carte d'occupation d'un réseau.
import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3396, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s7-'))
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

const S: Record<string, any> = {}
const kinds = (r: any) => (r.json.groups as any[]).map((g) => g.kind)
const group = (r: any, k: string) => (r.json.groups as any[]).find((g) => g.kind === k)

describe('recherche globale', () => {
  it('jeu de données', async () => {
    S.vlan = (await admin.post('/api/ipam/vlans', { vlan_id: 30, name: 'Manuel' })).json
    S.root = (await admin.post('/api/ipam/subnets', { cidr: '10.0.0.0/8', name: 'Tout le site', kind: 'container' })).json
    S.s1 = (await admin.post('/api/ipam/subnets', { cidr: '10.10.0.0/24', name: 'LAN A', site: 'Paris', gateway: '10.10.0.1', vlan_id: S.vlan.id })).json
    S.s2 = (await admin.post('/api/ipam/subnets', { cidr: '10.20.0.0/24', name: 'LAN B' })).json
    expect(S.s1.id).toBeGreaterThan(0)
    for (const [ip, hostname, mac] of [['10.10.0.5', 'srv05', 'aa:bb:cc:dd:ee:01'], ['10.10.0.6', 'srv06', null]] as const)
      expect((await admin.post(`/api/ipam/subnets/${S.s1.id}/addresses`, { ip, status: 'used', hostname, ...(mac ? { mac } : {}) })).status).toBe(200)
    S.z = (await admin.post('/api/dns/zones', { name: 'lab.example.com', type: 'primary', soa_mname: 'ns1.lab.example.com.', soa_rname: 'hostmaster.lab.example.com.' })).json
    expect((await admin.post('/api/dns/records', { zone_id: S.z.id, name: 'www', type: 'A', rdata: '10.10.0.80' })).status).toBe(200)
    S.sc = (await admin.post('/api/dhcp/scopes', { subnet_id: S.s1.id, name: 'scope-paris' })).json
    expect(S.sc.id).toBeGreaterThan(0)
    expect((await admin.post('/api/filter/rules', { domain: 'ads.tracker.example', action: 'block' })).status).toBe(200)
  })
  it('droits : anonyme refusé, lecteur autorisé', async () => {
    code(await anon.get('/api/search?q=paris'), 401, 'unauthenticated')
    expect((await viewer.get('/api/search?q=paris')).status).toBe(200)
  })
  it('moins de 2 caractères : réponse vide, sans requête', async () => {
    for (const q of ['', 'a', ' ']) expect((await admin.get(`/api/search?q=${encodeURIComponent(q)}`)).json).toMatchObject({ total: 0, groups: [] })
  })
  it('texte libre : réseau par site, lien profond vers les adresses du réseau', async () => {
    const r = await admin.get('/api/search?q=paris')
    const n = group(r, 'network')
    expect(n.items.map((i: any) => i.title)).toEqual(['10.10.0.0/24'])
    expect(n.items[0].to).toBe(`/ipam?subnet=${S.s1.id}#addresses`)
  })
  it('adresse IP : réseau le plus précis d\'abord, conteneur ensuite, puis l\'adresse', async () => {
    const r = await admin.get('/api/search?q=10.10.0.5')
    expect(group(r, 'network').items.map((i: any) => i.title)).toEqual(['10.10.0.0/24', '10.0.0.0/8'])
    const a = group(r, 'address')
    expect(a.items[0]).toMatchObject({ title: '10.10.0.5', to: `/ipam?subnet=${S.s1.id}#addresses` })
    expect(a.items[0].subtitle).toContain('srv05')
    expect(kinds(r).indexOf('network')).toBeLessThan(kinds(r).indexOf('address'))
  })
  it('CIDR : réseaux et adresses recoupés, pas les autres', async () => {
    const r = await admin.get('/api/search?q=10.10.0.0/16')
    expect(group(r, 'network').items.map((i: any) => i.title).sort()).toEqual(['10.0.0.0/8', '10.10.0.0/24'])
    expect(group(r, 'address').items.map((i: any) => i.title).sort()).toEqual(['10.10.0.1', '10.10.0.5', '10.10.0.6'])
    expect(JSON.stringify(r.json)).not.toContain('10.20.0.0/24')
  })
  it('MAC : fragment avec séparateurs et adresse complète sans séparateur', async () => {
    for (const q of ['bb:cc:dd', 'AABBCCDDEE01', 'aa-bb-cc'])
      expect(group(await admin.get(`/api/search?q=${encodeURIComponent(q)}`), 'address')?.items[0]?.title, q).toBe('10.10.0.5')
  })
  it('DNS : zone, enregistrement par nom complet et par donnée', async () => {
    const r1 = await admin.get('/api/search?q=www.lab.example')
    expect(group(r1, 'record').items[0]).toMatchObject({ title: 'www.lab.example.com', to: `/dns?zone=${S.z.id}#records` })
    expect(group(r1, 'record').items[0].subtitle).toBe('A 10.10.0.80')
    expect(group(await admin.get('/api/search?q=lab.example'), 'zone').items[0].title).toBe('lab.example.com')
    expect(group(await admin.get('/api/search?q=10.10.0.80'), 'record').items.map((i: any) => i.title)).toContain('www.lab.example.com')
  })
  it('DHCP : étendue par nom et par réseau', async () => {
    expect(group(await admin.get('/api/search?q=scope-paris'), 'scope').items[0]).toMatchObject({ title: 'scope-paris', to: `/dhcp?scope=${S.sc.id}#ranges` })
    expect(group(await admin.get('/api/search?q=10.10.0.9'), 'scope').items[0].title).toBe('scope-paris')
  })
  it('VLAN par numéro exact et par nom', async () => {
    expect(group(await admin.get('/api/search?q=30'), 'vlan').items[0].title).toBe('VLAN 30')
    expect(group(await admin.get('/api/search?q=manuel'), 'vlan').items[0].title).toBe('VLAN 30')
  })
  it('filtrage : règle trouvée par fragment', async () => {
    expect(group(await admin.get('/api/search?q=tracker'), 'filter').items[0].title).toBe('ads.tracker.example')
  })
  it('limite par catégorie : « more » signale des résultats supplémentaires', async () => {
    for (let i = 0; i < 6; i++) await admin.post(`/api/ipam/subnets/${S.s1.id}/addresses`, { ip: `10.10.0.${100 + i}`, status: 'used', hostname: `bulk-${i}` })
    const r = await admin.get('/api/search?q=bulk-&limit=3')
    expect(group(r, 'address')).toMatchObject({ more: true }); expect(group(r, 'address').items).toHaveLength(3)
    const all = await admin.get('/api/search?q=bulk-&limit=50'); expect(group(all, 'address')).toMatchObject({ more: false }); expect(group(all, 'address').items).toHaveLength(6)
  })
  it('jokers LIKE neutralisés : « %% » et « __ » ne correspondent pas à tout', async () => {
    for (const q of ['%%', '__', '\\\\', '%_']) { const r = await admin.get(`/api/search?q=${encodeURIComponent(q)}`); expect([r.status, r.json.total], q).toEqual([200, 0]) }
  })
  it('injection SQL : traitée comme du texte, base intacte', async () => {
    for (const q of ["'; drop table users;--", "\" or 1=1 --", "x'); delete from addresses;--", '10.0.0.1/24; select 1']) expect((await admin.get(`/api/search?q=${encodeURIComponent(q)}`)).status, q).toBe(200)
    expect(Number((await db.query('select count(*) from users')).rows[0].count)).toBe(2)
    expect(Number((await db.query('select count(*) from addresses')).rows[0].count)).toBeGreaterThanOrEqual(8)
  })
  it('entrées démesurées ou NUL : refusées proprement (400)', async () => {
    for (const q of ['a'.repeat(101), 'ab%00cd']) { const r = await admin.get(`/api/search?q=${q}`); code(r, 400, 'invalid_query') }
    expect((await admin.get(`/api/search?q=${'a'.repeat(100)}`)).status).toBe(200)
  })
})

describe('carte d\'occupation d\'un réseau', () => {
  it('droits et erreurs', async () => {
    code(await anon.get(`/api/ipam/subnets/${S.s1.id}/map`), 401, 'unauthenticated')
    expect((await viewer.get(`/api/ipam/subnets/${S.s1.id}/map`)).status).toBe(200)
    code(await admin.get('/api/ipam/subnets/999999/map'), 404, 'not_found')
    code(await admin.get('/api/ipam/subnets/abc/map'), 400, 'invalid_id')
    code(await admin.get(`/api/ipam/subnets/${S.root.id}/map`), 400, 'map_too_large')
    const v6 = (await admin.post('/api/ipam/subnets', { cidr: '2001:db8::/64', name: 'v6' })).json
    code(await admin.get(`/api/ipam/subnets/${v6.id}/map`), 400, 'map_unsupported_family')
  })
  it('états : réseau, diffusion, passerelle, adresses, libres', async () => {
    const m = (await admin.get(`/api/ipam/subnets/${S.s1.id}/map`)).json
    expect([m.cidr, m.base, m.size, m.cells.length]).toEqual(['10.10.0.0/24', '10.10.0.0', 256, 256])
    expect([m.cells[0], m.cells[255], m.cells[1], m.cells[5], m.cells[6], m.cells[2]]).toEqual(['n', 'b', 'g', 'u', 'u', '.'])
    expect(m.counts).toMatchObject({ n: 1, b: 1, g: 1, u: 8 })
    expect(m.items.find((i: any) => i[0] === 5)).toEqual([5, 'srv05', 'aa:bb:cc:dd:ee:01', null])
  })
  it('plages IPAM et DHCP, réservation DHCP ; un occupant l\'emporte sur une plage', async () => {
    expect((await admin.post(`/api/ipam/subnets/${S.s1.id}/pools`, { name: 'serveurs', start_ip: '10.10.0.50', end_ip: '10.10.0.60' })).status).toBe(200)
    expect((await admin.post(`/api/dhcp/scopes/${S.sc.id}/pools`, { start: '10.10.0.200', end: '10.10.0.210' })).status).toBe(200)
    const rs = await admin.post(`/api/dhcp/scopes/${S.sc.id}/reservations`, { mac: '11:22:33:44:55:66', ip: '10.10.0.30', hostname: 'imprimante' })
    expect(rs.status, rs.text).toBe(200)
    expect((await admin.post(`/api/ipam/subnets/${S.s1.id}/addresses`, { ip: '10.10.0.55', status: 'reserved' })).status).toBe(200)
    const m = (await admin.get(`/api/ipam/subnets/${S.s1.id}/map`)).json
    expect([m.cells[50], m.cells[60], m.cells[61]]).toEqual(['p', 'p', '.'])
    expect([m.cells[200], m.cells[210], m.cells[211]]).toEqual(['o', 'o', '.'])
    expect(['v', 'd']).toContain(m.cells[30])
    expect(m.cells[55]).toBe('r')
  })
  it('petits réseaux : /31 sans adresse réseau ni diffusion ; /30 avec', async () => {
    const a = (await admin.post('/api/ipam/subnets', { cidr: '192.168.5.0/31', name: 'p2p' })).json
    expect((await admin.get(`/api/ipam/subnets/${a.id}/map`)).json.cells).toBe('..')
    const b = (await admin.post('/api/ipam/subnets', { cidr: '192.168.6.0/30', name: 'mini' })).json
    expect((await admin.get(`/api/ipam/subnets/${b.id}/map`)).json.cells).toBe('n..b')
  })
  it('un /16 est accepté (65 536 cases)', async () => {
    const c = (await admin.post('/api/ipam/subnets', { cidr: '172.16.0.0/16', name: 'grand' })).json
    const m = (await admin.get(`/api/ipam/subnets/${c.id}/map`)).json
    expect([m.size, m.cells.length]).toEqual([65536, 65536])
  })
})
