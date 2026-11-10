// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : espaces IPAM, hiérarchie conteneurs/réseaux, pools, vue transverse des adresses.
import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtempSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3397, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const GEN = mkdtempSync(join(tmpdir(), 'ddi-ipam-'))
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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b); del = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 150)) } throw new Error('délai dépassé') }
const rows = async (sql: string, p: unknown[] = []) => (await db.query(sql, p)).rows
const list = async (q = '') => (await admin.get('/api/ipam/subnets' + q)).json.items as any[]

beforeAll(async () => {
  expect(existsSync('.output/server/index.mjs'), 'lancer « nuxt build » avant les tests').toBe(true)
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })

describe('espaces IPAM', () => {
  it('l’espace « Défaut » existe ; création, doublon, droits, suppression', async () => {
    const sp = (await admin.get('/api/ipam/spaces')).json.items
    expect(sp).toHaveLength(1); expect(sp[0]).toMatchObject({ id: 1, name: 'Défaut', subnets: 0 })
    const b = await admin.post('/api/ipam/spaces', { name: 'Client B', description: 'plan chevauchant' }); expect(b.status).toBe(200)
    code(await admin.post('/api/ipam/spaces', { name: 'client b' }), 409, 'duplicate')
    code(await viewer.post('/api/ipam/spaces', { name: 'x' }), 403, 'forbidden')
    expect((await viewer.get('/api/ipam/spaces')).status).toBe(200)
    code(await admin.del('/api/ipam/spaces/1'), 409, 'space_default')
    const tmp = await admin.post('/api/ipam/spaces', { name: 'temporaire' })
    expect((await admin.put(`/api/ipam/spaces/${tmp.json.id}`, { name: 'temp2' })).status).toBe(200)
    expect((await admin.del(`/api/ipam/spaces/${tmp.json.id}`)).status).toBe(200)
    code(await admin.put('/api/ipam/spaces/9999', { name: 'x' }), 404, 'not_found')
  })
  it('le même CIDR peut exister dans deux espaces, pas deux fois dans le même', async () => {
    const b = (await admin.get('/api/ipam/spaces')).json.items.find((s: any) => s.name === 'Client B').id
    expect((await admin.post('/api/ipam/subnets', { cidr: '10.0.0.0/8', name: 'Racine A', kind: 'container' })).status).toBe(200)
    expect((await admin.post('/api/ipam/subnets', { cidr: '10.0.0.0/8', name: 'Racine B', space_id: b })).status).toBe(200)
    code(await admin.post('/api/ipam/subnets', { cidr: '10.0.0.0/8', name: 'doublon', space_id: b }), 409, 'duplicate')
    code(await admin.post('/api/ipam/subnets', { cidr: '10.9.0.0/16', name: 'x', space_id: 4242 }), 400, 'space_not_found')
    const only = await list(`?space_id=${b}`); expect(only).toHaveLength(1); expect(only[0]).toMatchObject({ space: 'Client B', kind: 'network' })
    code(await admin.del(`/api/ipam/spaces/${b}`), 409, 'space_not_empty')
  })
})

describe('hiérarchie, conteneurs et agrégats', () => {
  it('profondeur, parent, enfants, ordre de parcours, filtre IPv4/IPv6', async () => {
    expect((await admin.post('/api/ipam/subnets', { cidr: '10.1.0.0/16', name: 'Site Paris' })).status).toBe(200)
    const leaf = await admin.post('/api/ipam/subnets', { cidr: '10.1.1.0/24', name: 'Serveurs', gateway: '10.1.1.1' }); expect(leaf.status).toBe(200)
    expect((await admin.post('/api/ipam/subnets', { cidr: '2001:db8:1::/64', name: 'v6' })).status).toBe(200)
    const a = (await list('?space_id=1')).filter((s) => s.family === 4)
    expect(a.map((s) => [s.cidr, s.depth])).toEqual([['10.0.0.0/8', 0], ['10.1.0.0/16', 1], ['10.1.1.0/24', 2]])
    expect(a[1]).toMatchObject({ parent: { cidr: '10.0.0.0/8', name: 'Racine A' }, children: 1 })
    expect(a[0].parent).toBeNull()
    expect(a[0].used_total).toBe(1)                        // l’adresse passerelle du /24 remonte jusqu’au conteneur
    expect(a[0].allocated).toBeGreaterThan(0); expect(a[0].allocated).toBeLessThan(1)   // /16 dans un /8
    expect((await list('?family=6')).every((s) => s.family === 6)).toBe(true)
    expect(a[0].size_label).toBe('16777214')
    expect((await list('?space_id=1&family=6'))[0].size_label).toBe('2^64')
  })
  it('un conteneur ne porte pas d’adresses ; un réseau avec adresses ne devient pas conteneur', async () => {
    const root = (await list('?space_id=1')).find((s) => s.cidr === '10.0.0.0/8')
    code(await admin.post(`/api/ipam/subnets/${root.id}/addresses`, { ip: '10.0.0.5' }), 400, 'container_no_addresses')
    code(await admin.post(`/api/ipam/subnets/${root.id}/next`, {}), 400, 'container_no_addresses')
    code(await admin.post(`/api/ipam/subnets/${root.id}/pools`, { name: 'p', start_ip: '10.0.0.10', end_ip: '10.0.0.20' }), 400, 'container_no_addresses')
    const leaf = (await list('?space_id=1')).find((s) => s.cidr === '10.1.1.0/24')
    code(await admin.put(`/api/ipam/subnets/${leaf.id}`, { kind: 'container' }), 409, 'container_no_addresses')
  })
  it('déplacer un réseau dans un autre espace', async () => {
    const b = (await admin.get('/api/ipam/spaces')).json.items.find((s: any) => s.name === 'Client B').id
    const t = (await admin.post('/api/ipam/subnets', { cidr: '172.16.0.0/24', name: 'mobile' })).json.id
    expect((await admin.put(`/api/ipam/subnets/${t}`, { space_id: b })).status).toBe(200)
    expect((await list(`?space_id=${b}`)).some((s) => s.cidr === '172.16.0.0/24')).toBe(true)
    code(await admin.put(`/api/ipam/subnets/${t}`, { space_id: 4242 }), 400, 'space_not_found')
  })
})

describe('DHCP et espaces', () => {
  it('une étendue DHCP n’est créée que sur un réseau de l’espace par défaut', async () => {
    const b = (await admin.get('/api/ipam/spaces')).json.items.find((s: any) => s.name === 'Client B').id
    const other = (await list(`?space_id=${b}`)).find((s) => s.cidr === '10.0.0.0/8')
    code(await admin.post('/api/dhcp/scopes', { subnet_id: other.id }), 400, 'dhcp_space_only')
    const root = (await list('?space_id=1')).find((s) => s.cidr === '10.0.0.0/8')
    code(await admin.post('/api/dhcp/scopes', { subnet_id: root.id }), 400, 'container_no_addresses')
  })
})

describe('pools d’adresses', () => {
  let sid = 0, pid = 0
  it('création, chevauchement, hors réseau, droits', async () => {
    sid = (await list('?space_id=1')).find((s) => s.cidr === '10.1.1.0/24').id
    const p = await admin.post(`/api/ipam/subnets/${sid}/pools`, { name: 'Postes', start_ip: '10.1.1.10', end_ip: '10.1.1.19' }); expect(p.status).toBe(200); pid = p.json.id
    code(await admin.post(`/api/ipam/subnets/${sid}/pools`, { name: 'chev', start_ip: '10.1.1.15', end_ip: '10.1.1.30' }), 400, 'pool_overlap')
    code(await admin.post(`/api/ipam/subnets/${sid}/pools`, { name: 'dehors', start_ip: '10.1.2.1', end_ip: '10.1.2.5' }), 400, 'pool_outside_subnet')
    code(await admin.post(`/api/ipam/subnets/${sid}/pools`, { name: 'inverse', start_ip: '10.1.1.50', end_ip: '10.1.1.40' }), 400, 'constraint')
    code(await viewer.post(`/api/ipam/subnets/${sid}/pools`, { name: 'x', start_ip: '10.1.1.60', end_ip: '10.1.1.70' }), 403, 'forbidden')
    expect((await admin.put(`/api/ipam/pools/${pid}`, { end_ip: '10.1.1.24' })).status).toBe(200)
    code(await admin.put(`/api/ipam/pools/${pid}`, { end_ip: '10.1.2.24' }), 400, 'pool_outside_subnet')
  })
  it('liste avec taille et utilisation ; allocation dans le pool ; pool plein', async () => {
    const one = (await admin.get(`/api/ipam/pools?subnet_id=${sid}`)).json.items[0]
    expect(one).toMatchObject({ name: 'Postes', start_ip: '10.1.1.10', end_ip: '10.1.1.24', cidr: '10.1.1.0/24', space: 'Défaut', size: 15, used: 0, percent: 0 })
    const r = await admin.post(`/api/ipam/subnets/${sid}/next`, { pool_id: pid, hostname: 'poste-01' }); expect([r.status, r.json.ip]).toEqual([200, '10.1.1.10'])
    expect((await admin.get(`/api/ipam/pools?subnet_id=${sid}`)).json.items[0]).toMatchObject({ used: 1, percent: 6.7 })
    for (let i = 0; i < 14; i++) expect((await admin.post(`/api/ipam/subnets/${sid}/next`, { pool_id: pid })).status).toBe(200)
    code(await admin.post(`/api/ipam/subnets/${sid}/next`, { pool_id: pid }), 409, 'pool_full')
    code(await admin.post(`/api/ipam/subnets/${sid}/next`, { pool_id: 999999 }), 404, 'pool_not_found')
    // sans pool : la plage DHCP seule est exclue, les adresses prises le sont aussi ; le pool IPAM n’est pas exclu
    expect((await admin.post(`/api/ipam/subnets/${sid}/next`, {})).json.ip).toBe('10.1.1.2')
    expect((await admin.get('/api/ipam/pools?q=postes')).json.items).toHaveLength(1)
    const rs = (await list('?space_id=1')).find((s) => s.id === sid); expect(rs.pools).toBe(1); expect(rs.allocated).toBeCloseTo(5.9, 0)
  })
  it('supprimer un pool', async () => {
    expect((await admin.del(`/api/ipam/pools/${pid}`)).status).toBe(200)
    expect((await admin.get(`/api/ipam/pools?subnet_id=${sid}`)).json.items).toHaveLength(0)
  })
})

describe('vue transverse des adresses', () => {
  it('filtres, pagination côté serveur, total', async () => {
    const all = (await admin.get('/api/ipam/addresses?limit=5')).json
    expect(all.total).toBeGreaterThan(10); expect(all.items).toHaveLength(5); expect(all.items[0]).toHaveProperty('space')
    const p2 = (await admin.get('/api/ipam/addresses?limit=5&offset=5')).json; expect(p2.items[0].ip).not.toBe(all.items[0].ip)
    const f = (await admin.get('/api/ipam/addresses?q=poste-01')).json; expect(f.total).toBe(1); expect(f.items[0]).toMatchObject({ hostname: 'poste-01', cidr: '10.1.1.0/24', network: 'Serveurs', space: 'Défaut' })
    expect((await admin.get('/api/ipam/addresses?status=gateway')).json.items.every((a: any) => a.status === 'gateway')).toBe(true)
    expect((await admin.get('/api/ipam/addresses?family=6')).json.total).toBe(0)
    code(await admin.get('/api/ipam/addresses?status=' + 'x'.repeat(300)), 400, 'invalid_query')
    expect((await admin.get('/api/ipam/addresses?q=' + encodeURIComponent("' OR 1=1 --"))).status).toBe(200)
    expect((await anon.get('/api/ipam/addresses')).status).toBe(401)
  })
})

describe('points de restauration et schéma', () => {
  it('un point conserve espaces, conteneurs et pools ; la restauration les rétablit', async () => {
    const sid = (await list('?space_id=1')).find((s) => s.cidr === '10.1.1.0/24').id
    expect((await admin.post(`/api/ipam/subnets/${sid}/pools`, { name: 'Imprimantes', start_ip: '10.1.1.100', end_ip: '10.1.1.109' })).status).toBe(200)
    const snap = (await admin.post('/api/snapshots', { label: 'ipam' })).json.id
    const before = JSON.stringify({ s: await rows('select id, space_id, kind, cidr::text from subnets order by id'), p: await rows('select id, name, start_ip::text, end_ip::text from ipam_pools order by id'), sp: await rows('select id, name from ipam_spaces order by id') })
    expect((await admin.post('/api/ipam/spaces', { name: 'éphémère' })).status).toBe(200)
    await db.query('delete from ipam_pools'); await db.query("update subnets set kind = 'network'")
    const r = await admin.post(`/api/snapshots/${snap}/restore`, {}); expect(r.status, JSON.stringify(r.json)).toBe(200)
    expect(JSON.stringify({ s: await rows('select id, space_id, kind, cidr::text from subnets order by id'), p: await rows('select id, name, start_ip::text, end_ip::text from ipam_pools order by id'), sp: await rows('select id, name from ipam_spaces order by id') })).toBe(before)
    expect((await admin.post('/api/ipam/spaces', { name: 'après restauration' })).status).toBe(200)   // séquence repartie après le plus grand id
    expect((await admin.get(`/api/snapshots/${snap}/diff`)).status).toBe(200)
  })
  it('migration : version 4 appliquée, ancienne contrainte unique(cidr) remplacée', async () => {
    expect((await rows('select max(version)::int v from schema_migrations'))[0].v).toBe(4)
    expect((await rows("select 1 from pg_constraint where conname = 'subnets_cidr_key'"))).toHaveLength(0)
    expect((await rows("select 1 from pg_indexes where indexname = 'subnets_space_cidr'"))).toHaveLength(1)
  })
})
