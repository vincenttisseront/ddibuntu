// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.13.5 — labels IPAM (espaces, réseaux, adresses, VLAN) : pose, filtre, catalogue, renommage, suppression, masse
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

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
