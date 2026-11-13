// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.8 — classes de clients DHCP (fabricant, utilisateur, MAC, option 43, rejet).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3431, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s30-')); mkdirSync(join(TMP, 'gen'))
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
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_DIG: join(TMP, 'dig.sh'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json'), DDI_OIDC_ALLOW_HTTP: '1' } })
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

const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const keaConf = async () => JSON.parse((await admin.get('/api/system/render')).json.files.find((f: any) => f.kind === 'kea').content).Dhcp4
const WIN = `<DHCPServer><IPv4><Classes><Class><Name>Cameras</Name><Type>Vendor</Type><Data>41584953</Data></Class><Class><Name>Bin</Name><Type>User</Type><Data>00ff</Data></Class></Classes>
<Filters><Filter><List>Deny</List><MacAddress>AA-BB-CC-DD-EE-FF</MacAddress></Filter><Filter><List>Allow</List><MacAddress>11-22-33-44-55-66</MacAddress></Filter></Filters></IPv4></DHCPServer>`

describe('classes de clients DHCP', () => {
  let cid = 0
  it('droits et validation', async () => {
    const b = { name: 'cam', kind: 'vendor', match: 'AXIS', option43: '01:04:c0:a8:00:01' }
    code(await anon.get('/api/dhcp/classes'), 401, 'unauthenticated'); code(await viewer.post('/api/dhcp/classes', b), 403, 'forbidden')
    expect((await oper.post('/api/dhcp/classes', { ...b, name: 'drop' })).status).toBe(400); expect((await oper.post('/api/dhcp/classes', { ...b, option43: 'zz' })).status).toBe(400)
    expect((await oper.post('/api/dhcp/classes', { ...b, match: "x'y" })).status).toBe(400); expect((await oper.post('/api/dhcp/classes', { ...b, action: 'drop' })).status).toBe(400)
    const r = await oper.post('/api/dhcp/classes', b); expect(r.status, r.text).toBe(200); cid = r.json.id
    expect((await oper.post('/api/dhcp/classes', b)).status).toBe(409)
    expect((await viewer.get('/api/dhcp/classes')).json.items).toMatchObject([{ name: 'cam', option43: '0104c0a80001', action: 'assign' }])
  })
  it('modification, suppression, 404', async () => {
    expect((await oper.put(`/api/dhcp/classes/${cid}`, { name: 'cam', kind: 'vendor', match: 'AXIS', option43: '0102', boot_file: 'pxe.0' })).status).toBe(200)
    expect((await rows('select option43, boot_file from dhcp_classes'))[0]).toEqual({ option43: '0102', boot_file: 'pxe.0' })
    code(await oper.put('/api/dhcp/classes/9999', { name: 'x', kind: 'user', match: 'x' }), 404, 'not_found'); code(await oper.delete('/api/dhcp/classes/9999'), 404, 'not_found')
  })
  it('configuration Kea générée : classes, option 43, classe DROP ; désactivée = absente', async () => {
    expect((await oper.post('/api/dhcp/classes', { name: 'bloque', kind: 'mac', match: 'aa:bb:cc', action: 'drop' })).status).toBe(200)
    let k = await keaConf(); expect(k['client-classes'].map((c: any) => c.name)).toEqual(['cam', 'DROP'])
    expect(k['client-classes'][0]).toMatchObject({ test: "substring(option[60].text,0,4) == 'AXIS'", 'option-data': [{ code: 43, data: '0102' }, { name: 'boot-file-name', data: 'pxe.0' }] })
    expect(k['client-classes'][1].test).toBe('(substring(pkt4.mac,0,3) == 0xaabbcc)')
    await oper.put(`/api/dhcp/classes/${cid}`, { name: 'cam', kind: 'vendor', match: 'AXIS', enabled: false })
    k = await keaConf(); expect(k['client-classes'].map((c: any) => c.name)).toEqual(['DROP'])
  })
  it('import Windows : analyse sans effet, création avec point de restauration, second passage sans doublon', async () => {
    code(await viewer.post('/api/migration/classes/preview', { content: WIN }), 403, 'forbidden'); code(await oper.post('/api/migration/classes/preview', { content: '<x' }), 400, 'dhcp_xml_invalid')
    const before = (await rows('select count(*)::int n from dhcp_classes'))[0].n
    const p = await oper.post('/api/migration/classes/preview', { content: WIN }); expect(p.status, p.text).toBe(200); expect(p.json).toMatchObject({ toCreate: 2, skipped: 2, exists: 0 })
    expect((await rows('select count(*)::int n from dhcp_classes'))[0].n).toBe(before)
    const r = await oper.post('/api/migration/classes/commit', { content: WIN, filename: 'dhcp.xml' }); expect(r.status, r.text).toBe(200); expect(r.json.created).toBe(2); expect(r.json.snapshotId).toBeGreaterThan(0)
    expect((await rows("select name, kind, match, action from dhcp_classes where comment like 'Import%' order by name")).map((x: any) => `${x.name}:${x.action}:${x.match}`)).toEqual(['cameras:assign:AXIS', 'deny-aa-bb-cc-dd-ee-ff:drop:aa:bb:cc:dd:ee:ff'])
    expect((await rows("select count(*)::int n from import_runs where kind = 'dhcp-classes'"))[0].n).toBe(1)
    expect((await oper.post('/api/migration/classes/commit', { content: WIN })).json).toEqual({ created: 0, snapshotId: null })
  })
  it('les classes font partie des points de restauration', async () => {
    const s = await admin.post('/api/snapshots', { label: 'test' }); expect(s.status, s.text).toBe(200)
    await oper.delete(`/api/dhcp/classes/${cid}`)
    const rr = await admin.post(`/api/snapshots/${s.json.id}/restore`, {}); expect(rr.status, rr.text).toBe(200)
    expect((await rows('select count(*)::int n from dhcp_classes where name = $1', ['cam']))[0].n).toBe(1)
  })
})
