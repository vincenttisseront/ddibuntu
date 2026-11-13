// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.9.52 — MFA obligatoire par rôle.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { hotp, totpStep } from '../server/utils/totp'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3419, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s18-')); mkdirSync(join(TMP, 'gen'))
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
const admin = new Client(), viewer = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }

beforeAll(async () => {
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json'), DDI_OIDC_ALLOW_HTTP: '1' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })

describe('MFA obligatoire par rôle', () => {
  it('politique : réservée à l’administrateur, validée, auditée', async () => {
    code(await anon.get('/api/mfa/policy'), 401, 'unauthenticated')
    let r = await admin.get('/api/mfa/policy'); expect(r.status).toBe(200); expect(r.json.roles).toEqual([]); expect(r.json.pending.admin).toBe(1)
    expect((await admin.put('/api/mfa/policy', { roles: ['root'] })).status).toBe(400)
    expect((await admin.put('/api/mfa/policy', { roles: 'admin' })).status).toBe(400)
  })
  it('sans politique : aucune restriction', async () => {
    expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
    expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
    expect((await admin.get('/api/ipam/spaces')).status).toBe(200)
    const me = await admin.get('/api/auth/me'); expect(me.json.mfaEnrol).toBe(false)
  })
  it('politique « operator » : l’opérateur n’a plus que l’inscription ; les autres rôles ne sont pas touchés', async () => {
    const r = await admin.put('/api/mfa/policy', { roles: ['operator'] }); expect(r.status).toBe(200); expect(r.json.roles).toEqual(['operator']); expect(r.json.pending.operator).toBe(1)
    const op = new Client(); const l = await op.login('oper', PW); expect(l.status).toBe(200); expect(l.json.mfaEnrol).toBe(true)
    code(await op.get('/api/ipam/spaces'), 403, 'mfa_enrol_required')
    code(await op.post('/api/ipam/spaces', { name: 'x' }), 403, 'mfa_enrol_required')
    code(await op.get('/api/auth/sessions'), 403, 'mfa_enrol_required')
    expect((await op.get('/api/auth/me')).json.mfaEnrol).toBe(true)
    expect((await op.get('/api/auth/mfa')).status).toBe(200)
    expect((await op.get('/api/auth/profile')).status).toBe(200)
    expect((await viewer.login('lect', PW)).status).toBe(200); expect((await viewer.get('/api/ipam/spaces')).status).toBe(200)
    expect((await admin.get('/api/ipam/spaces')).status).toBe(200)
  })
  it('l’opérateur s’inscrit (mot de passe + code), puis retrouve ses droits sans se reconnecter', async () => {
    const op = new Client(); expect((await op.login('oper', PW)).status).toBe(200)
    const su = await op.post('/api/auth/mfa/setup', { password: PW }); expect(su.status).toBe(200)
    const secret = su.json.secret
    const en = await op.post('/api/auth/mfa/enable', { code: hotp(secret, totpStep()) }); expect(en.status).toBe(200)
    expect((await op.get('/api/ipam/spaces')).status).toBe(200)
    expect((await op.get('/api/auth/me')).json.mfaEnrol).toBe(false)
    // reconnexion : mot de passe puis second facteur, pas d’inscription à refaire
    const again = new Client(); const l = await again.post('/api/auth/login', { username: 'oper', password: PW }); expect(l.json.mfa).toBe(true)
  })
  it('un compte AD / SSO du rôle visé n’est jamais bloqué (relève de son fournisseur)', async () => {
    await db.query("insert into users (username, role, source) values ('sso-op', 'operator', 'oidc')")
    const r = await db.query("select count(*)::int as n from users where source = 'oidc'"); expect(r.rows[0].n).toBe(1)
    const pol = await admin.get('/api/mfa/policy'); expect(pol.json.pending.operator).toBe(0)   // local seulement : oper inscrit, sso-op ignoré
  })
  it('retrait de la politique : les restrictions disparaissent aussitôt', async () => {
    expect((await admin.put('/api/mfa/policy', { roles: ['operator', 'viewer'] })).status).toBe(200)
    code(await viewer.get('/api/ipam/spaces'), 403, 'mfa_enrol_required')
    expect((await admin.put('/api/mfa/policy', { roles: [] })).status).toBe(200)
    await until(async () => (await viewer.get('/api/ipam/spaces')).status === 200)
    const a = await db.query("select count(*)::int as n from audit_log where action = 'mfa_policy'"); expect(a.rows[0].n).toBeGreaterThanOrEqual(3)
  })
})
