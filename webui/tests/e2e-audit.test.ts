// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.22.0 — journal d'audit : motif détaillé des échecs de connexion (local, LDAP injoignable, compte désactivé), nom d'utilisateur de la ligne, recherche par motif ou IP
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'; process.env.DDI_ALLOW_UNVERIFIED_AUTH = '1'

const PORT = 3492, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s64-')); mkdirSync(join(TMP, 'gen'))
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
