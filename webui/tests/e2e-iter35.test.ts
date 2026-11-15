// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.12.17 — l'authentification AD / LDAP ne s'active qu'avec une connexion testée (liaison réussie) ; toute modification de la connexion exige un nouveau test.
import { connFingerprint } from '../server/utils/auth-verify'
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3436, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s35-')); mkdirSync(join(TMP, 'gen'))
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


const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const AD = (o: Record<string, unknown> = {}) => ({ enabled: false, urls: ['ldaps://dc-inexistant.invalid'], baseDn: 'DC=corp,DC=example,DC=com', bindDn: 'CN=svc,DC=corp,DC=example,DC=com', bindPassword: 'secret-123', userAttr: 'sAMAccountName', groupMap: [{ groupDn: 'CN=Admins,DC=corp,DC=example,DC=com', role: 'admin' }], nestedGroups: true, tlsRejectUnauthorized: true, ...o })
const markVerifiedInDb = async (key: string) => {
  const v = (await rows('select value from settings where key = $1', [key]))[0]!.value
  const fp = connFingerprint(v)
  await db.query("insert into settings (key, value) values ($1, $2::jsonb) on conflict (key) do update set value = excluded.value", [`${key}_verified`, JSON.stringify({ fp, at: 1 })])
}
describe('Active Directory : activation seulement avec une connexion opérationnelle', () => {
  it('activer sans test préalable : refusé ; enregistrer désactivée : accepté', async () => {
    code(await admin.put('/api/ad/settings', AD({ enabled: true })), 409, 'auth_not_verified')
    expect((await admin.put('/api/ad/settings', AD())).status).toBe(200)
    expect((await admin.get('/api/ad/settings')).json).toMatchObject({ enabled: false, verified: false })
  })
  it('test échoué (contrôleur injoignable) : toujours impossible à activer', async () => {
    const t = await admin.post('/api/ad/test', {}); expect(t.status).toBe(200); expect(t.json.ok).toBe(false)
    expect((await admin.get('/api/ad/settings')).json.verified).toBe(false)
    code(await admin.put('/api/ad/settings', AD({ enabled: true })), 409, 'auth_not_verified')
  })
  it('connexion validée (liaison réussie enregistrée) : activation possible', async () => {
    await markVerifiedInDb('ad')
    expect((await admin.get('/api/ad/settings')).json.verified).toBe(true)
    expect((await admin.put('/api/ad/settings', AD({ enabled: true, bindPassword: undefined }))).status).toBe(200)
    expect((await admin.get('/api/ad/settings')).json).toMatchObject({ enabled: true, verified: true })
  })
  it('déjà active : modifier autre chose que la connexion (groupes) reste permis', async () => {
    expect((await admin.put('/api/ad/settings', AD({ enabled: true, bindPassword: undefined, groupMap: [{ groupDn: 'CN=Ops,DC=corp,DC=example,DC=com', role: 'operator' }] }))).status).toBe(200)
  })
  it('modifier la connexion (Base DN, serveur, mot de passe, TLS) : nouveau test exigé', async () => {
    code(await admin.put('/api/ad/settings', AD({ enabled: true, bindPassword: undefined, baseDn: 'DC=autre,DC=example,DC=com' })), 409, 'auth_not_verified')
    code(await admin.put('/api/ad/settings', AD({ enabled: true, bindPassword: undefined, urls: ['ldaps://dc2.example.com'] })), 409, 'auth_not_verified')
    code(await admin.put('/api/ad/settings', AD({ enabled: true, bindPassword: 'nouveau-mot-de-passe' })), 409, 'auth_not_verified')
    code(await admin.put('/api/ad/settings', AD({ enabled: true, bindPassword: undefined, tlsRejectUnauthorized: false })), 409, 'auth_not_verified')
    expect((await admin.get('/api/ad/settings')).json).toMatchObject({ enabled: true, baseDn: 'DC=corp,DC=example,DC=com', verified: true })   // rien n'a été modifié
    expect((await admin.put('/api/ad/settings', AD({ enabled: false, bindPassword: undefined, baseDn: 'DC=autre,DC=example,DC=com' }))).status).toBe(200)   // désactivée : accepté
    expect((await admin.get('/api/ad/settings')).json).toMatchObject({ enabled: false, verified: false })
  })
  it('réservé aux administrateurs', async () => { code(await oper.put('/api/ad/settings', AD({ enabled: true })), 403, 'forbidden') })
})
describe('LDAP générique : même règle', () => {
  const LD = (o: Record<string, unknown> = {}) => ({ enabled: false, urls: ['ldaps://ldap-inexistant.invalid'], baseDn: 'ou=people,dc=x', bindDn: 'cn=r,dc=x', bindPassword: 'secret-123', userFilter: '(uid={u})', userAttr: 'uid', displayAttr: 'cn', groupMode: 'memberOf', groupBaseDn: '', groupFilter: '', groupMap: [{ groupDn: 'cn=a,ou=groups,dc=x', role: 'admin' }], tlsRejectUnauthorized: true, ...o })
  it('activation refusée sans test, acceptée après validation, nouveau test si la connexion change', async () => {
    code(await admin.put('/api/ldap/settings', LD({ enabled: true })), 409, 'auth_not_verified')
    expect((await admin.put('/api/ldap/settings', LD())).status).toBe(200)
    expect((await admin.get('/api/ldap/settings')).json.verified).toBe(false)
    await markVerifiedInDb('ldap')
    expect((await admin.get('/api/ldap/settings')).json.verified).toBe(true)
    expect((await admin.put('/api/ldap/settings', LD({ enabled: true, bindPassword: undefined }))).status).toBe(200)
    code(await admin.put('/api/ldap/settings', LD({ enabled: true, bindPassword: undefined, baseDn: 'ou=autres,dc=x' })), 409, 'auth_not_verified')
    expect((await admin.put('/api/ldap/settings', LD({ enabled: true, bindPassword: undefined, userFilter: '(&(uid={u})(objectClass=person))' }))).status).toBe(200)   // hors connexion
  })
})
