// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.9.28 — traçabilité des baux (historique IP / MAC / nom).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3418, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s17-')); mkdirSync(join(TMP, 'gen'))
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
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })




const cfgBody = (o: any = {}) => ({ enabled: true, urls: ['ldaps://127.0.0.1:1'], baseDn: 'ou=people,dc=x', bindDn: 'cn=svc,dc=x', bindPassword: 'mdp-de-liaison-secret', userFilter: '(&(objectClass=inetOrgPerson)(uid={u}))', userAttr: 'uid', displayAttr: 'cn',
  groupMode: 'memberOf', groupBaseDn: '', groupFilter: '(member={dn})', groupMap: [{ groupDn: 'cn=admins,ou=groups,dc=x', role: 'admin' }, { groupDn: 'cn=paris,ou=groups,dc=x', role: 'operator', spaceIds: [2] }], tlsRejectUnauthorized: true, ...o })

describe('Connexion LDAP générique', () => {
  it('réglages : administrateur seulement, validés, mot de passe de liaison chiffré et jamais relu', async () => {
    code(await viewer.get('/api/ldap/settings'), 403, 'forbidden'); code(await viewer.put('/api/ldap/settings', cfgBody()), 403, 'forbidden'); code(await viewer.post('/api/ldap/test', {}), 403, 'forbidden')
    code(await admin.put('/api/ldap/settings', cfgBody({ userFilter: 'uid=x' })), 400, 'ldap_bad_filter')
    code(await admin.put('/api/ldap/settings', cfgBody({ userFilter: '(uid=fixe)' })), 400, 'ldap_bad_filter')               // sans {u} : tout le monde serait « fixe »
    code(await admin.put('/api/ldap/settings', cfgBody({ groupMode: 'search', groupFilter: '(objectClass=group)' })), 400, 'ldap_bad_filter')
    expect((await admin.put('/api/ldap/settings', cfgBody({ urls: ['ldap://clair.example'] }))).status).toBe(400)         // pas de LDAP en clair
    expect((await admin.put('/api/ldap/settings', cfgBody({ userAttr: 'uid)(x' }))).status).toBe(400)
    code(await admin.put('/api/ldap/settings', cfgBody({ urls: [] })), 400, 'ldap_incomplete')
    code(await admin.put('/api/ldap/settings', cfgBody({ groupMap: [] })), 400, 'ldap_no_mapping')
    const ok = await admin.put('/api/ldap/settings', cfgBody()); expect(ok.status, ok.text).toBe(200)
    const g = await admin.get('/api/ldap/settings'); expect(g.json).toMatchObject({ enabled: true, bindPasswordSet: true, baseDn: 'ou=people,dc=x', groupMode: 'memberOf' }); expect(JSON.stringify(g.json)).not.toContain('mdp-de-liaison-secret')
    expect((await db.query("select value::text v from settings where key = 'ldap'")).rows[0].v).not.toContain('mdp-de-liaison-secret')
    // sans nouveau mot de passe : le précédent est conservé ; avec clearPassword : effacé
    expect((await admin.put('/api/ldap/settings', cfgBody({ bindPassword: undefined }))).status).toBe(200); expect((await admin.get('/api/ldap/settings')).json.bindPasswordSet).toBe(true)
    expect((await admin.put('/api/ldap/settings', cfgBody({ bindPassword: undefined, clearPassword: true }))).status).toBe(200); expect((await admin.get('/api/ldap/settings')).json.bindPasswordSet).toBe(false)
    expect((await admin.put('/api/ldap/settings', cfgBody())).status).toBe(200)
    expect((await db.query("select count(*)::int n from audit_log where action = 'ldap_settings'")).rows[0].n).toBeGreaterThanOrEqual(3)
  })
  it('test de connexion : annuaire injoignable → échec propre, sans détail interne', async () => {
    const t = await admin.post('/api/ldap/test', {}); expect(t.status).toBe(200); expect(t.json.ok).toBe(false); expect(['bind', 'connect']).toContain(t.json.step)
    expect((await admin.post('/api/ldap/test', { username: 'bob)(uid=*' })).status).toBe(400)
  })
  it('annuaire injoignable : l’inconnu est refusé comme un mauvais mot de passe, les comptes locaux fonctionnent toujours', async () => {
    const r = await anon.post('/api/auth/login', { username: 'bob', password: 'n-importe-quoi' }); code(r, 401, 'bad_credentials')
    expect((await db.query("select 1 from users where username = 'bob'")).rowCount).toBe(0)
    expect((await anon.post('/api/auth/login', { username: 'admin', password: PW })).status).toBe(200)
  })
  it('compte LDAP existant : aucune connexion locale, refus si l’annuaire est injoignable ou désactivé ; désactivé = refusé', async () => {
    await db.query("insert into users (username, display_name, role, source) values ('carole', 'Carole', 'viewer', 'ldap')")
    code(await anon.post('/api/auth/login', { username: 'carole', password: PW }), 401, 'bad_credentials')
    expect((await admin.put('/api/ldap/settings', cfgBody({ enabled: false }))).status).toBe(200)
    code(await anon.post('/api/auth/login', { username: 'carole', password: PW }), 401, 'bad_credentials')
    code(await anon.post('/api/auth/login', { username: 'bob', password: 'x' }), 401, 'bad_credentials')
    const l = await admin.get('/api/users'); expect(l.json.items.find((u: any) => u.username === 'carole')).toMatchObject({ source: 'ldap', totp_enabled: false })
  })
})

describe('Profil et sessions', () => {
  it('profil : identité, origine, MFA, périmètre', async () => {
    const a = await admin.get('/api/auth/profile'); expect(a.json).toMatchObject({ username: 'admin', role: 'admin', source: 'local', mfa: false, spaces: null, replica: false }); expect(a.json.lastLogin).toBeTruthy()
    await db.query("update users set space_ids = (select array_agg(id) from ipam_spaces) where username = 'lect'")
    const sp = (await db.query('select id, name from ipam_spaces order by lower(name)')).rows
    expect((await viewer.get('/api/auth/profile')).json).toMatchObject({ username: 'lect', role: 'viewer', spaces: sp })
    expect((await new Client().get('/api/auth/profile')).status).toBe(401)
  })
  it('sessions : liste personnelle, session courante signalée, fermeture d’une autre session, jamais celle d’autrui ni la sienne', async () => {
    const second = new Client(); expect((await second.login('lect', PW)).status).toBe(200)
    const l = (await viewer.get('/api/auth/sessions')).json; expect(l.items.length).toBe(2); expect(l.items.filter((s: any) => s.current).length).toBe(1)
    const cur = l.items.find((s: any) => s.current), other = l.items.find((s: any) => !s.current)
    code(await viewer.delete(`/api/auth/sessions/${cur.id}`), 400, 'current_session')
    code(await admin.delete(`/api/auth/sessions/${other.id}`), 404, 'not_found')                                  // la session d'un autre utilisateur
    expect((await viewer.delete(`/api/auth/sessions/${other.id}`)).status).toBe(200)
    expect((await second.get('/api/auth/me')).json.user).toBeFalsy()                                           // la session fermée ne marche plus
    const adminList = (await admin.get('/api/auth/sessions')).json.items; expect(adminList.every((s: any) => s.id !== other.id)).toBe(true)
    const third = new Client(); await third.login('lect', PW)
    const r = await viewer.post('/api/auth/sessions/revoke-others', {}); expect(r.json.count).toBe(1); expect((await third.get('/api/auth/me')).json.user).toBeFalsy()
    expect((await viewer.get('/api/auth/me')).json.user.username).toBe('lect')
    expect((await db.query("select count(*)::int n from audit_log where action in ('session_revoked','sessions_revoked')")).rows[0].n).toBe(2)
  })
})
