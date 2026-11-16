// Bout en bout (serveur CONSTRUIT, PostgreSQL réel, et un VRAI contrôleur de domaine Samba AD en LDAPS) : 0.13.1 — annuaire AD du service RADIUS :
// réglages (mot de passe chiffré, jamais renvoyé), test de liaison par serveur, état d'un compte (activé / désactivé / verrouillé / expiré), groupes imbriqués,
// recherche de groupes, validation de certificat. L'AD réel est fabriqué par tests/samba-lab.sh ; sans ses prérequis (root, samba, ldap-utils, hôte dc1.lab.test),
// seules les vérifications sans annuaire s'exécutent.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3440, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s39-'))
const LAB = join(TMP, 'lab'), ROOT = resolve(__dirname, '../..')
const BIND_PW = 'Passw0rd-svc-radius-1!'
let srv: ChildProcess, db: pg.Client, srvLog = '', lab = false, CA = ''

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
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }

beforeAll(async () => {
  // annuaire réel (peut être ignoré : code 3)
  const l = spawnSync('bash', [join(ROOT, 'tests/samba-lab.sh'), 'start', LAB], { encoding: 'utf8', timeout: 150000 })
  lab = l.status === 0; if (!lab) console.warn(`[e2e-iter39] AD réel ignoré (${l.status}) : ${(l.stderr || l.stdout).trim().split('\n').pop()}`)
  else CA = readFileSync(join(LAB, 'private/tls/ca.pem'), 'utf8')
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: TMP } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  expect((await oper.login('oper', PW)).status).toBe(200)
}, 220000)
afterAll(async () => { srv?.kill('SIGTERM'); spawnSync('bash', [join(ROOT, 'tests/samba-lab.sh'), 'stop', LAB]); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const settings = (over: Record<string, unknown> = {}) => ({ urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test', bindPassword: BIND_PW, tlsRejectUnauthorized: true, caPem: CA, ...over })

describe('annuaire RADIUS — réglages (sans annuaire)', () => {
  it('réservé à l\'administrateur', async () => {
    code(await anon.get('/api/radius/directory'), 401, 'unauthenticated')
    for (const c of [viewer, oper]) {
      code(await c.get('/api/radius/directory'), 403, 'forbidden'); code(await c.put('/api/radius/directory', settings()), 403, 'forbidden')
      code(await c.post('/api/radius/directory/test'), 403, 'forbidden'); code(await c.post('/api/radius/directory/lookup', { kind: 'user', name: 'alice' }), 403, 'forbidden')
      code(await c.get('/api/radius/directory/groups?q=wifi'), 403, 'forbidden')
    }
  })
  it('sans réglages : valeurs par défaut ; test, recherche et groupes refusés (réglages incomplets)', async () => {
    expect((await admin.get('/api/radius/directory')).json).toMatchObject({ urls: [], baseDn: '', bindDn: '', bindPasswordSet: false, tlsRejectUnauthorized: true })
    code(await admin.post('/api/radius/directory/test'), 400, 'radius_dir_incomplete')
    code(await admin.post('/api/radius/directory/lookup', { kind: 'user', name: 'alice' }), 400, 'radius_dir_incomplete')
    code(await admin.get('/api/radius/directory/groups?q=wifi'), 400, 'radius_dir_incomplete')
  })
  it('validation : LDAPS obligatoire (jamais de LDAP en clair), au plus 5 serveurs, PEM valide, champs inconnus refusés', async () => {
    const bad: Array<Record<string, unknown>> = [{ urls: ['ldap://dc1.lab.test'] }, { urls: ['http://dc1'] }, { urls: ['ldaps://dc1/chemin'] }, { urls: ['ldaps://dc1:99999999'] }, { urls: Array.from({ length: 6 }, (_, i) => `ldaps://dc${i}.lab.test`) },
      { caPem: 'pas un certificat' }, { caPem: '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----' }, { baseDn: 'x'.repeat(501) }, { evil: 1 }, { tlsRejectUnauthorized: 'oui' }]
    for (const b of bad) { const r = await admin.put('/api/radius/directory', settings(b)); expect([r.status, JSON.stringify(b).slice(0, 60)], r.text).toEqual([400, JSON.stringify(b).slice(0, 60)]) }
    expect(await rows("select 1 from settings where key='radius_directory'")).toHaveLength(0)
  })
  it('mot de passe : chiffré en base, jamais renvoyé ni journalisé ; conservé s\'il n\'est pas fourni ; effacé sur demande', async () => {
    const r = await admin.put('/api/radius/directory', settings()); expect(r.status, r.text).toBe(200)
    const [row] = await rows("select value from settings where key='radius_directory'")
    expect(row.value.bindPasswordEnc).toBeTruthy(); expect(JSON.stringify(row.value)).not.toContain(BIND_PW)
    const g = await admin.get('/api/radius/directory'); expect(g.json).toMatchObject({ bindPasswordSet: true, baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test' })
    expect(g.text).not.toContain(BIND_PW); expect(g.text).not.toContain('bindPasswordEnc'); expect(g.text).not.toMatch(/"bindPassword"/)
    const enc = row.value.bindPasswordEnc
    expect((await admin.put('/api/radius/directory', settings({ bindPassword: undefined, baseDn: 'DC=lab,DC=test' }))).status).toBe(200)
    expect((await rows("select value from settings where key='radius_directory'"))[0].value.bindPasswordEnc).toBe(enc)
    expect((await admin.put('/api/radius/directory', settings({ bindPassword: undefined, clearPassword: true }))).status).toBe(200)
    expect((await admin.get('/api/radius/directory')).json.bindPasswordSet).toBe(false)
    code(await admin.post('/api/radius/directory/test'), 400, 'radius_dir_incomplete')   // sans mot de passe : jamais de liaison
    expect(JSON.stringify(await rows("select detail from audit_log where action='radius_directory'"))).not.toContain(BIND_PW)
  })
  it('entrées de recherche piégées refusées avant tout accès à l\'annuaire', async () => {
    expect((await admin.put('/api/radius/directory', settings())).status).toBe(200)
    for (const b of [{ kind: 'admin', name: 'x' }, { kind: 'user', name: '' }, { kind: 'user', name: '*)(objectClass=*' }, { kind: 'user', name: 'a'.repeat(257) }, { kind: 'user', name: 'x', extra: 1 }, { name: 'x' }])
      expect((await admin.post('/api/radius/directory/lookup', b)).status, JSON.stringify(b)).toBe(400)
    for (const q of ['', 'a', '*', 'a)(b', '%20%20', 'x'.repeat(101)]) expect((await admin.get(`/api/radius/directory/groups?q=${encodeURIComponent(q)}`)).status, q).toBe(400)
  })
})

describe.skipIf(false)('annuaire RADIUS — contre un vrai Samba AD (LDAPS)', () => {
  const run = (name: string, fn: () => Promise<void>) => it(name, async (ctx) => { if (!lab) return ctx.skip(); await fn() }, 60000)
  run('liaison : succès avec la CA ; un seul serveur sur deux répond → résultat par serveur', async () => {
    expect((await admin.put('/api/radius/directory', settings())).status).toBe(200)
    const r = await admin.post('/api/radius/directory/test'); expect(r.status, r.text).toBe(200)
    expect(r.json).toEqual({ ok: true, attempts: [{ server: 'ldaps://dc1.lab.test', ok: true }] })
    expect((await admin.put('/api/radius/directory', settings({ urls: ['ldaps://127.0.0.1:1', 'ldaps://dc1.lab.test'] }))).status).toBe(200)
    expect((await admin.post('/api/radius/directory/test')).json).toEqual({ ok: true, attempts: [{ server: 'ldaps://127.0.0.1:1', ok: false, reason: 'unreachable' }, { server: 'ldaps://dc1.lab.test', ok: true }] })
  })
  run('diagnostics : certificat non reconnu (tls), mauvais mot de passe (service_bind), validation désactivée acceptée', async () => {
    expect((await admin.put('/api/radius/directory', settings({ caPem: '' }))).status).toBe(200)
    expect((await admin.post('/api/radius/directory/test')).json).toEqual({ ok: false, attempts: [{ server: 'ldaps://dc1.lab.test', ok: false, reason: 'tls' }] })
    code(await admin.post('/api/radius/directory/lookup', { kind: 'user', name: 'alice' }), 502, 'radius_dir_tls')
    expect((await admin.put('/api/radius/directory', settings({ caPem: '', tlsRejectUnauthorized: false }))).status).toBe(200)
    expect((await admin.post('/api/radius/directory/test')).json.ok).toBe(true)
    expect((await admin.put('/api/radius/directory', settings({ bindPassword: 'mauvais-mot-de-passe' }))).status).toBe(200)
    expect((await admin.post('/api/radius/directory/test')).json).toEqual({ ok: false, attempts: [{ server: 'ldaps://dc1.lab.test', ok: false, reason: 'service_bind' }] })
    code(await admin.post('/api/radius/directory/lookup', { kind: 'user', name: 'alice' }), 502, 'radius_dir_bind')
    // pas de 3e essai : le domaine verrouille un compte après 3 mots de passe faux (seuil du lab) et le compte de service serait bloqué pour la suite
    expect((await admin.put('/api/radius/directory', settings())).status).toBe(200)
    expect((await admin.post('/api/radius/directory/test')).json.ok).toBe(true)   // une liaison réussie remet le compteur d'échecs à zéro
    expect((await admin.put('/api/radius/directory', settings({ urls: ['ldaps://127.0.0.1:1'] }))).status).toBe(200)
    code(await admin.post('/api/radius/directory/lookup', { kind: 'user', name: 'alice' }), 502, 'radius_dir_unreachable')
  })
  run('comptes : actif avec groupes directs et imbriqués sur trois niveaux ; désactivé ; expiré ; verrouillé ; introuvable', async () => {
    expect((await admin.put('/api/radius/directory', settings())).status).toBe(200)
    const look = async (kind: string, name: string) => { const r = await admin.post('/api/radius/directory/lookup', { kind, name }); expect(r.status, r.text).toBe(200); return r.json }
    const a = await look('user', 'alice')
    expect(a).toMatchObject({ found: true, kind: 'user', sam: 'alice', upn: 'alice@lab.test', dnsHostName: null, groupsTruncated: false, state: { enabled: true, locked: false, expired: false, usable: true, reasons: [] } })
    expect(a.groups.map((g: any) => `${g.name}${g.direct ? '*' : ''}`)).toEqual(['grp-vpn*', 'grp-wifi-it*', 'grp-tout-acces', 'grp-wifi'])   // « * » = appartenance directe
    expect(a.dn).toBe('CN=alice Test,CN=Users,DC=lab,DC=test')
    expect((await look('user', 'alice@lab.test')).sam).toBe('alice')
    expect((await look('user', 'bob')).state).toMatchObject({ enabled: false, usable: false, reasons: ['disabled'] })
    expect((await look('user', 'carol')).state).toMatchObject({ expired: true, usable: false, reasons: ['expired'], expiresAt: 1555526400000 })
    const d = await look('user', 'dave'); expect(d.state).toMatchObject({ locked: true, usable: false, reasons: ['locked'] })
    expect(d.groups.map((g: any) => g.name)).toEqual(['grp-wifi-it', 'grp-tout-acces', 'grp-wifi'])   // un compte verrouillé garde ses groupes : c'est l'état qui le refuse
    expect(await look('user', 'personne')).toEqual({ server: 'ldaps://dc1.lab.test', found: false, ambiguous: false })
    expect(await look('user', 'PC001$')).toMatchObject({ found: false })   // une machine n'est pas un utilisateur
  })
  run('machines : par nom DNS (SAN) ou nom SAM ; activée / désactivée ; groupes imbriqués', async () => {
    const look = async (name: string) => (await admin.post('/api/radius/directory/lookup', { kind: 'computer', name })).json
    const p1 = await look('pc001.lab.test'); expect(p1).toMatchObject({ found: true, kind: 'computer', sam: 'PC001$', dnsHostName: 'pc001.lab.test', upn: null, state: { usable: true } })
    expect(p1.groups.map((g: any) => g.name)).toEqual(['grp-wifi', 'grp-tout-acces'])
    expect((await look('PC001')).sam).toBe('PC001$'); expect((await look('PC001$')).sam).toBe('PC001$')
    expect((await look('pc002.lab.test')).state).toMatchObject({ usable: false, reasons: ['disabled'] })
    expect(await look('alice')).toMatchObject({ found: false })
  })
  run('recherche de groupes par fragment de nom', async () => {
    const r = await admin.get('/api/radius/directory/groups?q=wifi'); expect(r.status, r.text).toBe(200)
    expect(r.json.groups.map((g: any) => g.name)).toEqual(['grp-wifi', 'grp-wifi-it']); expect(r.json.truncated).toBe(false)
    expect(r.json.groups[0].dn).toBe('CN=grp-wifi,CN=Users,DC=lab,DC=test')
    expect((await admin.get('/api/radius/directory/groups?q=zzzz-inexistant')).json.groups).toEqual([])
    expect((await admin.get(`/api/radius/directory/groups?q=${encodeURIComponent('grp-*')}`)).status).toBe(400)   // pas de joker saisi par l'utilisateur
  })
  run('journal d\'audit : chaque interrogation tracée, sans mot de passe', async () => {
    const a = await rows("select action, detail from audit_log where action like 'radius.directory%' order by id")
    expect(a.map((x) => x.action)).toEqual(expect.arrayContaining(['radius.directory.test', 'radius.directory.lookup']))
    expect(JSON.stringify(a)).not.toContain(BIND_PW); expect(JSON.stringify(a)).not.toContain('mauvais-mot-de-passe')
    expect(a.find((x) => x.action === 'radius.directory.lookup' && x.detail.name === 'alice' && x.detail.found === true)).toBeTruthy()
  })
})
