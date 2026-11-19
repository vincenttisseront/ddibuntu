// Bout en bout (serveur CONSTRUIT, PostgreSQL réel, vrai openssl, et un VRAI contrôleur de domaine Samba AD) : 0.13.3 — règles d'accès du service RADIUS :
// droits, validation, liste ordonnée, suivi des clients renommés / supprimés, avertissements, refus de déployer tant qu'EAP-TLS ou l'annuaire manquent,
// dépôt pour root (données seules, fichiers privés), état « modifications non déployées », et simulation sur de vrais comptes (jeu de cas partagé avec
// tests/b30-radius-rules-live.sh, qui rejoue les mêmes cas sur FreeRADIUS). Sans l'AD (root, samba, hôte dc1.lab.test) seule la partie simulation est ignorée.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3443, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9', BIND_PW = 'Passw0rd-svc-radius-1!'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s41-')), P = join(TMP, 'pki'), LAB = join(TMP, 'lab'), ROOT = resolve(__dirname, '../..')
const GEN = join(TMP, 'gen'), REQ = join(GEN, '.radius-request'), CONF = join(GEN, 'radius-clients.conf'), PKIDIR = join(GEN, 'radius-pki'), AZDIR = join(GEN, 'radius-authz'), STATUS = join(TMP, 'rs.json'), RESULT = join(TMP, 'rr.json')
const FX = JSON.parse(readFileSync(join(ROOT, 'tests/radius-rules-cases.json'), 'utf8'))
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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b); delete = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }
const sh = (script: string) => { const r = spawnSync('bash', ['-c', `set -e; source ${ROOT}/tests/lib-pki.sh; cd ${P}; ${script}`], { encoding: 'utf8' }); if (r.status !== 0) throw new Error(r.stderr); return r.stdout }
const rd = (f: string) => readFileSync(join(P, f), 'utf8')
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
let rootN = 0
/** Le vrai root publie TOUJOURS un résultat après avoir traité une demande : la console s'en sert pour savoir ce qui a été accepté. */
const rootAnswered = () => { try { writeFileSync(RESULT, JSON.stringify({ at: Math.floor(Date.now() / 1000), action: JSON.parse(readFileSync(REQ, 'utf8')).action, ok: true, message: `traité ${++rootN}` })) } catch { /* pas de demande en attente */ } }
const rootDone = () => { rootAnswered(); rmSync(REQ, { force: true }); rmSync(CONF, { force: true }); rmSync(PKIDIR, { recursive: true, force: true }); rmSync(AZDIR, { recursive: true, force: true }) }   // root a traité la demande
const setStatus = (extra: Record<string, unknown> = {}) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, installed: true, version: '3.2.5', configured: true, active: true, enabled: true, clients: 1, ldap_module: true,
  eap: { enabled: false, checkCrl: true }, authz: { enabled: false, rules: 0, servers: [] }, ...extra }))
const rule = (o: Record<string, unknown> = {}) => ({ name: 'Règle', action: 'accept', ...o })
const list = async () => (await admin.get('/api/radius/rules')).json
const GROUP = 'CN=grp-wifi,CN=Users,DC=lab,DC=test'
const ids: Record<string, number> = {}

beforeAll(async () => {
  mkdirSync(P, { recursive: true }); mkdirSync(GEN, { recursive: true })
  sh(`pki_root R "Lab Root"; pki_inter I R "Lab Issuing CA"; pki_issue I srv "radius.lab.test" server "DNS:radius.lab.test"; openssl pkcs12 -export -in srv.pem -inkey srv.key -certfile I/ca.pem -passout pass:p12-pass -out srv.p12 2>/dev/null`)
  const l = spawnSync('bash', [join(ROOT, 'tests/samba-lab.sh'), 'start', LAB], { encoding: 'utf8', timeout: 150000 })
  lab = l.status === 0; if (!lab) console.warn(`[e2e-iter41] AD réel ignoré (${l.status}) : ${(l.stderr || l.stdout).trim().split('\n').pop()}`)
  else { const x = spawnSync('bash', [join(ROOT, 'tests/samba-lab.sh'), 'extra', LAB], { encoding: 'utf8', timeout: 150000 }); if (x.status !== 0) throw new Error(`samba-lab extra : ${x.stderr}`); CA = readFileSync(join(LAB, 'private/tls/ca.pem'), 'utf8') }
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  setStatus()
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_RADIUS_STATUS: STATUS, DDI_RADIUS_RESULT: RESULT, DDI_RADIUS_CRL_MS: '3600000' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  expect((await oper.login('oper', PW)).status).toBe(200)
}, 300000)
afterAll(async () => { srv?.kill('SIGTERM'); spawnSync('bash', [join(ROOT, 'tests/samba-lab.sh'), 'stop', LAB]); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('règles d\'accès — droits et état initial', () => {
  it('lecture : lecteur et plus ; écriture, simulation, ordre : administrateur seulement ; 401 sans session', async () => {
    const writes: Array<[string, string, unknown?]> = [['POST', '/api/radius/rules', rule()], ['PUT', '/api/radius/rules/1', rule()], ['DELETE', '/api/radius/rules/1'], ['PUT', '/api/radius/rules-order', { ids: [] }],
      ['POST', '/api/radius/rules/simulate', { kind: 'user', name: 'a@b.c' }]]
    code(await anon.get('/api/radius/rules'), 401, 'unauthenticated')
    expect((await viewer.get('/api/radius/rules')).status).toBe(200); expect((await oper.get('/api/radius/rules')).status).toBe(200)
    for (const [m, p, b] of writes) { code(await anon.req(m, p, b), 401, 'unauthenticated'); for (const c of [viewer, oper]) code(await c.req(m, p, b), 403, 'forbidden') }
  })
  it('liste vide : aucun avertissement (tout est refusé par défaut), rien à déployer, GET /radius le résume', async () => {
    const v = await list()
    expect(v).toMatchObject({ items: [], warnings: [], problems: [], active: 0, pending: false, max: 200, unknown: [] })
    expect((await viewer.get('/api/radius')).json.rules).toEqual({ active: 0, pending: false })
  })
})

describe('règles d\'accès — validation et liste ordonnée', () => {
  it('entrées refusées : champs inconnus, noms et caractères interdits, bornes, attributs hors liste blanche, refus avec réponse', async () => {
    const bad: unknown[] = [{ ...rule(), x: 1 }, rule({ name: '' }), rule({ name: 'a'.repeat(81) }), rule({ name: 'a\nb' }), rule({ action: 'peut-etre' }), rule({ kind: 'robot' }),
      rule({ reply: { vlan: 0 } }), rule({ reply: { vlan: 4095 } }), rule({ reply: { sessionTimeout: 10 } }), rule({ reply: { pool: 'a b' } }), rule({ reply: { filterId: "x'y" } }),
      rule({ reply: { attrs: [{ name: 'Service-Type', value: 'x' }] } }), rule({ reply: { attrs: [{ name: 'Aruba-User-Role', value: 'a"b' }] } }), rule({ action: 'reject', reply: { vlan: 5 } }),
      rule({ ssids: ["a'b"] }), rule({ ssids: ['a'.repeat(33)] }), rule({ clients: ['Mauvais Nom'] }), rule({ usages: ['satellite'] }),
      rule({ groups: [{ dn: 'CN=g"x,DC=y', name: '' }] }), rule({ groups: [{ dn: 'CN=${HOME},DC=y', name: '' }] }), rule({ groups: [{ dn: 'CN=%{x},DC=y', name: '' }] }), rule({ groups: [{ dn: 'sans-egal-du-tout', name: '' }] }),
      rule({ groups: [{ dn: 'CN=g,DC=y', name: '' }, { dn: 'cn=G,dc=y', name: '' }] })]
    for (const b of bad) { const r = await admin.post('/api/radius/rules', b); expect([r.status, JSON.stringify(b).slice(0, 80)], r.text).toEqual([400, JSON.stringify(b).slice(0, 80)]) }
    expect((await list()).items).toEqual([])
  })
  it('création (rang à la suite), lecture, modification, suppression ; identifiants inconnus', async () => {
    const a = await admin.post('/api/radius/rules', rule({ name: 'Wi-Fi tous', groups: [{ dn: GROUP, name: 'grp-wifi' }], usages: ['wifi'], reply: { vlan: 130, pool: 'wifi-pool' }, comment: 'essai' }))
    expect(a.status, a.text).toBe(200); ids.a = a.json.id
    const b = await admin.post('/api/radius/rules', rule({ name: 'Refus VPN', action: 'reject', kind: 'computer' })); ids.b = b.json.id
    const c = await admin.post('/api/radius/rules', rule({ name: 'Désactivée', enabled: false, groups: [{ dn: GROUP, name: '' }] })); ids.c = c.json.id
    const v = await list()
    expect(v.items.map((x: any) => [x.name, x.rank, x.enabled, x.action])).toEqual([['Wi-Fi tous', 1, true, 'accept'], ['Refus VPN', 2, true, 'reject'], ['Désactivée', 3, false, 'accept']])
    expect(v.items[0]).toMatchObject({ comment: 'essai', conds: { kind: null, usages: ['wifi'], clients: [], ssids: [], groups: [{ dn: GROUP, name: 'grp-wifi' }] }, reply: { vlan: 130, pool: 'wifi-pool' } })
    expect(v.items[2].conds.groups[0].name).toBe('grp-wifi')   // nom déduit du DN quand il n'est pas fourni
    expect(v.numbers).toEqual({ [ids.a]: 1, [ids.b]: 2 })       // les règles désactivées n'ont pas de numéro : c'est le numéro des journaux de FreeRADIUS
    expect((await admin.put(`/api/radius/rules/${ids.b}`, rule({ name: 'Refus machines', action: 'reject', kind: 'computer', enabled: true }))).status).toBe(200)
    expect((await list()).items[1].name).toBe('Refus machines')
    code(await admin.put('/api/radius/rules/99999', rule()), 404, 'not_found'); code(await admin.delete('/api/radius/rules/99999'), 404, 'not_found')
    expect((await admin.put(`/api/radius/rules/${ids.b}`, rule({ reply: { vlan: 1 }, action: 'reject' }))).status).toBe(400)
    expect((await admin.delete(`/api/radius/rules/${ids.c}`)).status).toBe(200); expect((await list()).items).toHaveLength(2)
  })
  it('nouvel ordre : permutation exacte exigée (sinon 409), rang réécrit, numéros suivent', async () => {
    code(await admin.put('/api/radius/rules-order', { ids: [ids.a] }), 409, 'radius_rules_changed')
    code(await admin.put('/api/radius/rules-order', { ids: [ids.a, ids.a] }), 409, 'radius_rules_changed')
    code(await admin.put('/api/radius/rules-order', { ids: [ids.a, 424242] }), 409, 'radius_rules_changed')
    expect((await admin.put('/api/radius/rules-order', { ids: 'x' })).status).toBe(400)
    expect((await admin.put('/api/radius/rules-order', { ids: [ids.b, ids.a] })).status).toBe(200)
    const v = await list(); expect(v.items.map((x: any) => x.id)).toEqual([ids.b, ids.a]); expect(v.numbers).toEqual({ [ids.b]: 1, [ids.a]: 2 })
    expect((await admin.put('/api/radius/rules-order', { ids: [ids.a, ids.b] })).status).toBe(200)
  })
  it('plafond de 200 règles', async () => {
    await db.query(`insert into radius_rules (rank, name, action, conds, reply) select 100 + g, 'bulk ' || g, 'reject', '{"kind":null,"groups":[],"clients":[],"usages":[],"ssids":[]}', '{}' from generate_series(1, 198) g`)
    code(await admin.post('/api/radius/rules', rule({ name: 'de trop' })), 409, 'radius_rules_too_many')
    await db.query("delete from radius_rules where name like 'bulk %'")
  })
})

describe('règles d\'accès — clients : renommage, suppression, désactivation', () => {
  it('une règle désigne ses clients par leur nom : le renommage la suit ; un client supprimé ne l\'élargit JAMAIS (elle ne s\'applique plus nulle part) et un avertissement le dit', async () => {
    const mk = async (name: string, address: string, usage: string, enabled = true) => (await admin.post('/api/radius/clients', { name, address, usage, enabled })).json.id as number
    const c1 = await mk('wifi-ctrl', '10.0.0.1', 'wifi'), c2 = await mk('vpn-gw', '10.0.0.2', 'vpn'); await mk('sw1', '10.0.0.3', 'switch'); await mk('arret', '10.0.0.4', 'wifi', false)
    const r = await admin.post('/api/radius/rules', rule({ name: 'Contrôleur', clients: ['wifi-ctrl', 'vpn-gw'], groups: [{ dn: GROUP, name: '' }] })); ids.d = r.json.id
    expect((await admin.put(`/api/radius/clients/${c1}`, { name: 'wifi-ctrl2', address: '10.0.0.1', usage: 'wifi', enabled: true })).status).toBe(200)
    expect((await list()).items.find((x: any) => x.id === ids.d).conds.clients).toEqual(['vpn-gw', 'wifi-ctrl2'])
    expect((await admin.put(`/api/radius/clients/${c1}`, { name: 'wifi-ctrl', address: '10.0.0.1', usage: 'wifi', enabled: true })).status).toBe(200)
    expect((await admin.delete(`/api/radius/clients/${c2}`)).status).toBe(200)
    let v = await list()
    expect(v.items.find((x: any) => x.id === ids.d).conds.clients).toEqual(['vpn-gw', 'wifi-ctrl'])   // le nom disparu reste écrit : la règle ne vise plus que wifi-ctrl
    expect(v.unknown).toEqual([{ id: ids.d, names: ['vpn-gw'] }]); expect(v.warnings).toContainEqual({ code: 'unknown_client', rule: v.numbers[ids.d], names: ['vpn-gw'] })
    expect((await admin.delete(`/api/radius/clients/${(await rows("select id from radius_clients where name='wifi-ctrl'"))[0].id}`)).status).toBe(200)
    v = await list(); expect(v.warnings.map((w: any) => w.code)).toContain('empty_nas')
    expect((await admin.delete(`/api/radius/rules/${ids.d}`)).status).toBe(200)
  })
})

describe('règles d\'accès — déploiement', () => {
  it('règles actives mais EAP-TLS non configuré : refus (409), rien n\'est déposé', async () => {
    const r = await admin.post('/api/radius/apply'); code(r, 409, 'radius_authz_not_ready'); expect(r.json.data.problems).toContain('eap_required')
    expect(existsSync(REQ)).toBe(false); expect(existsSync(AZDIR)).toBe(false)
    expect((await list()).problems).toContain('eap_required')
  })
  it('EAP-TLS prêt mais annuaire incomplet : refus', async () => {
    expect((await admin.post('/api/radius/pki/cas', { pem: rd('R/ca.pem') + rd('I/ca.pem') })).status).toBe(200)
    expect((await admin.post('/api/radius/pki/server/import', { p12Base64: readFileSync(join(P, 'srv.p12')).toString('base64'), p12Password: 'p12-pass' })).status).toBe(200)
    expect((await admin.put('/api/radius/pki/options', { checkCrl: false })).status).toBe(200)
    const r = await admin.post('/api/radius/apply'); code(r, 409, 'radius_authz_not_ready'); expect(r.json.data.problems).toEqual(['directory_incomplete'])
  })
  it('réglages d\'annuaire que root refuserait (mot de passe avec « ${ », URL en clair) : signalés AVANT le dépôt', async () => {
    const put = (o: Record<string, unknown>) => admin.put('/api/radius/directory', { urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test', bindPassword: BIND_PW, tlsRejectUnauthorized: true, ...o })
    expect((await put({ bindPassword: 'abc${HOME}def' })).status).toBe(200)
    let r = await admin.post('/api/radius/apply'); code(r, 409, 'radius_authz_not_ready'); expect(r.json.data.problems).toEqual(['directory_chars'])
    expect((await put({ bindPassword: BIND_PW, baseDn: 'DC=a"b' })).status).toBe(200)
    r = await admin.post('/api/radius/apply'); expect(r.json.data.problems).toEqual(['directory_settings'])
    expect((await put({ baseDn: 'DC=lab,DC=test', caPem: lab ? CA : undefined })).status).toBe(200)
  })
  it('module LDAP absent (état publié par root) : refus avec le bon motif', async () => {
    setStatus({ ldap_module: false })
    const r = await admin.post('/api/radius/apply'); code(r, 409, 'radius_authz_not_ready'); expect(r.json.data.problems).toEqual(['ldap_module_missing'])
    setStatus()
  })
  it('tout est prêt : demande « apply + pki + authz », dossier de données privé, mot de passe de liaison seulement dans ldap.json', async () => {
    const r = await admin.post('/api/radius/apply'); expect(r.status, r.text).toBe(200)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'apply', pki: true, authz: true })
    expect(readdirSync(AZDIR).sort()).toEqual(lab ? ['ldap-ca.pem', 'ldap.json', 'rules.json'] : ['ldap.json', 'rules.json'])
    for (const f of readdirSync(AZDIR)) expect(statSync(join(AZDIR, f)).mode & 0o777, f).toBe(0o600)
    const rules = JSON.parse(readFileSync(join(AZDIR, 'rules.json'), 'utf8')).rules
    expect(rules.map((x: any) => x.name)).toEqual(['Wi-Fi tous', 'Refus machines']); expect(rules[0]).toMatchObject({ action: 'accept', kind: null, groups: [GROUP], nas: [], reply: { vlan: 130, pool: 'wifi-pool' } })
    expect(Object.keys(rules[0]).sort()).toEqual(['action', 'groups', 'kind', 'name', 'nas', 'reply', 'ssids'])
    expect(JSON.parse(readFileSync(join(AZDIR, 'ldap.json'), 'utf8'))).toMatchObject({ urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test', bindPassword: BIND_PW, tlsRejectUnauthorized: true })
    expect(readFileSync(join(AZDIR, 'rules.json'), 'utf8')).not.toContain(BIND_PW)
    expect((await list()).pending).toBe(false); expect((await viewer.get('/api/radius')).json.rules).toEqual({ active: 2, pending: false })
    code(await admin.post('/api/radius/apply'), 409, 'request_pending')
    rootDone()
  })
  it('« modifications non déployées » : toute modification de règle, de client utile ou d\'annuaire; pas pour un commentaire', async () => {
    expect((await list()).pending).toBe(false)
    expect((await admin.put(`/api/radius/rules/${ids.a}`, rule({ name: 'Wi-Fi tous', groups: [{ dn: GROUP, name: 'grp-wifi' }], usages: ['wifi'], reply: { vlan: 131, pool: 'wifi-pool' } }))).status).toBe(200)
    expect((await list()).pending).toBe(true)
    expect((await admin.post('/api/radius/apply')).status).toBe(200); rootDone(); expect((await list()).pending).toBe(false)
    expect((await admin.put('/api/radius/rules-order', { ids: [(await list()).items[1].id, ids.a] })).status).toBe(200); expect((await list()).pending).toBe(true)   // l'ordre compte
    expect((await admin.post('/api/radius/apply')).status).toBe(200); rootDone(); expect((await list()).pending).toBe(false)
    expect((await admin.put('/api/radius/rules-order', { ids: [ids.a, (await list()).items[0].id] })).status).toBe(200)
    expect((await admin.post('/api/radius/apply')).status).toBe(200); rootDone()
    const cur = (await list()).items.find((x: any) => x.id === ids.a)
    expect((await admin.put(`/api/radius/rules/${ids.a}`, rule({ name: 'Wi-Fi tous', groups: cur.conds.groups, usages: ['wifi'], reply: cur.reply, comment: 'autre commentaire' }))).status).toBe(200)
    expect((await list()).pending).toBe(false)
    expect((await admin.put('/api/radius/directory', { urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test', bindPassword: 'Autre-mot-de-passe-1', tlsRejectUnauthorized: true, caPem: lab ? CA : undefined })).status).toBe(200)
    expect((await list()).pending).toBe(true)   // changer le mot de passe de liaison se voit, sans que le mot de passe ne figure nulle part
    expect((await admin.put('/api/radius/directory', { urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test', bindPassword: BIND_PW, tlsRejectUnauthorized: true, caPem: lab ? CA : undefined })).status).toBe(200)
    expect((await list()).pending).toBe(false)
  })
  it('plus aucune règle active : déploiement sans dossier de règles (refus par défaut), et la liste dit qu\'il y a des changements à déployer', async () => {
    for (const it of (await list()).items) expect((await admin.delete(`/api/radius/rules/${it.id}`)).status).toBe(200)
    expect((await list()).pending).toBe(true)
    const r = await admin.post('/api/radius/apply'); expect(r.status, r.text).toBe(200)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'apply', pki: true }); expect(existsSync(AZDIR)).toBe(false)
    expect((await list()).pending).toBe(false); rootDone()
  })
  it('un dépôt ancien non traité ne survit pas à un nouveau déploiement sans règles', async () => {
    mkdirSync(AZDIR, { recursive: true }); writeFileSync(join(AZDIR, 'ldap.json'), '{"bindPassword":"vieux"}')
    expect((await admin.post('/api/radius/apply')).status).toBe(200); expect(existsSync(AZDIR)).toBe(false); rootDone()
  })
  it('secrets : ni mot de passe de liaison ni clé dans les réponses, la base en clair ou le journal d\'audit', async () => {
    const all = (await admin.get('/api/radius/rules')).text + (await admin.get('/api/radius')).text + (await admin.get('/api/radius/directory')).text
    for (const s of [BIND_PW, 'PRIVATE KEY', 'bindPasswordEnc']) expect(all, s).not.toContain(s)
    const aud = JSON.stringify(await rows("select action, detail from audit_log where action like 'radius%'")); expect(aud).not.toContain(BIND_PW)
    expect(aud).toContain('radius_rule_create'); expect(aud).toContain('radius_rule_order'); expect(aud).toContain('radius_rule_delete')
    expect(JSON.stringify(await rows("select value from settings where key='radius_directory'"))).not.toContain(BIND_PW)
  })
})

describe('règles d\'accès — simulation sur un annuaire réel (jeu de cas partagé avec FreeRADIUS)', () => {
  const clientIds: Record<string, number> = {}
  it('entrées strictes comme le moteur réel : UPN pour un utilisateur, nom DNS pour une machine', async () => {
    code(await admin.post('/api/radius/rules/simulate', { kind: 'user', name: 'alice' }), 400, 'radius_sim_upn')
    code(await admin.post('/api/radius/rules/simulate', { kind: 'computer', name: 'PC001' }), 400, 'radius_sim_dns')
    for (const b of [{ kind: 'robot', name: 'a@b.c' }, { kind: 'user', name: 'a@b.c', x: 1 }, { kind: 'user', name: 'a*@b.c' }, { kind: 'user', name: 'a@b.c', ssid: "x'y" }, { kind: 'user', name: 'a@b.c', clientId: 0 }])
      expect((await admin.post('/api/radius/rules/simulate', b)).status, JSON.stringify(b)).toBe(400)
  })
  it('annuaire non réglé : erreur claire', async () => {
    await db.query("delete from settings where key='radius_directory'")
    code(await admin.post('/api/radius/rules/simulate', { kind: 'user', name: 'alice@lab.test' }), 400, 'radius_dir_incomplete')
    expect((await admin.put('/api/radius/directory', { urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test', bindPassword: BIND_PW, tlsRejectUnauthorized: true, caPem: lab ? CA : undefined })).status).toBe(200)
  })
  it('annuaire injoignable : la simulation répond « refusé, annuaire indisponible » (c\'est ce que fait le service), avec le motif', async () => {
    const cur = (await admin.get('/api/radius/directory')).json
    expect((await admin.put('/api/radius/directory', { urls: ['ldaps://127.0.0.1:1'], baseDn: cur.baseDn, bindDn: cur.bindDn, tlsRejectUnauthorized: false })).status).toBe(200)
    const r = await admin.post('/api/radius/rules/simulate', { kind: 'user', name: 'alice@lab.test' }); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ decision: 'reject', stage: 'directory', code: 'directory_unavailable', account: null }); expect(r.json.directoryError).toMatch(/^radius_dir_/)
    expect((await admin.put('/api/radius/directory', { urls: ['ldaps://dc1.lab.test'], baseDn: cur.baseDn, bindDn: cur.bindDn, tlsRejectUnauthorized: true, caPem: lab ? CA : undefined })).status).toBe(200)
  })
  it('liste des règles et clients du jeu de cas (créés par l\'API, comme un administrateur)', async () => {
    for (const it of (await list()).items) await admin.delete(`/api/radius/rules/${it.id}`)
    for (const c of await rows('select id from radius_clients')) await admin.delete(`/api/radius/clients/${c.id}`)
    for (const [i, c] of FX.clients.entries()) { const r = await admin.post('/api/radius/clients', { name: c.name, address: `10.1.0.${i + 1}`, usage: c.usage, enabled: c.enabled }); expect(r.status, r.text).toBe(200); clientIds[c.name] = r.json.id }
    for (const r of FX.rules) { const x = await admin.post('/api/radius/rules', r); expect(x.status, x.text).toBe(200) }
    const v = await list(); expect(v.items).toHaveLength(FX.rules.length); expect(Object.keys(v.numbers)).toHaveLength(7)
    expect(v.warnings.map((w: any) => w.code).sort()).toEqual(['empty_nas', 'unknown_client'])   // la règle « Client disparu »
  })
  for (const k of FX.cases) {
    it(`cas « ${k.id} »`, async (ctx) => {
      if (!lab) return ctx.skip()
      const kind = k.who.includes('@') ? 'user' : 'computer'
      const r = await admin.post('/api/radius/rules/simulate', { kind, name: k.who, clientId: clientIds[k.client], ssid: k.ssid })
      expect(r.status, r.text).toBe(200)
      expect([r.json.decision, r.json.code], JSON.stringify(r.json.trace)).toEqual([k.expect.decision, k.expect.code])
      if (k.expect.rule) expect(r.json.rule).toBe(k.expect.rule); else expect(r.json.rule).toBeNull()
      const get = (n: string) => r.json.reply.find((a: any) => a.name === n)?.value
      expect(get('Tunnel-Private-Group-Id')).toBe(k.expect.vlan ? String(k.expect.vlan) : undefined); expect(get('Framed-Pool')).toBe(k.expect.pool)
      if (k.expect.timeout) expect(get('Session-Timeout')).toBe(String(k.expect.timeout)); if (k.expect.filter) expect(get('Filter-Id')).toBe(k.expect.filter)
      for (const [n, v] of Object.entries(k.expect.attrs ?? {})) expect(get(n)).toBe(v)
      if (r.json.account) expect(JSON.stringify(r.json)).not.toContain(BIND_PW)
    })
  }
  it('Called-Station-Id : le SSID en est tiré comme le fait le service ; client désactivé : rien à simuler ; la trace dit pourquoi une règle n\'a pas correspondu', async (ctx) => {
    if (!lab) return ctx.skip()
    const r = await admin.post('/api/radius/rules/simulate', { kind: 'user', name: 'alice@lab.test', clientId: clientIds['wifi-ctrl'], calledStationId: 'AA-BB-CC-DD-EE-FF:Corp Wifi' })
    expect(r.json).toMatchObject({ code: 'rule_accept', rule: 2 })
    const t = r.json.trace as any[]; expect(t[0]).toMatchObject({ n: 1, matched: false, conds: [{ type: 'kind', ok: false, wanted: ['computer'], got: 'user' }, { type: 'groups', ok: true }] })   // alice est bien dans grp-vpn : seul le type de compte (machine) la fait écarter de la règle 1
    code(await admin.post('/api/radius/rules/simulate', { kind: 'user', name: 'alice@lab.test', clientId: clientIds['arret'] }), 409, 'radius_sim_client_disabled')
    code(await admin.post('/api/radius/rules/simulate', { kind: 'user', name: 'alice@lab.test', clientId: 987654 }), 404, 'not_found')
    expect(r.json.account).toMatchObject({ displayName: expect.any(String), state: { usable: true }, groupsTruncated: false }); expect(r.json.account.groups.map((g: any) => g.name)).toContain('grp-tout-acces')
  })
  it('la simulation est journalisée sans secret', async () => {
    const aud = await rows("select detail from audit_log where action = 'radius.rules.simulate'"); expect(aud.length).toBeGreaterThan(0)
    expect(JSON.stringify(aud)).not.toContain(BIND_PW)
  })
})
