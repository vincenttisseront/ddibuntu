// Bout en bout (serveur CONSTRUIT, PostgreSQL réel, et un VRAI contrôleur de domaine Samba AD) : 0.13.4 — import d'un NPS Windows : aperçu sans écriture, groupes
// résolus par SID dans l'annuaire, plan (repris / adapté / non pris en charge), validation sous verrou avec empreinte, secrets (repris chiffrés, générés montrés une
// fois, jamais journalisés), idempotence, règles jamais actives sans demande. Sans l'AD (root, samba, hôte dc1.lab.test) seule la partie « groupes » est ignorée.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { decryptSecret } from '../server/utils/auth'
import { SECRET_RE } from '../server/utils/radius'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3444, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9', BIND_PW = 'Passw0rd-svc-radius-1!'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s43-')), LAB = join(TMP, 'lab'), ROOT = resolve(__dirname, '../..'), GEN = join(TMP, 'gen')
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
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows

// ---- SID réels du labo ----
function sidOf(b64: string): string { const b = Buffer.from(b64, 'base64'); const subs: number[] = []; for (let i = 0; i < b[1]!; i++) subs.push(b.readUInt32LE(8 + 4 * i)); return `S-${b[0]}-${b.readUIntBE(2, 6)}-${subs.join('-')}` }
function labSid(cn: string): string {
  const r = spawnSync('ldapsearch', ['-LLL', '-H', 'ldaps://dc1.lab.test', '-D', 'administrator@lab.test', '-w', 'Passw0rd-Lab-1!', '-b', 'DC=lab,DC=test', `(&(objectCategory=group)(cn=${cn}))`, 'objectSid'],
    { encoding: 'utf8', env: { ...process.env, LDAPTLS_CACERT: join(LAB, 'private/tls/ca.pem') } })
  const m = /objectSid:: (\S+)/.exec(r.stdout); if (!m) throw new Error(`SID de ${cn} introuvable : ${r.stderr}`)
  return sidOf(m[1]!)
}
const S: Record<string, string> = { wifi: 'S-1-5-21-111-222-333-1107', vpn: 'S-1-5-21-111-222-333-1106', gone: 'S-1-5-21-111-222-333-9999', hex: 'S-1-5-21-111-222-333-1109', domUsers: 'S-1-5-21-111-222-333-513' }

const EAP_TLS = '0D00000000000000', PEAP = '1900000000000000'
const client = (name: string, ip: string, secret?: string) => `<${name.replace(/[^A-Za-z0-9]/g, '_')} name="${name}"><Properties><IP_Address dt:dt="string">${ip}</IP_Address>${secret ? `<Shared_Secret dt:dt="string">${secret}</Shared_Secret>` : ''}</Properties></${name.replace(/[^A-Za-z0-9]/g, '_')}>`
const profile = (name: string, eap: string, grant = 1, extra = '') => `<P_${name.replace(/[^A-Za-z0-9]/g, '_')} name="${name}"><Properties><msNPAllowDialin dt:dt="boolean">${grant}</msNPAllowDialin><msEAPConfiguration dt:dt="string">${eap}</msEAPConfiguration>${extra}</Properties></P_${name.replace(/[^A-Za-z0-9]/g, '_')}>`
const policy = (name: string, seq: number, conds: string[], enabled = 1) => `<${name.replace(/[^A-Za-z0-9]/g, '_')} name="${name}"><Properties><Policy_Enabled dt:dt="boolean">${enabled}</Policy_Enabled><msNPSequence dt:dt="i4">${seq}</msNPSequence><msNPAction dt:dt="string">${name}</msNPAction>${conds.map((c) => `<msNPConstraint dt:dt="string">${c}</msNPConstraint>`).join('')}</Properties></${name.replace(/[^A-Za-z0-9]/g, '_')}>`
const SECRET_A = 'Zk3mPq8vTn5wRb7yHc2LdX9a', SECRET_B = 'Hq7nVd4sKf2jXm9tBw6pLz3R', WEAK = 'partage'
function exportXml(): string {
  return `<?xml version="1.0" encoding="UTF-16"?><Root xmlns:dt="urn:schemas-microsoft-com:datatypes"><Children><Microsoft_Internet_Authentication_Service name="Microsoft_Internet_Authentication_Service"><Children>
<Protocols name="Protocols"><Children><Microsoft_Radius_Protocol name="Microsoft_Radius_Protocol"><Children><Clients name="Clients"><Children>
${client('AP Étage 1', '10.43.0.11', SECRET_A)}${client('wlc-1', '10.43.0.2', SECRET_B)}${client('VPN-FW', '10.43.1.1', WEAK)}${client('Switch Core', '10.43.2.0/24')}${client('ap9', 'ap9.corp.local', SECRET_A)}
</Children></Clients></Children></Microsoft_Radius_Protocol></Children></Protocols>
<RadiusProfiles name="RadiusProfiles"><Children>${profile('Admins', EAP_TLS)}${profile('Wifi', PEAP)}${profile('Tous', EAP_TLS)}${profile('Refus', EAP_TLS, 0)}${profile('Legacy', '', 1, '<msNPAuthenticationType2 dt:dt="i4">4</msNPAuthenticationType2>')}${profile('VLAN', EAP_TLS, 1, '<msRADIUSTunnelPvtGroupID dt:dt="string">30</msRADIUSTunnelPvtGroupID>')}</Children></RadiusProfiles>
<NetworkPolicy name="NetworkPolicy"><Children>
${policy('Admins', 1, [`NTGROUPS("${S.vpn}")`, 'MATCH("Client-Friendly-Name=^wlc-1$")'])}
${policy('Wifi', 2, ['MATCH("NAS-Port-Type=^19$")', `USERGROUPS("${S.wifi};${S.gone}")`, 'MATCH("Called-Station-Id=^.*:CorpWiFi$")'])}
${policy('Tous', 3, [`NTGROUPS("${S.domUsers}")`])}
${policy('Refus', 4, [`NTGROUPS("${S.hex}")`])}
${policy('Legacy', 5, [`NTGROUPS("${S.vpn}")`])}
${policy('VLAN', 6, [`NTGROUPS("${S.vpn}")`, 'TIMEOFDAY("Lundi 08:00-18:00")'])}
</Children></NetworkPolicy>
<Proxy_Policies name="Proxy_Policies"><Children>${policy('Use Windows authentication', 1, ['MATCH("User-Name=.*")'])}</Children></Proxy_Policies>
</Children></Microsoft_Internet_Authentication_Service></Children></Root>`
}
const XML = exportXml
const DIRCFG = () => ({ urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test', bindPassword: BIND_PW, tlsRejectUnauthorized: true, caPem: CA })

beforeAll(async () => {
  mkdirSync(GEN, { recursive: true })
  const l = spawnSync('bash', [join(ROOT, 'tests/samba-lab.sh'), 'start', LAB], { encoding: 'utf8', timeout: 150000 })
  lab = l.status === 0; if (!lab) console.warn(`[e2e-iter43] AD réel ignoré (${l.status}) : ${(l.stderr || l.stdout).trim().split('\n').pop()}`)
  else {
    const x = spawnSync('bash', [join(ROOT, 'tests/samba-lab.sh'), 'extra', LAB], { encoding: 'utf8', timeout: 150000 }); if (x.status !== 0) throw new Error(`samba-lab extra : ${x.stderr}`)
    CA = readFileSync(join(LAB, 'private/tls/ca.pem'), 'utf8')
    S.wifi = labSid('grp-wifi'); S.vpn = labSid('grp-vpn'); S.domUsers = labSid('Domain Users')
    S.gone = S.wifi.replace(/-\d+$/, '-99999'); S.hex = S.wifi.replace(/-\d+$/, '-99998')
    // un groupe dont le nom contient « = » : l'annuaire le renvoie avec un échappement hexadécimal (« \3D »), que le serveur RADIUS ne sait pas comparer
    const dn = Buffer.from('CN=eq\\=grp,CN=Users,DC=lab,DC=test').toString('base64')
    const a = spawnSync('ldapmodify', ['-H', 'ldaps://dc1.lab.test', '-D', 'administrator@lab.test', '-w', 'Passw0rd-Lab-1!', '-a'], { input: `dn:: ${dn}\nobjectClass: group\nsAMAccountName: eq-grp\n`, encoding: 'utf8', env: { ...process.env, LDAPTLS_CACERT: join(LAB, 'private/tls/ca.pem') } })
    if (a.status !== 0) throw new Error(`groupe « = » : ${a.stderr}`)
    S.hex = labSid('eq=grp')
  }
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
  expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  expect((await oper.login('oper', PW)).status).toBe(200)
}, 300000)
afterAll(async () => { srv?.kill('SIGTERM'); spawnSync('bash', [join(ROOT, 'tests/samba-lab.sh'), 'stop', LAB]); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

const prev = (extra: Record<string, unknown> = {}) => admin.post('/api/radius/nps/preview', { content: XML(), filename: 'nps.xml', ...extra })
const commit = (digest: string, extra: Record<string, unknown> = {}) => admin.post('/api/radius/nps/commit', { content: XML(), filename: 'nps.xml', digest, ...extra })
const byName = (xs: any[], n: string) => xs.find((x) => x.name === n || x.original === n)
const codes = (x: any) => x.notes.map((n: any) => n.code)

describe('import NPS — droits et fichiers refusés', () => {
  it('administrateur seulement ; 401 sans session', async () => {
    for (const p of ['/api/radius/nps/preview', '/api/radius/nps/commit']) {
      code(await anon.post(p, { content: 'x' }), 401, 'unauthenticated')
      for (const c of [viewer, oper]) code(await c.post(p, { content: 'x' }), 403, 'forbidden')
    }
  })
  it('fichiers refusés avec un code précis, rien n\'est écrit', async () => {
    code(await admin.post('/api/radius/nps/preview', { content: '<a><b></a>' }), 400, 'radius_nps_xml')
    code(await admin.post('/api/radius/nps/preview', { content: '<?xml version="1.0"?><Root><x/></Root>' }), 400, 'radius_nps_not_nps')
    code(await admin.post('/api/radius/nps/preview', { content: '<!DOCTYPE r [<!ENTITY a "b">]><Root/>' }), 400, 'radius_nps_doctype')
    expect((await admin.post('/api/radius/nps/preview', { content: '' })).status).toBe(400)
    expect((await admin.post('/api/radius/nps/preview', { content: XML(), extra: 1 })).status).toBe(400)
    expect((await admin.post('/api/radius/nps/preview', { content: XML(), usages: { x: 'satellite' } })).status).toBe(400)
    expect((await admin.post('/api/radius/nps/commit', { content: XML(), digest: 'pas-une-empreinte' })).status).toBe(400)
    expect(await rows('select 1 from radius_clients')).toHaveLength(0)
  })
})

describe('import NPS — aperçu sans annuaire', () => {
  it('clients planifiés, règles à groupes non reprises avec la raison, aucune écriture, aucun secret dans la réponse', async () => {
    const r = await prev()
    expect(r.status, r.text).toBe(200)
    const p = r.json.plan
    expect(p.directory).toBe('missing')
    expect(byName(p.clients, 'AP Étage 1')).toMatchObject({ status: 'adapted', name: 'ap-etage-1', address: '10.43.0.11/32', secret: 'reused' })
    expect(byName(p.clients, 'VPN-FW')).toMatchObject({ status: 'adapted', secret: 'generated' })
    expect(codes(byName(p.clients, 'ap9'))).toEqual(['address_dns'])
    expect(byName(p.rules, 'Admins')).toMatchObject({ status: 'skipped' })
    expect(byName(p.rules, 'Admins').notes[0]).toMatchObject({ code: 'group_directory', params: { why: 'missing' } })
    expect(byName(p.rules, 'Tous')).toMatchObject({ status: 'adapted', kind: 'user' })   // groupe principal : pas besoin de l'annuaire
    expect(p.connectionPolicies).toBe(1)
    expect(r.json.digest).toMatch(/^[0-9a-f]{64}$/)
    for (const s of [SECRET_A, SECRET_B, WEAK]) expect(r.text).not.toContain(s)
    expect(await rows('select 1 from radius_clients')).toHaveLength(0); expect(await rows('select 1 from radius_rules')).toHaveLength(0)
  })
})

describe('import NPS — groupes résolus par SID dans un vrai annuaire', () => {
  it('annuaire configuré : groupes retrouvés, introuvable et inutilisable signalés', async () => {
    if (!lab) return
    expect((await admin.put('/api/radius/directory', DIRCFG())).status).toBe(200)
    const r = await prev(); expect(r.status, r.text).toBe(200)
    const p = r.json.plan
    expect(p.directory).toBe('ok')
    const a = byName(p.rules, 'Admins')
    expect(a).toMatchObject({ status: 'imported', action: 'accept', clients: ['wlc-1'], enabled: false })
    expect(a.groups).toEqual([{ dn: 'CN=grp-vpn,CN=Users,DC=lab,DC=test', name: 'grp-vpn' }])
    const w = byName(p.rules, 'Wifi')
    expect(w).toMatchObject({ status: 'adapted', kind: 'user', usages: ['wifi'], ssids: ['CorpWiFi'] })
    expect(w.groups.map((g: any) => g.name)).toEqual(['grp-wifi'])
    expect(codes(w)).toEqual(expect.arrayContaining(['group_notfound', 'groups_partial', 'auth_converted', 'port_type']))
    expect(byName(p.rules, 'Refus')).toMatchObject({ status: 'skipped' }); expect(codes(byName(p.rules, 'Refus'))).toEqual(['group_unusable'])
    expect(byName(p.rules, 'Legacy')).toMatchObject({ status: 'skipped' }); expect(codes(byName(p.rules, 'Legacy'))).toEqual(['auth_none'])
    expect(byName(p.rules, 'VLAN').status).toBe('adapted')
    expect(byName(p.rules, 'VLAN').notes).toEqual(expect.arrayContaining([{ code: 'cond_dropped', params: { type: 'TIMEOFDAY' } }, { code: 'attrs_lost', params: { names: 'msRADIUSTunnelPvtGroupID' } }]))
    expect(r.text).not.toContain(BIND_PW)
  })
})

describe('import NPS — validation', () => {
  let digest = ''
  const opts = { usages: { 'wlc-1': 'wifi', 'VPN-FW': 'vpn' }, exclude: ['c:Switch Core'] }
  it('une empreinte qui ne correspond pas : 409, rien d\'écrit ; modification entre l\'aperçu et la validation : 409', async () => {
    code(await commit('0'.repeat(64)), 409, 'radius_nps_changed')
    const r = await prev(); digest = r.json.digest
    // quelqu'un crée un client à la même adresse entre l'aperçu et la validation
    const c = await admin.post('/api/radius/clients', { name: 'intrus', address: '10.43.0.11', usage: 'other' }); expect(c.status).toBe(200)
    code(await commit(digest), 409, 'radius_nps_changed')
    expect(await rows('select 1 from radius_clients where name <> $1', ['intrus'])).toHaveLength(0)
    await db.query('delete from radius_clients')
  })
  it('validation : clients (secrets chiffrés, repris ou générés), règles inactives, usage choisi, journal sans secret', async () => {
    const r0 = await prev(opts); digest = r0.json.digest
    const r = await commit(digest, opts)
    expect(r.status, r.text + srvLog.slice(-800)).toBe(200)
    expect(r.json).toMatchObject({ clients: 3, rules: lab ? 4 : 1, activeRules: 0 })
    expect(r.json.generated.map((g: any) => g.name)).toEqual(['vpn-fw'])
    expect(r.json.generated[0].secret).toMatch(SECRET_RE)
    const cl = await rows('select name, address::text as address, usage, secret_enc, enabled, comment from radius_clients order by name')
    expect(cl.map((c) => [c.name, c.address, c.usage])).toEqual([['ap-etage-1', '10.43.0.11/32', 'other'], ['vpn-fw', '10.43.1.1/32', 'vpn'], ['wlc-1', '10.43.0.2/32', 'wifi']])
    expect(cl.every((c) => c.enabled && /Import NPS/.test(c.comment))).toBe(true)
    // secrets : chiffrés au repos ; ceux du fichier sont repris tels quels, le secret faible est remplacé par celui qui a été montré
    for (const c of cl) expect(c.secret_enc).not.toContain('Zk3m')
    expect(decryptSecret(cl[0].secret_enc)).toBe(SECRET_A); expect(decryptSecret(cl[2].secret_enc)).toBe(SECRET_B)
    expect(decryptSecret(cl[1].secret_enc)).toBe(r.json.generated[0].secret); expect(decryptSecret(cl[1].secret_enc)).not.toBe(WEAK)
    // règles : à la suite, dans l'ordre NPS, jamais actives sans demande
    const ru = await rows('select rank, name, enabled, action, conds, comment from radius_rules order by rank')
    expect(ru.every((x) => x.enabled === false && /^Import NPS · ordre \d/.test(x.comment))).toBe(true)
    expect(ru.map((x) => x.rank)).toEqual(ru.map((_, i) => i + 1))
    if (lab) {
      expect(ru.map((x) => x.name)).toEqual(['Admins', 'Wifi', 'Tous', 'VLAN'])
      expect(ru[0].conds).toMatchObject({ clients: ['wlc-1'], groups: [{ dn: 'CN=grp-vpn,CN=Users,DC=lab,DC=test', name: 'grp-vpn' }] })
      expect(ru[1].conds).toMatchObject({ kind: 'user', usages: ['wifi'], ssids: ['CorpWiFi'] })
    }
    // aucune trace d'un secret dans le journal d'audit, l'historique des imports ni les journaux du serveur
    const trail = JSON.stringify(await rows('select action, detail from audit_log')) + JSON.stringify(await rows('select kind, filename, summary from import_runs'))
    for (const s of [SECRET_A, SECRET_B, WEAK, r.json.generated[0].secret]) { expect(trail).not.toContain(s); expect(srvLog).not.toContain(s) }
    expect((await rows("select summary from import_runs where kind = 'radius-nps'"))[0].summary).toMatchObject({ clients: 3, generatedSecrets: 1 })
    expect((await rows("select 1 from audit_log where action = 'radius_nps_import'")).length).toBe(1)
    // les règles importées sont des règles comme les autres : modifiables, et rien n'attend d'être déployé tant qu'aucune n'est active
    const v = (await admin.get('/api/radius/rules')).json
    expect(v.items).toHaveLength(ru.length); expect(v).toMatchObject({ active: 0, pending: false })
  })
  it('même fichier une seconde fois : tout est « déjà présent », rien n\'est dupliqué', async () => {
    const r = await prev(opts); const p = r.json.plan
    expect(p.clients.filter((c: any) => c.status !== 'skipped' && c.selected)).toEqual([])
    expect(codes(byName(p.clients, 'wlc-1'))).toEqual(['exists'])
    if (lab) expect(codes(byName(p.rules, 'Admins'))).toEqual(['rule_exists'])
    const before = (await rows('select count(*)::int as n from radius_clients'))[0].n
    const c = await commit(r.json.digest, opts); expect(c.status, c.text).toBe(200)
    expect(c.json).toMatchObject({ clients: 0, generated: [] }); expect((await rows('select count(*)::int as n from radius_clients'))[0].n).toBe(before)
  })
  it('« activer » : seules les règles reprises sans réserve sont créées actives, et la liste devient « à déployer »', async () => {
    if (!lab) return
    await db.query('delete from radius_rules')
    const r = await prev({ activate: true }); expect(byName(r.json.plan.rules, 'Admins').enabled).toBe(true); expect(byName(r.json.plan.rules, 'Wifi').enabled).toBe(false)
    const c = await commit(r.json.digest, { activate: true }); expect(c.status, c.text).toBe(200); expect(c.json.activeRules).toBe(1)
    expect((await rows('select name from radius_rules where enabled')).map((x) => x.name)).toEqual(['Admins'])
    expect((await admin.get('/api/radius/rules')).json).toMatchObject({ active: 1, pending: true })
  })
})

describe('import NPS — hors annuaire', () => {
  it('annuaire injoignable : les règles à groupes sont non reprises avec la raison, les clients restent importables', async () => {
    if (!lab) return
    await db.query('delete from radius_rules')
    expect((await admin.put('/api/radius/directory', { ...DIRCFG(), urls: ['ldaps://127.0.0.1:1'] })).status).toBe(200)
    const r = await prev(); expect(r.json.plan.directory).toBe('unreachable')
    expect(byName(r.json.plan.rules, 'Admins').notes[0]).toMatchObject({ code: 'group_directory', params: { why: 'unreachable' } })
  })
})
