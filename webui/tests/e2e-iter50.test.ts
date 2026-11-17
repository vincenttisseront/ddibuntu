// Bout en bout (serveur CONSTRUIT, PostgreSQL réel, et un VRAI contrôleur de domaine Samba AD en LDAPS) : 0.14.2 — publication automatique des autorités de la PKI du
// DDI dans l'Active Directory. Les certificats sont de vrais certificats openssl ; l'annuaire est relu avec ldapsearch (pas avec le code testé) pour constater ce
// qui a réellement été écrit. La délégation proposée par la console est APPLIQUÉE pour de vrai avec samba-tool : la commande est donc validée, pas seulement
// écrite. Sans les prérequis du laboratoire (root, samba, ldap-utils, hôte dc1.lab.test) seules les vérifications sans annuaire s'exécutent.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3477, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s46-'))
const LAB = join(TMP, 'lab'), ROOT = resolve(__dirname, '../..'), GEN = join(TMP, 'gen'), CADIR = join(TMP, 'ca'), CAS = join(TMP, 'pki-cas.json'), PKI = join(TMP, 'pki')
const ADM_PW = 'Passw0rd-Lab-1!', SVC_PW = 'Passw0rd-svc-pki-1!', SVC = 'svc-ddi-pki@lab.test', NODELEG_PW = 'Passw0rd-nodeleg-1!', NODELEG = 'svc-nodeleg@lab.test'
const CONFIG_NC = 'CN=Configuration,DC=lab,DC=test'
const ROOTS = `CN=Certification Authorities,CN=Public Key Services,CN=Services,${CONFIG_NC}`, AIA = `CN=AIA,CN=Public Key Services,CN=Services,${CONFIG_NC}`
let srv: ChildProcess, db: pg.Client, srvLog = '', lab = false, CA = ''

class Client {
  cookie = ''; csrf = ''
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { cookie: this.cookie }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* fichier */ }
    return { status: r.status, json, text, headers: r.headers }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows

// ---- Certificats réels (openssl) ----
const sh = (cmd: string, args: string[], o: Record<string, unknown> = {}) => { const r = spawnSync(cmd, args, { encoding: 'utf8', ...o }); if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} : ${r.stderr}`); return r.stdout }
const EXT = 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
let seq = 0
function mkCert(cn: string, signer?: { cert: string; key: string }): { cert: string; key: string; pem: string } {
  const base = join(TMP, `c${++seq}`), key = base + '.key', cert = base + '.pem'
  const subj = `/CN=${cn}/O=Lab/C=FR`, ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1']
  if (!signer) sh('openssl', ['req', '-x509', ...ec, '-nodes', '-keyout', key, '-out', cert, '-subj', subj, '-days', '3650', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
  else {
    writeFileSync(base + '.ext', EXT)
    sh('openssl', ['req', '-new', ...ec, '-nodes', '-keyout', key, '-out', base + '.csr', '-subj', subj])
    sh('openssl', ['x509', '-req', '-in', base + '.csr', '-CA', signer.cert, '-CAkey', signer.key, '-CAcreateserial', '-out', cert, '-days', '1800', '-extfile', base + '.ext'])
  }
  return { cert, key, pem: readFileSync(cert, 'utf8') }
}
const derOf = (pem: string) => Buffer.from(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64')
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex')
const shaOfPem = (pem: string) => sha(derOf(pem))

// ---- Fixtures de la PKI (ce que root publie) ----
const ca = (o: Record<string, unknown>) => ({ name: 'Lab-Root', kind: 'root', state: 'active', status: 1, dn: 'CN=Lab Root CA,O=Lab,C=FR', issuer: 'CN=Lab Root CA,O=Lab,C=FR', selfSigned: true, serial: 'ab', notBefore: '2026-01-01T00:00:00Z',
  notAfter: '2036-01-01T00:00:00Z', keyAlg: 'EC', keyBits: 256, curve: 'prime256v1', sigAlg: 'ecdsa-with-SHA256', pathLen: null, sha256: 'a'.repeat(64), signedBy: 'self', alg: 'ecp256', createdAt: 1700000000, extRoot: null,
  crlUrl: '', certUrl: '', crl: null, files: { cert: true, chain: false, csr: false, crl: false }, ...o })
const place = (name: string, pem: string) => { mkdirSync(join(CADIR, name), { recursive: true }); writeFileSync(join(CADIR, name, 'cert.pem'), pem) }
const publishFixture = (cas: unknown[]) => writeFileSync(CAS, JSON.stringify({ at: 1700000000, ok: true, hostname: 'pki.lab.test', port: 8080, cas }))
const certs: Record<string, ReturnType<typeof mkCert>> = {}
const FIXTURE = () => [
  ca({ name: 'Lab-Root', kind: 'root' }),
  ca({ name: 'Lab-Sub', kind: 'issuing', selfSigned: false, signedBy: 'Lab-Root' }),
  ca({ name: 'ExtRoot-0a1b2c3d', kind: 'extroot', state: 'external', status: 6, signedBy: '' }),
  ca({ name: 'Lab-Wait', kind: 'issuing', state: 'waiting', status: 2, selfSigned: false, signedBy: 'external', files: { cert: false, chain: true, csr: true, crl: false } }),
]

// ---- Annuaire réel : outils de laboratoire ----
const PY = ['/usr/bin/python3.12', '/usr/bin/python3'].find((p) => existsSync(p) && spawnSync(p, ['-c', 'import ldb']).status === 0) ?? ''
const sambaTool = (args: string[]) => { const r = spawnSync(PY, [spawnSync('bash', ['-c', 'command -v samba-tool'], { encoding: 'utf8' }).stdout.trim(), ...args, `--configfile=${join(LAB, 'etc/smb.conf')}`], { encoding: 'utf8' }); return r }
const ldap = (cmd: string, args: string[], input?: string) => spawnSync(cmd, ['-H', 'ldaps://dc1.lab.test', '-D', 'administrator@lab.test', '-w', ADM_PW, ...args], { encoding: 'utf8', input, env: { ...process.env, LDAPTLS_CACERT: join(LAB, 'private/tls/ca.pem') } })
/** Empreinte du certificat que l'AD porte réellement (relue par ldapsearch), ou null si l'objet n'existe pas. */
function adSha(container: string, name: string): string | null {
  const r = ldap('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', `CN=${name},${container}`, '-s', 'base', 'cACertificate'])
  if (r.status === 32) return null
  if (r.status !== 0) throw new Error(`ldapsearch ${name} : ${r.stderr}`)
  const m = /^cACertificate:: (.+)$/m.exec(r.stdout)
  return m ? sha(Buffer.from(m[1]!, 'base64')) : null
}
const adDelete = (container: string, name: string) => { const r = ldap('ldapdelete', [`CN=${name},${container}`]); expect(r.status, r.stderr).toBe(0) }
const live = (name: string, fn: () => Promise<void>) => it(name, async () => { if (!lab) return; await fn() }, 120000)

const own = (over: Record<string, unknown> = {}) => ({ enabled: false, source: 'own', urls: ['ldaps://dc1.lab.test'], tlsRejectUnauthorized: true, caPem: CA, bindDn: SVC, bindPassword: SVC_PW, repair: 'auto', ...over })

beforeAll(async () => {
  for (const d of [GEN, CADIR, PKI]) mkdirSync(d, { recursive: true })
  const l = spawnSync('bash', [join(ROOT, 'tests/samba-lab.sh'), 'start', LAB], { encoding: 'utf8', timeout: 150000 })
  lab = l.status === 0 && !!PY; if (!lab) console.warn(`[e2e-iter50] AD réel ignoré (${l.status}) : ${(l.stderr || l.stdout).trim().split('\n').pop()}`)
  else {
    CA = readFileSync(join(LAB, 'private/tls/ca.pem'), 'utf8')
    for (const [u, p] of [['svc-ddi-pki', SVC_PW], ['svc-nodeleg', NODELEG_PW]] as const) { const r = sambaTool(['user', 'create', u, p]); expect(r.status, r.stderr).toBe(0) }
  }
  certs.root = mkCert('Lab Root CA'); certs.sub = mkCert('Lab Issuing CA', certs.root); certs.ext = mkCert('Offline Root CA')
  place('Lab-Root', certs.root.pem); place('Lab-Sub', certs.sub.pem); place('ExtRoot-0a1b2c3d', certs.ext.pem)
  publishFixture(FIXTURE())
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_PKI_STATUS: join(PKI, 'status.json'), DDI_PKI_RESULT: join(PKI, 'result.json'),
    DDI_PKI_CAS: CAS, DDI_PKI_CA_DIR: CADIR, DDI_PKI_AD_MS: '0' } })   // 0 : pas de tâche de fond, les passages sont déclenchés par le test
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

describe('publication AD — droits, valeurs par défaut, validation (sans annuaire)', () => {
  it('réservé à l\'administrateur (toutes les routes)', async () => {
    const calls: Array<[string, string, unknown?]> = [['GET', '/api/pki/ad'], ['PUT', '/api/pki/ad', own()], ['POST', '/api/pki/ad/test', {}], ['POST', '/api/pki/ad/publish', {}], ['POST', '/api/pki/ad/reconcile', {}],
      ['POST', '/api/pki/ad/Lab-Root/withdraw', { confirm: 'Lab-Root' }], ['GET', '/api/pki/ad/script']]
    for (const [m, p, b] of calls) {
      code(await anon.req(m, p, b), 401, 'unauthenticated')
      for (const c of [viewer, oper]) code(await c.req(m, p, b), 403, 'forbidden')
    }
  })
  it('sans réglages : désactivée, incomplète ; les trois autorités à certificat sont publiables, pas celle qui attend sa signature', async () => {
    const r = await admin.get('/api/pki/ad')
    expect(r.status, r.text).toBe(200)
    expect(r.json.settings).toMatchObject({ enabled: false, source: 'radius', urls: [], bindDn: '', bindPasswordSet: false, caSet: false, repair: 'auto', tlsRejectUnauthorized: true, configNc: null })
    expect(r.json).toMatchObject({ complete: false, eligible: 3, delegation: null })
    expect(r.json.publications.map((p: any) => [p.name, p.container, p.state]).sort()).toEqual([['ExtRoot-0a1b2c3d', 'roots', 'not_published'], ['Lab-Root', 'roots', 'not_published'], ['Lab-Sub', 'aia', 'not_published']])
    code(await admin.post('/api/pki/ad/test', {}), 400, 'pkiad_incomplete')
    code(await admin.post('/api/pki/ad/publish', {}), 409, 'pkiad_disabled')
    code(await admin.post('/api/pki/ad/reconcile', {}), 409, 'pkiad_disabled')
    code(await admin.post('/api/pki/ad/publish', { name: 'Inconnue' }), 404, 'not_found')
    code(await admin.post('/api/pki/ad/publish', { name: 'Lab-Wait' }), 404, 'not_found')   // pas de certificat : rien à publier
    code(await admin.post('/api/pki/ad/publish', { republish: true }), 400, 'validation')   // « republier » désigne une autorité
    const cas = await admin.get('/api/pki/cas')
    expect(cas.json.adEnabled).toBe(false); expect(cas.json.cas.every((c: any) => c.publication === null)).toBe(true)
  })
  it('validation : LDAPS obligatoire, au plus 5 serveurs, PEM de certificat seulement, champs inconnus refusés ; rien n\'est enregistré', async () => {
    const bad: Array<Record<string, unknown>> = [{ urls: ['ldap://dc1.lab.test'] }, { urls: ['http://dc1'] }, { urls: ['ldaps://dc1/chemin'] }, { urls: ['ldaps://dc1:99999999'] }, { urls: Array.from({ length: 6 }, (_, i) => `ldaps://dc${i}.lab.test`) },
      { caPem: 'pas un certificat' }, { caPem: '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----' }, { bindDn: 'x'.repeat(501) }, { bindDn: 'a\u0000b' }, { evil: 1 }, { tlsRejectUnauthorized: 'oui' },
      { repair: 'jamais' }, { source: 'autre' }, { enabled: 'oui' }, { bindPassword: 'x'.repeat(201) }]
    for (const b of bad) { const r = await admin.put('/api/pki/ad', own(b)); expect([r.status, JSON.stringify(b).slice(0, 50)], r.text).toEqual([400, JSON.stringify(b).slice(0, 50)]) }
    const { enabled: _e, ...noEnabled } = own(); code(await admin.put('/api/pki/ad', noEnabled), 400, 'validation')
    code(await admin.put('/api/pki/ad', own({ enabled: true, source: 'radius' })), 400, 'pkiad_incomplete')          // l'annuaire RADIUS n'a pas de serveur
    code(await admin.put('/api/pki/ad', own({ enabled: true, bindPassword: undefined })), 400, 'pkiad_incomplete')    // pas de mot de passe
    code(await admin.put('/api/pki/ad', own({ enabled: true, urls: [] })), 400, 'pkiad_incomplete')
    expect(await rows("select 1 from settings where key='pki_ad'")).toHaveLength(0)
  })
  it('retrait : nom de confirmation obligatoire et corps strict', async () => {
    code(await admin.post('/api/pki/ad/Lab-Root/withdraw', { confirm: 'autre' }), 400, 'pkiad_confirm_mismatch')
    code(await admin.post('/api/pki/ad/Lab-Root/withdraw', {}), 400, 'validation')
    code(await admin.post('/api/pki/ad/Lab-Root/withdraw', { confirm: 'Lab-Root', extra: 1 }), 400, 'validation')
    code(await admin.post('/api/pki/ad/a%20b/withdraw', { confirm: 'a b' }), 404, 'not_found')
    code(await admin.post('/api/pki/ad/Lab-Root/withdraw', { confirm: 'Lab-Root' }), 404, 'pkiad_not_found')   // jamais publiée : aucune ligne
  })
  it('script de repli : PowerShell en pièce jointe, certificats et empreintes intégrés, sans clé ; refusé s\'il n\'y a aucune autorité', async () => {
    const r = await admin.get('/api/pki/ad/script')
    expect(r.status).toBe(200); expect(r.headers.get('content-disposition')).toContain('ddi-pki-publication-ad.ps1')
    for (const [n, c] of [['Lab-Root', certs.root], ['Lab-Sub', certs.sub], ['ExtRoot-0a1b2c3d', certs.ext]] as const) {
      expect(r.text).toContain(`Name = '${n}'`); expect(r.text).toContain(shaOfPem(c.pem)); expect(r.text).toContain(derOf(c.pem).toString('base64'))
    }
    expect(r.text).toContain('certutil'); expect(r.text).toContain('RootCA'); expect(r.text).toContain('SubCA'); expect(r.text).not.toContain('PRIVATE KEY'); expect(r.text).not.toContain('Lab-Wait')
    publishFixture([]); code(await admin.get('/api/pki/ad/script'), 409, 'pkiad_no_ca'); publishFixture(FIXTURE())
  })
})

describe('publication AD — réglages, test sans écriture, délégation (vrai Samba AD)', () => {
  live('réglages : le mot de passe est chiffré, jamais renvoyé ni journalisé', async () => {
    const r = await admin.put('/api/pki/ad', own())
    expect(r.status, r.text).toBe(200)
    const g = await admin.get('/api/pki/ad')
    expect(g.json.settings).toMatchObject({ enabled: false, source: 'own', urls: ['ldaps://dc1.lab.test'], bindDn: SVC, bindPasswordSet: true, caSet: true })
    expect(g.text).not.toContain(SVC_PW); expect(g.text).not.toContain('BEGIN CERTIFICATE'); expect(g.json.complete).toBe(true)
    const stored = JSON.stringify((await rows("select value from settings where key='pki_ad'"))[0].value)
    expect(stored).not.toContain(SVC_PW); expect(JSON.parse(stored).bindPasswordEnc).toMatch(/^[A-Za-z0-9+/=:._-]{20,}$/)
    // un enregistrement sans mot de passe ni certificat les conserve (ils ne sont jamais renvoyés à l'interface)
    expect((await admin.put('/api/pki/ad', own({ bindPassword: undefined, caPem: undefined, repair: 'manual' }))).status).toBe(200)
    expect((await admin.get('/api/pki/ad')).json.settings).toMatchObject({ bindPasswordSet: true, caSet: true, repair: 'manual' })
    expect((await admin.put('/api/pki/ad', own({ repair: 'auto' }))).status).toBe(200)
    const a = await rows("select detail from audit_log where action='pki.ad_settings' order by id")
    expect(a.length).toBeGreaterThanOrEqual(3); expect(JSON.stringify(a)).not.toContain(SVC_PW)
    expect(a[0].detail).toMatchObject({ enabled: false, source: 'own', servers: 1, passwordChanged: true })
  })
  live('test sans écriture : liaison, partition Configuration, conteneurs présents, SID du compte ; le droit de création manque encore', async () => {
    const r = await admin.post('/api/pki/ad/test', {})
    expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ ok: true, configNc: CONFIG_NC, host: expect.stringMatching(/dc1/i) })
    expect(r.json.server).toContain('dc1.lab.test')
    expect(r.json.containers.map((c: any) => [c.container, c.exists, c.canCreate]).sort()).toEqual([['aia', true, false], ['roots', true, false]])
    expect(r.json.account).toMatchObject({ sam: 'svc-ddi-pki', upn: SVC }); expect(r.json.account.sid).toMatch(/^S-1-5-21-\d+-\d+-\d+-\d+$/)
    const d = r.json.delegation as any[]
    expect(d.map((x) => x.container).sort()).toEqual(['aia', 'roots'])
    for (const x of d) {
      expect(x.dsacls).toMatch(/^dsacls ".+" \/I:T \/G ".+:CCDCLCLORPWPSDRC"$/); expect(x.sddl).toBe(`(A;CIOI;CCDCLCLORPWPSDRC;;;${r.json.account.sid})`)
      expect(x.samba).toContain('samba-tool dsacl set'); expect(x.dn).toBe(x.container === 'roots' ? ROOTS : AIA)
    }
    const g = await admin.get('/api/pki/ad')
    expect(g.json.settings).toMatchObject({ configNc: CONFIG_NC, account: { sam: 'svc-ddi-pki' } }); expect(g.json.delegation).toHaveLength(2)
    // rien n'a été écrit dans l'annuaire
    expect(adSha(ROOTS, 'Lab-Root')).toBeNull(); expect(adSha(AIA, 'Lab-Sub')).toBeNull()
  })
  live('échecs de test : mauvais mot de passe (bind), serveur injoignable, certificat du serveur non reconnu (tls) ; compte sans délégation', async () => {
    expect((await admin.put('/api/pki/ad', own({ bindPassword: 'mauvais-mot-de-passe-1!' }))).status).toBe(200)
    let r = await admin.post('/api/pki/ad/test', {}); expect(r.status).toBe(200); expect(r.json).toMatchObject({ ok: false, reason: 'bind' })
    expect((await admin.put('/api/pki/ad', own({ urls: ['ldaps://dc1.lab.test:1'] }))).status).toBe(200)
    r = await admin.post('/api/pki/ad/test', {}); expect(r.json).toMatchObject({ ok: false, reason: 'unreachable' })
    expect((await admin.put('/api/pki/ad', own({ caPem: '' }))).status).toBe(200)   // chaîne vide : le certificat enregistré est effacé
    expect((await admin.get('/api/pki/ad')).json.settings.caSet).toBe(false)
    r = await admin.post('/api/pki/ad/test', {}); expect(r.json).toMatchObject({ ok: false, reason: 'tls' })
    // compte qui existe mais sans la délégation : le test réussit et dit que le droit manque
    expect((await admin.put('/api/pki/ad', own({ bindDn: NODELEG, bindPassword: NODELEG_PW }))).status).toBe(200)
    r = await admin.post('/api/pki/ad/test', {}); expect(r.json.ok, r.text).toBe(true)
    expect(r.json.containers.every((c: any) => c.exists && !c.canCreate)).toBe(true); expect(r.json.account.sam).toBe('svc-nodeleg')
    // changer de compte efface ce que le test précédent avait appris
    expect((await admin.put('/api/pki/ad', own())).status).toBe(200)
    const g = await admin.get('/api/pki/ad'); expect(g.json.settings).toMatchObject({ bindDn: SVC, caSet: true, configNc: null, account: null }); expect(g.json.delegation).toBeNull()
  })
  live('la délégation proposée est appliquée pour de vrai avec samba-tool : le test constate alors le droit de création, sans rien écrire', async () => {
    const t = await admin.post('/api/pki/ad/test', {}); expect(t.json.ok, t.text).toBe(true)
    for (const x of t.json.delegation as any[]) {
      const m = /--objectdn="([^"]+)" --sddl="([^"]+)"/.exec(x.samba); expect(m, x.samba).not.toBeNull()
      const r = sambaTool(['dsacl', 'set', `--objectdn=${m![1]}`, `--sddl=${m![2]}`]); expect(r.status, r.stdout + r.stderr).toBe(0)
    }
    const r = await admin.post('/api/pki/ad/test', {})
    expect(r.json.containers.map((c: any) => [c.container, c.exists, c.canCreate]).sort()).toEqual([['aia', true, true], ['roots', true, true]])
    expect(adSha(ROOTS, 'Lab-Root')).toBeNull()
  })
})


const pub = async (name: string) => (await admin.get('/api/pki/ad')).json.publications.find((p: any) => p.name === name)
const run = async (path: string, body: unknown = {}) => { const r = await admin.post(path, body); expect(r.status, r.text).toBe(200); return r.json }
const b64 = (pem: string) => derOf(pem).toString('base64')
const addForeign = (name: string, pem: string) => { const r = ldap('ldapmodify', ['-a'], `dn: CN=${name},${ROOTS}\nobjectClass: top\nobjectClass: certificationAuthority\ncn: ${name}\ncACertificate:: ${b64(pem)}\ncertificateRevocationList:: AA==\nauthorityRevocationList:: AA==\n`); expect(r.status, r.stderr).toBe(0) }
const setCert = (container: string, name: string, pem: string) => { const r = ldap('ldapmodify', [], `dn: CN=${name},${container}\nchangetype: modify\nreplace: cACertificate\ncACertificate:: ${b64(pem)}\n`); expect(r.status, r.stderr).toBe(0) }
const renew = (name: string, cn: string, signer?: ReturnType<typeof mkCert>) => { const c = mkCert(cn, signer); place(name, c.pem); return c }

describe('publication AD — publication, renouvellement, conflit, écart, retrait, échecs (vrai Samba AD)', () => {
  live('activation puis publication : racines dans « Certification Authorities », émettrice dans « AIA » ; empreintes relues dans l\'annuaire', async () => {
    expect((await admin.put('/api/pki/ad', own({ enabled: true, bindPassword: undefined }))).status).toBe(200)
    const r = await run('/api/pki/ad/publish')
    expect(r).toMatchObject({ status: 'done', summary: { ok: true, trigger: 'manual', published: 3, unchanged: 0, failed: 0, conflicts: 0, drift: 0 } })
    expect(adSha(ROOTS, 'Lab-Root')).toBe(shaOfPem(certs.root!.pem)); expect(adSha(ROOTS, 'ExtRoot-0a1b2c3d')).toBe(shaOfPem(certs.ext!.pem)); expect(adSha(AIA, 'Lab-Sub')).toBe(shaOfPem(certs.sub!.pem))
    expect(adSha(AIA, 'Lab-Root')).toBeNull(); expect(adSha(ROOTS, 'Lab-Sub')).toBeNull()   // chaque autorité au bon endroit seulement
    const g = (await admin.get('/api/pki/ad')).json
    expect(g.publications.map((p: any) => [p.name, p.state, p.publishedSha256 === p.sha256]).sort()).toEqual([['ExtRoot-0a1b2c3d', 'published', true], ['Lab-Root', 'published', true], ['Lab-Sub', 'published', true]])
    expect(g.publications.every((p: any) => p.dn.endsWith(CONFIG_NC) && p.publishedAt && p.attempts === 0)).toBe(true)
    expect(g.state.lastRun).toMatchObject({ published: 3, ok: true })
    const cas = (await admin.get('/api/pki/cas')).json
    expect(cas.adEnabled).toBe(true)
    expect(Object.fromEntries(cas.cas.map((c: any) => [c.name, c.publication && [c.publication.state, c.publication.current]]))).toEqual({ 'Lab-Root': ['published', true], 'Lab-Sub': ['published', true], 'ExtRoot-0a1b2c3d': ['published', true], 'Lab-Wait': null })
    expect((await rows("select detail from audit_log where action='pki.ad_publish'")).map((x) => x.detail.action)).toEqual(['added', 'added', 'added'])
  })
  live('idempotence : un second passage ne réécrit rien (contrôle seul), une publication ciblée constate « déjà à jour »', async () => {
    const before = [adSha(ROOTS, 'Lab-Root'), adSha(AIA, 'Lab-Sub')]
    expect((await run('/api/pki/ad/publish')).summary).toMatchObject({ published: 0, unchanged: 0, failed: 0, drift: 0, checked: 3 })
    expect((await run('/api/pki/ad/publish', { name: 'Lab-Root' })).summary).toMatchObject({ published: 0, unchanged: 1, failed: 0 })
    expect([adSha(ROOTS, 'Lab-Root'), adSha(AIA, 'Lab-Sub')]).toEqual(before)
    expect(await rows("select 1 from audit_log where action='pki.ad_publish'")).toHaveLength(3)
  })
  live('renouvellement : un nouveau certificat de même nom remplace l\'ancien dans l\'annuaire', async () => {
    const old = shaOfPem(certs.root!.pem)
    certs.root2 = renew('Lab-Root', 'Lab Root CA renouvelée')
    const r = await run('/api/pki/ad/publish', { name: 'Lab-Root' })
    expect(r.summary).toMatchObject({ published: 1, failed: 0 })
    const now = shaOfPem(certs.root2.pem); expect(now).not.toBe(old); expect(adSha(ROOTS, 'Lab-Root')).toBe(now)
    expect(await pub('Lab-Root')).toMatchObject({ state: 'published', sha256: now, publishedSha256: now })
    expect((await rows("select detail from audit_log where action='pki.ad_publish' order by id desc limit 1"))[0].detail).toMatchObject({ action: 'replaced', container: 'roots', sha256: now })
  })
  live('conflit : un objet du même nom qui n\'est pas le nôtre n\'est jamais écrasé ni retiré', async () => {
    const theirs = mkCert('Autre autorité'), ours = mkCert('Lab Foreign CA')
    addForeign('Lab-Foreign', theirs.pem); place('Lab-Foreign', ours.pem)
    publishFixture([...FIXTURE(), ca({ name: 'Lab-Foreign', kind: 'root' })])
    const r = await run('/api/pki/ad/publish')
    expect(r.summary).toMatchObject({ published: 0, conflicts: 1, failed: 0 })
    expect(adSha(ROOTS, 'Lab-Foreign')).toBe(shaOfPem(theirs.pem))
    expect(await pub('Lab-Foreign')).toMatchObject({ state: 'conflict', reason: 'conflict' })
    expect((await run('/api/pki/ad/publish', { name: 'Lab-Foreign' })).summary).toMatchObject({ conflicts: 1 })   // une demande explicite ne force rien non plus
    code(await admin.post('/api/pki/ad/Lab-Foreign/withdraw', { confirm: 'Lab-Foreign' }), 409, 'pkiad_conflict')
    expect(adSha(ROOTS, 'Lab-Foreign')).toBe(shaOfPem(theirs.pem))
    publishFixture(FIXTURE())   // l'autorité quitte la PKI : sa ligne reste (orpheline), l'objet de l'AD aussi
    const o = await pub('Lab-Foreign'); expect(o).toMatchObject({ orphan: true, state: 'conflict' })
    expect((await run('/api/pki/ad/reconcile')).summary.failed).toBe(0); expect(adSha(ROOTS, 'Lab-Foreign')).toBe(shaOfPem(theirs.pem))
    adDelete(ROOTS, 'Lab-Foreign')
  })
  live('écart, réglage « auto » : un objet supprimé ou modifié dans l\'annuaire est republié au rapprochement', async () => {
    adDelete(AIA, 'Lab-Sub')
    let r = await run('/api/pki/ad/reconcile')
    expect(r.summary).toMatchObject({ trigger: 'reconcile', drift: 1, published: 1, failed: 0 })
    expect(adSha(AIA, 'Lab-Sub')).toBe(shaOfPem(certs.sub!.pem)); expect(await pub('Lab-Sub')).toMatchObject({ state: 'published', reason: null })
    setCert(ROOTS, 'ExtRoot-0a1b2c3d', mkCert('Quelqu\'un d\'autre').pem)   // objet remplacé par un autre certificat
    r = await run('/api/pki/ad/reconcile')
    expect(r.summary).toMatchObject({ drift: 1, published: 1 }); expect(adSha(ROOTS, 'ExtRoot-0a1b2c3d')).toBe(shaOfPem(certs.ext!.pem))
    const d = await rows("select detail from audit_log where action='pki.ad_drift' order by id")
    expect(d.map((x) => x.detail.found)).toEqual(['missing', 'different'])
  })
  live('écart, réglage « seulement signaler » : l\'écart est signalé, l\'annuaire n\'est pas touché ; une publication ciblée le corrige', async () => {
    expect((await admin.put('/api/pki/ad', own({ enabled: true, bindPassword: undefined, repair: 'manual' }))).status).toBe(200)
    adDelete(AIA, 'Lab-Sub')
    const r = await run('/api/pki/ad/reconcile')
    expect(r.summary).toMatchObject({ drift: 1, published: 0 }); expect(adSha(AIA, 'Lab-Sub')).toBeNull()
    expect(await pub('Lab-Sub')).toMatchObject({ state: 'drift', reason: 'missing' })
    expect((await admin.get('/api/pki/cas')).json.cas.find((c: any) => c.name === 'Lab-Sub').publication).toMatchObject({ state: 'drift', reason: 'missing' })
    expect((await run('/api/pki/ad/reconcile')).summary).toMatchObject({ published: 0 }); expect(adSha(AIA, 'Lab-Sub')).toBeNull()   // « manual » : jamais de réécriture automatique
    expect((await run('/api/pki/ad/publish', { name: 'Lab-Sub' })).summary).toMatchObject({ published: 1 })
    expect(adSha(AIA, 'Lab-Sub')).toBe(shaOfPem(certs.sub!.pem)); expect(await pub('Lab-Sub')).toMatchObject({ state: 'published', reason: null })
    expect((await admin.put('/api/pki/ad', own({ enabled: true, bindPassword: undefined, repair: 'auto' }))).status).toBe(200)
  })
  live('retrait : confirmé par le nom, supprime l\'objet, n\'est jamais annulé automatiquement ; « republier » le rétablit', async () => {
    code(await admin.post('/api/pki/ad/Lab-Sub/withdraw', { confirm: 'Lab-Root' }), 400, 'pkiad_confirm_mismatch'); expect(adSha(AIA, 'Lab-Sub')).not.toBeNull()
    const w = await admin.post('/api/pki/ad/Lab-Sub/withdraw', { confirm: 'lab-sub' })
    expect(w.status, w.text).toBe(200); expect(w.json).toEqual({ ok: true, action: 'deleted' })
    expect(adSha(AIA, 'Lab-Sub')).toBeNull(); expect(await pub('Lab-Sub')).toMatchObject({ state: 'withdrawn', publishedSha256: null })
    for (const p of ['/api/pki/ad/publish', '/api/pki/ad/reconcile']) { await run(p); expect(adSha(AIA, 'Lab-Sub')).toBeNull() }   // ni publication ni rapprochement ne le rétablissent
    expect(await pub('Lab-Sub')).toMatchObject({ state: 'withdrawn' })
    expect((await admin.post('/api/pki/ad/Lab-Sub/withdraw', { confirm: 'Lab-Sub' })).json).toEqual({ ok: true, action: 'absent' })   // déjà absent : sans erreur
    expect(await run('/api/pki/ad/publish', { name: 'Lab-Sub' })).toEqual({ status: 'idle' })   // sans « republish » : toujours retirée, rien à faire
    expect((await run('/api/pki/ad/publish', { name: 'Lab-Sub', republish: true })).summary).toMatchObject({ published: 1 })
    expect(adSha(AIA, 'Lab-Sub')).toBe(shaOfPem(certs.sub!.pem)); expect(await pub('Lab-Sub')).toMatchObject({ state: 'published' })
    expect((await rows("select detail from audit_log where action='pki.ad_withdraw' order by id")).map((x) => x.detail.action)).toEqual(['deleted', 'absent'])
  })
  live('échecs : mauvais mot de passe (état « échec », reprise espacée, autorités déjà publiées intactes), puis reprise après correction', async () => {
    expect((await admin.put('/api/pki/ad', own({ enabled: true, bindPassword: 'mauvais-mot-de-passe-1!' }))).status).toBe(200)
    certs.sub2 = renew('Lab-Sub', 'Lab Issuing CA renouvelée', certs.root2)
    let r = await run('/api/pki/ad/publish')
    expect(r.summary).toMatchObject({ ok: false, reason: 'bind', failed: 1, published: 0 })
    let p = await pub('Lab-Sub'); expect(p).toMatchObject({ state: 'failed', reason: 'bind', attempts: 1 }); expect(Date.parse(p.nextTryAt)).toBeGreaterThan(Date.now() + 30_000)
    expect(await pub('Lab-Root')).toMatchObject({ state: 'published' })   // une panne ne dit rien des autorités déjà publiées
    expect(adSha(AIA, 'Lab-Sub')).toBe(shaOfPem(certs.sub!.pem))          // l'ancien certificat est toujours là
    r = await run('/api/pki/ad/publish'); p = await pub('Lab-Sub'); expect(p).toMatchObject({ state: 'failed', attempts: 2 })
    const t1 = Date.parse(p.nextTryAt); expect(t1).toBeGreaterThan(Date.now() + 90_000)   // 60 s puis 120 s : l'espacement double
    expect((await admin.put('/api/pki/ad', own({ enabled: true, bindPassword: SVC_PW }))).status).toBe(200)
    expect(Date.parse((await pub('Lab-Sub')).nextTryAt)).toBeLessThanOrEqual(Date.now() + 1000)   // réglage corrigé : reprise immédiate au prochain passage
    r = await run('/api/pki/ad/publish'); expect(r.summary).toMatchObject({ ok: true, published: 1, failed: 0 })
    expect(adSha(AIA, 'Lab-Sub')).toBe(shaOfPem(certs.sub2.pem)); expect(await pub('Lab-Sub')).toMatchObject({ state: 'published', reason: null, attempts: 0, nextTryAt: null })
  })
  live('droits insuffisants : un compte sans délégation reçoit « denied » et n\'écrit rien ; la reprise avec le bon compte réussit', async () => {
    certs.new = renew('Lab-New', 'Lab New Root'); publishFixture([...FIXTURE(), ca({ name: 'Lab-New', kind: 'root' })])
    expect((await admin.put('/api/pki/ad', own({ enabled: true, bindDn: NODELEG, bindPassword: NODELEG_PW }))).status).toBe(200)
    const r = await run('/api/pki/ad/publish', { name: 'Lab-New' })
    expect(r.summary).toMatchObject({ failed: 1, published: 0, ok: true }); expect(await pub('Lab-New')).toMatchObject({ state: 'failed', reason: 'denied', attempts: 1 })   // l'annuaire répond : l'échec est celui de cette autorité
    expect(adSha(ROOTS, 'Lab-New')).toBeNull()
    expect((await admin.put('/api/pki/ad', own({ enabled: true, bindDn: SVC, bindPassword: SVC_PW }))).status).toBe(200)
    expect((await run('/api/pki/ad/publish', { name: 'Lab-New' })).summary).toMatchObject({ published: 1, failed: 0 })
    expect(adSha(ROOTS, 'Lab-New')).toBe(shaOfPem(certs.new.pem))
  })
  live('autorité qui quitte la PKI : sa ligne reste (orpheline) et l\'objet de l\'AD n\'est jamais retiré tout seul', async () => {
    publishFixture(FIXTURE())
    const r = await run('/api/pki/ad/reconcile'); expect(r.summary.failed).toBe(0)
    expect(await pub('Lab-New')).toMatchObject({ orphan: true, state: 'published' }); expect(adSha(ROOTS, 'Lab-New')).toBe(shaOfPem(certs.new!.pem))
    expect((await admin.get('/api/pki/ad')).json.eligible).toBe(3)
  })
  live('désactivation : plus aucune écriture ; rien n\'est retiré de l\'annuaire ; l\'audit ne contient ni mot de passe ni certificat', async () => {
    expect((await admin.put('/api/pki/ad', own({ enabled: false, bindPassword: undefined }))).status).toBe(200)
    code(await admin.post('/api/pki/ad/publish', {}), 409, 'pkiad_disabled'); code(await admin.post('/api/pki/ad/reconcile', {}), 409, 'pkiad_disabled')
    for (const [c, n] of [[ROOTS, 'Lab-Root'], [ROOTS, 'ExtRoot-0a1b2c3d'], [AIA, 'Lab-Sub']] as const) expect(adSha(c, n)).not.toBeNull()
    expect((await admin.get('/api/pki/cas')).json.adEnabled).toBe(false)
    const audit = JSON.stringify(await rows("select action, entity, entity_id, detail from audit_log where action like 'pki.ad_%'"))
    for (const bad of [SVC_PW, NODELEG_PW, 'mauvais-mot-de-passe', 'BEGIN CERTIFICATE', b64(certs.root!.pem).slice(20, 80), b64(certs.sub2!.pem).slice(20, 80)]) expect(audit).not.toContain(bad)
    const actions = new Set((await rows("select distinct action from audit_log where action like 'pki.ad_%'")).map((x) => x.action))
    for (const a of ['pki.ad_settings', 'pki.ad_test', 'pki.ad_run', 'pki.ad_reconcile', 'pki.ad_publish', 'pki.ad_failed', 'pki.ad_drift', 'pki.ad_withdraw']) expect(actions.has(a), a).toBe(true)
  })
})
