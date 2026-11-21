// Bout en bout (serveur CONSTRUIT, PostgreSQL réel, Samba AD réel) : 0.18.0 — enrôlement des postes. Un VRAI ticket Kerberos du compte machine PC003$ (KDC de Samba,
// keytab HTTP/ddi.lab.test exporté par samba-tool) est accepté par l'assistant enroll-gss, l'annuaire réel donne le nom DNS et les groupes, « root » est simulé comme dans
// e2e-iter51 (il signe vraiment la demande). Sans AD réel (root, samba, python3-gssapi, kinit) les cas Kerberos sont ignorés ; les contrôles de réglages restent exécutés.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3490, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const EJURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_ejbca_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s62-')), GEN = join(TMP, 'gen'), IN = join(GEN, 'pki-in'), REQ = join(GEN, '.pki-request')
const STATUS = join(TMP, 'ps.json'), RESULT = join(TMP, 'pr.json'), CAS = join(TMP, 'pki-cas.json'), CADIR = join(TMP, 'pki-ca'), CERTDIR = join(TMP, 'pki-cert'), SSL = join(TMP, 'ssl')
let srv: ChildProcess, db: pg.Client, ej: pg.Client, srvLog = ''

class Client {
  cookie = ''; csrf = ''
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { cookie: this.cookie }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const buf = Buffer.from(await r.arrayBuffer()); const text = buf.toString('utf8'); let json: any = null; try { json = JSON.parse(text) } catch { /* fichier */ }
    return { status: r.status, json, text, buf, headers: r.headers }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b)
  put = (p: string, b: unknown = {}) => this.req('PUT', p, b); del = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 200)) } throw new Error('délai dépassé') }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const setStatus = (o: Record<string, unknown>) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', digest: '', nets: [], health: 'ALLOK', port: 8080,
  dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab.test', casCount: 2, resetAllowed: false, ...o }))
const SUBDN = 'CN=Lab Sub CA,O=Lab,C=FR', ROOTDN = 'CN=Lab Root CA,O=Lab,C=FR'
const ca = (o: Record<string, unknown>) => ({ name: 'Lab-Root', kind: 'root', state: 'active', dn: ROOTDN, issuer: ROOTDN, selfSigned: true, serial: 'ab', notBefore: '2026-01-01T00:00:00Z', notAfter: '2036-01-01T00:00:00Z',
  keyAlg: 'RSA', keyBits: 3072, curve: '', sigAlg: 'sha256WithRSAEncryption', pathLen: null, sha256: 'a'.repeat(64), signedBy: 'self', alg: 'rsa3072', createdAt: 1700000000, extRoot: '',
  crlUrl: 'http://pki.lab.test:8080/crl', certUrl: 'http://pki.lab.test:8080/cert', crl: null, files: { cert: true, chain: false, csr: false, crl: true }, ...o })
const FIXTURE = [ca({}), ca({ name: 'Lab-Sub', kind: 'issuing', dn: SUBDN, issuer: ROOTDN, selfSigned: false, signedBy: 'Lab-Root', files: { cert: true, chain: true, csr: false, crl: true } }),
  ca({ name: 'Lab-Wait', kind: 'issuing', state: 'waiting', dn: 'CN=Lab Wait,O=Lab,C=FR', selfSigned: false, files: { cert: false, chain: true, csr: true, crl: false } })]
const publish = (cas: unknown[]) => writeFileSync(CAS, JSON.stringify({ at: 1700000000, ok: true, hostname: 'pki.lab.test', port: 8080, cas }))

const sh = (args: string[], input?: string | Buffer) => spawnSync('openssl', args, { encoding: 'utf8', input })
const read = (p: string) => readFileSync(p, 'utf8')
// ---- Autorités et certificats de test (openssl) ----
/** Le « root » simulé : signe vraiment les demandes avec l'émettrice de test, publie dossier + résultat comme ddibuntu-pki. */
const rootLog: Array<{ req: any; csr: string | null }> = []
let rootBusy = false, rootDelay = 0, rootRefuse: string | null = null, rootMute = false, rootTimer: NodeJS.Timeout | null = null
const publishResult = (action: string, ok: boolean, message: string, ref?: string) => writeFileSync(RESULT, JSON.stringify({ at: Math.floor(Date.now() / 1000), action, ok, message, ...(ref ? { ref } : {}) }))
function startRoot() {
  rootTimer = setInterval(async () => {
    if (rootBusy || rootMute || !existsSync(REQ)) return
    rootBusy = true
    let req: any = {}
    try {
      req = JSON.parse(read(REQ)); rmSync(REQ, { force: true })
      const dep = join(IN, `${req.id}.csr.pem`)
      const raw = existsSync(dep) ? readFileSync(dep) : null
      const csr = raw ? (raw[0] === 0x30 ? '[DER]' : raw.toString('utf8')) : null
      rootLog.push({ req, csr }); if (raw) rmSync(dep, { force: true })
      if (rootDelay) await sleep(rootDelay)
      if (rootRefuse) { publishResult(req.action, false, rootRefuse, req.id); return }
      if (req.action === 'cert_issue') {
        const f = (s: string) => join(SSL, `iss-${req.id}.${s}`)
        writeFileSync(f('csr'), raw!)
        const san = [...(req.dns ?? []).map((d: string) => `DNS:${d}`), ...(req.ip ?? []).map((i: string) => `IP:${i}`), ...(req.mail ?? []).map((m: string) => `email:${m}`)].join(',')
        writeFileSync(f('ext'), 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n' + (san ? `subjectAltName=${san}\n` : ''))
        const r1 = sh(['x509', '-req', ...(raw![0] === 0x30 ? ['-inform', 'DER'] : []), '-in', f('csr'), '-CA', join(SSL, 'sub.pem'), '-CAkey', join(SSL, 'sub.key'), '-CAcreateserial', '-out', f('pem'), '-days', '365', '-extfile', f('ext'), '-subj', `/CN=${req.cn}`])
        if (r1.status !== 0) throw new Error(r1.stderr)
        const d = join(CERTDIR, req.id); mkdirSync(d, { recursive: true })
        const cert = read(f('pem'))
        writeFileSync(join(d, 'cert.pem'), cert); writeFileSync(join(d, 'chain.pem'), read(join(SSL, 'sub.pem')) + read(join(SSL, 'root.pem')))
        const serial = sh(['x509', '-in', f('pem'), '-noout', '-serial']).stdout.trim().split('=')[1]!.toUpperCase().replace(/^0+/, '')
        writeFileSync(join(d, 'meta.json'), JSON.stringify({ id: req.id, ca: req.ca, profile: req.profile, serial, sha256: createHash('sha256').update(Buffer.from(cert.replace(/-----[A-Z ]+-----|\s/g, ''), 'base64')).digest('hex'),
          notBefore: '2026-11-17T09:00:00Z', notAfter: '2027-11-17T09:00:00Z', subject: `C=FR,O=Lab,CN=${req.cn}`, issuedAt: 1 }))
        publishResult('cert_issue', true, `Certificat émis par « ${req.ca} »`, req.id)
      } else if (req.action === 'cert_revoke') {
        await ej.query(`update certificatedata set status = 40, revocationdate = $3, revocationreason = $4 where issuerdn = $1 and serialnumber = $2`, [SUBDN, BigInt('0x' + req.serial).toString(10), Date.now(), req.reason])
        publishResult('cert_revoke', true, `Certificat ${req.serial} révoqué (motif ${req.reason}) ; la CRL est à jour.`, req.id)
      }
    } catch (e) { publishResult(req.action ?? 'cert_issue', false, `erreur du root simulé : ${(e as Error).message}`, req.id) } finally { rootBusy = false }
  }, 40)
}
const sent = () => JSON.parse(read(REQ))
const clearAll = () => { for (const d of [IN, CERTDIR]) if (existsSync(d)) for (const f of readdirSync(d)) rmSync(join(d, f), { recursive: true, force: true }); rmSync(REQ, { force: true }); rmSync(RESULT, { force: true }); rootLog.length = 0 }
const newCsr = (alg: 'rsa' | 'ec' = 'ec', n = 'x') => {
  const k = join(SSL, `csr-${n}-${Math.random().toString(36).slice(2)}`)
  if (alg === 'rsa') sh(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', k + '.key', '-out', k + '.csr', '-subj', `/CN=${n}`])
  else sh(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', k + '.key', '-out', k + '.csr', '-subj', `/CN=${n}`])
  return { csr: read(k + '.csr'), key: k + '.key' }
}
const LAB = join(TMP, 'lab'), ROOTD = resolve(__dirname, '../..'), PY = '/usr/bin/python3.12', BIND_PW = 'Passw0rd-svc-radius-1!'
let lab = false, CA = ''
const smb = (...a: string[]) => spawnSync(PY, [spawnSync('which', ['samba-tool'], { encoding: 'utf8' }).stdout.trim(), ...a, `--configfile=${join(LAB, 'etc/smb.conf')}`], { encoding: 'utf8' })
const krbEnv = (cc: string) => ({ ...process.env, KRB5_CONFIG: join(LAB, 'krb5.conf'), KRB5CCNAME: `FILE:${cc}` })
/** Un jeton SPNEGO frais (authentificateur neuf) du compte donné pour le service HTTP/ddi.lab.test. */
function ticket(principal: string, password: string): string {
  const cc = join(TMP, `cc-${Math.random().toString(36).slice(2)}`)
  const k = spawnSync('kinit', [principal], { input: password + '\n', encoding: 'utf8', env: krbEnv(cc) })
  if (k.status !== 0) throw new Error(`kinit ${principal} : ${k.stderr}`)
  const t = spawnSync(PY, [join(TMP, 'mk-token.py')], { encoding: 'utf8', env: krbEnv(cc) })
  if (t.status !== 0) throw new Error(`jeton : ${t.stderr}`)
  rmSync(cc, { force: true })
  return t.stdout.trim()
}
const enroll = async (token: string | null, body: unknown = undefined, auth = token ? `Negotiate ${token}` : '') =>
  fetch(BASE + '/api/enroll/v1/machine', { method: 'POST', headers: { 'content-type': 'application/json', ...(auth ? { authorization: auth } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) })
const enrollJson = async (r: Response) => { const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* texte */ } return { status: r.status, json, text, headers: r.headers } }
/** Keytab MIT (format 0x0502) fabriqué ici : une entrée par (principal, type de chiffrement). */
function keytab(entries: Array<{ comps: string[]; realm: string; enctype: number; kvno?: number }>): Buffer {
  const parts: Buffer[] = [Buffer.from([5, 2])]
  for (const e of entries) {
    const u16 = (n: number) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b }
    const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b }
    const s = (v: string) => Buffer.concat([u16(Buffer.byteLength(v)), Buffer.from(v)])
    const body = Buffer.concat([u16(e.comps.length), s(e.realm), ...e.comps.map(s), u32(1), u32(1700000000), Buffer.from([e.kvno ?? 1]), u16(e.enctype), u16(32), Buffer.alloc(32, 7), u32(e.kvno ?? 1)])
    parts.push(u32(body.length), body)
  }
  return Buffer.concat(parts)
}
const GROUP_OK = 'CN=grp-wifi,CN=Users,DC=lab,DC=test', GROUP_NO = 'CN=Domain Admins,CN=Users,DC=lab,DC=test'


beforeAll(async () => {
  mkdirSync(GEN, { recursive: true }); mkdirSync(SSL, { recursive: true });
  const l = spawnSync('bash', [join(ROOTD, 'tests/samba-lab.sh'), 'start', LAB], { encoding: 'utf8', timeout: 150000 })
  lab = l.status === 0 && !spawnSync('kinit', ['--version'], { encoding: 'utf8' }).error && spawnSync(PY, ['-c', 'import gssapi'], { encoding: 'utf8' }).status === 0
  if (!lab) console.warn(`[e2e-iter62] AD / Kerberos réels ignorés (${l.status}) : ${(l.stderr || l.stdout).trim().split('\n').pop()}`)
  else {
    const x = spawnSync('bash', [join(ROOTD, 'tests/samba-lab.sh'), 'extra', LAB], { encoding: 'utf8', timeout: 150000 }); if (x.status !== 0) throw new Error(`samba-lab extra : ${x.stderr}`)
    CA = readFileSync(join(LAB, 'private/tls/ca.pem'), 'utf8')
    // compte de service : « prend en charge AES » (msDS-SupportedEncryptionTypes = 24) PUIS mot de passe renouvelé, sinon le keytab exporté ne porte que du RC4
    const steps: Array<() => { status: number | null; stderr: string }> = [
      () => smb('user', 'create', 'svc-ddi-http', 'Passw0rd-svc-1!'), () => smb('spn', 'add', 'HTTP/ddi.lab.test', 'svc-ddi-http'),
      () => spawnSync('ldapmodify', ['-H', 'ldaps://dc1.lab.test', '-D', 'administrator@lab.test', '-w', 'Passw0rd-Lab-1!'], { encoding: 'utf8', env: { ...process.env, LDAPTLS_CACERT: join(LAB, 'private/tls/ca.pem') },
        input: 'dn: CN=svc-ddi-http,CN=Users,DC=lab,DC=test\nchangetype: modify\nreplace: msDS-SupportedEncryptionTypes\nmsDS-SupportedEncryptionTypes: 24\n' }),
      () => smb('user', 'setpassword', 'svc-ddi-http', '--newpassword=Passw0rd-svc-2!'), () => smb('user', 'setpassword', 'PC003$', '--newpassword=Machine-Passw0rd-1!'),
      () => smb('domain', 'exportkeytab', join(TMP, 'http.keytab'), '--principal=HTTP/ddi.lab.test@LAB.TEST')]
    for (const [i, st] of steps.entries()) { const r = st(); if (r.status !== 0) throw new Error(`préparation de l'AD, étape ${i} : ${r.stderr}`) }
    writeFileSync(join(LAB, 'krb5.conf'), '[libdefaults]\n default_realm = LAB.TEST\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n dns_canonicalize_hostname = false\n udp_preference_limit = 1\n[realms]\n LAB.TEST = {\n  kdc = 127.0.0.1:88\n }\n[domain_realm]\n .lab.test = LAB.TEST\n lab.test = LAB.TEST\n')
  }
  writeFileSync(join(TMP, 'mk-token.py'), 'import gssapi, base64\nname = gssapi.Name("HTTP@ddi.lab.test", gssapi.NameType.hostbased_service)\nprint(base64.b64encode(gssapi.SecurityContext(name=name, usage="initiate").step()).decode())\n')
  writeFileSync(join(TMP, 'gss-wrapper'), `#!/bin/sh\nexec ${PY} ${join(ROOTD, 'src/rootfs/usr/local/lib/ddibuntu/enroll-gss')}\n`, { mode: 0o755 })
  mkdirSync(IN, { recursive: true }); mkdirSync(CERTDIR, { recursive: true })
  mkdirSync(join(CADIR, 'Lab-Sub'), { recursive: true })
  // autorités de test : racine → émettrice
  sh(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(SSL, 'root.key'), '-out', join(SSL, 'root.pem'), '-days', '3650', '-subj', '/CN=Lab Root CA/O=Lab/C=FR',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
  sh(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(SSL, 'sub.key'), '-out', join(SSL, 'sub.csr'), '-subj', '/CN=Lab Sub CA/O=Lab/C=FR'])
  writeFileSync(join(SSL, 'ca.ext'), 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
  sh(['x509', '-req', '-in', join(SSL, 'sub.csr'), '-CA', join(SSL, 'root.pem'), '-CAkey', join(SSL, 'root.key'), '-CAcreateserial', '-out', join(SSL, 'sub.pem'), '-days', '3000', '-extfile', join(SSL, 'ca.ext')])
  writeFileSync(join(CADIR, 'Lab-Sub', 'cert.pem'), read(join(SSL, 'sub.pem'))); writeFileSync(join(CADIR, 'Lab-Sub', 'chain.pem'), read(join(SSL, 'root.pem')))
  // copie minimale de la base d'EJBCA (mêmes noms de tables et de colonnes que EJBCA 9)
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  await db.query('drop database if exists ddibuntu_ejbca_test with (force)'); await db.query('create database ddibuntu_ejbca_test')
  ej = new pg.Client({ connectionString: EJURL }); await ej.connect()
  await ej.query(`create table certificatedata (fingerprint text primary key, base64cert text, cafingerprint text, certificateprofileid int, endentityprofileid int, crlpartitionindex int, expiredate bigint, issuerdn text,
    notbefore bigint, invaliditydate bigint, revocationdate bigint, revocationreason int, rowprotection text, rowversion int, serialnumber text, status int, subjectaltname text, subjectdn text, subjectkeyid text,
    accountbindingid text, tag text, type int, updatetime bigint, username text, certificaterequest text);
    create table base64certdata (fingerprint text primary key, base64cert text, rowprotection text, rowversion int, certificaterequest text);
    create table cadata (cakey text, secret text)`)
  await ej.query('revoke all on all tables in schema public from public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_EJBCA_DATABASE_URL: EJURL, DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN,
    DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT, DDI_PKI_CAS: CAS, DDI_PKI_CA_DIR: CADIR, DDI_PKI_CERT_DIR: CERTDIR, DDI_PKI_ISSUE_TIMEOUT_MS: '3500', DDI_ENROLL_GSS: join(TMP, 'gss-wrapper'), DDI_ENROLL_RCACHE: join(TMP, 'rcache'), DDI_TLS_GEN_DIR: join(TMP, 'tlsgen'), DDI_CONSOLE_TLS_NO_RESTART: '1', DDI_CONSOLE_TLS_MS: '0' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  expect((await oper.login('oper', PW)).status).toBe(200)
  setStatus({}); publish(FIXTURE); startRoot()
}, 300000)
afterAll(async () => {
  if (rootTimer) clearInterval(rootTimer)
  srv?.kill('SIGTERM'); spawnSync('bash', [join(ROOTD, 'tests/samba-lab.sh'), 'stop', LAB]); await ej?.end().catch(() => {})
  await db?.query('drop database if exists ddibuntu_ejbca_test with (force)').catch(() => {}); await db?.end(); rmSync(TMP, { recursive: true, force: true })
})

const cfgBody = (o: Record<string, unknown> = {}) => ({ enabled: true, ca: 'Lab-Sub', groupDn: GROUP_OK, host: 'ddi.lab.test', minIntervalSec: 300, maxPerDay: 6, maxPerMinute: 30, ...o })
const setDir = () => admin.put('/api/radius/directory', { urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test', bindPassword: BIND_PW, tlsRejectUnauthorized: true, caPem: CA })
const PC = 'PC003$@LAB.TEST', PCPW = 'Machine-Passw0rd-1!'
const age = () => db.query("update audit_log set at = at - interval '2 hours' where action = 'enroll.issued'")
const audits = async (action: string) => rows('select entity_id, detail from audit_log where action = $1 order by id', [action])

describe('droits et service éteint', () => {
  it('les réglages, le keytab et le script sont réservés à l\'administrateur', async () => {
    code(await anon.get('/api/enroll'), 401, 'unauthenticated')
    for (const c of [viewer, oper]) {
      code(await c.get('/api/enroll'), 403, 'forbidden'); code(await c.put('/api/enroll/config', cfgBody()), 403, 'forbidden')
      code(await c.put('/api/enroll/keytab', { keytab: 'AAAA' }), 403, 'forbidden'); code(await c.del('/api/enroll/keytab'), 403, 'forbidden'); code(await c.get('/api/enroll/script'), 403, 'forbidden')
    }
  })
  it('service éteint : la route d\'enrôlement n\'existe pas pour un poste (rien ne la distingue d\'une route absente)', async () => {
    const r = await enrollJson(await enroll(null)); code(r, 404, 'not_found')
    expect(r.headers.get('www-authenticate')).toBeNull()
    const g = await admin.get('/api/enroll'); expect(g.status, g.text).toBe(200)
    expect(g.json.settings).toMatchObject({ enabled: false, ca: '', groupDn: '', host: '' }); expect(g.json.keytab).toBeNull(); expect(g.json.ready).toBe(false)
    expect(g.json.issuers).toEqual(['Lab-Sub'])
  })
})

describe('keytab du service', () => {
  it('refuse ce qui n\'est pas un keytab, un mélange de domaines et un keytab sans service HTTP', async () => {
    code(await admin.put('/api/enroll/keytab', { keytab: Buffer.from('pas un keytab du tout').toString('base64') }), 400, 'invalid_keytab')
    code(await admin.put('/api/enroll/keytab', { keytab: keytab([{ comps: ['HTTP', 'ddi.a.test'], realm: 'A.TEST', enctype: 18 }, { comps: ['HTTP', 'ddi.b.test'], realm: 'B.TEST', enctype: 18 }]).toString('base64') }), 400, 'enroll_keytab_realms')
    code(await admin.put('/api/enroll/keytab', { keytab: keytab([{ comps: ['host', 'pc1.a.test'], realm: 'A.TEST', enctype: 18 }]).toString('base64') }), 400, 'enroll_keytab_spn')
    code(await admin.put('/api/enroll/keytab', { keytab: keytab([{ comps: ['HTTP', 'ddi.a.test'], realm: 'A.TEST', enctype: 18 }, { comps: ['host', 'ddi.a.test'], realm: 'A.TEST', enctype: 18 }]).toString('base64') }), 400, 'enroll_keytab_extra')
    expect((await admin.get('/api/enroll')).json.keytab).toBeNull()
  })
  it('enregistre un keytab AES : seuls les noms de principaux sont rendus, jamais la clé', async () => {
    const kt = keytab([{ comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 18, kvno: 3 }, { comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 17, kvno: 3 }])
    const r = await admin.put('/api/enroll/keytab', { keytab: kt.toString('base64') }); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ principals: ['HTTP/ddi.lab.test@LAB.TEST'], realm: 'LAB.TEST' })
    const g = await admin.get('/api/enroll'); expect(g.json.keytab).toMatchObject({ principals: ['HTTP/ddi.lab.test@LAB.TEST'], realm: 'LAB.TEST', kvno: { 'HTTP/ddi.lab.test@LAB.TEST': 3 } })
    expect(g.text).not.toContain(kt.toString('base64')); expect(g.text).not.toContain('v1:')
    const row = (await rows("select value::text as v from settings where key = 'enroll_keytab'"))[0].v
    expect(row).toContain('"enc": "v1:'); expect(row).not.toContain(kt.toString('base64'))
    expect((await audits('enroll.keytab')).map((a) => JSON.stringify(a.detail)).join()).not.toContain(kt.toString('base64'))
  })
  it('un keytab qui ne porte que du RC4 / DES est refusé quand le nom de la console est connu', async () => {
    expect((await admin.put('/api/enroll/config', cfgBody({ enabled: false }))).status).toBe(200)
    code(await admin.put('/api/enroll/keytab', { keytab: keytab([{ comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 23 }]).toString('base64') }), 400, 'enroll_keytab_enctype')
    code(await admin.put('/api/enroll/keytab', { keytab: keytab([{ comps: ['HTTP', 'autre.lab.test'], realm: 'LAB.TEST', enctype: 18 }]).toString('base64') }), 400, 'enroll_keytab_spn')
  })
})

describe('réglages', () => {
  it('l\'activation exige l\'autorité, le groupe, le nom, un keytab, l\'annuaire et une émettrice du DDI', async () => {
    code(await admin.put('/api/enroll/config', cfgBody({ ca: '' })), 400, 'enroll_incomplete')
    code(await admin.put('/api/enroll/config', cfgBody({ groupDn: '' })), 400, 'enroll_incomplete')
    code(await admin.put('/api/enroll/config', cfgBody({ ca: 'Lab-Root' })), 409, 'pki_ca_not_issuing')
    code(await admin.put('/api/enroll/config', cfgBody({ ca: 'Lab-Wait' })), 409, 'pki_ca_not_issuing')
    code(await admin.put('/api/enroll/config', cfgBody()), 409, 'enroll_no_directory')
    code(await admin.put('/api/enroll/config', cfgBody({ minIntervalSec: 1 })), 400, 'validation')
    code(await admin.put('/api/enroll/config', cfgBody({ maxPerDay: 0 })), 400, 'validation')
    code(await admin.put('/api/enroll/config', { ...cfgBody(), extra: 1 }), 400, 'validation')
  })
  it('le script contient la console et l\'autorité, en CRLF, sans rien d\'autre venu de l\'extérieur', async (ctx) => {
    const r = await admin.get('/api/enroll/script'); expect(r.status, r.text).toBe(200)
    expect(r.headers.get('content-disposition')).toContain('enroll.ps1')
    expect(r.text).toContain("$Console   = 'ddi.lab.test'"); expect(r.text).toContain("$IssuerCn  = 'Lab Sub CA'")
    expect(r.text).toContain('-UseDefaultCredentials'); expect(r.text).toContain('Exportable = FALSE'); expect(r.text).toContain('MachineKeySet = TRUE')
    expect(r.text.split('\n').every((l, i, a) => i === a.length - 1 || l.endsWith('\r'))).toBe(true)
    expect(r.text).not.toContain('__HOST__'); expect(r.text).not.toContain('__ISSUER__')
    expect((await audits('enroll.script')).length).toBeGreaterThan(0)
    void ctx
  })
  it('le script de GPO embarque enroll.ps1, le démarrage et rien d\'interpolé ; réservé à l\'administrateur', async () => {
    const r = await admin.get('/api/enroll/gpo-script'); expect(r.status, r.text).toBe(200)
    expect(r.headers.get('content-disposition')).toContain('deploy-gpo.ps1')
    expect(r.text).toContain('SupportsShouldProcess'); expect(r.text).toContain("'enroll.ps1' = '"); expect(r.text).toContain("'ddi-demarrage.ps1' = '")
    expect(r.text).not.toContain('__FILES__')
    expect(r.text.split('\n').every((l, i, a) => i === a.length - 1 || l.endsWith('\r'))).toBe(true)
    const b64 = /'enroll\.ps1' = '([A-Za-z0-9+/=]+)'/.exec(r.text)![1]!
    expect(Buffer.from(b64, 'base64').toString('utf8')).toContain("$Console   = 'ddi.lab.test'")
    expect((await audits('enroll.gpo_script')).length).toBeGreaterThan(0)
    code(await anon.get('/api/enroll/gpo-script'), 401, 'unauthenticated'); code(await viewer.get('/api/enroll/gpo-script'), 403, 'forbidden')
  })
})

describe('enrôlement d\'un poste (Kerberos et annuaire réels)', () => {
  it('prépare : annuaire, keytab réel du service, activation', async (ctx) => {
    if (!lab) return ctx.skip()
    expect((await setDir()).status).toBe(200)
    const kt = readFileSync(join(TMP, 'http.keytab'))
    const r = await admin.put('/api/enroll/keytab', { keytab: kt.toString('base64') }); expect(r.status, r.text).toBe(200)
    expect(r.json.principals).toContain('HTTP/ddi.lab.test@LAB.TEST')
    code(await admin.put('/api/enroll/config', cfgBody({ host: 'autre.lab.test' })), 409, 'enroll_keytab_spn')   // le nom de la console doit rester celui du service du keytab
    for (const bad of ['CN=Computers,DC=lab,DC=test', 'CN=Absent,CN=Users,DC=lab,DC=test', 'CN=Administrator,CN=Users,DC=lab,DC=test']) code(await admin.put('/api/enroll/config', cfgBody({ groupDn: bad })), 400, 'enroll_group_invalid')   // conteneur, objet absent, compte : pas des groupes
    const c = await admin.put('/api/enroll/config', cfgBody()); expect(c.status, c.text).toBe(200)
    expect((await admin.get('/api/enroll')).json.ready).toBe(true)
  })
  it('sans ticket : défi « Negotiate » ; ticket illisible : refus sans détail', async (ctx) => {
    if (!lab) return ctx.skip()
    const a = await enrollJson(await enroll(null)); code(a, 401, 'enroll_negotiate'); expect(a.headers.get('www-authenticate')).toBe('Negotiate')
    code(await enrollJson(await enroll(null, undefined, 'Basic dXNlcjpwdw==')), 401, 'enroll_negotiate')
    code(await enrollJson(await enroll(null, undefined, 'Bearer ddi_abcdefghijklmnopqrstuvwxyz')), 401, 'invalid_token')   // jeton d'API inconnu : refusé par le routeur, comme partout
    code(await enrollJson(await enroll(null, undefined, 'Bearer autre-chose')), 401, 'enroll_negotiate')
    code(await enrollJson(await enroll('AAAAAAAAAAAAAAAAAAAAAAAA', { csr: { pem: 'x' } })), 401, 'enroll_negotiate')   // ne commence pas par une étiquette SPNEGO : refusé avant tout déchiffrement
    code(await enrollJson(await enroll('YIIAAAAAAAAAAAAAAAAAAAAA', { csr: { pem: 'x' } })), 401, 'enroll_kerberos')   // forme plausible mais illisible : refus Kerberos sans détail
    const last = (await audits('enroll.refused')).slice(-1)[0]; expect(last.detail.reason).toBe('enroll_kerberos')
  })
  it('émet le certificat du poste : le nom vient de l\'annuaire, pas de la demande', async (ctx) => {
    if (!lab) return ctx.skip()
    clearAll(); rootLog.length = 0
    const { csr } = newCsr('rsa', 'evil')   // le sujet de la demande est « evil » : il doit être ignoré
    const r = await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: csr } })); expect(r.status, `${r.text}\n${srvLog.slice(-800)}`).toBe(200)
    expect(r.json.certificate).toContain('BEGIN CERTIFICATE'); expect(r.json.chain).toContain('BEGIN CERTIFICATE'); expect(r.json.serial).toMatch(/^[0-9A-F]+$/)
    const q = rootLog.find((x) => x.req.action === 'cert_issue')!.req
    expect(q).toMatchObject({ action: 'cert_issue', ca: 'Lab-Sub', profile: 'machine', cn: 'PC003', dns: ['pc003.lab.test'] })
    expect(JSON.stringify(q)).not.toContain('evil')
    const txt = sh(['x509', '-noout', '-text'], r.json.certificate).stdout
    expect(txt).toContain('DNS:pc003.lab.test'); expect(txt).not.toContain('email:'); expect(txt).toContain('TLS Web Client Authentication')
    const a = (await audits('enroll.issued')).slice(-1)[0]; expect(a.entity_id).toBe('PC003$'); expect(a.detail).toMatchObject({ dns: 'pc003.lab.test', ca: 'Lab-Sub' })
  })
  it('un ticket déjà utilisé (rejeu) est refusé', async (ctx) => {
    if (!lab) return ctx.skip()
    await age(); clearAll()
    const tk = ticket(PC, PCPW), { csr } = newCsr('rsa', 'x')
    expect((await enroll(tk, { csr: { pem: csr } })).status).toBe(200)
    await age(); clearAll()
    const again = await enrollJson(await enroll(tk, { csr: { pem: csr } })); code(again, 401, 'enroll_kerberos')
  })
  it('limitation : délai minimal, plafond par jour, plafond global', async (ctx) => {
    if (!lab) return ctx.skip()
    await age(); clearAll()
    const { csr } = newCsr('rsa', 'x')
    expect((await enroll(ticket(PC, PCPW), { csr: { pem: csr } })).status).toBe(200)
    code(await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: csr } })), 429, 'enroll_rate_too_soon')
    await age(); clearAll()
    expect((await admin.put('/api/enroll/config', cfgBody({ maxPerDay: 1 }))).status).toBe(200)
    code(await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: csr } })), 429, 'enroll_rate_daily')
    expect((await admin.put('/api/enroll/config', cfgBody({ maxPerDay: 50, maxPerMinute: 1 }))).status).toBe(200)
    await db.query("update audit_log set at = now() - interval '2 hours' where action = 'enroll.issued'")   // plus rien « aujourd'hui » pour PC003$ mais une émission à l'instant : plafond global
    await db.query("insert into audit_log (action, entity, entity_id, detail) values ('enroll.issued', 'machine', 'AUTRE$', '{}')")
    code(await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: csr } })), 429, 'enroll_rate_busy')
    expect((await admin.put('/api/enroll/config', cfgBody())).status).toBe(200); await age()
  })
  it('requêtes simultanées d\'un même poste : une seule émission, les autres sont refusées', async (ctx) => {
    if (!lab) return ctx.skip()
    await age(); clearAll(); rootLog.length = 0
    const { csr } = newCsr('rsa', 'x'), before = (await audits('enroll.issued')).length
    const tickets = Array.from({ length: 5 }, () => ticket(PC, PCPW))
    const res = await Promise.all(tickets.map((t) => enroll(t, { csr: { pem: csr } }).then((r) => r.status)))
    expect(res.filter((x) => x === 200).length, JSON.stringify(res)).toBe(1)
    expect(res.filter((x) => x === 429).length, JSON.stringify(res)).toBe(4)
    expect(rootLog.filter((x) => x.req.action === 'cert_issue').length).toBe(1)
    expect((await audits('enroll.issued')).length - before).toBe(1)
    await age()
  })
  it('un nom DNS de l\'annuaire qui n\'est pas celui du compte est refusé', async (ctx) => {
    if (!lab) return ctx.skip()
    await age(); clearAll()
    const ldif = (dns: string) => `dn: CN=PC003,CN=Computers,DC=lab,DC=test\nchangetype: modify\nreplace: dNSHostName\ndNSHostName: ${dns}\n`
    const mod = (dns: string) => spawnSync('ldapmodify', ['-H', 'ldaps://dc1.lab.test', '-D', 'administrator@lab.test', '-w', 'Passw0rd-Lab-1!'], { encoding: 'utf8', input: ldif(dns), env: { ...process.env, LDAPTLS_CACERT: join(LAB, 'private/tls/ca.pem') } })
    const m = mod('srv01.lab.test'); expect(m.status, m.stderr).toBe(0)
    try { code(await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: newCsr('rsa', 'x').csr } })), 403, 'enroll_name_mismatch') }
    finally { expect(mod('PC003.lab.test').status).toBe(0) }
    expect((await enroll(ticket(PC, PCPW), { csr: { pem: newCsr('rsa', 'x').csr } })).status).toBe(200)   // rétabli : l'émission reprend
    await age()
  })
  it('un nom DNS hors du domaine du compte est refusé, même avec le bon premier label', async (ctx) => {
    if (!lab) return ctx.skip()
    await age(); clearAll()
    const mod = (dns: string) => spawnSync('ldapmodify', ['-H', 'ldaps://dc1.lab.test', '-D', 'administrator@lab.test', '-w', 'Passw0rd-Lab-1!'], { encoding: 'utf8', input: `dn: CN=PC003,CN=Computers,DC=lab,DC=test\nchangetype: modify\nreplace: dNSHostName\ndNSHostName: ${dns}\n`, env: { ...process.env, LDAPTLS_CACERT: join(LAB, 'private/tls/ca.pem') } })
    const m = mod('pc003.autre.example'); expect(m.status, m.stderr).toBe(0)
    try { code(await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: newCsr('rsa', 'x').csr } })), 403, 'enroll_name_mismatch') }
    finally { expect(mod('PC003.lab.test').status).toBe(0) }
    await age()
  })
  it('un flot de tickets illisibles ne remplit pas le journal d\'audit', async (ctx) => {
    if (!lab) return ctx.skip()
    const n = async () => Number((await rows("select count(*)::int as n from audit_log where action = 'enroll.refused' and entity_id = '-'"))[0].n)
    const before = await n()
    for (let i = 0; i < 40; i++) await enroll('YIIAAAAAAAAAAAAAAAAAAAA' + String(i).padStart(4, '0'), { csr: { pem: 'x' } })
    expect(await n() - before).toBeLessThanOrEqual(20)
  })
  it('refuse un ordinateur hors du groupe autorisé, puis accepte quand le groupe change', async (ctx) => {
    if (!lab) return ctx.skip()
    await age(); clearAll()
    const { csr } = newCsr('rsa', 'x')
    expect((await admin.put('/api/enroll/config', cfgBody({ groupDn: GROUP_NO }))).status).toBe(200)
    code(await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: csr } })), 403, 'enroll_not_in_group')
    expect(rootLog.filter((x) => x.req.action === 'cert_issue').length).toBe(0)
    expect((await admin.put('/api/enroll/config', cfgBody({ groupDn: 'CN=grp-wifi-it,CN=Users,DC=lab,DC=test' }))).status).toBe(200)
    code(await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: csr } })), 403, 'enroll_not_in_group')   // PC003$ n'est PAS dans grp-wifi-it : imbriqué seulement pour alice
    expect((await admin.put('/api/enroll/config', cfgBody({ groupDn: 'CN=grp-vpn,CN=Users,DC=lab,DC=test' }))).status).toBe(200)
    expect((await enroll(ticket(PC, PCPW), { csr: { pem: csr } })).status).toBe(200)   // PC003$ est membre direct de grp-vpn
    expect((await admin.put('/api/enroll/config', cfgBody())).status).toBe(200); await age()
  })
  it('un compte d\'utilisateur ne peut pas s\'enrôler comme un poste', async (ctx) => {
    if (!lab) return ctx.skip()
    const { csr } = newCsr('rsa', 'x')
    const r = await enrollJson(await enroll(ticket('alice@LAB.TEST', 'Passw0rd-alice-1!'), { csr: { pem: csr } })); code(r, 403, 'enroll_not_machine')
    const last = (await audits('enroll.refused')).slice(-1)[0]; expect(last.detail).toMatchObject({ reason: 'enroll_not_machine' })
  })
  it('un compte du domaine qui insiste n\'inonde pas le journal : refus écrits plafonnés par principal', async (ctx) => {
    if (!lab) return ctx.skip()
    const n = async () => Number((await rows("select count(*)::int as n from audit_log where action = 'enroll.refused' and lower(entity_id) like 'alice@%'"))[0].n)
    const before = await n()
    for (let i = 0; i < 26; i++) await enroll(ticket('alice@LAB.TEST', 'Passw0rd-alice-1!'), { csr: { pem: 'x' } })
    expect(await n() - before).toBeLessThanOrEqual(20)
  })
  it('un compte d\'ordinateur désactivé est refusé même avec un ticket valide', async (ctx) => {
    if (!lab) return ctx.skip()
    await age(); clearAll()
    const { csr } = newCsr('rsa', 'x'), tk = ticket(PC, PCPW)
    expect(smb('user', 'disable', 'PC003$').status).toBe(0)
    try { code(await enrollJson(await enroll(tk, { csr: { pem: csr } })), 403, 'enroll_account_unusable') } finally { smb('user', 'enable', 'PC003$') }
  })
  it('demande mal formée : refus sans émission', async (ctx) => {
    if (!lab) return ctx.skip()
    await age(); clearAll(); rootLog.length = 0
    code(await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: 'pas une demande' } })), 400, 'pki_bad_file')
    await age()
    code(await enrollJson(await enroll(ticket(PC, PCPW), { csr: { pem: newCsr('rsa', 'x').csr }, extra: 1 })), 400, 'validation')
    expect(rootLog.length).toBe(0)
  })
})

describe('GPO mise en place par la console (LDAPS et SMB réels, identifiants à usage unique)', () => {
  const ADM = 'administrator@lab.test', ADM_PW = 'Passw0rd-Lab-1!', OU = 'OU=Postes,DC=lab,DC=test'
  const policies = () => join(LAB, 'state/sysvol/lab.test/Policies')
  const ldap = (base: string, filter: string, ...attrs: string[]) => spawnSync('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-H', 'ldaps://dc1.lab.test', '-D', ADM, '-w', ADM_PW, '-b', base, '-s', 'base', filter, ...attrs],
    { encoding: 'utf8', env: { ...process.env, LDAPTLS_CACERT: join(LAB, 'private/tls/ca.pem') } }).stdout
  const gpoBody = (o: Record<string, unknown> = {}) => ({ ou: OU, account: ADM, password: ADM_PW, dry: false, ...o })
  let ouGpo = ''
  const guidsOnDisk = () => (existsSync(policies()) ? readdirSync(policies()).filter((x) => x.startsWith('{') && !x.startsWith('{31B2F340') && !x.startsWith('{6AC1786C')) : [])

  it('réservé à l\'administrateur ; corps strict (compte, mot de passe, unité d\'organisation)', async (ctx) => {
    if (!lab) return ctx.skip()
    code(await anon.post('/api/enroll/gpo', gpoBody()), 401, 'unauthenticated'); code(await viewer.post('/api/enroll/gpo', gpoBody()), 403, 'forbidden')
    for (const bad of [{ account: 'administrator' }, { account: 'a b@lab.test' }, { account: 'x%secret@lab.test' }, { password: '' }, { ou: 'OU=x' }, { dry: 'oui' }, { extra: 1 }]) code(await admin.post('/api/enroll/gpo', gpoBody(bad)), 400, 'validation')
  })
  it('refuse la racine du domaine, « Domain Controllers », une unité inconnue, un mot de passe faux et un annuaire sans LDAPS ; rien n\'est créé', async (ctx) => {
    if (!lab) return ctx.skip()
    expect(smb('ou', 'create', OU).status).toBe(0)
    const before = guidsOnDisk()
    for (const ou of ['DC=lab,DC=test', 'OU=Domain Controllers,DC=lab,DC=test', 'OU=Postes,DC=autre,DC=test']) code(await admin.post('/api/enroll/gpo', gpoBody({ ou })), 400, 'enroll_gpo_ou')
    code(await admin.post('/api/enroll/gpo', gpoBody({ ou: 'OU=Inconnue,DC=lab,DC=test' })), 400, 'enroll_gpo_ou_missing')   // absente : la console propose de la créer
    for (const ou of ['CN=Computers,DC=lab,DC=test', 'CN=Users,DC=lab,DC=test']) code(await admin.post('/api/enroll/gpo', gpoBody({ ou })), 400, 'enroll_gpo_ou_container')   // un conteneur n'accepte pas de GPO
    code(await admin.post('/api/enroll/gpo', gpoBody({ password: 'Mauvais-1!' })), 409, 'enroll_gpo_bind')
    code(await admin.post('/api/enroll/gpo', gpoBody({ account: 'svc-radius@lab.test', password: BIND_PW })), 409, 'enroll_gpo_denied')   // un compte sans droit d'écriture
    const put = await admin.put('/api/radius/directory', { urls: ['ldap://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc-radius@lab.test', bindPassword: BIND_PW, tlsRejectUnauthorized: true, caPem: CA })
    if (put.status === 200) { code(await admin.post('/api/enroll/gpo', gpoBody()), 409, 'enroll_gpo_tls'); expect((await setDir()).status).toBe(200) }
    expect(guidsOnDisk()).toEqual(before)
    expect(ldap(`CN=Policies,CN=System,DC=lab,DC=test`, '(displayName=DDI-Buntu enrolement)', 'cn')).not.toContain('{')
  })
  it('création d\'une unité d\'organisation : mêmes garde-fous, jamais deux fois, jamais sans droit', async (ctx) => {
    if (!lab) return ctx.skip()
    const mk = (o: Record<string, unknown> = {}) => admin.post('/api/enroll/gpo/ou', { ou: 'OU=Nouvelle,DC=lab,DC=test', account: ADM, password: ADM_PW, ...o })
    code(await anon.post('/api/enroll/gpo/ou', { ou: OU, account: ADM, password: ADM_PW }), 401, 'unauthenticated'); code(await viewer.post('/api/enroll/gpo/ou', { ou: OU, account: ADM, password: ADM_PW }), 403, 'forbidden')
    code(await mk({ dry: true }), 400, 'validation')
    for (const ou of ['DC=lab,DC=test', 'OU=Domain Controllers,DC=lab,DC=test', 'CN=Nouvelle,DC=lab,DC=test', 'OU=Nouvelle,DC=autre,DC=test', 'OU=Fille,OU=Absente,DC=lab,DC=test']) code(await mk({ ou }), 400, 'enroll_gpo_ou')
    code(await mk({ password: 'Mauvais-1!' }), 409, 'enroll_gpo_bind'); code(await mk({ account: 'svc-radius@lab.test', password: BIND_PW }), 409, 'enroll_gpo_denied')
    expect(ldap('OU=Nouvelle,DC=lab,DC=test', '(objectClass=*)', 'ou')).not.toContain('ou: Nouvelle')
    const r = await mk(); expect(r.status, r.text).toBe(200); expect(r.json).toMatchObject({ ou: 'OU=Nouvelle,DC=lab,DC=test', created: true })
    expect(ldap('OU=Nouvelle,DC=lab,DC=test', '(objectClass=*)', 'ou', 'objectClass')).toContain('objectClass: organizationalUnit')
    expect((await mk()).json).toMatchObject({ created: false })
    expect((await audits('enroll.gpo_ou')).length).toBe(2)
    expect(JSON.stringify(await rows("select detail from audit_log where action like 'enroll.gpo%'"))).not.toContain(ADM_PW)
    expect(smb('ou', 'delete', 'OU=Nouvelle,DC=lab,DC=test').status).toBe(0)
  })
  it('simulation : vérifie compte, unité et SYSVOL sans rien écrire', async (ctx) => {
    if (!lab) return ctx.skip()
    const before = guidsOnDisk()
    const r = await admin.post('/api/enroll/gpo', gpoBody({ dry: true })); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ dry: true, created: true, domain: 'lab.test', ou: OU }); expect(r.json.steps.map((x: any) => x.id)).toEqual(['bind', 'ou', 'gpo', 'files', 'link'])
    expect(guidsOnDisk()).toEqual(before); expect(ldap(OU, '(objectClass=*)', 'gPLink')).not.toContain('gPLink')
    expect((await audits('enroll.gpo_checked')).length).toBeGreaterThan(0)
  })
  it('création : objet d\'annuaire, fichiers dans SYSVOL, lien sur l\'unité ; Samba relit la GPO', async (ctx) => {
    if (!lab) return ctx.skip()
    const r = await admin.post('/api/enroll/gpo', gpoBody()); expect(r.status, r.text).toBe(200)
    const id = r.json.gpoId as string; ouGpo = id; expect(id).toMatch(/^\{[0-9A-F-]{36}\}$/); expect(r.json.created).toBe(true)
    const dir = join(policies(), id), startup = join(dir, 'Machine/Scripts/Startup')
    expect(readFileSync(join(dir, 'GPT.INI'), 'utf8')).toBe('[General]\r\nVersion=1\r\n')
    expect(readdirSync(startup).sort()).toEqual(expect.arrayContaining(['ddi-demarrage.ps1', 'enroll.ps1']))
    expect([...readFileSync(join(startup, 'enroll.ps1')).subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]); expect(readFileSync(join(startup, 'enroll.ps1'), 'utf8')).toContain("$Console   = 'ddi.lab.test'")
    const ini = readFileSync(join(dir, 'Machine/Scripts/scripts.ini')); expect([...ini.subarray(0, 2)]).toEqual([0xff, 0xfe])
    expect(ini.subarray(2).toString('utf16le')).toContain(`-File "\\\\lab.test\\SYSVOL\\lab.test\\Policies\\${id}\\Machine\\Scripts\\Startup\\ddi-demarrage.ps1"`)
    expect(existsSync(join(dir, 'User'))).toBe(true)
    const o = ldap(`CN=${id},CN=Policies,CN=System,DC=lab,DC=test`, '(objectClass=*)', 'displayName', 'versionNumber', 'gPCMachineExtensionNames', 'gPCFileSysPath', 'flags')
    expect(o).toContain('displayName: DDI-Buntu enrolement'); expect(o).toContain('versionNumber: 1'); expect(o).toContain('gPCMachineExtensionNames: [{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]')
    expect(o).toContain(`gPCFileSysPath: \\\\lab.test\\SysVol\\lab.test\\Policies\\${id}`)
    expect(ldap(OU, '(objectClass=*)', 'gPLink')).toContain(`[LDAP://CN=${id},CN=Policies,CN=System,DC=lab,DC=test;0]`)
    const st = (...a: string[]) => spawnSync(PY, [spawnSync('which', ['samba-tool'], { encoding: 'utf8' }).stdout.trim(), 'gpo', ...a, '-H', join(LAB, 'private/sam.ldb'), `--configfile=${join(LAB, 'etc/smb.conf')}`], { encoding: 'utf8' })
    const list = st('listall'); expect(list.stdout, list.stderr).toContain(`GPO          : ${id}`); expect(list.stdout).toContain('display name : DDI-Buntu enrolement')
    const gl = st('getlink', OU); expect(gl.stdout, gl.stderr).toContain(id)   // Samba relit le lien comme le ferait un contrôleur de domaine
    expect((await audits('enroll.gpo_applied')).length).toBeGreaterThan(0)
  })
  it('relance : la même GPO est mise à jour (version +1), le lien n\'est pas dupliqué', async (ctx) => {
    if (!lab) return ctx.skip()
    const first = guidsOnDisk(); expect(first).toHaveLength(1)
    const r = await admin.post('/api/enroll/gpo', gpoBody()); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ created: false, gpoId: first[0] }); expect(guidsOnDisk()).toEqual(first)
    expect(readFileSync(join(policies(), first[0]!, 'GPT.INI'), 'utf8')).toBe('[General]\r\nVersion=2\r\n')
    expect(ldap(`CN=${first[0]},CN=Policies,CN=System,DC=lab,DC=test`, '(objectClass=*)', 'versionNumber')).toContain('versionNumber: 2')
    expect(ldap(OU, '(objectClass=*)', 'gPLink').split(`CN=${first[0]},`).length).toBe(2)
    expect(r.json.steps.find((x: any) => x.id === 'link').action).toBe('keep')
  })
  it('le mot de passe ne figure ni dans les réponses, ni dans le journal d\'audit, ni dans la base', async (ctx) => {
    if (!lab) return ctx.skip()
    const bad = await admin.post('/api/enroll/gpo', gpoBody({ password: 'Secret-a-ne-pas-voir-1!' }))
    expect(bad.text).not.toContain('Secret-a-ne-pas-voir-1!')
    const all = JSON.stringify(await rows("select action, detail, entity_id from audit_log where action like 'enroll.gpo%'")) + JSON.stringify(await rows("select key, value from settings where value::text like '%Secret-a-ne-pas-voir%' or value::text like '%Passw0rd-Lab-1%'"))
    expect(all).not.toContain('Secret-a-ne-pas-voir-1!'); expect(all).not.toContain(ADM_PW)
    expect((await audits('enroll.gpo_refused')).length).toBeGreaterThan(0)
  })
  it('groupe d\'ordinateurs : GPO liée à la racine et filtrée sur le groupe ; refus des cibles trop larges ; groupe créé par la console', async (ctx) => {
    if (!lab) return ctx.skip()
    const G = 'CN=Postes-DDI,CN=Users,DC=lab,DC=test', ROOT = 'DC=lab,DC=test'
    const g = (o: Record<string, unknown> = {}) => admin.post('/api/enroll/gpo', { group: G, account: ADM, password: ADM_PW, dry: false, ...o })
    const sddl = (id: string) => { const r = spawnSync(PY, [spawnSync('which', ['samba-tool'], { encoding: 'utf8' }).stdout.trim(), 'dsacl', 'get', `--objectdn=CN=${id},CN=Policies,CN=System,${ROOT}`, '-H', join(LAB, 'private/sam.ldb'), `--configfile=${join(LAB, 'etc/smb.conf')}`], { encoding: 'utf8' }); expect(r.status, r.stderr).toBe(0); return r.stdout }
    const APPLY = 'OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;'
    code(await admin.post('/api/enroll/gpo', { account: ADM, password: ADM_PW, dry: true }), 400, 'validation'); code(await admin.post('/api/enroll/gpo', gpoBody({ group: G })), 400, 'validation')   // exactement une cible
    code(await g({ group: 'CN=Postes-DDI,CN=Users,DC=autre,DC=test' }), 400, 'enroll_gpo_group'); code(await g({ group: 'CN=Computers,DC=lab,DC=test' }), 400, 'enroll_gpo_group')   // hors domaine ; un conteneur n'est pas un groupe
    code(await g(), 400, 'enroll_gpo_group_missing')
    for (const broad of ['CN=Domain Computers,CN=Users,DC=lab,DC=test', 'CN=Domain Users,CN=Users,DC=lab,DC=test', 'CN=Domain Controllers,CN=Users,DC=lab,DC=test']) code(await g({ group: broad }), 400, 'enroll_gpo_group_broad')
    // création du groupe par la console
    const mk = (o: Record<string, unknown> = {}) => admin.post('/api/enroll/gpo/group', { group: G, account: ADM, password: ADM_PW, ...o })
    code(await anon.post('/api/enroll/gpo/group', { group: G, account: ADM, password: ADM_PW }), 401, 'unauthenticated'); code(await viewer.post('/api/enroll/gpo/group', { group: G, account: ADM, password: ADM_PW }), 403, 'forbidden')
    code(await mk({ group: 'CN=Un-nom-de-groupe-beaucoup-trop-long,CN=Users,DC=lab,DC=test' }), 400, 'enroll_gpo_group'); code(await mk({ group: 'CN=X,CN=Absent,DC=lab,DC=test' }), 400, 'enroll_gpo_group')
    code(await mk({ account: 'svc-radius@lab.test', password: BIND_PW }), 409, 'enroll_gpo_denied'); code(await mk({ password: 'Mauvais-1!' }), 409, 'enroll_gpo_bind')
    expect((await mk()).json).toMatchObject({ group: G, created: true }); expect((await mk()).json).toMatchObject({ created: false })
    expect(ldap(G, '(objectClass=*)', 'sAMAccountName', 'groupType')).toContain('sAMAccountName: Postes-DDI')
    // groupe vide, puis avec un ordinateur ; un groupe qui contient un contrôleur de domaine est refusé
    expect((await g({ dry: true })).json.members).toMatchObject({ count: 0, names: [] })
    expect(smb('group', 'addmembers', 'Postes-DDI', 'PC003$').status).toBe(0)
    const dry = await g({ dry: true }); expect(dry.status, dry.text).toBe(200)
    expect(dry.json.members).toMatchObject({ count: 1, names: ['PC003'], truncated: false }); expect(dry.json.steps.map((x: any) => x.id)).toEqual(['bind', 'group', 'gpo', 'files', 'filter', 'link'])
    const dc = spawnSync('ldapsearch', ['-LLL', '-H', 'ldaps://dc1.lab.test', '-D', ADM, '-w', ADM_PW, '-b', ROOT, '(&(objectClass=computer)(primaryGroupID=516))', 'sAMAccountName'], { encoding: 'utf8', env: { ...process.env, LDAPTLS_CACERT: join(LAB, 'private/tls/ca.pem') } }).stdout.match(/sAMAccountName: (\S+)/)![1]!
    expect(smb('group', 'add', 'Postes-DC').status).toBe(0); expect(smb('group', 'addmembers', 'Postes-DC', dc).status).toBe(0)
    code(await g({ group: 'CN=Postes-DC,CN=Users,DC=lab,DC=test' }), 400, 'enroll_gpo_group_dc')
    // mise en place : une GPO à part, liée à la racine ; « Utilisateurs authentifiés » ne peut plus l'appliquer, le groupe seul le peut
    const before = guidsOnDisk(); const r = await g(); expect(r.status, r.text).toBe(200)
    const id = r.json.gpoId as string; expect(r.json).toMatchObject({ created: true, group: G, ou: ROOT }); expect(id).not.toBe(ouGpo); expect(guidsOnDisk()).toHaveLength(before.length + 1)
    expect(ldap(`CN=${id},CN=Policies,CN=System,${ROOT}`, '(objectClass=*)', 'displayName')).toContain('displayName: DDI-Buntu enrolement (groupe)')
    const acl = sddl(id); expect(acl).not.toContain(`${APPLY}AU)`); expect(acl).toMatch(new RegExp(`${APPLY}S-1-5-21-[0-9-]+\\)`)); expect(acl).toMatch(/;;;AU\)/)   // lecture conservée pour les authentifiés
    expect(ldap(ROOT, '(objectClass=*)', 'gPLink')).toContain(`[LDAP://CN=${id},CN=Policies,CN=System,DC=lab,DC=test;0]`)
    expect(sddl(ouGpo)).toContain(`${APPLY}AU)`)   // la GPO de l'unité d'organisation n'est pas touchée
    // relance : même GPO, filtre déjà en place, lien et ACE non dupliqués
    const again = await g(); expect(again.json).toMatchObject({ created: false, gpoId: id })
    expect(again.json.steps.find((x: any) => x.id === 'filter').action).toBe('keep'); expect(again.json.steps.find((x: any) => x.id === 'link').action).toBe('keep')
    expect(sddl(id).split(APPLY).length).toBe(2); expect(ldap(ROOT, '(objectClass=*)', 'gPLink').split(`CN=${id},`).length).toBe(2)
  })
})

describe('arrêt', () => {
  it('désactiver éteint la route ; retirer le keytab désactive aussi', async () => {
    expect((await admin.put('/api/enroll/config', cfgBody({ enabled: false }))).status).toBe(200)
    code(await enrollJson(await enroll(null)), 404, 'not_found')
    const kt = keytab([{ comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 18 }])
    expect((await admin.put('/api/enroll/keytab', { keytab: kt.toString('base64') })).status).toBe(200)
    if (lab) { expect((await admin.put('/api/enroll/config', cfgBody())).status).toBe(200) }
    expect((await admin.del('/api/enroll/keytab')).status).toBe(200)
    const g = (await admin.get('/api/enroll')).json; expect(g.keytab).toBeNull(); expect(g.settings.enabled).toBe(false); expect(g.ready).toBe(false)
    code(await enrollJson(await enroll(null)), 404, 'not_found')
  })
})

describe('certificat HTTPS de la console, automatique (0.21.0)', () => {
  const GENDIR = () => join(TMP, 'tlsgen'), view = () => admin.get('/api/system/console-tls')
  it('réservé à l\'administrateur ; réglages validés', async () => {
    code(await anon.get('/api/system/console-tls'), 401, 'unauthenticated'); code(await viewer.get('/api/system/console-tls'), 403, 'forbidden'); code(await oper.get('/api/system/console-tls'), 403, 'forbidden')
    code(await viewer.put('/api/system/console-tls', { auto: false, ca: '', names: [] }), 403, 'forbidden'); code(await viewer.post('/api/system/console-tls/issue', { force: false }), 403, 'forbidden')
    code(await admin.put('/api/system/console-tls', { auto: true, ca: '', names: ['console.lab.test'] }), 400, 'console_tls_ca_required')
    code(await admin.put('/api/system/console-tls', { auto: true, ca: 'Lab-Root', names: [] }), 409, 'pki_ca_not_issuing')
    code(await admin.put('/api/system/console-tls', { auto: false, ca: '', names: ['pas valide!'] }), 400, 'validation'); code(await admin.put('/api/system/console-tls', { auto: false, ca: '', names: [], x: 1 }), 400, 'validation')
    code(await admin.post('/api/system/console-tls/issue', { force: false }), 409, 'console_tls_disabled')
    const g = await view(); expect(g.status, g.text).toBe(200); expect(g.json).toMatchObject({ auto: false, cert: null, issuers: ['Lab-Sub'], leader: true })
  })
  it('émet par la PKI avec tous les noms, range la clé chiffrée, dépose les fichiers du nœud ; une passe de plus ne refait rien', async (ctx) => {
    if (!lab) return ctx.skip()
    expect((await admin.put('/api/enroll/config', cfgBody({ enabled: false }))).status).toBe(200)   // la console des postes (ddi.lab.test) fait partie des noms voulus
    const put = await admin.put('/api/system/console-tls', { auto: true, ca: 'Lab-Sub', names: ['console.lab.test'] }); expect(put.status, put.text).toBe(200)
    expect(put.json.want.dns).toEqual(['console.lab.test', 'ddi.lab.test'])
    const r = await admin.post('/api/system/console-tls/issue', { force: false }); expect(r.status, r.text + srvLog.slice(-800)).toBe(200)
    expect(r.json.cert).toMatchObject({ dns: ['console.lab.test', 'ddi.lab.test'] }); expect(r.json.last).toMatchObject({ ok: true }); const first = r.json.cert.serial
    expect(rootLog.filter((x) => x.req.action === 'cert_issue' && x.req.profile === 'server').length).toBeGreaterThan(0)
    // dépôt : clé 0600 qui correspond au certificat, chaîne jusqu'à la racine
    const crt = join(GENDIR(), 'console.crt'), key = join(GENDIR(), 'console.key')
    expect(existsSync(crt) && existsSync(key)).toBe(true); expect(statSync(key).mode & 0o777).toBe(0o600)
    expect(sh(['x509', '-in', crt, '-noout', '-pubkey']).stdout.trim()).toBe(sh(['pkey', '-in', key, '-pubout']).stdout.trim())
    expect((read(crt).match(/BEGIN CERTIFICATE/g) ?? []).length).toBeGreaterThanOrEqual(2)
    // en base : la clé est chiffrée, jamais en clair
    const saved = (await rows("select value::text as v from settings where key = 'console_tls'"))[0]!.v as string
    expect(saved).not.toContain('PRIVATE KEY'); expect(saved).toContain('v1:')
    // certificat à jour : une passe de plus ne demande rien à la PKI
    const n = rootLog.length; const again = await admin.post('/api/system/console-tls/issue', { force: false }); expect(again.status).toBe(200)
    expect(rootLog.length).toBe(n); expect(again.json.cert.serial).toBe(first)
    // renouvellement demandé : un autre certificat
    const f = await admin.post('/api/system/console-tls/issue', { force: true }); expect(f.status, f.text).toBe(200); expect(f.json.cert.serial).not.toBe(first)
    expect((await audits('system.console_tls')).length).toBeGreaterThan(0); expect((await audits('system.console_tls_issue')).length).toBeGreaterThan(0)
    // les noms voulus changent : un nouveau certificat est émis à la passe suivante
    const names = await admin.put('/api/system/console-tls', { auto: true, ca: 'Lab-Sub', names: ['console.lab.test', 'vip.lab.test'] }); expect(names.status).toBe(200)
    const third = await admin.post('/api/system/console-tls/issue', { force: false }); expect(third.json.cert.dns).toContain('vip.lab.test')
  })
  it('refuse un renouvellement quand la PKI refuse, en gardant le certificat en place', async (ctx) => {
    if (!lab) return ctx.skip()
    const before = (await view()).json.cert.serial
    rootRefuse = 'refus simulé'
    try { code(await admin.post('/api/system/console-tls/issue', { force: true }), 502, 'console_tls_issue_failed') } finally { rootRefuse = null }
    const g = await view(); expect(g.json.cert.serial).toBe(before)
  })
  it('test de confiance : réglé mais injoignable depuis ici, sans rien inventer', async () => {
    code(await anon.get('/api/enroll/trust'), 401, 'unauthenticated'); code(await viewer.get('/api/enroll/trust'), 403, 'forbidden')
    const t = await admin.get('/api/enroll/trust'); expect(t.status, t.text).toBe(200)
    expect(t.json).toMatchObject({ configured: true, reachable: false, reasons: [] })
  })
})
