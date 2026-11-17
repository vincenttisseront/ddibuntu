// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.3 — certificats de la PKI : droits, validation, liste / recherche / filtres / pagination lues dans la base
// d'EJBCA (ici une copie minimale de ses deux tables, avec le rôle de la console), export CSV, téléchargements, émission depuis une demande de certificat, émission
// avec une clé fabriquée ici (PKCS#12 ouvert avec openssl), révocation, refus de root, délai, une émission à la fois, audit sans clé ni mot de passe. « root » est
// simulé par ce test : il lit la demande et le dépôt, signe VRAIMENT la demande avec openssl, publie le dossier du certificat et le résultat (même format que
// ddibuntu-pki). Ce que root fait avec le vrai EJBCA est vérifié par tests/b34-pki-cert.sh et tests/b33-pki-ca-live.sh.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3478, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const EJURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_ejbca_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s51-')), GEN = join(TMP, 'gen'), IN = join(GEN, 'pki-in'), REQ = join(GEN, '.pki-request')
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
function mint(name: string, subject: string, days: number, san: string, ext = 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth'): { pem: string; der: Buffer; serialHex: string; serialDec: string; fp: string } {
  const f = (s: string) => join(SSL, `${name}.${s}`)
  sh(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', f('key'), '-out', f('csr'), '-subj', subject])
  writeFileSync(f('ext'), ext + (san ? `\nsubjectAltName=${san}` : '') + '\n')
  sh(['x509', '-req', '-in', f('csr'), '-CA', join(SSL, 'sub.pem'), '-CAkey', join(SSL, 'sub.key'), '-CAcreateserial', '-out', f('pem'), '-days', String(days), '-extfile', f('ext')])
  const pem = read(f('pem'))
  const der = Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ''), 'base64')
  const serialHex = sh(['x509', '-in', f('pem'), '-noout', '-serial']).stdout.trim().split('=')[1]!.toUpperCase().replace(/^0+/, '')
  return { pem, der, serialHex, serialDec: BigInt('0x' + serialHex).toString(10), fp: createHash('sha1').update(der).digest('hex') }
}
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
const F: Record<string, ReturnType<typeof mint>> = {}

beforeAll(async () => {
  mkdirSync(GEN, { recursive: true }); mkdirSync(SSL, { recursive: true }); mkdirSync(IN, { recursive: true }); mkdirSync(CERTDIR, { recursive: true })
  mkdirSync(join(CADIR, 'Lab-Sub'), { recursive: true })
  // autorités de test : racine → émettrice
  sh(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(SSL, 'root.key'), '-out', join(SSL, 'root.pem'), '-days', '3650', '-subj', '/CN=Lab Root CA/O=Lab/C=FR',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
  sh(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(SSL, 'sub.key'), '-out', join(SSL, 'sub.csr'), '-subj', '/CN=Lab Sub CA/O=Lab/C=FR'])
  writeFileSync(join(SSL, 'ca.ext'), 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
  sh(['x509', '-req', '-in', join(SSL, 'sub.csr'), '-CA', join(SSL, 'root.pem'), '-CAkey', join(SSL, 'root.key'), '-CAcreateserial', '-out', join(SSL, 'sub.pem'), '-days', '3000', '-extfile', join(SSL, 'ca.ext')])
  writeFileSync(join(CADIR, 'Lab-Sub', 'cert.pem'), read(join(SSL, 'sub.pem'))); writeFileSync(join(CADIR, 'Lab-Sub', 'chain.pem'), read(join(SSL, 'root.pem')))
  F.srv = mint('srv', '/CN=radius1.lab.test/O=Lab/C=FR', 700, 'DNS:radius1.lab.test,IP:10.1.2.3')
  F.usr = mint('usr', '/CN=Jean Dupont/O=Lab/C=FR', 10, 'email:jdupont@lab.test', 'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth')
  F.mac = mint('mac', '/CN=pc01/O=Lab/C=FR', 300, 'DNS:pc01.lab.test', 'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth')
  F.net = mint('net', '/CN=sw1/O=Lab/C=FR', 100, 'DNS:sw1.lab.test')
  F.oth = mint('oth', '/CN=autre/O=Lab/C=FR', 100, '')
  F.mgt = mint('mgt', '/CN=mgmt/O=Lab/C=FR', 100, '')
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
  const day = 86_400_000, now = Date.now()
  const ins = async (x: ReturnType<typeof mint>, o: { issuer?: string; subject: string; san?: string; profile: number; status?: number; type?: number; nb?: number; exp?: number; revAt?: number; reason?: number; b64?: boolean }) => {
    await ej.query(`insert into certificatedata (fingerprint, base64cert, certificateprofileid, endentityprofileid, expiredate, issuerdn, notbefore, revocationdate, revocationreason, serialnumber, status, subjectaltname, subjectdn, type, updatetime, username)
      values ($1,$2,$3,5020001,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'ddi-x')`,
      [x.fp, o.b64 === false ? null : x.der.toString('base64'), o.profile, o.exp ?? now + 300 * day, o.issuer ?? SUBDN, o.nb ?? now - day, o.revAt ?? -1, o.reason ?? -1, x.serialDec, o.status ?? 20, o.san ?? '', o.subject, o.type ?? 1, now])
  }
  await ins(F.srv!, { subject: 'CN=radius1.lab.test,O=Lab,C=FR', san: 'dNSName=radius1.lab.test, iPAddress=10.1.2.3', profile: 5010001, nb: now - 5 * day, exp: now + 700 * day })
  await ins(F.usr!, { subject: 'CN=Jean Dupont,O=Lab,C=FR', san: 'rfc822Name=jdupont@lab.test', profile: 5010003, nb: now - 355 * day, exp: now + 10 * day })
  await ins(F.mac!, { subject: 'CN=pc01,O=Lab,C=FR', san: 'dNSName=pc01.lab.test', profile: 5010002, status: 40, revAt: now - 2 * day, reason: 1, nb: now - 60 * day, exp: now + 300 * day })
  await ins(F.net!, { subject: 'CN=sw1,O=Lab,C=FR', san: 'dNSName=sw1.lab.test', profile: 5010004, nb: now - 400 * day, exp: now - 35 * day })
  await ins(F.oth!, { subject: 'CN=autre,O=Lab,C=FR', profile: 12345, nb: now - 20 * day, exp: now + 100 * day })
  await ins(F.mgt!, { subject: 'CN=mgmt,O=Lab,C=FR', profile: 5010001, issuer: 'CN=ManagementCA,O=EJBCA Sample,C=SE' })
  await ej.query(`insert into certificatedata (fingerprint, base64cert, certificateprofileid, endentityprofileid, expiredate, issuerdn, notbefore, revocationdate, revocationreason, serialnumber, status, subjectaltname, subjectdn, type, updatetime)
    values ($1,$2,2,0,$3,$4,$5,-1,-1,'1',20,'', $6, 2, $7)`, ['c'.repeat(40), 'AAAA', now + day, ROOTDN, now - day, SUBDN, now])   // le certificat de l'émettrice : type 2, jamais listé
  for (let i = 0; i < 60; i++) await ej.query(`insert into certificatedata (fingerprint, certificateprofileid, endentityprofileid, expiredate, issuerdn, notbefore, revocationdate, revocationreason, serialnumber, status, subjectaltname, subjectdn, type, updatetime)
    values ($1,5010002,5020001,$2,$3,$4,-1,-1,$5,20,'',$6,1,$7)`, [(i + 1).toString(16).padStart(40, 'f'), now + 200 * day, SUBDN, now - (100 + i) * 1000, String(9000 + i), `CN=lot-${String(i).padStart(2, '0')},O=Lab,C=FR`, now])
  await ej.query('revoke all on all tables in schema public from public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_EJBCA_DATABASE_URL: EJURL, DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN,
    DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT, DDI_PKI_CAS: CAS, DDI_PKI_CA_DIR: CADIR, DDI_PKI_CERT_DIR: CERTDIR, DDI_PKI_ISSUE_TIMEOUT_MS: '3500' } })
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
  srv?.kill('SIGTERM'); await ej?.end().catch(() => {})
  await db?.query('drop database if exists ddibuntu_ejbca_test with (force)').catch(() => {}); await db?.end(); rmSync(TMP, { recursive: true, force: true })
})

describe('droits', () => {
  it('les certificats sont réservés à l\'administrateur', async () => {
    code(await anon.get('/api/pki/certs'), 401, 'unauthenticated')
    for (const c of [viewer, oper]) {
      code(await c.get('/api/pki/certs'), 403, 'forbidden'); code(await c.get('/api/pki/certs.csv'), 403, 'forbidden'); code(await c.get('/api/pki/certs/meta'), 403, 'forbidden')
      code(await c.get(`/api/pki/certs/${F.srv!.fp}/cert.pem`), 403, 'forbidden')
      code(await c.post('/api/pki/certs/csr', {}), 403, 'forbidden'); code(await c.post('/api/pki/certs/p12', {}), 403, 'forbidden')
      code(await c.post(`/api/pki/certs/${F.srv!.fp}/revoke`, { reason: 1 }), 403, 'forbidden')
    }
    expect(existsSync(REQ)).toBe(false)
  })
})

describe('liste, recherche, filtres', () => {
  it('métadonnées pour le formulaire', async () => {
    const r = (await admin.get('/api/pki/certs/meta')).json
    expect(r.profiles.map((p: any) => p.key)).toEqual(['server', 'machine', 'user', 'network']); expect(r.keyAlgs).toEqual(['rsa2048', 'rsa3072', 'ecp256', 'ecp384']); expect(r.reasons).toEqual([0, 1, 3, 4, 5])
    expect(r.profiles[0]).toMatchObject({ name: 'DDI-RADIUS-Server', allowed: ['dns', 'ip'], needAny: ['dns'], days: 730 })
  })
  it('liste les certificats finaux des émettrices du DDI, du plus récent au plus ancien, sans ManagementCA ni certificats d\'autorité', async () => {
    const r = (await admin.get('/api/pki/certs?limit=200')).json
    expect(r.total).toBe(65); expect(r.issuers).toEqual(['Lab-Sub'])
    expect(r.rows.map((x: any) => x.fingerprint)).not.toContain(F.mgt!.fp)
    expect(r.rows.map((x: any) => x.subject)).not.toContain(SUBDN)
    const subjects = r.rows.map((x: any) => x.subject)
    expect(subjects.slice(0, 3)).toEqual(['CN=lot-00,O=Lab,C=FR', 'CN=lot-01,O=Lab,C=FR', 'CN=lot-02,O=Lab,C=FR'])
    expect(subjects.slice(60)).toEqual(['CN=radius1.lab.test,O=Lab,C=FR', 'CN=autre,O=Lab,C=FR', 'CN=pc01,O=Lab,C=FR', 'CN=Jean Dupont,O=Lab,C=FR', 'CN=sw1,O=Lab,C=FR'])
  })
  it('états, séries en hexadécimal, profils et motif de révocation', async () => {
    const by = async (q: string) => (await admin.get(`/api/pki/certs?${q}`)).json.rows
    const srv = (await by('q=radius1'))[0]
    expect(srv).toMatchObject({ ca: 'Lab-Sub', profile: 'server', state: 'active', serial: F.srv!.serialHex, san: 'dNSName=radius1.lab.test, iPAddress=10.1.2.3', revokedAt: null, reason: null })
    expect(srv.notAfter > srv.notBefore).toBe(true)
    const mac = (await by('q=pc01'))[0]; expect(mac).toMatchObject({ profile: 'machine', state: 'revoked', reason: 1 }); expect(mac.revokedAt).toMatch(/^\d{4}-\d\d-\d\dT.*Z$/)
    expect((await by('q=sw1'))[0]).toMatchObject({ profile: 'network', state: 'expired', revokedAt: null })
    expect((await by('q=autre'))[0]).toMatchObject({ profile: 'other', state: 'active' })
    expect((await by('q=Jean'))[0]).toMatchObject({ profile: 'user', state: 'active' })
  })
  it('recherche : nom, nom alternatif, série en hexadécimal (minuscules ou majuscules)', async () => {
    const n = async (q: string) => (await admin.get(`/api/pki/certs?q=${encodeURIComponent(q)}`)).json.total
    expect(await n('radius1')).toBe(1); expect(await n('RADIUS1')).toBe(1); expect(await n('10.1.2.3')).toBe(1); expect(await n('jdupont@lab.test')).toBe(1)
    expect(await n(F.srv!.serialHex)).toBe(1); expect(await n(F.srv!.serialHex.toLowerCase())).toBe(1)
    expect(await n('lot-')).toBe(60); expect(await n('inexistant')).toBe(0)
    expect(await n('100%')).toBe(0); expect(await n("'; drop table certificatedata; --")).toBe(0)   // jamais interprété
    expect((await ej.query('select count(*)::int as n from certificatedata')).rows[0].n).toBe(67)
  })
  it('filtres : autorité, profil, état, expiration proche', async () => {
    const n = async (q: string) => (await admin.get(`/api/pki/certs?${q}`)).json.total
    expect(await n('ca=Lab-Sub')).toBe(65); expect(await n('ca=Lab-Root')).toBe(0); expect(await n('ca=Inconnue')).toBe(0)
    expect(await n('profile=server')).toBe(1); expect(await n('profile=machine')).toBe(61); expect(await n('profile=user')).toBe(1); expect(await n('profile=network')).toBe(1); expect(await n('profile=other')).toBe(1)
    expect(await n('state=active')).toBe(63); expect(await n('state=revoked')).toBe(1); expect(await n('state=expired')).toBe(1)
    expect(await n('expiring=30')).toBe(1); expect(await n('expiring=1')).toBe(0); expect(await n('expiring=800')).toBeGreaterThanOrEqual(62)
    expect(await n('state=active&profile=machine')).toBe(60); expect(await n('state=revoked&profile=server')).toBe(0)
  })
  it('pagination', async () => {
    const p1 = (await admin.get('/api/pki/certs?limit=10&offset=0')).json, p2 = (await admin.get('/api/pki/certs?limit=10&offset=10')).json, last = (await admin.get('/api/pki/certs?limit=10&offset=60')).json
    expect([p1.rows.length, p2.rows.length, last.rows.length, p1.total, p1.limit, p2.offset]).toEqual([10, 10, 5, 65, 10, 10])
    expect(new Set([...p1.rows, ...p2.rows].map((x: any) => x.fingerprint)).size).toBe(20)
    expect((await admin.get('/api/pki/certs?limit=5000')).json.limit).toBe(200)
  })
  it('paramètres refusés', async () => {
    for (const q of ['profile=EMPTY', 'state=tout', 'limit=abc', 'offset=-1', 'expiring=x', `q=${'a'.repeat(101)}`, 'ca=' + 'a'.repeat(49)]) code(await admin.get(`/api/pki/certs?${q}`), 400, 'invalid_query')
  })
  it('aucune émettrice active : liste vide sans lire la base', async () => {
    publish([FIXTURE[0], FIXTURE[2]])
    expect((await admin.get('/api/pki/certs')).json).toMatchObject({ rows: [], total: 0, issuers: [] })
    publish(FIXTURE)
  })
  it('base d\'EJBCA illisible : 503 lisible, pas d\'erreur interne', async () => {
    await ej.query('alter table certificatedata rename to certificatedata_x')
    try { code(await admin.get('/api/pki/certs'), 503, 'pki_certs_unavailable') } finally { await ej.query('alter table certificatedata_x rename to certificatedata') }
    expect((await admin.get('/api/pki/certs')).status).toBe(200)
  })
})

describe('export CSV et téléchargements', () => {
  it('CSV : en-tête, lignes, filtres, formules neutralisées, audit', async () => {
    await ej.query(`update certificatedata set subjectdn = '=HYPERLINK("http://x")' where fingerprint = $1`, [F.oth!.fp])
    try {
      const r = await admin.get('/api/pki/certs.csv?state=active&profile=other')
      expect(r.status).toBe(200); expect(r.headers.get('content-type')).toMatch(/text\/csv/); expect(r.headers.get('content-disposition')).toMatch(/attachment; filename="certificats-pki.csv"/)
      const lines = r.text.trimEnd().split('\n')
      expect(lines[0]).toBe('autorite,profil,serie,sujet,noms_alternatifs,debut,fin,etat,revoque_le,motif,empreinte_sha1'); expect(lines.length).toBe(2)
      expect(lines[1]).toContain(`"'=HYPERLINK(""http://x"")"`); expect(lines[1]).toContain(F.oth!.fp)
    } finally { await ej.query(`update certificatedata set subjectdn = 'CN=autre,O=Lab,C=FR' where fingerprint = $1`, [F.oth!.fp]) }
    const all = await admin.get('/api/pki/certs.csv'); expect(all.text.trimEnd().split('\n').length).toBe(66)
    expect((await rows(`select count(*)::int as n from audit_log where action = 'pki.cert_export'`))[0].n).toBe(2)
  })
  it('certificat et chaîne en PEM', async () => {
    const c = await admin.get(`/api/pki/certs/${F.srv!.fp}/cert.pem`)
    expect(c.status).toBe(200); expect(c.text).toBe(F.srv!.pem.replace(/\r/g, '')); expect(c.headers.get('content-disposition')).toMatch(/attachment; filename="radius1\.lab\.test-[0-9A-F]{1,8}\.pem"/)
    const ch = await admin.get(`/api/pki/certs/${F.srv!.fp}/chain.pem`)
    expect((ch.text.match(/BEGIN CERTIFICATE/g) ?? []).length).toBe(3)
    const f = join(TMP, 'dl.pem'); writeFileSync(f, ch.text)
    expect(sh(['verify', '-CAfile', join(SSL, 'root.pem'), '-untrusted', join(SSL, 'sub.pem'), f]).stdout).toMatch(/OK/)
  })
  it('introuvable : empreinte inconnue, autorité hors DDI, mauvais format, mauvais fichier', async () => {
    code(await admin.get(`/api/pki/certs/${'0'.repeat(40)}/cert.pem`), 404, 'not_found'); code(await admin.get(`/api/pki/certs/${F.mgt!.fp}/cert.pem`), 404, 'not_found')
    code(await admin.get('/api/pki/certs/nimporte/cert.pem'), 404, 'not_found'); code(await admin.get(`/api/pki/certs/${F.srv!.fp}/key.pem`), 404, 'not_found')
    code(await admin.get(`/api/pki/certs/${'c'.repeat(40)}/cert.pem`), 404, 'not_found')   // le certificat d'une autorité n'est pas un certificat final
  })
})

describe('émission depuis une demande de certificat', () => {
  const body = (o: Record<string, unknown> = {}) => ({ ca: 'Lab-Sub', profile: 'server', cn: 'radius2.lab.test', o: 'Lab', c: 'FR', dns: ['Radius2.Lab.Test'], ip: ['10.1.2.4'], csr: { pem: newCsr('rsa').csr }, ...o })
  it('émet : demande JSON minuscule, dépôt de la demande publique, certificat rendu', async () => {
    clearAll()
    const r = await admin.post('/api/pki/certs/csr', body())
    expect(r.status, `${r.text}\n${srvLog.slice(-800)}`).toBe(200)
    expect(r.json).toMatchObject({ ca: 'Lab-Sub', profile: 'server', subject: 'C=FR,O=Lab,CN=radius2.lab.test' }); expect(r.json.id).toMatch(/^[0-9a-f]{16}$/)
    expect(r.json.certificate).toContain('BEGIN CERTIFICATE'); expect(r.json.chain).toContain('BEGIN CERTIFICATE')
    const q = rootLog[0]!.req
    expect(q).toEqual({ action: 'cert_issue', id: r.json.id, ca: 'Lab-Sub', profile: 'server', cn: 'radius2.lab.test', o: 'Lab', c: 'FR', dns: ['radius2.lab.test'], ip: ['10.1.2.4'] })
    expect(JSON.stringify(q).length).toBeLessThan(4000)
    expect(rootLog[0]!.csr).toContain('BEGIN CERTIFICATE REQUEST'); expect(rootLog[0]!.csr).not.toMatch(/PRIVATE KEY/)
    const f = join(TMP, 'issued.pem'); writeFileSync(f, r.json.certificate)
    expect(sh(['verify', '-CAfile', join(SSL, 'root.pem'), '-untrusted', join(SSL, 'sub.pem'), f]).stdout).toMatch(/OK/)
    expect(sh(['x509', '-in', f, '-noout', '-text']).stdout).toMatch(/DNS:radius2\.lab\.test, IP Address:10\.1\.2\.4/)
    expect(existsSync(REQ)).toBe(false)
  })
  it('accepte une demande DER (base64)', async () => {
    clearAll()
    const c = newCsr('ec')
    const derB64 = spawnSync('openssl', ['req', '-outform', 'DER'], { input: c.csr }).stdout.toString('base64')
    const r = await admin.post('/api/pki/certs/csr', body({ csr: { der: derB64 } })); expect(r.status, r.text).toBe(200)
    expect(rootLog[0]!.csr).toBe('[DER]')
  })
  it('profil utilisateur : mail et UPN', async () => {
    clearAll()
    const r = await admin.post('/api/pki/certs/csr', body({ profile: 'user', cn: 'Jean Martin', dns: [], ip: [], mail: ['jmartin@lab.test'], upn: ['jmartin@lab.test'] }))
    expect(r.status, r.text).toBe(200); expect(rootLog[0]!.req).toMatchObject({ profile: 'user', mail: ['jmartin@lab.test'], upn: ['jmartin@lab.test'] })
  })
  it('validation : mêmes règles que root, rien n\'est déposé', async () => {
    clearAll()
    for (const bad of [{ profile: 'EMPTY' }, { dns: [], ip: [] }, { mail: ['a@b.test'] }, { dns: ['a b.test'] }, { ip: ['999.1.1.1'] }, { cn: 'x,O=Evil' }, { ca: '../x' }, { extra: 1 }, { csr: { pem: 'rien' } }, { csr: {} }]) {
      const r = await admin.post('/api/pki/certs/csr', body(bad)); expect([400], `${JSON.stringify(bad).slice(0, 60)} → ${r.text}`).toContain(r.status)
    }
    expect(existsSync(REQ)).toBe(false); expect(readdirSync(IN)).toEqual([]); expect(rootLog).toEqual([])
  })
  it('préconditions : PKI absente, pas prête, autorité inconnue, racine, en attente, demande déjà en cours', async () => {
    clearAll()
    setStatus({ installed: false, state: 'absent' }); code(await admin.post('/api/pki/certs/csr', body()), 409, 'pki_not_installed')
    setStatus({ state: 'starting' }); code(await admin.post('/api/pki/certs/csr', body()), 409, 'pki_not_ready'); setStatus({})
    code(await admin.post('/api/pki/certs/csr', body({ ca: 'Inconnue' })), 404, 'not_found')
    code(await admin.post('/api/pki/certs/csr', body({ ca: 'Lab-Root' })), 409, 'pki_ca_not_issuing')
    code(await admin.post('/api/pki/certs/csr', body({ ca: 'Lab-Wait' })), 409, 'pki_ca_not_issuing')
    rootMute = true
    try { writeFileSync(REQ, '{}'); code(await admin.post('/api/pki/certs/csr', body()), 409, 'request_pending') } finally { rmSync(REQ, { force: true }); rootMute = false }
    expect(readdirSync(IN)).toEqual([])
  })
  it('root refuse : 422 avec son message, la demande déposée n\'est pas conservée', async () => {
    clearAll(); rootRefuse = 'demande de certificat refusée : clé RSA de 1024 bits refusée'
    try {
      const r = await admin.post('/api/pki/certs/csr', body()); code(r, 422, 'pki_issue_refused')
      expect(r.json.data.detail).toBe('demande de certificat refusée : clé RSA de 1024 bits refusée')
    } finally { rootRefuse = null }
    expect((await rows(`select detail from audit_log where action = 'pki.cert_issue_failed' order by id desc limit 1`))[0].detail).toMatchObject({ reason: 'refused', ca: 'Lab-Sub', profile: 'server' })
  })
  it('root ne répond pas : 504 au bout du délai', async () => {
    clearAll(); rootMute = true
    try { code(await admin.post('/api/pki/certs/csr', body()), 504, 'pki_timeout') } finally { rootMute = false; rmSync(REQ, { force: true }) }
  }, 20000)
  it('une émission à la fois : deux demandes simultanées aboutissent toutes les deux, l\'une après l\'autre', async () => {
    clearAll(); rootDelay = 400
    try {
      const [a, b] = await Promise.all([admin.post('/api/pki/certs/csr', body({ cn: 'une.lab.test', dns: ['une.lab.test'] })), admin.post('/api/pki/certs/csr', body({ cn: 'deux.lab.test', dns: ['deux.lab.test'] }))])
      expect([a.status, b.status], `${a.text} ${b.text}`).toEqual([200, 200]); expect(a.json.id).not.toBe(b.json.id)
      expect(rootLog.map((x) => x.req.cn).sort()).toEqual(['deux.lab.test', 'une.lab.test'])
    } finally { rootDelay = 0 }
  }, 20000)
  it('audit : qui, quoi, numéro de série ; jamais le contenu de la demande', async () => {
    const a = (await rows(`select username, entity_id, detail::text as detail from audit_log where action = 'pki.cert_issue' order by id desc limit 1`))[0]
    expect(a.username).toBe('admin'); expect(a.entity_id).toMatch(/^[0-9a-f]{16}$/); expect(a.detail).toMatch(/"serial"/); expect(a.detail).not.toMatch(/CERTIFICATE REQUEST|PRIVATE KEY/)
  })
})

describe('émission avec une clé fabriquée ici (PKCS#12)', () => {
  const body = (o: Record<string, unknown> = {}) => ({ ca: 'Lab-Sub', profile: 'machine', cn: 'pc42.lab.test', o: 'Lab', c: 'FR', dns: ['pc42.lab.test'], alg: 'ecp256', password: 'Mot-de-passe-Secret-42', compat: false, ...o })
  const open = (buf: Buffer, pw: string) => spawnSync('openssl', ['pkcs12', '-info', '-nodes', '-passin', `pass:${pw}`], { input: buf, encoding: 'utf8' })
  it('rend un PKCS#12 qui contient la clé, le certificat signé par l\'émettrice et la chaîne', async () => {
    clearAll()
    const r = await admin.req('POST', '/api/pki/certs/p12', body())
    expect(r.status, `${r.text.slice(0, 300)}\n${srvLog.slice(-800)}`).toBe(200)
    expect(r.headers.get('content-type')).toBe('application/x-pkcs12'); expect(r.headers.get('content-disposition')).toBe('attachment; filename="pc42.lab.test.p12"')
    expect(r.headers.get('x-pki-serial')).toMatch(/^[0-9A-F]+$/); expect(r.headers.get('x-pki-id')).toMatch(/^[0-9a-f]{16}$/); expect(r.headers.get('cache-control')).toBe('no-store')
    const o = open(r.buf, 'Mot-de-passe-Secret-42'); expect(o.status, o.stderr).toBe(0)
    expect((o.stdout.match(/BEGIN CERTIFICATE/g) ?? []).length).toBe(3); expect(o.stdout).toMatch(/BEGIN PRIVATE KEY/)
    // la clé du fichier est bien celle du certificat
    const d = join(TMP, 'p12out'); mkdirSync(d, { recursive: true })
    writeFileSync(join(d, 'all.pem'), o.stdout)
    const key = spawnSync('openssl', ['pkey', '-in', join(d, 'all.pem'), '-pubout'], { encoding: 'utf8' }).stdout
    const first = o.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)!
    const leaf = first.find((p) => /CN\s*=\s*pc42/.test(spawnSync('openssl', ['x509', '-noout', '-subject'], { input: p, encoding: 'utf8' }).stdout))!
    expect(spawnSync('openssl', ['x509', '-noout', '-pubkey'], { input: leaf, encoding: 'utf8' }).stdout).toBe(key)
    expect(open(r.buf, 'mauvais').status).not.toBe(0)
  })
  it('root ne reçoit JAMAIS la clé ni le mot de passe', async () => {
    const q = rootLog[0]!
    expect(JSON.stringify(q.req)).not.toMatch(/Mot-de-passe|password|PRIVATE|key/i); expect(q.csr).toContain('BEGIN CERTIFICATE REQUEST'); expect(q.csr).not.toMatch(/PRIVATE KEY/)
    expect(q.req).toMatchObject({ action: 'cert_issue', profile: 'machine', cn: 'pc42.lab.test', dns: ['pc42.lab.test'] })
  })
  it('ni la clé ni le mot de passe ne sont dans l\'audit, le journal, les dossiers publiés ou les dépôts', async () => {
    const all = JSON.stringify(await rows('select detail from audit_log'))
    expect(all).not.toMatch(/Mot-de-passe|PRIVATE KEY/)
    expect((await rows(`select detail::text as d from audit_log where action = 'pki.cert_p12'`))[0].d).toMatch(/"alg": "ecp256"/)
    expect(srvLog).not.toMatch(/Mot-de-passe|PRIVATE KEY/)
    const grep = spawnSync('grep', ['-rlE', 'PRIVATE KEY|Mot-de-passe-Secret', GEN, CERTDIR, IN]); expect(grep.status).toBe(1)
    expect((existsSync('/dev/shm') ? readdirSync('/dev/shm') : []).filter((n) => n.startsWith('ddi-ssl-'))).toEqual([])
  })
  it.each([['rsa2048'], ['rsa3072'], ['ecp384']])('algorithme %s', async (alg) => {
    clearAll(); const r = await admin.req('POST', '/api/pki/certs/p12', body({ alg })); expect(r.status, r.text.slice(0, 200)).toBe(200); expect(open(r.buf, 'Mot-de-passe-Secret-42').status).toBe(0)
  }, 60000)
  it('compat : 3DES et SHA-1', async () => {
    clearAll(); const r = await admin.req('POST', '/api/pki/certs/p12', body({ compat: true })); expect(r.status).toBe(200)
    const o = open(r.buf, 'Mot-de-passe-Secret-42'); expect(o.status, o.stderr).toBe(0); expect(o.stderr + o.stdout).toMatch(/3DES|TripleDES|des-ede3/i)
  })
  it('validation : mot de passe trop court, algorithme inconnu, demande de certificat en trop, SAN interdit', async () => {
    clearAll()
    for (const bad of [{ password: 'court' }, { alg: 'rsa1024' }, { csr: { pem: 'x' } }, { profile: 'user' }, { password: undefined }]) {
      const r = await admin.req('POST', '/api/pki/certs/p12', body(bad)); expect(r.status, JSON.stringify(bad)).toBe(400)
    }
    expect(rootLog).toEqual([])
  })
  it('root refuse : aucun fichier n\'est rendu', async () => {
    clearAll(); rootRefuse = 'refus de root'
    try { const r = await admin.req('POST', '/api/pki/certs/p12', body()); code(r, 422, 'pki_issue_refused'); expect(r.json.data.detail).toBe('refus de root') } finally { rootRefuse = null }
  })
})

describe('révocation', () => {
  it('révoque : demande minuscule portant une référence, état relu dans la liste', async () => {
    clearAll()
    const r = await admin.post(`/api/pki/certs/${F.srv!.fp}/revoke`, { reason: 4 })
    expect(r.status, `${r.text}\n${srvLog.slice(-600)}`).toBe(200); expect(r.json).toMatchObject({ ok: true, serial: F.srv!.serialHex, ca: 'Lab-Sub' })
    expect(rootLog[0]!.req).toMatchObject({ action: 'cert_revoke', ca: 'Lab-Sub', serial: F.srv!.serialHex, reason: 4 }); expect(rootLog[0]!.req.id).toMatch(/^[0-9a-f]{16}$/)
    const row = (await admin.get('/api/pki/certs?q=radius1')).json.rows[0]; expect(row).toMatchObject({ state: 'revoked', reason: 4 })
    expect((await rows(`select entity_id, detail from audit_log where action = 'pki.cert_revoke' order by id desc limit 1`))[0]).toMatchObject({ entity_id: F.srv!.fp })
  })
  it('refuse : déjà révoqué, inconnu, motif invalide, autorité hors DDI, certificat d\'autorité', async () => {
    clearAll()
    code(await admin.post(`/api/pki/certs/${F.srv!.fp}/revoke`, { reason: 1 }), 409, 'pki_cert_revoked')
    code(await admin.post(`/api/pki/certs/${'0'.repeat(40)}/revoke`, { reason: 1 }), 404, 'not_found')
    code(await admin.post(`/api/pki/certs/${F.mgt!.fp}/revoke`, { reason: 1 }), 404, 'not_found')
    code(await admin.post(`/api/pki/certs/${'c'.repeat(40)}/revoke`, { reason: 1 }), 404, 'not_found')
    code(await admin.post('/api/pki/certs/xyz/revoke', { reason: 1 }), 400, 'invalid_id')
    for (const reason of [2, 6, 9, -1, '1', null, 1.5]) expect((await admin.post(`/api/pki/certs/${F.usr!.fp}/revoke`, { reason })).status).toBe(400)
    expect((await admin.post(`/api/pki/certs/${F.usr!.fp}/revoke`, {})).status).toBe(400)
    expect(rootLog).toEqual([]); expect(existsSync(REQ)).toBe(false)
  })
  it('PKI pas prête : 409 sans rien déposer', async () => {
    clearAll(); setStatus({ state: 'unhealthy' }); code(await admin.post(`/api/pki/certs/${F.usr!.fp}/revoke`, { reason: 1 }), 409, 'pki_not_ready'); setStatus({})
    expect(existsSync(REQ)).toBe(false)
  })
  it('root refuse : 422 avec son message, le certificat reste actif', async () => {
    clearAll(); rootRefuse = 'aucun certificat de série X émis par « Lab-Sub »'
    try { const r = await admin.post(`/api/pki/certs/${F.usr!.fp}/revoke`, { reason: 1 }); code(r, 422, 'pki_revoke_refused'); expect(r.json.data.detail).toMatch(/aucun certificat/) } finally { rootRefuse = null }
    expect((await admin.get('/api/pki/certs?q=Jean')).json.rows[0].state).toBe('active')
  })
  it('root ne répond pas : 504', async () => {
    clearAll(); rootMute = true
    try { code(await admin.post(`/api/pki/certs/${F.usr!.fp}/revoke`, { reason: 1 }), 504, 'pki_timeout') } finally { rootMute = false; rmSync(REQ, { force: true }) }
  }, 20000)
})
