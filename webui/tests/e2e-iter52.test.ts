// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.3 — lien « Utiliser la PKI du DDI » de l'accès réseau (RADIUS, EAP-TLS) : confiance en une autorité du DDI
// (chaîne + CRL LUES en local, jamais téléchargées), CRL resynchronisée par la tâche horaire, certificat du serveur RADIUS émis par la PKI du DDI (la clé reste ici,
// chiffrée ; la PKI ne reçoit que la demande de certificat), préparation au déploiement. Les autorités et la CRL sont de vrais fichiers openssl ; « root » est simulé
// (il signe vraiment la demande avec openssl). Ce que root fait avec le vrai EJBCA est vérifié par tests/b34-pki-cert.sh et tests/b33-pki-ca-live.sh.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3480, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s52-')), GEN = join(TMP, 'gen'), IN = join(GEN, 'pki-in'), REQ = join(GEN, '.pki-request')
const STATUS = join(TMP, 'ps.json'), RESULT = join(TMP, 'pr.json'), CAS = join(TMP, 'pki-cas.json'), CADIR = join(TMP, 'pki-ca'), CERTDIR = join(TMP, 'pki-cert'), SSL = join(TMP, 'ssl')
let srv: ChildProcess, db: pg.Client, srvLog = ''

class Client {
  cookie = ''; csrf = ''
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { cookie: this.cookie }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* texte */ }
    return { status: r.status, json, text, headers: r.headers }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 200)) } throw new Error('délai dépassé') }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const read = (p: string) => readFileSync(p, 'utf8')
const sh = (args: string[], input?: string | Buffer) => spawnSync('openssl', args, { encoding: 'utf8', input })
const setStatus = (o: Record<string, unknown>) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', digest: '', nets: [], health: 'ALLOK', port: 8080,
  dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab.test', casCount: 2, resetAllowed: false, ...o }))
const derSha = (pem: string) => createHash('sha256').update(Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ''), 'base64')).digest('hex')

// ---- Autorités et CRL de test (vrais fichiers openssl) ----
function gencrl(revoked: Array<{ serial: string; cn: string }>, o: { next?: string; last?: string } = {}) {
  const d = join(SSL, 'crl'); mkdirSync(d, { recursive: true })
  writeFileSync(join(d, 'index.txt'), revoked.map((r) => `R\t301117000000Z\t261115000000Z\t${r.serial}\tunknown\t/CN=${r.cn}\n`).join(''))
  if (!existsSync(join(d, 'crlnumber'))) writeFileSync(join(d, 'crlnumber'), '01\n')
  writeFileSync(join(d, 'cnf'), `[ca]\ndefault_ca=c\n[c]\ndatabase=${d}/index.txt\ncrlnumber=${d}/crlnumber\ndefault_md=sha256\ndefault_crl_days=7\ncertificate=${SSL}/sub.pem\nprivate_key=${SSL}/sub.key\n`)
  const r = sh(['ca', '-config', join(d, 'cnf'), '-gencrl', ...(o.last ? ['-crl_lastupdate', o.last] : []), ...(o.next ? ['-crl_nextupdate', o.next] : []), '-outdir', d, '-out', join(d, 'out.pem')])
  if (r.status !== 0) throw new Error('gencrl : ' + r.stderr)
  return spawnSync('openssl', ['crl', '-in', join(d, 'out.pem'), '-outform', 'DER']).stdout
}
const putCrl = (b: Buffer) => writeFileSync(join(CADIR, 'Lab-Sub', 'crl.der'), b)
const FIX = { sub: '', root: '' }
const pubCa = (o: Record<string, unknown>) => ({ name: 'Lab-Root', kind: 'root', state: 'active', dn: 'CN=Lab Root CA,O=Lab,C=FR', issuer: 'CN=Lab Root CA,O=Lab,C=FR', selfSigned: true, serial: 'ab', notBefore: '2026-01-01T00:00:00Z', notAfter: '2036-01-01T00:00:00Z',
  keyAlg: 'EC', keyBits: 256, curve: 'prime256v1', sigAlg: 'ecdsa-with-SHA256', pathLen: null, sha256: FIX.root, signedBy: 'self', alg: 'ecp256', createdAt: 1700000000, extRoot: '',
  crlUrl: 'http://pki.lab.test:8080/crl/Lab-Root', certUrl: 'http://pki.lab.test:8080/cert/Lab-Root', crl: null, files: { cert: true, chain: false, csr: false, crl: false }, ...o })
const publish = (waiting = true) => writeFileSync(CAS, JSON.stringify({ at: 1700000000, ok: true, hostname: 'pki.lab.test', port: 8080, cas: [
  pubCa({}),
  pubCa({ name: 'Lab-Sub', kind: 'issuing', dn: 'CN=Lab Sub CA,O=Lab,C=FR', selfSigned: false, signedBy: 'Lab-Root', sha256: FIX.sub, crlUrl: 'http://pki.lab.test:8080/crl/Lab-Sub', certUrl: 'http://pki.lab.test:8080/cert/Lab-Sub',
    files: { cert: true, chain: true, csr: false, crl: existsSync(join(CADIR, 'Lab-Sub', 'crl.der')) } }),
  ...(waiting ? [pubCa({ name: 'Lab-Wait', kind: 'issuing', state: 'waiting', dn: 'CN=Lab Wait,O=Lab,C=FR', selfSigned: false, sha256: '', files: { cert: false, chain: true, csr: true, crl: false } })] : []),
] }))

// ---- « root » simulé : signe vraiment la demande ----
const rootLog: Array<{ req: any; csr: string | null }> = []
let rootBusy = false, rootRefuse: string | null = null, rootMute = false, rootTimer: NodeJS.Timeout | null = null
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
      rootLog.push({ req, csr: raw ? raw.toString('utf8') : null }); if (raw) rmSync(dep, { force: true })
      if (rootRefuse) { publishResult(req.action, false, rootRefuse, req.id); return }
      const f = (s: string) => join(SSL, `iss-${req.id}.${s}`)
      writeFileSync(f('csr'), raw!)
      const san = [...(req.dns ?? []).map((d: string) => `DNS:${d}`), ...(req.ip ?? []).map((i: string) => `IP:${i}`)].join(',')
      writeFileSync(f('ext'), 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n' + (san ? `subjectAltName=${san}\n` : ''))
      const r1 = sh(['x509', '-req', '-in', f('csr'), '-CA', join(SSL, 'sub.pem'), '-CAkey', join(SSL, 'sub.key'), '-CAcreateserial', '-out', f('pem'), '-days', '365', '-extfile', f('ext'), '-subj', `/CN=${req.cn}`])
      if (r1.status !== 0) throw new Error(r1.stderr)
      const d = join(CERTDIR, req.id); mkdirSync(d, { recursive: true })
      const cert = read(f('pem'))
      writeFileSync(join(d, 'cert.pem'), cert); writeFileSync(join(d, 'chain.pem'), read(join(SSL, 'sub.pem')) + read(join(SSL, 'root.pem')))
      const serial = sh(['x509', '-in', f('pem'), '-noout', '-serial']).stdout.trim().split('=')[1]!.toUpperCase().replace(/^0+/, '')
      writeFileSync(join(d, 'meta.json'), JSON.stringify({ id: req.id, ca: req.ca, profile: req.profile, serial, sha256: derSha(cert), notBefore: '2026-11-17T09:00:00Z', notAfter: '2027-11-17T09:00:00Z', subject: `CN=${req.cn},O=Lab,C=FR`, issuedAt: 1 }))
      publishResult('cert_issue', true, `Certificat émis par « ${req.ca} »`, req.id)
    } catch (e) { publishResult(req.action ?? 'cert_issue', false, `erreur du root simulé : ${(e as Error).message}`, req.id) } finally { rootBusy = false }
  }, 40)
}
const clear = () => { rmSync(REQ, { force: true }); rmSync(RESULT, { force: true }); rootLog.length = 0 }
const view = async () => (await admin.get('/api/radius/pki')).json

beforeAll(async () => {
  for (const d of [GEN, IN, SSL, CERTDIR, join(CADIR, 'Lab-Sub')]) mkdirSync(d, { recursive: true })
  sh(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(SSL, 'root.key'), '-out', join(SSL, 'root.pem'), '-days', '3650', '-subj', '/CN=Lab Root CA/O=Lab/C=FR',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
  sh(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(SSL, 'sub.key'), '-out', join(SSL, 'sub.csr'), '-subj', '/CN=Lab Sub CA/O=Lab/C=FR'])
  writeFileSync(join(SSL, 'ca.ext'), 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
  sh(['x509', '-req', '-in', join(SSL, 'sub.csr'), '-CA', join(SSL, 'root.pem'), '-CAkey', join(SSL, 'root.key'), '-CAcreateserial', '-out', join(SSL, 'sub.pem'), '-days', '3000', '-extfile', join(SSL, 'ca.ext')])
  writeFileSync(join(CADIR, 'Lab-Sub', 'cert.pem'), read(join(SSL, 'sub.pem'))); writeFileSync(join(CADIR, 'Lab-Sub', 'chain.pem'), read(join(SSL, 'root.pem')))
  FIX.sub = derSha(read(join(SSL, 'sub.pem'))); FIX.root = derSha(read(join(SSL, 'root.pem')))
  putCrl(gencrl([{ serial: '0A', cn: 'revoque-1' }]))
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_RADIUS_CRL_MS: '1500',
    DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT, DDI_PKI_CAS: CAS, DDI_PKI_CA_DIR: CADIR, DDI_PKI_CERT_DIR: CERTDIR, DDI_PKI_ISSUE_TIMEOUT_MS: '3500' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  for (const [u, r, c] of [['lect', 'viewer', viewer], ['oper', 'operator', oper]] as const) { expect((await admin.post('/api/users', { username: u, role: r, password: PW })).status).toBe(200); expect((await c.login(u, PW)).status).toBe(200) }
  setStatus({}); publish(); startRoot()
}, 300000)
afterAll(async () => { if (rootTimer) clearInterval(rootTimer); srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('droits et préconditions', () => {
  it('réservé à l\'administrateur', async () => {
    for (const [m, p] of [['GET', '/api/radius/pki/ddi'], ['POST', '/api/radius/pki/ddi/trust'], ['POST', '/api/radius/pki/ddi/server']] as const) {
      code(await anon.req(m, p, m === 'POST' ? {} : undefined), 401, 'unauthenticated')
      for (const c of [viewer, oper]) code(await c.req(m, p, m === 'POST' ? {} : undefined), 403, 'forbidden')
    }
  })
  it('propose les émettrices utilisables du DDI, pas les racines ni celles en attente', async () => {
    const r = (await admin.get('/api/radius/pki/ddi')).json
    expect(r).toMatchObject({ installed: true, ready: true, hostname: 'pki.lab.test' })
    expect(r.issuers).toEqual([{ name: 'Lab-Sub', dn: 'CN=Lab Sub CA,O=Lab,C=FR', notAfter: '2036-01-01T00:00:00Z', signedBy: 'Lab-Root', crlUrl: 'http://pki.lab.test:8080/crl/Lab-Sub', hasCrl: true, trusted: false }])
  })
  it('refuse une autorité inconnue, une racine, une autorité en attente, une demande mal formée', async () => {
    for (const ca of ['Inconnue', 'Lab-Root', 'Lab-Wait']) code(await admin.post('/api/radius/pki/ddi/trust', { ca }), 404, 'not_found')
    expect((await admin.post('/api/radius/pki/ddi/trust', {})).status).toBe(400); expect((await admin.post('/api/radius/pki/ddi/trust', { ca: 'a/../b' })).status).toBe(400)
    expect((await admin.post('/api/radius/pki/ddi/trust', { ca: 'Lab-Sub', extra: 1 })).status).toBe(400)
    expect((await view()).cas).toEqual([])
  })
})

describe('confiance : chaîne et CRL lues en local', () => {
  it('ajoute l\'émettrice et sa racine, marque leur origine, retient l\'adresse de CRL, charge la CRL', async () => {
    const r = await admin.post('/api/radius/pki/ddi/trust', { ca: 'Lab-Sub' })
    expect(r.status, `${r.text}\n${srvLog.slice(-600)}`).toBe(200)
    expect([r.json.added, r.json.skipped]).toEqual([2, 0]); expect(r.json.crl).toEqual({ loaded: 1, failed: 0, missing: ['Lab-Root'] })
    const cas = r.json.view.cas as any[]
    const sub = cas.find((x) => x.name === 'Lab-Sub'), root = cas.find((x) => x.name === 'Lab-Root')
    expect(sub).toMatchObject({ ddi: 'Lab-Sub', root: false, issuing: true, chainOk: true, crlUrl: 'http://pki.lab.test:8080/crl/Lab-Sub' }); expect(sub.crl).toMatchObject({ revoked: 1, source: 'upload' })
    expect(root).toMatchObject({ ddi: 'Lab-Root', root: true, chainOk: true })
    expect(r.json.view.readiness.problems).toEqual([{ code: 'no_server' }])   // la confiance et la CRL sont prêtes ; il ne manque que le certificat du serveur
    expect((await rows(`select detail::text as d from audit_log where action = 'radius.pki.ddi_trust'`))[0].d).toMatch(/"ca": "Lab-Sub"/)
  })
  it('idempotent, et l\'état « déjà de confiance » est relu', async () => {
    const r = await admin.post('/api/radius/pki/ddi/trust', { ca: 'Lab-Sub' })
    expect([r.json.added, r.json.skipped, r.json.crl.loaded]).toEqual([0, 2, 0]); expect(r.json.view.cas.length).toBe(2)
    expect((await admin.get('/api/radius/pki/ddi')).json.issuers[0].trusted).toBe(true)
  })
  it('la tâche horaire relit la CRL du DDI sur place', async () => {
    putCrl(gencrl([{ serial: '0A', cn: 'revoque-1' }, { serial: '0B', cn: 'revoque-2' }]))
    await until(async () => (await view()).cas.find((x: any) => x.name === 'Lab-Sub').crl.revoked === 2, 20000)
    expect((await view()).cas.find((x: any) => x.name === 'Lab-Sub').crlError).toBeNull()
  })
  it('CRL périmée, illisible ou d\'un autre émetteur : mémorisée sur l\'autorité, la CRL en place est conservée', async () => {
    putCrl(gencrl([{ serial: '0A', cn: 'revoque-1' }], { last: '20200101000000Z', next: '20200201000000Z' }))
    await until(async () => (await view()).cas.find((x: any) => x.name === 'Lab-Sub').crlError?.code === 'crl_expired', 20000)
    expect((await view()).cas.find((x: any) => x.name === 'Lab-Sub').crl.revoked).toBe(2)
    putCrl(Buffer.from('pas une CRL'))
    await until(async () => (await view()).cas.find((x: any) => x.name === 'Lab-Sub').crlError?.code === 'crl_invalid', 20000)
    putCrl(gencrl([{ serial: '0A', cn: 'revoque-1' }, { serial: '0B', cn: 'revoque-2' }, { serial: '0C', cn: 'revoque-3' }]))
    await until(async () => { const c = (await view()).cas.find((x: any) => x.name === 'Lab-Sub'); return c.crl.revoked === 3 && c.crlError === null }, 20000)
  })
})

describe('certificat du serveur RADIUS émis par la PKI du DDI', () => {
  const body = (o: Record<string, unknown> = {}) => ({ ca: 'Lab-Sub', cn: 'radius.lab.test', dns: ['Radius.Lab.Test', 'radius2.lab.test'], ip: ['10.1.2.3'], alg: 'ecp256', ...o })
  it('émet avec le profil serveur : la PKI ne reçoit que la demande, la clé reste ici', async () => {
    clear()
    const r = await admin.post('/api/radius/pki/ddi/server', body())
    expect(r.status, `${r.text}\n${srvLog.slice(-800)}`).toBe(200)
    expect(rootLog[0]!.req).toEqual({ action: 'cert_issue', id: expect.stringMatching(/^[0-9a-f]{16}$/), ca: 'Lab-Sub', profile: 'server', cn: 'radius.lab.test', dns: ['radius.lab.test', 'radius2.lab.test'], ip: ['10.1.2.3'] })
    expect(rootLog[0]!.csr).toContain('BEGIN CERTIFICATE REQUEST'); expect(rootLog[0]!.csr).not.toMatch(/PRIVATE KEY/)
    const s = r.json.view.server
    expect(s).toMatchObject({ subject: 'CN=radius.lab.test', chainOk: true, keyType: 'ec' }); expect(s.sans).toEqual(expect.arrayContaining(['DNS:radius.lab.test', 'IP Address:10.1.2.3']))
    expect(r.text).not.toMatch(/PRIVATE KEY/); expect(r.json.serial).toMatch(/^[0-9A-F]+$/)
    expect((await view()).readiness).toMatchObject({ ready: true, problems: [] })
  })
  it('la clé est chiffrée en base, jamais dans l\'audit, le journal ni les dépôts', async () => {
    const st = (await rows(`select value::text as v from settings where key = 'radius_pki'`))[0].v
    expect(st).toMatch(/"keyEnc"/); expect(st).not.toMatch(/PRIVATE KEY/)
    expect(JSON.stringify(await rows('select detail from audit_log'))).not.toMatch(/PRIVATE KEY/)
    expect(srvLog).not.toMatch(/PRIVATE KEY/)
    expect(spawnSync('grep', ['-rl', 'PRIVATE KEY', GEN, CERTDIR, IN]).status).toBe(1)
    expect((await rows(`select detail::text as d from audit_log where action = 'radius.pki.ddi_server'`))[0].d).toMatch(/"ca": "Lab-Sub"/)
  })
  it('un nouveau certificat remplace le précédent', async () => {
    const before = (await view()).server.fingerprint
    clear(); const r = await admin.post('/api/radius/pki/ddi/server', body({ cn: 'radius-b.lab.test', dns: ['radius-b.lab.test'], ip: [], alg: 'rsa2048' }))
    expect(r.status, r.text).toBe(200); expect(r.json.view.server.fingerprint).not.toBe(before); expect(r.json.view.server).toMatchObject({ subject: 'CN=radius-b.lab.test', keyType: 'rsa', keyBits: 2048, chainOk: true })
  })
  it('refus : sans nom DNS, autorité inconnue, racine, valeurs mal formées', async () => {
    clear()
    const fp = (await view()).server.fingerprint
    for (const bad of [{ dns: [] }, { dns: ['a b'] }, { ip: ['999.1.1.1'] }, { cn: 'x,O=Evil' }, { alg: 'rsa1024' }, { extra: 1 }]) expect((await admin.post('/api/radius/pki/ddi/server', body(bad))).status, JSON.stringify(bad)).toBe(400)
    code(await admin.post('/api/radius/pki/ddi/server', body({ ca: 'Inconnue' })), 404, 'not_found'); code(await admin.post('/api/radius/pki/ddi/server', body({ ca: 'Lab-Root' })), 404, 'not_found')
    expect(rootLog).toEqual([]); expect((await view()).server.fingerprint).toBe(fp)
  })
  it('PKI pas prête : 409 ; root refuse : 422 et le certificat en place est conservé', async () => {
    clear(); const fp = (await view()).server.fingerprint
    setStatus({ state: 'unhealthy' }); code(await admin.post('/api/radius/pki/ddi/server', body()), 409, 'pki_not_ready'); setStatus({})
    rootRefuse = 'demande de certificat refusée : profil'
    try { const r = await admin.post('/api/radius/pki/ddi/server', body()); code(r, 422, 'pki_issue_refused'); expect(r.json.data.detail).toBe('demande de certificat refusée : profil') } finally { rootRefuse = null }
    expect((await view()).server.fingerprint).toBe(fp)
  })
  it('root ne répond pas : 504 et le certificat en place est conservé', async () => {
    clear(); const fp = (await view()).server.fingerprint; rootMute = true
    try { code(await admin.post('/api/radius/pki/ddi/server', body()), 504, 'pki_timeout') } finally { rootMute = false; rmSync(REQ, { force: true }) }
    expect((await view()).server.fingerprint).toBe(fp); await sleep(100)
  }, 20000)
})
