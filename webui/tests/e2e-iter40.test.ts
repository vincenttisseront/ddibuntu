// Bout en bout (serveur CONSTRUIT, PostgreSQL réel, vrai openssl) : 0.13.2 — certificats EAP-TLS du service RADIUS : autorités de confiance, certificat du serveur
// (demande CSR signée par une vraie autorité de test, import PEM chiffré, PKCS#12), CRL (envoi, téléchargement depuis un vrai serveur HTTP, retour en arrière,
// actualisation automatique + envoi à root), refus du déploiement si la PKI est incomplète, dépôt pour root, vérification d'un certificat client,
// et secrets : jamais renvoyés, jamais journalisés, clé chiffrée en base. Le comportement du service lui-même est vérifié par tests/b29-radius-eaptls-live.sh.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3441, BASE = `http://127.0.0.1:${PORT}`, CRLPORT = 3442
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s40-')), P = join(TMP, 'pki'), ROOT = resolve(__dirname, '../..')
const GEN = join(TMP, 'gen'), REQ = join(GEN, '.radius-request'), CONF = join(GEN, 'radius-clients.conf'), PKIDIR = join(GEN, 'radius-pki'), STATUS = join(TMP, 'rs.json'), RESULT = join(TMP, 'rr.json')
let srv: ChildProcess, httpSrv: Server, db: pg.Client, srvLog = ''
let crlMode: 'ok' | '404' = 'ok', crlBody: Buffer = Buffer.alloc(0)

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
const b64 = (f: string) => readFileSync(join(P, f)).toString('base64')
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const dateOf = (days: number) => new Date(Date.now() + days * 86400_000).toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z').replace('T', '')
const caId = (view: any, name: string) => view.cas.find((c: any) => c.name === name).id
const getView = async () => (await admin.get('/api/radius/pki')).json
const setStatus = (eap: Record<string, unknown>) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, installed: true, version: '3.2.5', configured: true, active: true, enabled: true, clients: 1, eap }))
const rootDone = () => { rmSync(REQ, { force: true }); rmSync(CONF, { force: true }); rmSync(PKIDIR, { recursive: true, force: true }) }   // root a traité la demande

beforeAll(async () => {
  mkdirSync(P, { recursive: true }); mkdirSync(GEN, { recursive: true })
  sh(`
    pki_root R "Lab Root"; pki_inter I R "Lab Issuing CA"; pki_root X "Foreign Root"; pki_root Y "Lab Issuing CA"
    pki_issue I srv2 "radius2.lab.test" server "DNS:radius2.lab.test"
    pki_issue I alice "alice" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:alice@lab.test"
    pki_issue I bob "bob" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:bob@lab.test"
    pki_issue I carl "carl" clientbad "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:carl@lab.test"
    pki_issue X frank "frank" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:frank@lab.test"
    pki_issue I dave "dave" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:dave@lab.test" 20200101000000Z 20210101000000Z
    pki_issue Y rogue "rogue" client; pki_crl Y crl-rogue.pem 7
    openssl ca -batch -config I/openssl.cnf -gencrl -crlexts crl_ext -crl_lastupdate ${dateOf(1)} -crl_nextupdate ${dateOf(8)} -out crl-future.pem 2>/dev/null
    pki_crl R crl-root.pem 30; pki_crl X crl-foreign.pem 7; pki_crl I crl-expired.pem expire
    openssl x509 -in I/ca.pem -outform DER -out inter.der
    openssl pkey -in srv2.key -aes256 -passout pass:cle-secrete-1 -out srv2-enc.key
    openssl pkcs12 -export -in srv2.pem -inkey srv2.key -certfile I/ca.pem -passout pass:p12-pass -out srv2.p12 2>/dev/null
    openssl genrsa -out k1024.key 1024 2>/dev/null
    # deux CRL de l'autorité émettrice, de dates différentes (anti-retour-en-arrière), puis une troisième avec bob ET carl révoqués
    openssl ca -batch -config I/openssl.cnf -gencrl -crlexts crl_ext -crl_lastupdate ${dateOf(-3)} -crl_nextupdate ${dateOf(4)} -out crl-old.pem 2>/dev/null
    pki_revoke I bob.pem
    openssl ca -batch -config I/openssl.cnf -gencrl -crlexts crl_ext -crl_lastupdate ${dateOf(-2)} -crl_nextupdate ${dateOf(5)} -out crl-bob.pem 2>/dev/null
    pki_revoke I carl.pem
    openssl ca -batch -config I/openssl.cnf -gencrl -crlexts crl_ext -crl_lastupdate ${dateOf(-1)} -crl_nextupdate ${dateOf(6)} -out crl-carl.pem 2>/dev/null
    openssl crl -in crl-bob.pem -outform DER -out crl-bob.der
  `)
  httpSrv = createServer((req, res) => { if (crlMode === 'ok') { res.writeHead(200, { 'content-type': 'application/pkix-crl' }); res.end(crlBody) } else { res.writeHead(404); res.end('absent') } })
  await new Promise<void>((r) => httpSrv.listen(CRLPORT, '127.0.0.1', () => r()))
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_RADIUS_STATUS: STATUS, DDI_RADIUS_RESULT: RESULT, DDI_RADIUS_CRL_MS: '1500' } })
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
afterAll(async () => { srv?.kill('SIGTERM'); httpSrv?.close(); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('PKI RADIUS — accès et état initial', () => {
  it('réservé à l\'administrateur : 401 sans session, 403 pour lecteur et opérateur, sur toutes les routes', async () => {
    const routes: Array<[string, string, unknown?]> = [['GET', '/api/radius/pki'], ['PUT', '/api/radius/pki/options', { checkCrl: true }], ['POST', '/api/radius/pki/cas', { pem: 'x' }], ['PUT', '/api/radius/pki/cas/abcdef01', { name: 'x' }],
      ['DELETE', '/api/radius/pki/cas/abcdef01'], ['POST', '/api/radius/pki/cas/abcdef01/crl', { dataBase64: 'AA==' }], ['POST', '/api/radius/pki/cas/abcdef01/crl/refresh', {}],
      ['POST', '/api/radius/pki/server/csr', { cn: 'x', sans: [], keyType: 'ec256' }], ['POST', '/api/radius/pki/server/cert', { pem: 'x' }], ['POST', '/api/radius/pki/server/import', {}],
      ['DELETE', '/api/radius/pki/server'], ['DELETE', '/api/radius/pki/server/pending'], ['POST', '/api/radius/pki/check-client', { pem: 'x' }]]
    for (const [m, p, b] of routes) {
      code(await anon.req(m, p, b), 401, 'unauthenticated')
      for (const c of [viewer, oper]) code(await c.req(m, p, b), 403, 'forbidden')
    }
  })
  it('état vide : aucune autorité, aucun serveur, « non configuré » (ni prêt ni en erreur) ; GET /radius le résume', async () => {
    const v = await getView()
    expect(v).toMatchObject({ checkCrl: true, cas: [], server: null, pending: null, readiness: { empty: true, ready: false, problems: [] } })
    expect((await viewer.get('/api/radius')).json.pki).toEqual({ configured: false, ready: false, problems: 0 })
  })
  it('PKI vide : le déploiement reste celui d\'avant (aucun EAP, aucun dossier de certificats)', async () => {
    const r = await admin.post('/api/radius/apply'); expect(r.status, r.text).toBe(200)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'apply' }); expect(existsSync(PKIDIR)).toBe(false); expect(existsSync(CONF)).toBe(true)
    rootDone()
  })
})

describe('PKI RADIUS — autorités de confiance', () => {
  it('entrées refusées : clé privée, texte, certificat tronqué, certificat de serveur (pas une autorité), champs inconnus', async () => {
    code(await admin.post('/api/radius/pki/cas', { pem: rd('I/ca.pem') + rd('srv2.key') }), 400, 'radius_pki_pem_has_private_key')
    code(await admin.post('/api/radius/pki/cas', { pem: 'bonjour' }), 400, 'radius_pki_pem_no_certificate')
    code(await admin.post('/api/radius/pki/cas', { pem: rd('I/ca.pem').slice(0, 200) }), 400, 'radius_pki_pem_no_certificate')
    code(await admin.post('/api/radius/pki/cas', { pem: rd('srv2.pem') }), 400, 'radius_pki_ca_not_a_ca')
    code(await admin.post('/api/radius/pki/cas', {}), 400, 'radius_pki_pem_no_certificate')
    expect((await admin.post('/api/radius/pki/cas', { pem: rd('R/ca.pem'), evil: 1 })).status).toBe(400)
    code(await admin.post('/api/radius/pki/cas', { dataBase64: Buffer.from('pas un certificat').toString('base64') }), 400, 'radius_pki_pem_invalid')
    expect((await getView()).cas).toEqual([])
  })
  it('intermédiaire AVANT la racine : chaîne incomplète signalée ; fichier DER (.cer d\'AD CS) ; puis la racine complète la chaîne ; doublon ignoré', async () => {
    const r = await admin.post('/api/radius/pki/cas', { dataBase64: b64('inter.der') }); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ added: 1, skipped: 0 })
    let v = r.json.view; expect(v.cas).toHaveLength(1); expect(v.cas[0]).toMatchObject({ name: 'Lab Issuing CA', root: false, chainOk: false, issuing: true })
    expect(v.readiness.problems.map((p: any) => p.code)).toEqual(expect.arrayContaining(['no_root', 'ca_chain', 'no_server']))
    const r2 = await admin.post('/api/radius/pki/cas', { pem: rd('R/ca.pem'), name: 'Racine interne' }); expect(r2.json).toMatchObject({ added: 1, skipped: 0 })
    v = r2.json.view; expect(v.cas.map((c: any) => [c.name, c.root, c.chainOk])).toEqual([['Lab Issuing CA', false, true], ['Racine interne', true, true]])
    const r3 = await admin.post('/api/radius/pki/cas', { pem: rd('R/ca.pem') + rd('I/ca.pem') }); expect(r3.json).toMatchObject({ added: 0, skipped: 2 })
    expect(v.cas.every((c: any) => /^[0-9a-f]{8}$/.test(c.hash))).toBe(true)
  })
  it('renommer une autorité ; identifiants invalides ou inconnus', async () => {
    const v = await getView(), id = caId(v, 'Racine interne')
    expect((await admin.put(`/api/radius/pki/cas/${id}`, { name: 'Lab Root' })).status).toBe(200); expect(caId(await getView(), 'Lab Root')).toBe(id)
    code(await admin.put('/api/radius/pki/cas/ffffffff', { name: 'x' }), 404, 'radius_pki_ca_not_found'); code(await admin.delete('/api/radius/pki/cas/ffffffff'), 404, 'radius_pki_ca_not_found')
    code(await admin.put('/api/radius/pki/cas/zz', { name: 'x' }), 400, 'invalid_id'); code(await admin.delete('/api/radius/pki/cas/..%2Fx'), 400, 'invalid_id')
  })
  it('déploiement refusé tant que la PKI est commencée mais incomplète : aucune demande déposée', async () => {
    const r = await admin.post('/api/radius/apply'); code(r, 409, 'radius_pki_not_ready')
    expect(r.json.data.problems.map((p: any) => p.code)).toEqual(expect.arrayContaining(['no_server', 'crl_missing']))
    expect(existsSync(REQ)).toBe(false); expect(existsSync(PKIDIR)).toBe(false); expect(existsSync(CONF)).toBe(false)
    expect((await viewer.get('/api/radius')).json.pki).toMatchObject({ configured: true, ready: false })
  })
})

describe('PKI RADIUS — certificat du serveur', () => {
  let csr = ''
  it('demande (CSR) : noms invalides refusés ; clé générée, jamais renvoyée, chiffrée en base ; CSR valide pour le CN et les noms DNS', async () => {
    for (const b of [{ cn: 'a,O=evil', sans: [], keyType: 'ec256' }, { cn: 'ok', sans: ['mauvais nom'], keyType: 'ec256' }, { cn: 'ok', sans: [], keyType: 'des' }, { cn: '', sans: [], keyType: 'ec256' }])
      expect((await admin.post('/api/radius/pki/server/csr', b)).status, JSON.stringify(b)).toBe(400)
    const r = await admin.post('/api/radius/pki/server/csr', { cn: 'radius.lab.test', sans: ['radius-bis.lab.test'], keyType: 'rsa2048' }); expect(r.status, r.text).toBe(200)
    csr = r.json.csrPem; expect(csr).toContain('BEGIN CERTIFICATE REQUEST'); expect(r.text).not.toContain('PRIVATE KEY')
    writeFileSync(join(P, 'srv.csr'), csr)
    const t = sh('openssl req -in srv.csr -noout -text -verify 2>&1'); expect(t).toContain('verify OK'); expect(t).toContain('radius-bis.lab.test'); expect(t).toContain('TLS Web Server Authentication')
    const [row] = await rows("select value from settings where key='radius_pki'"); expect(JSON.stringify(row.value)).not.toContain('PRIVATE KEY'); expect(row.value.pending.keyEnc).toBeTruthy()
    const v = await getView(); expect(v.pending).toMatchObject({ cn: 'radius.lab.test', sans: ['radius-bis.lab.test'], keyType: 'rsa2048' }); expect(JSON.stringify(v)).not.toContain('keyEnc'); expect(v.server).toBeNull()
  })
  it('certificat signé : celui d\'une autre clé refusé ; certificat de la bonne demande accepté, demande consommée', async () => {
    code(await admin.post('/api/radius/pki/server/cert', { pem: rd('srv2.pem') }), 400, 'radius_pki_server_key_mismatch')
    code(await admin.post('/api/radius/pki/server/cert', { pem: 'texte' }), 400, 'radius_pki_pem_no_certificate')
    writeFileSync(join(P, 'srv.ext'), 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:radius.lab.test,DNS:radius-bis.lab.test\n')
    sh('openssl x509 -req -in srv.csr -CA I/ca.pem -CAkey I/ca.key -CAcreateserial -days 90 -sha256 -extfile srv.ext -out srv-signed.pem 2>/dev/null')
    const r = await admin.post('/api/radius/pki/server/cert', { dataBase64: b64('srv-signed.pem') }); expect(r.status, r.text).toBe(200)
    expect(r.json.view.server).toMatchObject({ chainOk: true, keyType: 'rsa' }); expect(r.json.view.server.subject).toContain('radius.lab.test'); expect(r.json.view.pending).toBeNull()
    expect(r.json.view.server.sans.join(',')).toContain('DNS:radius-bis.lab.test')
    code(await admin.post('/api/radius/pki/server/cert', { pem: rd('srv-signed.pem') }), 400, 'radius_pki_no_pending')
  })
  it('import PEM + clé chiffrée : mot de passe exigé, faux refusé, clé faible refusée, certificat d\'une autre clé refusé ; puis accepté', async () => {
    const base = { pem: rd('srv2.pem'), key: rd('srv2-enc.key') }
    code(await admin.post('/api/radius/pki/server/import', base), 400, 'radius_pki_key_needs_password')
    code(await admin.post('/api/radius/pki/server/import', { ...base, keyPassword: 'faux' }), 400, 'radius_pki_key_bad_password')
    code(await admin.post('/api/radius/pki/server/import', { pem: rd('srv2.pem'), key: rd('k1024.key') }), 400, 'radius_pki_key_weak')
    code(await admin.post('/api/radius/pki/server/import', { pem: rd('alice.pem'), key: rd('srv2.key') }), 400, 'radius_pki_server_key_mismatch')
    code(await admin.post('/api/radius/pki/server/import', { pem: rd('srv2.pem') }), 400, 'radius_pki_import_incomplete')
    expect((await getView()).server.subject).toContain('radius.lab.test')   // les refus n'ont rien changé
    const r = await admin.post('/api/radius/pki/server/import', { ...base, keyPassword: 'cle-secrete-1' }); expect(r.status, r.text).toBe(200)
    expect(r.json.view.server.subject).toContain('radius2.lab.test'); expect(r.text).not.toContain('PRIVATE KEY')
  })
  it('import PKCS#12 : mauvais mot de passe, fichier invalide, puis succès (clé stockée sans mot de passe, chiffrée)', async () => {
    code(await admin.post('/api/radius/pki/server/import', { p12Base64: b64('srv2.p12'), p12Password: 'faux' }), 400, 'radius_pki_p12_bad_password')
    code(await admin.post('/api/radius/pki/server/import', { p12Base64: Buffer.from('pas un p12').toString('base64'), p12Password: 'x' }), 400, 'radius_pki_p12_invalid')
    const r = await admin.post('/api/radius/pki/server/import', { p12Base64: b64('srv2.p12'), p12Password: 'p12-pass' }); expect(r.status, r.text).toBe(200)
    const [row] = await rows("select value from settings where key='radius_pki'"); const s = JSON.stringify(row.value)
    for (const secret of ['PRIVATE KEY', 'p12-pass', 'cle-secrete-1']) expect(s).not.toContain(secret)
    expect(row.value.server.keyEnc).toBeTruthy()
  })
})

describe('PKI RADIUS — CRL', () => {
  it('sans CRL : prêt = non (crl_missing pour l\'émettrice seulement, la racine n\'émet pas de certificat client)', async () => {
    const v = await getView(); const probs = v.readiness.problems.filter((p: any) => p.code.startsWith('crl_'))
    expect(probs).toEqual([{ code: 'crl_missing', ref: caId(v, 'Lab Issuing CA') }]); expect(v.readiness.ready).toBe(false)
  })
  it('envoi de fichier : émettrice inconnue, signature fausse (homonyme), périmée, illisible, autre autorité refusés', async () => {
    const id = caId(await getView(), 'Lab Issuing CA'), up = (f: string) => admin.post(`/api/radius/pki/cas/${id}/crl`, { dataBase64: b64(f) })
    code(await up('crl-foreign.pem'), 400, 'radius_pki_crl_unknown_issuer')
    code(await up('crl-rogue.pem'), 400, 'radius_pki_crl_bad_signature')
    code(await up('crl-expired.pem'), 400, 'radius_pki_crl_expired')
    code(await up('crl-future.pem'), 400, 'radius_pki_crl_not_yet_valid')
    code(await up('crl-root.pem'), 400, 'radius_pki_crl_wrong_issuer')
    code(await admin.post(`/api/radius/pki/cas/${id}/crl`, { dataBase64: Buffer.from('rien').toString('base64') }), 400, 'radius_pki_crl_invalid')
    expect(((await getView()).cas.find((c: any) => c.id === id)).crl).toBeNull()
  })
  it('CRL valides (DER pour l\'émettrice, PEM pour la racine) : enregistrées, comptées ; ancienne refusée, même CRL = inchangée', async () => {
    const v = await getView(), id = caId(v, 'Lab Issuing CA'), rid = caId(v, 'Lab Root')
    const a = await admin.post(`/api/radius/pki/cas/${id}/crl`, { dataBase64: b64('crl-bob.der') }); expect(a.status, a.text).toBe(200); expect(a.json).toMatchObject({ changed: true, revoked: 1 })
    expect((await admin.post(`/api/radius/pki/cas/${rid}/crl`, { dataBase64: b64('crl-root.pem') })).json).toMatchObject({ changed: true, revoked: 0 })
    code(await admin.post(`/api/radius/pki/cas/${id}/crl`, { dataBase64: b64('crl-old.pem') }), 400, 'radius_pki_crl_older')
    expect((await admin.post(`/api/radius/pki/cas/${id}/crl`, { dataBase64: b64('crl-bob.pem') })).json).toMatchObject({ changed: false })
    const w = await getView(); expect(w.cas.find((c: any) => c.id === id).crl).toMatchObject({ revoked: 1, source: 'upload' }); expect(w.cas.find((c: any) => c.id === id).crl.pem).toBeUndefined()
    expect(w.readiness).toMatchObject({ ready: true, problems: [] })
  })
  it('adresse de CRL : refus des adresses dangereuses ; téléchargement depuis un vrai serveur HTTP ; erreur mémorisée puis effacée', async () => {
    const id = caId(await getView(), 'Lab Issuing CA'), url = `http://127.0.0.1:${CRLPORT}/ca.crl`
    for (const bad of ['ftp://pki/ca.crl', 'http://u:p@pki/ca.crl', 'http://169.254.169.254/x', 'file:///etc/passwd', 'http://pki/ca crl'])
      code(await admin.put(`/api/radius/pki/cas/${id}`, { crlUrl: bad }), 400, 'radius_pki_crl_url_invalid')
    expect((await admin.put(`/api/radius/pki/cas/${id}`, { crlUrl: url })).status).toBe(200)
    crlBody = readFileSync(join(P, 'crl-carl.pem')); crlMode = '404'
    code(await admin.post(`/api/radius/pki/cas/${id}/crl/refresh`, {}), 400, 'radius_pki_crl_fetch_status')
    expect((await getView()).cas.find((c: any) => c.id === id).crlError).toMatchObject({ code: 'crl_fetch_status' })
    crlMode = 'ok'
    const r = await admin.post(`/api/radius/pki/cas/${id}/crl/refresh`, {}); expect(r.status, r.text).toBe(200); expect(r.json).toMatchObject({ changed: true, revoked: 2 })
    const c = (await getView()).cas.find((x: any) => x.id === id); expect(c.crlError).toBeNull(); expect(c.crl).toMatchObject({ revoked: 2, source: 'url' }); expect(c.crlUrl).toBe(url)
    crlBody = readFileSync(join(P, 'crl-bob.pem'))   // le serveur ressert une CRL plus ancienne : refusée
    code(await admin.post(`/api/radius/pki/cas/${id}/crl/refresh`, {}), 400, 'radius_pki_crl_older')
    code(await admin.post(`/api/radius/pki/cas/${caId(await getView(), 'Lab Root')}/crl/refresh`, {}), 400, 'radius_pki_crl_no_url')
  })
})

describe('PKI RADIUS — déploiement et secrets', () => {
  it('PKI prête : dépôt complet pour root (fichiers privés), demande « apply + pki », clients à côté', async () => {
    const v = await getView(); expect(v.readiness.ready).toBe(true)
    const r = await admin.post('/api/radius/apply'); expect(r.status, r.text).toBe(200)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'apply', pki: true })
    expect(JSON.parse(readFileSync(join(PKIDIR, 'pki.json'), 'utf8'))).toEqual({ checkCrl: true })
    expect((readFileSync(join(PKIDIR, 'ca.pem'), 'utf8').match(/BEGIN CERTIFICATE/g) ?? []).length).toBe(2)
    expect((readFileSync(join(PKIDIR, 'server.pem'), 'utf8').match(/BEGIN CERTIFICATE/g) ?? []).length).toBe(2)   // certificat + intermédiaire, jamais la racine
    const key = readFileSync(join(PKIDIR, 'server.key'), 'utf8'); expect(key).toContain('PRIVATE KEY')
    expect(sh(`openssl pkey -in ${join(PKIDIR, 'server.key')} -pubout | openssl sha256; openssl x509 -in ${join(PKIDIR, 'server.pem')} -pubkey -noout | openssl sha256`).trim().split('\n').map((l) => l.split('= ')[1]).filter((x, i, a) => a.indexOf(x) === i)).toHaveLength(1)   // la clé déposée est celle du certificat
    for (const f of ['pki.json', 'ca.pem', 'server.pem', 'server.key']) expect(statSync(join(PKIDIR, f)).mode & 0o777, f).toBe(0o600)
    expect(readdirSync(join(PKIDIR, 'crl')).sort()).toEqual([`${caId(v, 'Lab Issuing CA')}.pem`, `${caId(v, 'Lab Root')}.pem`].sort())
    expect(existsSync(CONF)).toBe(true)
    const aud = JSON.stringify(await rows("select detail from audit_log where action like 'radius.%'")); expect(aud).not.toContain('PRIVATE KEY'); expect(aud).not.toContain('p12-pass')
    code(await admin.post('/api/radius/apply'), 409, 'request_pending')
    rootDone()
  })
  it('désactiver la vérification de révocation : accepté (CRL non exigées), déposé avec checkCrl=false', async () => {
    expect((await admin.put('/api/radius/pki/options', { checkCrl: false })).status).toBe(200)
    expect((await admin.put('/api/radius/pki/options', { checkCrl: 'non' })).status).toBe(400)
    const r = await admin.post('/api/radius/apply'); expect(r.status, r.text).toBe(200)
    expect(JSON.parse(readFileSync(join(PKIDIR, 'pki.json'), 'utf8'))).toEqual({ checkCrl: false }); rootDone()
    expect((await admin.put('/api/radius/pki/options', { checkCrl: true })).status).toBe(200)
  })
  it('aucun secret dans les réponses, la base en clair ni le journal d\'audit', async () => {
    const all = (await admin.get('/api/radius/pki')).text + (await admin.get('/api/radius')).text
    for (const s of ['PRIVATE KEY', 'keyEnc', 'p12-pass', 'cle-secrete-1']) expect(all, s).not.toContain(s)
    const [row] = await rows("select value from settings where key='radius_pki'"); expect(JSON.stringify(row.value)).not.toContain('PRIVATE KEY')
    expect(JSON.stringify(await rows('select detail from audit_log'))).not.toMatch(/PRIVATE KEY|p12-pass|cle-secrete-1/)
  })
})

describe('PKI RADIUS — actualisation automatique des CRL et envoi à root', () => {
  it('EAP-TLS déployé : une CRL plus récente publiée sur l\'adresse est téléchargée, enregistrée puis envoyée à root (une seule fois)', async () => {
    const v = await getView(), id = caId(v, 'Lab Issuing CA')
    setStatus({ enabled: true, server: { subject: 'CN=radius2.lab.test', not_after: 1900000000 }, cas: 2, crls: [], check_crl: true })
    sh(`openssl ca -batch -config I/openssl.cnf -gencrl -crlexts crl_ext -crl_lastupdate ${dateOf(-0.5)} -crl_nextupdate ${dateOf(7)} -out crl-now.pem 2>/dev/null`)
    // l'envoi de la CRL de l'étape précédente (déjà téléchargée par l'API) n'a pas été fait : root n'avait pas encore EAP ; la tâche envoie l'ensemble courant
    crlBody = readFileSync(join(P, 'crl-now.pem')); crlMode = 'ok'
    await until(async () => existsSync(REQ), 30000)
    expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'crl' })
    expect(readdirSync(join(PKIDIR, 'crl')).sort()).toEqual([`${id}.pem`, `${caId(v, 'Lab Root')}.pem`].sort())
    const c = (await getView()).cas.find((x: any) => x.id === id); expect(c.crl.source).toBe('url'); expect(c.crl.thisUpdate).toBeGreaterThan(Date.now() - 2 * 86400_000)
    for (const f of readdirSync(join(PKIDIR, 'crl'))) expect(statSync(join(PKIDIR, 'crl', f)).mode & 0o777).toBe(0o600)
    rootDone()
    await new Promise((r) => setTimeout(r, 5000))   // plusieurs passages de la tâche : CRL inchangées → aucun nouvel envoi
    expect(existsSync(REQ)).toBe(false)
  }, 60000)
  it('EAP-TLS non déployé : la CRL est enregistrée mais rien n\'est envoyé à root', async () => {
    setStatus({ enabled: false, cas: 0, crls: [], check_crl: false })
    const id = caId(await getView(), 'Lab Issuing CA')
    sh(`openssl ca -batch -config I/openssl.cnf -gencrl -crlexts crl_ext -crl_lastupdate ${dateOf(-0.25)} -crl_nextupdate ${dateOf(8)} -out crl-later.pem 2>/dev/null`)
    crlBody = readFileSync(join(P, 'crl-later.pem'))
    await until(async () => (await getView()).cas.find((c: any) => c.id === id).crl.nextUpdate > Date.now() + 7.5 * 86400_000, 30000)
    await new Promise((r) => setTimeout(r, 2500)); expect(existsSync(REQ)).toBe(false)
  }, 60000)
})

describe('PKI RADIUS — vérification d\'un certificat client', () => {
  const check = (f: string, extra: Record<string, unknown> = {}) => admin.post('/api/radius/pki/check-client', { pem: rd(f), ...extra })
  it('valide : acceptée, UPN et usage lus ; fichier DER accepté', async () => {
    const r = await check('alice.pem'); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ ok: true, revocation: 'good', identity: { upn: 'alice@lab.test', clientAuth: true } }); expect(r.json.account).toBeNull()
    const der = await admin.post('/api/radius/pki/check-client', { dataBase64: b64('inter.der') }); expect(der.status).toBe(200); expect(der.json.identity.subject).toContain('Lab Issuing CA')
  })
  it('révoqué, expiré, hors liste de confiance, mauvais usage : refus avec le bon motif', async () => {
    expect((await check('bob.pem')).json).toMatchObject({ ok: false, revocation: 'revoked', chain: { code: 'revoked' } })
    expect((await check('dave.pem')).json).toMatchObject({ ok: false, chain: { code: 'expired' } })
    expect((await check('frank.pem')).json).toMatchObject({ ok: false, chain: { code: 'untrusted' } })
    expect((await check('carl.pem')).json).toMatchObject({ ok: false, chain: { code: 'usage' } })
  })
  it('annuaire demandé mais non configuré : le contrôle de chaîne répond quand même, avec la raison', async () => {
    const r = await check('alice.pem', { directory: true }); expect(r.status).toBe(200)
    expect(r.json).toMatchObject({ ok: true, account: { checked: false, reason: 'radius_dir_incomplete' } })
  })
  it('entrées invalides : clé privée, rien, texte ; champs inconnus', async () => {
    code(await admin.post('/api/radius/pki/check-client', { pem: rd('alice.key') }), 400, 'radius_pki_pem_no_certificate')
    code(await admin.post('/api/radius/pki/check-client', {}), 400, 'radius_pki_pem_no_certificate')
    expect((await admin.post('/api/radius/pki/check-client', { pem: rd('alice.pem'), x: 1 })).status).toBe(400)
  })
  it('CRL retirée : refus du certificat (comme le service) avec le motif « CRL absente »', async () => {
    // une autorité sans CRL : on retire la racine puis on la rajoute ; la CRL de l'émettrice reste. On teste plutôt avec un état propre à l'émettrice.
    const id = caId(await getView(), 'Lab Issuing CA')
    expect((await admin.delete(`/api/radius/pki/cas/${id}`)).status).toBe(200)
    expect((await check('alice.pem')).json).toMatchObject({ ok: false, chain: { code: 'untrusted' } })   // l'intermédiaire n'est plus connue
    expect((await admin.post('/api/radius/pki/cas', { pem: rd('I/ca.pem') })).status).toBe(200)
    expect((await check('alice.pem')).json).toMatchObject({ ok: false, revocation: 'crl_missing' })     // ré-ajoutée : plus de CRL
  })
})

describe('PKI RADIUS — suppressions', () => {
  it('suppression du certificat du serveur et de la demande en attente ; retour à « non prêt »', async () => {
    expect((await admin.post('/api/radius/pki/server/csr', { cn: 'x.lab.test', sans: [], keyType: 'ec256' })).status).toBe(200)
    expect((await getView()).pending).not.toBeNull()
    expect((await admin.delete('/api/radius/pki/server/pending')).status).toBe(200); expect((await getView()).pending).toBeNull()
    expect((await admin.delete('/api/radius/pki/server')).status).toBe(200)
    const v = await getView(); expect(v.server).toBeNull(); expect(v.readiness.ready).toBe(false)
    const aud = await rows("select action from audit_log where action like 'radius.pki.%' order by id"); expect(aud.map((a: any) => a.action)).toEqual(expect.arrayContaining(['radius.pki.ca_add', 'radius.pki.csr', 'radius.pki.server_cert', 'radius.pki.server_import', 'radius.pki.crl_upload', 'radius.pki.crl_refresh', 'radius.pki.check_client', 'radius.pki.server_delete', 'radius.pki.csr_delete', 'radius.pki.ca_delete']))
  })
  it('vider la liste de confiance : retour à l\'état « non configuré » (déploiement sans EAP possible)', async () => {
    for (const c of (await getView()).cas) expect((await admin.delete(`/api/radius/pki/cas/${c.id}`)).status).toBe(200)
    expect((await getView()).readiness).toMatchObject({ empty: true })
    const r = await admin.post('/api/radius/apply'); expect(r.status, r.text).toBe(200); expect(JSON.parse(readFileSync(REQ, 'utf8'))).toEqual({ action: 'apply' }); rootDone()
  })
})
