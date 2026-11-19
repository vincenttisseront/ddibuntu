// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.8 — SCEP de la PKI du DDI. La console fabrique le défi à usage unique, le remet à « root » dans un fichier SECRET
// (pki-in/<id>.scepw, 0600) et ne dépose qu'une demande JSON courte qui n'en porte jamais la valeur ; ici un « root » simulé lit la demande et le dépôt, publie pki-scep.json et le résultat.
// On vérifie : les droits, les préconditions (PKI prête, SCEP activé, émettrice active en RSA, nom libre), le contenu EXACT de chaque demande, le défi (24 caractères, 0600, rendu une seule
// fois, ni dans l'audit, ni dans le journal, ni dans la demande, ni sur le disque ensuite), les refus de root et le silence de root, la lecture bornée d'un fichier hostile.
// Le parcours réel (alias EJBCA, entité préenregistrée, inscription avec sscep) est vérifié par tests/b38-pki-scep.sh (doublures) et par tests/b39-pki-scep-live.sh (vrai conteneur).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3484, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s56-')), GEN = join(TMP, 'gen'), IN = join(GEN, 'pki-in'), REQ = join(GEN, '.pki-request')
const STATUS = join(TMP, 'ps.json'), RESULT = join(TMP, 'pr.json'), CAS = join(TMP, 'pki-cas.json'), SCEP = join(TMP, 'pki-scep.json')
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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); del = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), oper = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 200)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const NOW = () => Math.floor(Date.now() / 1000)
const D = (c: string) => 'sha256:' + c.repeat(64)
const setStatus = (o: Record<string, unknown> = {}) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', digest: D('a'), nets: [],
  health: 'ALLOK', port: 8080, dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab.test', casCount: 3, resetAllowed: false, recovery: null, ...o }))
const pubCa = (o: Record<string, unknown>) => ({ name: 'Lab-Root', kind: 'root', state: 'active', dn: 'CN=Lab Root CA,O=Lab,C=FR', issuer: 'CN=Lab Root CA,O=Lab,C=FR', selfSigned: true, serial: 'ab', notBefore: '2026-01-01T00:00:00Z', notAfter: '2036-01-01T00:00:00Z',
  keyAlg: 'RSA', keyBits: 3072, curve: '', sigAlg: 'sha256WithRSAEncryption', pathLen: null, sha256: 'a'.repeat(64), signedBy: 'self', alg: 'rsa3072', createdAt: 1700000000, extRoot: '',
  crlUrl: 'http://pki.lab.test:8080/crl/Lab-Root', certUrl: 'http://pki.lab.test:8080/cert/Lab-Root', crl: null, files: { cert: true, chain: false, csr: false, crl: false }, ...o })
const publishCas = () => writeFileSync(CAS, JSON.stringify({ at: 1700000000, ok: true, hostname: 'pki.lab.test', port: 8080, cas: [
  pubCa({}),
  pubCa({ name: 'Lab-SubRSA', kind: 'issuing', dn: 'CN=Lab SubRSA,O=Lab,C=FR', selfSigned: false, signedBy: 'Lab-Root', sha256: 'b'.repeat(64), files: { cert: true, chain: true, csr: false, crl: true } }),
  pubCa({ name: 'Lab-SubEC', kind: 'issuing', dn: 'CN=Lab SubEC,O=Lab,C=FR', selfSigned: false, signedBy: 'Lab-Root', keyAlg: 'EC', keyBits: 256, curve: 'prime256v1', sha256: 'c'.repeat(64), files: { cert: true, chain: true, csr: false, crl: true } }),
  pubCa({ name: 'Lab-Wait', kind: 'issuing', state: 'waiting', dn: 'CN=Lab Wait,O=Lab,C=FR', selfSigned: false, sha256: '', files: { cert: false, chain: true, csr: true, crl: false } }),
] }))

// ---- « root » simulé : tient pki-scep.json, lit la demande ET le dépôt du défi, publie le résultat comme le vrai ----
interface Offer { cn: string; state: string; status: number; ca: string; profile: string; dn: string; san: string; createdAt: number; modifiedAt: number; expiresAt: number | null; cert: unknown }
const scep = { enabled: false, offers: [] as Offer[] }
const writeScep = () => writeFileSync(SCEP, JSON.stringify({ at: NOW(), enabled: scep.enabled, alias: 'ddibuntu', path: '/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe', port: 8080,
  url: 'http://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe', offerDays: 7, offers: scep.offers }))
const rootLog: Array<{ req: any; raw: string; deposit: string | null; mode: number | null }> = []
let rootBusy = false, rootRefuse: string | null = null, rootMute = false, rootTimer: NodeJS.Timeout | null = null
const publishResult = (action: string, ok: boolean, message: string, ref?: string) => writeFileSync(RESULT, JSON.stringify({ at: NOW(), action, ok, message, ...(ref ? { ref } : {}) }))
function startRoot() {
  rootTimer = setInterval(() => {
    if (rootBusy || rootMute || !existsSync(REQ)) return
    rootBusy = true
    let req: any = {}
    try {
      const raw = readFileSync(REQ, 'utf8'); req = JSON.parse(raw); rmSync(REQ, { force: true })
      const dep = join(IN, `${req.id}.scepw`)
      const deposit = existsSync(dep) ? readFileSync(dep, 'utf8') : null
      const mode = existsSync(dep) ? statSync(dep).mode & 0o777 : null
      rootLog.push({ req, raw, deposit, mode }); rmSync(dep, { force: true })   // root efface le dépôt quoi qu'il arrive
      if (rootRefuse) { publishResult(req.action, false, rootRefuse, req.id); return }
      const now = NOW()
      switch (req.action) {
        case 'scep_enable': scep.enabled = true; writeScep(); publishResult('scep_enable', true, 'SCEP activé'); break
        case 'scep_disable': scep.enabled = false; writeScep(); publishResult('scep_disable', true, 'SCEP désactivé'); break
        case 'scep_offer':
          scep.offers.push({ cn: req.cn, state: 'waiting', status: 10, ca: req.ca, profile: req.profile, dn: `CN=${req.cn}`, san: [...(req.dns ?? []).map((d: string) => `dNSName=${d}`), ...(req.ip ?? []).map((i: string) => `iPAddress=${i}`)].join(','),
            createdAt: now, modifiedAt: now, expiresAt: now + 7 * 86400, cert: null })
          writeScep(); publishResult('scep_offer', true, `Équipement « ${req.cn} » préenregistré`, req.id); break
        case 'scep_rearm': {
          const o = scep.offers.find((x) => x.cn === req.cn)!; Object.assign(o, { state: 'waiting', status: 10, modifiedAt: now, expiresAt: now + 7 * 86400 })
          writeScep(); publishResult('scep_rearm', true, `Nouveau défi pour « ${req.cn} »`, req.id); break
        }
        case 'scep_cancel': scep.offers = scep.offers.filter((x) => x.cn !== req.cn); writeScep(); publishResult('scep_cancel', true, `« ${req.cn} » annulé`); break
        default: publishResult(req.action, false, 'action inconnue', req.id)
      }
    } catch (e) { publishResult(req.action ?? 'scep_offer', false, `erreur du root simulé : ${(e as Error).message}`, req.id) } finally { rootBusy = false }
  }, 40)
}
const clear = () => { rmSync(REQ, { force: true }); rmSync(RESULT, { force: true }); rootLog.length = 0; rootRefuse = null; rootMute = false }
const lastReq = () => rootLog[rootLog.length - 1]!
const S = '/api/pki/scep'
const OFFER = { ca: 'Lab-SubRSA', profile: 'network', cn: 'sw-core-1', o: 'Laboratoire', c: 'FR', dns: ['sw-core-1.lab.test'], ip: ['10.1.2.3'] }
const CHALLENGE_RE = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{24}$/
const challenges: string[] = []

beforeAll(async () => {
  for (const d of [GEN, IN]) mkdirSync(d, { recursive: true })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN,
    DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT, DDI_PKI_CAS: CAS, DDI_PKI_SCEP: SCEP, DDI_PKI_ISSUE_TIMEOUT_MS: '3000' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  for (const [u, ro, c] of [['lect', 'viewer', viewer], ['oper', 'operator', oper]] as const) { expect((await admin.post('/api/users', { username: u, role: ro, password: PW })).status).toBe(200); expect((await c.login(u, PW)).status).toBe(200) }
  setStatus(); publishCas(); startRoot()
}, 300000)
afterAll(async () => { if (rootTimer) clearInterval(rootTimer); srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('droits (rien n\'est déposé pour un refus)', () => {
  it('réservé à l\'administrateur, en lecture comme en écriture', async () => {
    const all: Array<[string, string, unknown?]> = [['GET', S], ['POST', S + '/enable', {}], ['POST', S + '/disable', {}], ['POST', S + '/offers', OFFER], ['POST', S + '/offers/sw1/rearm', {}], ['DELETE', S + '/offers/sw1']]
    for (const [m, p, b] of all) {
      code(await anon.req(m, p, b), 401, 'unauthenticated')
      for (const c of [viewer, oper]) code(await c.req(m, p, b), 403, 'forbidden')
    }
    expect(existsSync(REQ)).toBe(false); expect(rootLog).toHaveLength(0)
  })
})

describe('état et préconditions', () => {
  it('sans fichier publié : SCEP inconnu, les émettrices RSA sont signalées, ni racine ni autorité en attente', async () => {
    const r = await admin.get(S); expect(r.status, r.text).toBe(200)
    expect(r.json.scep).toBeNull(); expect(r.json.ready).toBe(true); expect(r.json.alias).toBe('ddibuntu'); expect(r.json.challengeLen).toBe(24)
    expect(r.json.issuers.map((x: any) => [x.name, x.rsa])).toEqual([['Lab-SubRSA', true], ['Lab-SubEC', false]])
    expect(r.json.issuers[0].certUrl).toBe('/pki/cas/Lab-SubRSA/cert')
    expect(typeof r.json.issuers[0].dn).toBe('string'); expect(r.json.issuers[0].dn).not.toBe('')   // 0.14.15 : le préenregistrement reprend l'organisation, l'unité et le pays de l'autorité
  })
  it('un fichier publié hostile (illisible, trop gros) est ignoré', async () => {
    writeFileSync(SCEP, '{pas du json'); expect((await admin.get(S)).json.scep).toBeNull()
    writeFileSync(SCEP, ' '.repeat(2_100_000)); expect((await admin.get(S)).json.scep).toBeNull()
    rmSync(SCEP, { force: true })
  })
  it('PKI absente ou pas prête : activation et préenregistrement refusés sans rien déposer', async () => {
    setStatus({ installed: false, state: 'absent' }); code(await admin.post(S + '/enable'), 409, 'pki_not_installed'); code(await admin.post(S + '/offers', OFFER), 409, 'pki_not_installed')
    setStatus({ state: 'unhealthy' }); code(await admin.post(S + '/enable'), 409, 'pki_not_ready'); code(await admin.post(S + '/disable'), 409, 'pki_not_ready'); code(await admin.post(S + '/offers', OFFER), 409, 'pki_not_ready')
    setStatus(); expect(existsSync(REQ)).toBe(false); expect(rootLog).toHaveLength(0)
  })
  it('SCEP pas activé : préenregistrement, nouveau défi refusés', async () => {
    code(await admin.post(S + '/offers', OFFER), 409, 'pki_scep_disabled')
    code(await admin.post(S + '/offers/sw1/rearm'), 409, 'pki_scep_disabled')
    expect(rootLog).toHaveLength(0)
  })
  it('une demande déjà en attente chez root : refus sans rien écraser', async () => {
    writeFileSync(REQ, '{"action":"status"}\n'); rootMute = true
    code(await admin.post(S + '/enable'), 409, 'request_pending')
    rmSync(REQ, { force: true }); rootMute = false
  })
})

describe('activation', () => {
  it('dépose exactement la demande, rend le message de root, l\'audit la nomme', async () => {
    clear()
    const r = await admin.post(S + '/enable'); expect(r.status, r.text).toBe(200)
    expect(r.json).toEqual({ ok: true, message: 'SCEP activé' }); expect(lastReq().raw).toBe('{"action":"scep_enable"}\n')
    const g = await admin.get(S); expect(g.json.scep.enabled).toBe(true); expect(g.json.scep.url).toBe('http://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe')
    expect((await rows(`select count(*)::int as n from audit_log where action = 'pki.scep_enable'`))[0].n).toBe(1)
  })
  it('root refuse : 422, le message de root est rendu, l\'audit garde l\'échec', async () => {
    clear(); rootRefuse = 'EJBCA a refusé l\'alias'
    const r = await admin.post(S + '/enable'); code(r, 422, 'pki_scep_refused'); expect(r.json.data.detail).toContain('refusé l\'alias')
    expect((await rows(`select count(*)::int as n from audit_log where action = 'pki.scep_enable_failed'`))[0].n).toBe(1)
  })
  it('root ne répond pas : 504', async () => {
    clear(); rootMute = true
    code(await admin.post(S + '/enable'), 504, 'pki_timeout')
    rmSync(REQ, { force: true }); rootMute = false
  })
})

describe('préenregistrement', () => {
  it('refuse les corps invalides avant tout dépôt', async () => {
    clear()
    const bad: Array<[string, Record<string, unknown>]> = [
      ['nom avec espace', { cn: 'Jean Dupont' }], ['nom avec virgule', { cn: 'x,O=Evil' }], ['nom superadmin', { cn: 'superadmin' }], ['nom ejbca', { cn: 'EJBCA' }], ['nom ddi-', { cn: 'ddi-0123456789abcdef' }],
      ['nom trop long', { cn: 'a'.repeat(64) }], ['sans nom', { cn: '' }], ['sans SAN pour un équipement réseau', { dns: [], ip: [] }], ['SAN qui en cache un autre', { dns: ['a.lab.test,dNSName=evil.test'] }],
      ['profil inconnu', { profile: 'EMPTY' }], ['défi fourni par le client', { challenge: 'ABCDEFGHJKLMNPQRSTUVWXYZ' }], ['mot de passe fourni par le client', { password: 'x'.repeat(20) }],
      ['identifiant fourni par le client', { id: '0123456789abcdef' }], ['action fournie par le client', { action: 'scep_offer' }], ['autorité avec une barre', { ca: 'a/b' }], ['ManagementCA', { ca: 'ManagementCA' }],
    ]
    for (const [why, over] of bad) { const r = await admin.post(S + '/offers', { ...OFFER, ...over }); expect([r.status, r.json?.data?.code, why], `${why} : ${r.text}`).toEqual([400, expect.any(String), why]) }
    expect(existsSync(REQ)).toBe(false); expect(rootLog).toHaveLength(0)
  })
  it('refuse une autorité inconnue, une racine, une autorité en attente, une émettrice ECDSA', async () => {
    clear()
    code(await admin.post(S + '/offers', { ...OFFER, ca: 'Lab-Inconnue' }), 404, 'not_found')
    code(await admin.post(S + '/offers', { ...OFFER, ca: 'Lab-Root' }), 409, 'pki_ca_not_issuing')
    code(await admin.post(S + '/offers', { ...OFFER, ca: 'Lab-Wait' }), 409, 'pki_ca_not_issuing')
    code(await admin.post(S + '/offers', { ...OFFER, ca: 'Lab-SubEC' }), 409, 'pki_scep_ca_not_rsa')
    expect(rootLog).toHaveLength(0)
  })
  it('succès : le défi est rendu une fois ; root le lit dans un fichier 0600 et la demande n\'en porte pas la valeur', async () => {
    clear()
    const r = await admin.post(S + '/offers', OFFER); expect(r.status, r.text).toBe(200)
    const c = r.json.challenge as string; challenges.push(c)
    expect(c).toMatch(CHALLENGE_RE); expect(r.json.cn).toBe('sw-core-1'); expect(r.json.ca).toBe('Lab-SubRSA'); expect(r.json.profile).toBe('network'); expect(r.json.offerDays).toBe(7)
    expect(r.json.url).toContain('/scep/ddibuntu/pkiclient.exe'); expect(r.headers.get('cache-control')).toBe('no-store')
    const l = lastReq()
    expect(l.deposit).toBe(c); expect(l.mode).toBe(0o600)
    expect(l.req).toEqual({ action: 'scep_offer', id: l.req.id, ca: 'Lab-SubRSA', profile: 'network', cn: 'sw-core-1', o: 'Laboratoire', c: 'FR', dns: ['sw-core-1.lab.test'], ip: ['10.1.2.3'] })
    expect(l.req.id).toMatch(/^[0-9a-f]{16}$/); expect(l.raw).not.toContain(c); expect(l.raw.length).toBeLessThan(4000)
    expect(r.json.id).toBe(l.req.id)
    expect(existsSync(join(IN, `${l.req.id}.scepw`))).toBe(false)   // plus rien sur le disque
  })
  it('l\'équipement apparaît « en attente » ; le même nom (casse ignorée) est refusé', async () => {
    const g = (await admin.get(S)).json.scep
    expect(g.offers).toHaveLength(1); expect(g.offers[0]).toMatchObject({ cn: 'sw-core-1', state: 'waiting', ca: 'Lab-SubRSA', profile: 'network', san: 'dNSName=sw-core-1.lab.test,iPAddress=10.1.2.3' })
    expect(JSON.stringify(g)).not.toContain(challenges[0]!)
    clear(); code(await admin.post(S + '/offers', OFFER), 409, 'pki_scep_name_taken'); code(await admin.post(S + '/offers', { ...OFFER, cn: 'SW-CORE-1' }), 409, 'pki_scep_name_taken')
    expect(rootLog).toHaveLength(0)
  })
  it('un second équipement a un autre défi', async () => {
    clear()
    const r = await admin.post(S + '/offers', { ...OFFER, cn: 'sw-core-2', dns: ['sw-core-2.lab.test'], ip: [] }); expect(r.status, r.text).toBe(200)
    expect(r.json.challenge).toMatch(CHALLENGE_RE); expect(challenges).not.toContain(r.json.challenge); challenges.push(r.json.challenge)
    expect(lastReq().deposit).toBe(r.json.challenge)
  })
  it('root refuse : 422 avec son message, le dépôt ne reste pas, le défi n\'est pas rendu', async () => {
    clear(); rootRefuse = 'ce nom existe déjà dans EJBCA'
    const r = await admin.post(S + '/offers', { ...OFFER, cn: 'sw-refuse', dns: ['sw-refuse.lab.test'] }); code(r, 422, 'pki_scep_refused')
    expect(r.json.data.detail).toContain('existe déjà'); expect(r.text).not.toMatch(/ABCDEFGHJKLMNPQRSTUVWXYZ|[A-Z2-9]{24}/)
    expect(lastReq().deposit).toMatch(CHALLENGE_RE); expect(existsSync(join(IN, `${lastReq().req.id}.scepw`))).toBe(false)
    expect((await rows(`select count(*)::int as n from audit_log where action = 'pki.scep_offer_failed'`))[0].n).toBe(1)
  })
  it('root ne répond pas : 504 et le dépôt du défi est effacé par la console', async () => {
    clear(); rootMute = true
    const r = await admin.post(S + '/offers', { ...OFFER, cn: 'sw-muet', dns: ['sw-muet.lab.test'] }); code(r, 504, 'pki_timeout')
    const left = existsSync(IN) ? readdirSync(IN) : []
    expect(left.filter((f) => f.endsWith('.scepw'))).toEqual([])
    rmSync(REQ, { force: true }); rootMute = false
  })
  it('les autres profils passent par la même voie', async () => {
    clear()
    for (const [p, over] of [['machine', { dns: ['pc01.lab.test'], ip: [], cn: 'pc01' }], ['server', { dns: ['radius.lab.test'], ip: ['10.0.0.9'], cn: 'radius-1' }], ['user', { dns: [], ip: [], mail: ['j.dupont@lab.test'], upn: ['jdupont@lab.test'], cn: 'jdupont' }]] as const) {
      const r = await admin.post(S + '/offers', { ...OFFER, profile: p, ...over }); expect(r.status, `${p} : ${r.text}`).toBe(200)
      expect(lastReq().req.profile).toBe(p)
    }
  })
})

describe('nouveau défi et annulation', () => {
  it('nouveau défi : demande {action, id, cn}, autre défi, l\'ancien n\'est plus rien', async () => {
    clear()
    const r = await admin.post(`${S}/offers/sw-core-1/rearm`); expect(r.status, r.text).toBe(200)
    expect(r.json.challenge).toMatch(CHALLENGE_RE); expect(challenges).not.toContain(r.json.challenge)
    const l = lastReq()
    expect(l.req).toEqual({ action: 'scep_rearm', id: l.req.id, cn: 'sw-core-1' }); expect(l.deposit).toBe(r.json.challenge); expect(l.mode).toBe(0o600); expect(l.raw).not.toContain(r.json.challenge)
    expect(r.json).toMatchObject({ cn: 'sw-core-1', ca: 'Lab-SubRSA', profile: 'network', offerDays: 7 }); expect(r.headers.get('cache-control')).toBe('no-store')
    challenges.push(r.json.challenge)
  })
  it('nom inconnu : 404 ; nom invalide : 400 ; rien n\'est déposé', async () => {
    clear()
    code(await admin.post(`${S}/offers/inconnu/rearm`), 404, 'not_found'); code(await admin.post(`${S}/offers/superadmin/rearm`), 400, 'invalid_id'); code(await admin.post(`${S}/offers/a%20b/rearm`), 400, 'invalid_id')
    code(await admin.del(`${S}/offers/inconnu`), 404, 'not_found'); code(await admin.del(`${S}/offers/ddi-0123456789abcdef`), 400, 'invalid_id'); code(await admin.del(`${S}/offers/x%3By`), 400, 'invalid_id')
    expect(rootLog).toHaveLength(0)
  })
  it('root refuse le nouveau défi : 422, dépôt effacé', async () => {
    clear(); rootRefuse = 'entité introuvable'
    const r = await admin.post(`${S}/offers/sw-core-2/rearm`); code(r, 422, 'pki_scep_refused'); expect(existsSync(join(IN, `${lastReq().req.id}.scepw`))).toBe(false)
  })
  it('annulation : demande {action, cn}, l\'équipement disparaît, l\'audit la nomme', async () => {
    clear()
    const r = await admin.del(`${S}/offers/sw-core-2`); expect(r.status, r.text).toBe(200)
    expect(lastReq().raw).toBe('{"action":"scep_cancel","cn":"sw-core-2"}\n')
    expect((await admin.get(S)).json.scep.offers.map((o: any) => o.cn)).not.toContain('sw-core-2')
    expect((await rows(`select count(*)::int as n from audit_log where action = 'pki.scep_cancel'`))[0].n).toBe(1)
  })
  it('désactivation : demande {action}, le nouveau défi est alors refusé', async () => {
    clear()
    const r = await admin.post(S + '/disable'); expect(r.status, r.text).toBe(200); expect(lastReq().raw).toBe('{"action":"scep_disable"}\n')
    expect((await admin.get(S)).json.scep.enabled).toBe(false)
    code(await admin.post(`${S}/offers/sw-core-1/rearm`), 409, 'pki_scep_disabled'); code(await admin.post(S + '/offers', { ...OFFER, cn: 'sw-9' }), 409, 'pki_scep_disabled')
    expect((await admin.get(S)).json.scep.offers.length).toBeGreaterThan(0)   // les équipements préenregistrés restent
    const c = await admin.del(`${S}/offers/sw-core-1`); expect(c.status, 'annuler reste possible SCEP désactivé').toBe(200)
  })
})

describe('le défi ne laisse aucune trace', () => {
  it('ni dans l\'audit, ni dans le journal de la console, ni dans les états publiés, ni sur le disque', async () => {
    expect(challenges.length).toBeGreaterThanOrEqual(3)
    const audit = JSON.stringify(await rows('select * from audit_log'))
    const files = [STATUS, RESULT, CAS, SCEP].filter((f) => existsSync(f)).map((f) => readFileSync(f, 'utf8')).join('\n')
    for (const c of challenges) {
      expect(audit, 'audit').not.toContain(c); expect(srvLog, 'journal').not.toContain(c); expect(files, 'états publiés').not.toContain(c)
    }
    const left = existsSync(IN) ? readdirSync(IN) : []
    expect(left).toEqual([])
    expect((await rows(`select count(*)::int as n from audit_log where action in ('pki.scep_offer','pki.scep_rearm')`))[0].n).toBeGreaterThanOrEqual(5)
  })
})
