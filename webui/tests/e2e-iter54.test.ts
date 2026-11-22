// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.5 — clé de récupération de la PKI. La console fabrique la paire de clés (RSA 4096), ne transmet à « root » que le certificat
// PUBLIC (dépôt pki-in/recovery.pem 0640 + demande {"action":"recovery_set"}) et rend la clé privée UNE seule fois à l'administrateur : jamais dans la demande, l'audit, le journal ni
// la base. « root » est simulé par ce test (il lit la demande et le dépôt, calcule l'empreinte, efface le dépôt, publie le résultat et l'état comme ddibuntu-pki) ; l'enregistrement réel
// (taille de clé, validité, chiffrement d'essai) est vérifié par tests/b35-pki-backup.sh.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3482, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s54-')), GEN = join(TMP, 'gen'), IN = join(GEN, 'pki-in'), REQ = join(GEN, '.pki-request')
const STATUS = join(TMP, 'ps.json'), RESULT = join(TMP, 'pr.json'), BKSTATUS = join(TMP, 'backup-status.json')
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
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 100)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const read = (p: string) => readFileSync(p, 'utf8')
const sh = (args: string[], input?: string | Buffer) => spawnSync('openssl', args, { encoding: 'utf8', input })
const setStatus = (o: Record<string, unknown>) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', digest: '', nets: [], health: 'ALLOK', port: 8080,
  dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab.test', casCount: 1, resetAllowed: false, ...o }))
const NOW = () => Math.floor(Date.now() / 1000)
const setBackups = (items: Array<Record<string, unknown>>, o: Record<string, unknown> = {}) => writeFileSync(BKSTATUS, JSON.stringify({ at: NOW(), enabled: true, role: 'primary', node: 'n1', hostname: 'h', cluster: null, repo: '/r', keepFull: 3, intervalHours: 24, startHour: 2,
  mirrorDir: null, archiveMode: 'on', archiver: null, diskFreeBytes: 1, preRestoreDirs: 0, walFiles: 1, walBytes: 1, lastWalAt: NOW(), pitrFrom: NOW() - 7200,
  backups: items.map((b) => ({ node: 'n1', startedAt: (b.finishedAt as number) - 10, sizeBytes: 5, timeline: 1, walArchived: true, ...b })), ...o }))

// ---- « root » simulé : lit la demande et le dépôt (certificat public), l'efface, publie le résultat et l'état ----
interface Seen { req: any; reqText: string; cert: string | null; mode: number | null; fp: string }
const rootLog: Seen[] = []
let rootBusy = false, rootMute = false, rootRefuse: string | null = null, rootTimer: NodeJS.Timeout | null = null
const publishResult = (action: string, ok: boolean, message: string) => writeFileSync(RESULT, JSON.stringify({ at: Math.floor(Date.now() / 1000), action, ok, message }))
const fingerprint = (pem: string) => (sh(['x509', '-noout', '-fingerprint', '-sha256'], pem).stdout.split('=')[1] ?? '').replace(/[:\n]/g, '').toLowerCase()
function startRoot() {
  rootTimer = setInterval(() => {
    if (rootBusy || rootMute || !existsSync(REQ)) return
    rootBusy = true
    try {
      const reqText = read(REQ); const req = JSON.parse(reqText); rmSync(REQ, { force: true })
      const f = join(IN, 'recovery.pem')
      const cert = existsSync(f) ? read(f) : null, mode = existsSync(f) ? statSync(f).mode & 0o777 : null
      const fp = cert ? fingerprint(cert) : ''
      rootLog.push({ req, reqText, cert, mode, fp })
      rmSync(f, { force: true })   // consommé quoi qu'il arrive
      if (rootRefuse) { publishResult(req.action, false, rootRefuse); return }
      if (!cert || fp.length !== 64) { publishResult(req.action, false, 'dépôt absent ou illisible'); return }
      setStatus({ recovery: { fingerprint: fp, bits: 4096, notAfter: NOW() + 3_000_000_000, subject: 'CN=Ipnoria PKI recovery test', registeredAt: NOW() } })
      publishResult(req.action, true, `Clé de récupération enregistrée (empreinte ${fp.slice(0, 16)}…) : gardez la clé PRIVÉE hors de cette machine.`)
    } catch (e) { publishResult('recovery_set', false, `erreur du root simulé : ${(e as Error).message}`) } finally { rootBusy = false }
  }, 40)
}
const clear = () => { rmSync(REQ, { force: true }); rmSync(RESULT, { force: true }); rootLog.length = 0; for (const f of existsSync(IN) ? readdirSync(IN) : []) rmSync(join(IN, f), { force: true }) }
const inDir = () => (existsSync(IN) ? readdirSync(IN) : [])
const URL = '/api/pki/recovery'
const pubOfKey = (keyPem: string, pass?: string) => sh(['pkey', '-pubout', ...(pass ? ['-passin', `pass:${pass}`] : [])], keyPem).stdout.trim()
const pubOfCert = (certPem: string) => sh(['x509', '-pubkey', '-noout'], certPem).stdout.trim()
let k1: any, k1cert = '', k2: any

beforeAll(async () => {
  for (const d of [GEN, IN]) mkdirSync(d, { recursive: true })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT,
    DDI_BACKUP_STATUS: BKSTATUS, DDI_PKI_RECOVERY_WAIT_MS: '2500' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  for (const [u, ro, c] of [['lect', 'viewer', viewer], ['oper', 'operator', oper]] as const) { expect((await admin.post('/api/users', { username: u, role: ro, password: PW })).status).toBe(200); expect((await c.login(u, PW)).status).toBe(200) }
  setStatus({}); setBackups([]); startRoot()
}, 300000)
afterAll(async () => { if (rootTimer) clearInterval(rootTimer); srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('droits et validation (rien n\'est déposé tant que la demande est refusée)', () => {
  it('réservé à l\'administrateur, en lecture comme en écriture', async () => {
    code(await anon.get(URL), 401, 'unauthenticated'); code(await anon.post(URL, {}), 401, 'unauthenticated')
    for (const c of [viewer, oper]) { code(await c.get(URL), 403, 'forbidden'); code(await c.post(URL, {}), 403, 'forbidden') }
    expect(inDir()).toEqual([]); expect(existsSync(REQ)).toBe(false)
  })
  it('corps strict : phrase secrète trop courte / trop longue / avec caractère de contrôle, champ inconnu, replace non booléen', async () => {
    const bad: Array<[string, Record<string, unknown>]> = [['phrase de 9 caractères', { passphrase: 'a'.repeat(9) }], ['phrase de 129 caractères', { passphrase: 'a'.repeat(129) }],
      ['retour à la ligne', { passphrase: 'abcdefghij\n' }], ['octet nul', { passphrase: 'abcdefghij\u0000' }], ['phrase numérique', { passphrase: 1234567890 }], ['champ inconnu', { extra: 1 }],
      ['replace en texte', { replace: 'oui' }], ['la phrase vide est refusée aussi', { passphrase: '' }]]
    for (const [what, o] of bad) { const r = await admin.post(URL, o); expect(r.status, `${what} : ${r.text}`).toBe(400); expect(r.json?.data?.code, what).toBe('validation') }
    expect(inDir()).toEqual([]); expect(existsSync(REQ)).toBe(false)
  })
})

describe('état avant toute clé', () => {
  it('sans clé : protection « no_key », rien de secret dans la réponse', async () => {
    const r = await admin.get(URL)
    expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ recovery: null, casCount: 1, installed: true, protection: { state: 'no_key', last: null, lastWithBundle: null }, bits: 4096 })
  })
  it('PKI absente (rien à protéger) : « none »', async () => {
    setStatus({ installed: false, state: 'absent', dataPresent: false, secretsPresent: false, casCount: 0 })
    expect((await admin.get(URL)).json.protection.state).toBe('none')
    setStatus({})
  })
})

describe('création de la clé', () => {
  it('une demande déjà en cours : 409, aucun dépôt', async () => {
    writeFileSync(REQ, '{"action":"status"}\n')
    code(await admin.post(URL, {}), 409, 'request_pending'); expect(inDir()).toEqual([]); expect(read(REQ)).toBe('{"action":"status"}\n')
    clear()
  })
  it('création sans phrase : la clé privée correspond au certificat que root a reçu, dépôt 0640 sans secret, demande minimale', async () => {
    clear()
    const r = await admin.post(URL, {})
    expect(r.status, r.text).toBe(200)
    k1 = r.json
    expect(k1).toMatchObject({ bits: 4096, encrypted: false, replaced: false }); expect(k1.fingerprint).toMatch(/^[0-9a-f]{64}$/); expect(k1.keyPem).toContain('BEGIN PRIVATE KEY')
    await until(async () => rootLog.length === 1)
    const s = rootLog[0]!; k1cert = s.cert!
    expect(s.req).toEqual({ action: 'recovery_set' }); expect(s.reqText.length).toBeLessThan(60)
    expect(s.cert).toContain('BEGIN CERTIFICATE'); expect(s.cert).not.toContain('PRIVATE'); expect(s.mode).toBe(0o640)
    expect(s.fp).toBe(k1.fingerprint)
    expect(pubOfKey(k1.keyPem)).toBe(pubOfCert(s.cert!)); expect(pubOfKey(k1.keyPem)).toContain('BEGIN PUBLIC KEY')
    expect(inDir()).toEqual([])
  })
  it('l\'état publié par root est relayé : empreinte, taille, dates ; protection « pending » tant qu\'aucune sauvegarde ne la contient', async () => {
    const g = (await admin.get(URL)).json
    expect(g.recovery).toMatchObject({ fingerprint: k1.fingerprint, bits: 4096 }); expect(g.recovery.registeredAt).toBeGreaterThan(0)
    expect(g.protection.state).toBe('pending')   // sauvegardes actives, aucune encore
    expect(JSON.stringify(g)).not.toMatch(/PRIVATE KEY/)
  })
  it('une clé déjà enregistrée : 409 sans « replace », rien déposé', async () => {
    clear(); code(await admin.post(URL, {}), 409, 'pki_recovery_exists'); expect(inDir()).toEqual([]); expect(existsSync(REQ)).toBe(false)
    expect(rootLog).toHaveLength(0)
  })
  it('remplacement avec phrase secrète : nouvelle paire, clé chiffrée, ancienne empreinte différente', async () => {
    clear()
    const pass = 'phrase très secrète 2026'
    const r = await admin.post(URL, { passphrase: pass, replace: true })
    expect(r.status, r.text).toBe(200); k2 = r.json
    expect(k2).toMatchObject({ encrypted: true, replaced: true }); expect(k2.keyPem).toContain('BEGIN ENCRYPTED PRIVATE KEY'); expect(k2.fingerprint).not.toBe(k1.fingerprint)
    await until(async () => rootLog.length === 1)
    expect(pubOfKey(k2.keyPem, pass)).toBe(pubOfCert(rootLog[0]!.cert!)); expect(pubOfCert(rootLog[0]!.cert!)).not.toBe(pubOfCert(k1cert))
    expect(sh(['pkey', '-noout', '-passin', 'pass:mauvaise'], k2.keyPem).status).not.toBe(0)
    expect((await admin.get(URL)).json.recovery.fingerprint).toBe(k2.fingerprint)
  })
})

describe('protection des secrets dans les sauvegardes', () => {
  const FP = () => k2.fingerprint as string
  it('dernière sauvegarde chiffrée pour la clé actuelle : « ok »', async () => {
    setBackups([{ id: '20261117T020000Z', finishedAt: NOW() + 5, pki: { secrets: true, recoveryFp: FP(), bytes: 100, cas: 1, tag: '9.6.3' } }])
    const p = (await admin.get(URL)).json
    expect(p.protection).toMatchObject({ state: 'ok', last: { id: '20261117T020000Z' }, lastWithBundle: { id: '20261117T020000Z' } }); expect(p.backup).toMatchObject({ enabled: true, count: 1, withBundle: 1 })
  })
  it('sauvegarde sans lot après l\'enregistrement de la clé : « no_bundle » avec le motif ; lot pour une autre clé : « other_key »', async () => {
    setBackups([{ id: '20261117T020000Z', finishedAt: NOW() + 5, pki: { secrets: false, reason: 'error' } }])
    expect((await admin.get(URL)).json.protection).toMatchObject({ state: 'no_bundle', reason: 'error' })
    setBackups([{ id: '20261117T020000Z', finishedAt: NOW() + 5, pki: { secrets: true, recoveryFp: k1.fingerprint, bytes: 1, cas: 1, tag: 'x' } }])
    expect((await admin.get(URL)).json.protection).toMatchObject({ state: 'no_bundle', reason: 'other_key' })
  })
  it('sauvegarde antérieure à la clé : « pending » ; sauvegardes désactivées : « backup_off » ; état périmé : « unknown »', async () => {
    setBackups([{ id: '20261117T020000Z', finishedAt: NOW() - 100000, pki: { secrets: false, reason: 'no-recovery-key' } }])
    expect((await admin.get(URL)).json.protection.state).toBe('pending')
    setBackups([], { enabled: false }); expect((await admin.get(URL)).json.protection.state).toBe('backup_off')
    setBackups([], { at: NOW() - 99999 }); expect((await admin.get(URL)).json.protection.state).toBe('unknown')
    setBackups([])
  })
})

describe('refus de root, silence de root, audit, journal', () => {
  it('root refuse : 409 « pki_recovery_refused », AUCUNE clé n\'est rendue, aucun dépôt ne reste', async () => {
    clear(); rootRefuse = 'certificat refusé : clé RSA de 2048 bits (3072 minimum)'
    const r = await admin.post(URL, { replace: true })
    code(r, 409, 'pki_recovery_refused'); expect(r.text).not.toMatch(/PRIVATE KEY/); expect(r.json.data.message).toContain('3072 minimum')
    expect(inDir()).toEqual([]); rootRefuse = null
  })
  it('root muet : 504 « pki_recovery_timeout », aucune clé rendue, dépôt retiré', async () => {
    clear(); rootMute = true
    const r = await admin.post(URL, { replace: true })
    code(r, 504, 'pki_recovery_timeout'); expect(r.text).not.toMatch(/PRIVATE KEY/); expect(inDir()).toEqual([])
    rootMute = false; await until(async () => !existsSync(REQ)); clear()
  })
  it('un ancien résultat « recovery_set » réussi ne vaut jamais pour une nouvelle demande', async () => {
    clear(); rootMute = true
    writeFileSync(RESULT, JSON.stringify({ at: NOW() - 5, action: 'recovery_set', ok: true, message: `Clé de récupération enregistrée (empreinte ${k2.fingerprint.slice(0, 16)}…)` }))
    code(await admin.post(URL, { replace: true }), 504, 'pki_recovery_timeout')
    rootMute = false; await until(async () => !existsSync(REQ)); clear()
  })
  it('l\'audit nomme l\'action et l\'empreinte du certificat public, jamais la clé ni la phrase', async () => {
    const a = await rows(`select detail::text as d from audit_log where action = 'pki.recovery_create' order by id`)
    expect(a.length).toBeGreaterThanOrEqual(4)
    expect(a[0].d).toContain(k1.fingerprint); expect(a[1].d).toMatch(/"encrypted": true/)
    const all = JSON.stringify(await rows('select * from audit_log'))
    expect(all).not.toMatch(/PRIVATE KEY|ENCRYPTED/); expect(all).not.toContain('phrase très secrète'); expect(all).not.toContain(k1.keyPem.split('\n')[1]); expect(all).not.toContain(k2.keyPem.split('\n')[1])
  })
  it('ni le journal du serveur ni aucune table de la console ne contiennent la clé privée ou la phrase', async () => {
    for (const k of [k1, k2]) { expect(srvLog).not.toContain(k.keyPem.split('\n')[1]); expect(srvLog).not.toMatch(/PRIVATE KEY/) }
    expect(srvLog).not.toContain('phrase très secrète')
    for (const t of (await rows(`select table_name from information_schema.tables where table_schema = 'public' and table_type = 'BASE TABLE'`)).map((x) => x.table_name as string)) {
      const dump = JSON.stringify(await rows(`select * from "${t}"`))
      expect(dump, `table ${t}`).not.toMatch(/PRIVATE KEY/); expect(dump, `table ${t}`).not.toContain('phrase très secrète'); expect(dump, `table ${t}`).not.toContain(k2.keyPem.split('\n')[1])
    }
  })
})
