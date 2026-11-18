// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.7 — mises à jour d'EJBCA Community. La console lit l'état que root publie (pki-update.json) et ne dépose que des demandes
// courtes ({"action":"update_check|update_apply|update_validate|update_rollback"}) que root revalide : ici on vérifie les droits, la validation des corps, les refus de la console
// (version inconnue ou interdite, PKI pas en service, mise à jour en attente ou en cours), le contenu EXACT de chaque demande déposée, l'audit et la lecture bornée d'un fichier hostile.
// Le parcours réel (tirage, sauvegarde, migration, contrôles, retour arrière) est vérifié par tests/b36-pki-update.sh (doublures) et par tests/b37-pki-update-live.sh (vrai conteneur).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3483, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s55-')), GEN = join(TMP, 'gen'), REQ = join(GEN, '.pki-request')
const STATUS = join(TMP, 'ps.json'), RESULT = join(TMP, 'pr.json'), UPDATE = join(TMP, 'pu.json')
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
const admin = new Client(), viewer = new Client(), oper = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 200)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const NOW = () => Math.floor(Date.now() / 1000)
const D = (c: string) => 'sha256:' + c.repeat(64)
const setStatus = (o: Record<string, unknown> = {}) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.3.7', digest: D('a'), nets: [],
  health: 'ALLOK', port: 8080, dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab.test', casCount: 1, resetAllowed: false, recovery: null, ...o }))
const notes = (v: string) => ({ release: `https://docs.keyfactor.com/ejbca/latest/ejbca-${v.replace('.', '-')}-release-notes`, upgrade: `https://docs.keyfactor.com/ejbca/latest/ejbca-${v.replace('.', '-')}-upgrade-notes` })
const item = (tag: string, over: Record<string, unknown> = {}) => ({ tag, pushedAt: '2026-09-01', kind: 'minor', allowed: true, reason: '', digest: D('b'), notes: notes(tag.split('.').slice(0, 2).join('.')), ...over })
const job = (over: Record<string, unknown> = {}) => ({ state: 'pending', step: 'checks', from: '9.3.7', to: '9.6.3', message: 'ok', reason: '', startedAt: NOW() - 600, finishedAt: NOW() - 60, updatedAt: NOW() - 60,
  certsAtBackup: 5, casAtBackup: 2, backupBytes: 3_145_728, steps: [{ id: 'pull', status: 'done' }, { id: 'checks', status: 'done' }], checks: [{ id: 'health', ok: true, detail: '' }], rollbackAvailable: true, ...over })
const setUpdate = (o: Record<string, unknown> = {}) => writeFileSync(UPDATE, JSON.stringify({ at: NOW(), current: '9.3.7', dbTag: '9.3.7', checkedAt: NOW() - 3600, checkError: '', latest: '9.6.3',
  available: [item('9.6.3'), item('10.0.0', { kind: 'major', allowed: false, reason: 'major_jump', notes: notes('10.0') })], job: null, certsSince: null, ...o }))
const clear = () => { rmSync(REQ, { force: true }); rmSync(RESULT, { force: true }) }
const sent = () => (existsSync(REQ) ? readFileSync(REQ, 'utf8') : null)
const U = '/api/pki/update'

beforeAll(async () => {
  mkdirSync(GEN, { recursive: true })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT, DDI_PKI_UPDATE: UPDATE } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  for (const [u, ro, c] of [['lect', 'viewer', viewer], ['oper', 'operator', oper]] as const) { expect((await admin.post('/api/users', { username: u, role: ro, password: PW })).status).toBe(200); expect((await c.login(u, PW)).status).toBe(200) }
  setStatus(); setUpdate()
}, 300000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('droits (rien n\'est déposé pour un refus)', () => {
  it('réservé à l\'administrateur, en lecture comme en écriture', async () => {
    for (const [m, p] of [['get', ''], ['post', '/check'], ['post', '/apply'], ['post', '/validate'], ['post', '/rollback']] as const) {
      code(await (anon as any)[m](U + p, ...(m === 'post' ? [{}] : [])), 401, 'unauthenticated')
      for (const c of [viewer, oper]) code(await (c as any)[m](U + p, ...(m === 'post' ? [{}] : [])), 403, 'forbidden')
    }
    expect(sent()).toBeNull()
  })
})

describe('lecture', () => {
  it('rend l\'état publié par root, borné', async () => {
    const r = await admin.get(U)
    expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ installed: true, version: '9.3.7', state: 'healthy', requestPending: false })
    expect(r.json.update).toMatchObject({ current: '9.3.7', latest: '9.6.3', job: null })
    expect(r.json.update.available.map((a: any) => [a.tag, a.allowed, a.reason])).toEqual([['9.6.3', true, ''], ['10.0.0', false, 'major_jump']])
    expect(r.json.update.available[0].notes.release).toBe('https://docs.keyfactor.com/ejbca/latest/ejbca-9-6-release-notes')
  })
  it('fichier absent ou corrompu : « update » nul, aucune erreur', async () => {
    rmSync(UPDATE, { force: true }); expect((await admin.get(U)).json.update).toBeNull()
    writeFileSync(UPDATE, '{pas du json'); expect((await admin.get(U)).json.update).toBeNull()
    setUpdate()
  })
  it('contenu hostile : adresses de notes étrangères, versions piégées et textes de contrôle nettoyés', async () => {
    setUpdate({ available: [item('9.6.3', { notes: { release: 'https://evil.example/x', upgrade: 'javascript:alert(1)' } }), item('9.6.4; id'), item('latest')],
      job: job({ message: 'a\u0007b', checks: [{ id: 'signing', ok: false, detail: 'x\u0001y' }] }) })
    const u = (await admin.get(U)).json.update
    expect(u.available).toHaveLength(1); expect(u.available[0].notes).toEqual({}); expect(u.job.message).toBe('a b'); expect(u.job.checks[0].detail).toBe('x y')
    setUpdate()
  })
  it('/pki donne l\'état de la tâche (grise les autres actions)', async () => {
    expect((await admin.get('/api/pki')).json.updateJob).toBeNull()
    setUpdate({ job: job({ state: 'running', rollbackAvailable: false }) })
    expect((await admin.get('/api/pki')).json.updateJob).toMatchObject({ state: 'running', from: '9.3.7', to: '9.6.3' })
    setUpdate()
  })
})

describe('recherche de nouvelles versions', () => {
  it('PKI non installée : 409', async () => {
    setStatus({ installed: false, state: 'absent' }); code(await admin.post(U + '/check'), 409, 'pki_not_installed'); expect(sent()).toBeNull(); setStatus()
  })
  it('dépose exactement {"action":"update_check"}', async () => {
    clear()
    const r = await admin.post(U + '/check'); expect(r.status, r.text).toBe(200); expect(r.json.accepted).toBe(true)
    expect(sent()).toBe('{"action":"update_check"}\n'); clear()
  })
  it('une demande déjà en attente : 409', async () => {
    writeFileSync(REQ, '{"action":"status"}\n'); code(await admin.post(U + '/check'), 409, 'request_pending'); expect(sent()).toBe('{"action":"status"}\n'); clear()
  })
})

describe('mise à jour', () => {
  it('corps strict : version piégée, vide, absente, numérique ou champ inconnu → 400, rien déposé', async () => {
    const bad: Array<[string, unknown]> = [['latest', { version: 'latest' }], ['injection', { version: '9.6.3; rm -rf /' }], ['vide', { version: '' }], ['absente', {}], ['numérique', { version: 963 }],
      ['étiquette candidate', { version: '9.6.3-rc1' }], ['image au lieu de version', { image: 'docker.io/keyfactor/ejbca-ce:9.6.3' }], ['champ en trop', { version: '9.6.3', image: 'x' }], ['corps nul', null]]
    for (const [what, b] of bad) { const r = await admin.post(U + '/apply', b); expect([r.status, r.json?.data?.code], `${what} : ${r.text}`).toEqual([400, 'validation']) }
    expect(sent()).toBeNull()
  })
  it('version hors de la liste publiée par root : 409 ; version interdite : 409 avec le motif', async () => {
    code(await admin.post(U + '/apply', { version: '9.6.9' }), 409, 'pki_update_unknown_version')
    const r = await admin.post(U + '/apply', { version: '10.0.0' }); code(r, 409, 'pki_update_refused'); expect(r.json.data.params?.reason ?? r.text).toContain('major_jump')
    rmSync(UPDATE, { force: true }); code(await admin.post(U + '/apply', { version: '9.6.3' }), 409, 'pki_update_unknown_version'); setUpdate()
    expect(sent()).toBeNull()
  })
  it('PKI non installée ou pas en service : 409', async () => {
    setStatus({ installed: false, state: 'absent' }); code(await admin.post(U + '/apply', { version: '9.6.3' }), 409, 'pki_not_installed')
    for (const state of ['unhealthy', 'starting', 'stopped']) { setStatus({ state }); code(await admin.post(U + '/apply', { version: '9.6.3' }), 409, 'pki_update_not_healthy') }
    setStatus(); expect(sent()).toBeNull()
  })
  it('mise à jour en attente de validation, ou en échec avec un point de retour : 409', async () => {
    setUpdate({ job: job({ state: 'pending' }) }); code(await admin.post(U + '/apply', { version: '9.6.3' }), 409, 'pki_update_pending')
    setUpdate({ job: job({ state: 'failed' }) }); code(await admin.post(U + '/apply', { version: '9.6.3' }), 409, 'pki_update_rollback_first')
    setUpdate(); expect(sent()).toBeNull()
  })
  it('mise à jour permise : dépose exactement la demande, l\'audit la nomme', async () => {
    clear()
    const r = await admin.post(U + '/apply', { version: '9.6.3' }); expect(r.status, r.text).toBe(200)
    expect(sent()).toBe('{"action":"update_apply","image":"docker.io/keyfactor/ejbca-ce:9.6.3"}\n')
    const a = await rows(`select detail::text as d from audit_log where action = 'pki.update_apply' order by id desc limit 1`)
    expect(a).toHaveLength(1); expect(JSON.parse(a[0].d)).toMatchObject({ from: '9.3.7', to: '9.6.3', kind: 'minor' }); clear()
  })
  it('une tâche terminée (validée ou annulée) n\'empêche pas la suivante', async () => {
    for (const state of ['validated', 'rolled_back']) { setUpdate({ job: job({ state, rollbackAvailable: false }) }); clear(); expect((await admin.post(U + '/apply', { version: '9.6.3' })).status, state).toBe(200); expect(sent()).toContain('update_apply'); clear() }
    setUpdate()
  })
})

describe('pendant une mise à jour', () => {
  it('aucune autre demande PKI n\'est déposée (409), ni par cette API ni par les autres', async () => {
    setUpdate({ job: job({ state: 'running', rollbackAvailable: false }) }); clear()
    for (const [p, b] of [['/api/pki/stop', {}], ['/api/pki/restart', {}], ['/api/pki/status', {}], [U + '/check', {}], [U + '/apply', { version: '9.6.3' }], [U + '/validate', {}], [U + '/rollback', { confirm: true }]] as const) {
      const r = await admin.post(p, b); expect([r.status, r.json?.data?.code], `${p} : ${r.text}`).toEqual([409, p === U + '/validate' || p === U + '/rollback' ? 'pki_update_none' : 'pki_update_running'])
    }
    expect(sent()).toBeNull(); setUpdate()
  })
  it('la lecture reste possible', async () => {
    setUpdate({ job: job({ state: 'running', rollbackAvailable: false, step: 'migrate' }) })
    const r = await admin.get(U); expect(r.status).toBe(200); expect(r.json.update.job).toMatchObject({ state: 'running', step: 'migrate' }); setUpdate()
  })
})

describe('validation et retour arrière', () => {
  it('valider sans mise à jour en attente : 409 ; en attente : dépose {"action":"update_validate"}', async () => {
    code(await admin.post(U + '/validate'), 409, 'pki_update_none')
    for (const state of ['validated', 'failed', 'rolled_back']) { setUpdate({ job: job({ state }) }); code(await admin.post(U + '/validate'), 409, 'pki_update_none') }
    expect(sent()).toBeNull()
    setUpdate({ job: job({ state: 'pending' }) }); clear()
    expect((await admin.post(U + '/validate')).status).toBe(200); expect(sent()).toBe('{"action":"update_validate"}\n'); clear()
  })
  it('retour arrière : confirmation obligatoire dans le corps', async () => {
    setUpdate({ job: job({ state: 'pending' }) })
    for (const b of [{}, { confirm: false }, { confirm: 'true' }, { confirm: true, x: 1 }]) { const r = await admin.post(U + '/rollback', b); expect([r.status, r.json?.data?.code]).toEqual([400, 'validation']) }
    expect(sent()).toBeNull()
  })
  it('retour arrière : refusé sans tâche, après validation, ou sans point de retour', async () => {
    rmSync(UPDATE, { force: true }); code(await admin.post(U + '/rollback', { confirm: true }), 409, 'pki_update_none')
    setUpdate({ job: job({ state: 'validated', rollbackAvailable: false }) }); code(await admin.post(U + '/rollback', { confirm: true }), 409, 'pki_update_none')
    setUpdate({ job: job({ state: 'failed', rollbackAvailable: false }) }); code(await admin.post(U + '/rollback', { confirm: true }), 409, 'pki_update_none')
    setUpdate({ job: job({ state: 'rolled_back', rollbackAvailable: true }) }); code(await admin.post(U + '/rollback', { confirm: true }), 409, 'pki_update_none')
    expect(sent()).toBeNull()
  })
  it('retour arrière permis (en attente, ou en échec avec point de retour) : dépose la demande, l\'audit garde le décompte des certificats', async () => {
    for (const state of ['pending', 'failed']) {
      setUpdate({ job: job({ state }), certsSince: 3 }); clear()
      const r = await admin.post(U + '/rollback', { confirm: true }); expect(r.status, `${state} : ${r.text}`).toBe(200)
      expect(sent()).toBe('{"action":"update_rollback"}\n'); clear()
    }
    const a = await rows(`select detail::text as d from audit_log where action = 'pki.update_rollback' order by id desc limit 1`)
    expect(JSON.parse(a[0].d)).toMatchObject({ from: '9.3.7', to: '9.6.3', certsSince: 3 })
  })
})

describe('journal et audit', () => {
  it('aucune demande de mise à jour ne laisse de secret ni de chemin dans l\'audit ou le journal', async () => {
    const all = JSON.stringify(await rows('select * from audit_log')) + srvLog
    expect(all).not.toMatch(/PASSWORD|-----BEGIN|\/etc\/ddibuntu|\.dump/)
    expect((await rows(`select count(*)::int as n from audit_log where action like 'pki.update_%'`))[0].n).toBeGreaterThanOrEqual(5)
  })
})
