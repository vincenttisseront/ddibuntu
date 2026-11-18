// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.14.0 — service PKI (EJBCA Community) : droits, validation, dépôt de la demande pour root,
// nom public et version figés après l'installation, désinstallation confirmée, enregistrement DNS du nom public (zone réelle, enregistrement protégé),
// audit sans secret. Le comportement de root (secrets, base, Quadlet, pare-feu) est vérifié par tests/b31-pki-service.sh.
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3475, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s44-')), GEN = join(TMP, 'gen'), REQ = join(GEN, '.pki-request'), STATUS = join(TMP, 'ps.json'), RESULT = join(TMP, 'pr.json')
let srv: ChildProcess, db: pg.Client, srvLog = ''

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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); delete = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows
const setStatus = (o: Record<string, unknown>) => writeFileSync(STATUS, JSON.stringify({ at: 1700000000, podman: true, installed: false, active: false, state: 'absent', hostname: '', version: '', digest: '', nets: [], health: '', port: 8080, ...o }))
const rootDone = () => rmSync(REQ, { force: true })   // root a traité la demande
const sent = () => JSON.parse(readFileSync(REQ, 'utf8'))

beforeAll(async () => {
  mkdirSync(GEN, { recursive: true })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_PKI_STATUS: STATUS, DDI_PKI_RESULT: RESULT } })
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
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

describe('droits', () => {
  it('toute la PKI est réservée à l\'administrateur', async () => {
    code(await anon.get('/api/pki'), 401, 'unauthenticated')
    for (const c of [viewer, oper]) {
      code(await c.get('/api/pki'), 403, 'forbidden')
      code(await c.post('/api/pki/apply', { hostname: 'pki.lab.test' }), 403, 'forbidden')
      for (const a of ['start', 'stop', 'restart', 'status', 'uninstall', 'dns']) code(await c.post(`/api/pki/${a}`, {}), 403, 'forbidden')
    }
    expect(existsSync(REQ)).toBe(false)
  })
})

describe('avant l\'installation', () => {
  it('rien de publié : état vide, rien de verrouillé, aucune demande', async () => {
    const r = await admin.get('/api/pki')
    expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ status: null, result: null, requestPending: false, locked: false, settings: { version: '9.6.3', nets: [] } })
    expect(r.json.endpoints.port).toBe(8080)
  })
  it('démarrer / arrêter / redémarrer exigent une PKI installée ; l\'état peut toujours être demandé', async () => {
    setStatus({})
    for (const a of ['start', 'stop', 'restart']) code(await admin.post(`/api/pki/${a}`, {}), 409, 'pki_not_installed')
    code(await admin.post('/api/pki/uninstall', { confirm: 'pki.lab.test' }), 409, 'pki_not_installed')
    expect(existsSync(REQ)).toBe(false)
    expect((await admin.post('/api/pki/status', {})).status).toBe(200); expect(sent()).toEqual({ action: 'status' }); rootDone()
  })
  it('validation : nom public, version, réseaux, champs inconnus (dont l\'image, que la console construit seule)', async () => {
    const bad: Array<Record<string, unknown>> = [
      { hostname: 'pki' }, { hostname: 'pki.lab.test;id' }, { hostname: '10.0.0.1' }, { hostname: '' }, { hostname: 'pki.lab.test', version: 'latest' }, { hostname: 'pki.lab.test', version: '9.6.3; id' },
      { hostname: 'pki.lab.test', nets: ['0.0.0.0/0'] }, { hostname: 'pki.lab.test', nets: ['10.0.0.0/8; reboot'] }, { hostname: 'pki.lab.test', nets: ['oups'] },
      { hostname: 'pki.lab.test', image: 'docker.io/evil/x:1.0.0' }, { nets: [] },
    ]
    for (const b of bad) { const r = await admin.post('/api/pki/apply', b); expect([400], `${JSON.stringify(b)} → ${r.status} ${r.text}`).toContain(r.status) }
    expect(existsSync(REQ)).toBe(false)
  })
  it('sans Podman, l\'installation est acceptée : c\'est root qui installe le paquet (0.14.6)', async () => {
    setStatus({ podman: false })
    const r = await admin.post('/api/pki/apply', { hostname: 'pki.lab.test' })
    expect(r.status, r.text).toBe(200)
    expect(sent().action).toBe('apply')
    rootDone()
  })
})

describe('installation', () => {
  it('dépose pour root une demande minimale (image officielle construite par la console, nom et réseaux normalisés)', async () => {
    setStatus({})
    const r = await admin.post('/api/pki/apply', { hostname: ' PKI.Lab.Test ', nets: ['10.0.0.0/8', '192.168.1.5', '10.0.0.0/8'] })
    expect(r.status, r.text).toBe(200); expect(r.json).toMatchObject({ accepted: true })
    expect(sent()).toEqual({ action: 'apply', image: 'docker.io/keyfactor/ejbca-ce:9.6.3', hostname: 'pki.lab.test', nets: ['10.0.0.0/8', '192.168.1.5/32'] })
    expect((statSync(REQ).mode & 0o777).toString(8)).toBe('640')
    expect(readFileSync(REQ, 'utf8')).not.toMatch(/PASSWORD|KEYSTORE|secret/i)
  })
  it('une demande en attente bloque la suivante', async () => {
    code(await admin.post('/api/pki/apply', { hostname: 'pki.lab.test' }), 409, 'request_pending')
    code(await admin.post('/api/pki/status', {}), 409, 'request_pending')
    expect((await admin.get('/api/pki')).json.requestPending).toBe(true)
  })
  it('les choix sont conservés (réglages) pour préremplir la page', async () => {
    rootDone()
    const r = await admin.get('/api/pki')
    expect(r.json.settings).toMatchObject({ hostname: 'pki.lab.test', version: '9.6.3', nets: ['10.0.0.0/8', '192.168.1.5/32'] })
    expect(r.json.hostname).toBe('pki.lab.test'); expect(r.json.endpoints.health).toBe('http://pki.lab.test:8080/ejbca/publicweb/healthcheck/ejbcahealth')
  })
})

describe('instance installée', () => {
  it('lit l\'état publié par root et le résultat de la dernière demande', async () => {
    setStatus({ installed: true, active: true, state: 'starting', hostname: 'pki.lab.test', version: '9.6.3', nets: ['10.0.0.0/8'], digest: 'sha256:' + 'a'.repeat(64) })
    writeFileSync(RESULT, JSON.stringify({ at: 1700000001, action: 'apply', ok: true, message: 'PKI installée (EJBCA 9.6.3)' }))
    const r = (await admin.get('/api/pki')).json
    expect(r.locked).toBe(true); expect(r.status).toMatchObject({ installed: true, state: 'starting', hostname: 'pki.lab.test' }); expect(r.result).toMatchObject({ ok: true, action: 'apply' })
  })
  it('le nom public et la version ne changent plus ; les réseaux, oui', async () => {
    code(await admin.post('/api/pki/apply', { hostname: 'autre.lab.test' }), 409, 'pki_hostname_locked')
    code(await admin.post('/api/pki/apply', { hostname: 'pki.lab.test', version: '9.6.4' }), 409, 'pki_version_locked')
    expect(existsSync(REQ)).toBe(false)
    expect((await admin.post('/api/pki/apply', { hostname: 'pki.lab.test', version: '9.6.3', nets: ['172.16.0.0/12'] })).status).toBe(200)
    expect(sent().nets).toEqual(['172.16.0.0/12']); rootDone()
  })
  it('un état illisible ou une valeur inconnue ne casse rien', async () => {
    setStatus({ installed: true, state: 'bizarre', hostname: 'pki.lab.test', version: '9.6.3' })
    expect((await admin.get('/api/pki')).json.status.state).toBe('absent')
    writeFileSync(STATUS, 'pas du json'); const r = await admin.get('/api/pki'); expect(r.status).toBe(200); expect(r.json.status).toBeNull()
    setStatus({ installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', health: 'ALLOK' })
  })
  it('démarrer, arrêter, redémarrer déposent l\'action seule', async () => {
    for (const a of ['start', 'stop', 'restart']) { expect((await admin.post(`/api/pki/${a}`, {})).status).toBe(200); expect(sent()).toEqual({ action: a }); rootDone() }
  })
  it('désinstaller : confirmation par le nom public', async () => {
    code(await admin.post('/api/pki/uninstall', { confirm: 'mauvais.lab.test' }), 400, 'pki_confirm_mismatch')
    code(await admin.post('/api/pki/uninstall', {}), 400, 'validation')
    expect(existsSync(REQ)).toBe(false)
    expect((await admin.post('/api/pki/uninstall', { confirm: 'PKI.lab.test' })).status).toBe(200); expect(sent()).toEqual({ action: 'uninstall' }); rootDone()
  })
})

describe('nom public dans le DNS du DDI', () => {
  let zoneId = 0
  it('aucune zone ne contient le nom : refus clair', async () => {
    expect((await admin.get('/api/pki')).json.dns).toMatchObject({ hostname: 'pki.lab.test', zone: null, records: [] })
    code(await admin.post('/api/pki/dns', { address: '10.0.0.5' }), 409, 'pki_dns_no_zone')
  })
  it('zone présente, enregistrement absent : proposé ; adresse invalide refusée', async () => {
    const z = await admin.post('/api/dns/zones', { name: 'lab.test', type: 'primary', soa_mname: 'ns1.lab.test.', soa_rname: 'hostmaster.lab.test.' })
    expect(z.status, z.text).toBe(200); zoneId = z.json.id
    expect((await admin.post('/api/dns/records', { zone_id: zoneId, name: '@', type: 'NS', rdata: 'ns1.lab.test.' })).status).toBe(200)
    const d = (await admin.get('/api/pki')).json.dns
    expect(d).toMatchObject({ zone: 'lab.test', records: [] })
    for (const a of ['pas-une-ip', '10.0.0.5; drop', '']) expect([400], a).toContain((await admin.post('/api/pki/dns', { address: a })).status)
  })
  it('création : enregistrement A protégé, zone marquée à republier, historique et audit', async () => {
    await rows('update dns_zones set dirty = false where id = $1', [zoneId])
    const r = await admin.post('/api/pki/dns', { address: '10.0.0.5' })
    expect(r.status, r.text).toBe(200); expect(r.json).toMatchObject({ name: 'pki.lab.test', type: 'A', address: '10.0.0.5' })
    const rec = (await rows("select name, type, rdata, protected from dns_records where zone_id = $1 and name = 'pki'", [zoneId]))[0]
    expect(rec).toEqual({ name: 'pki', type: 'A', rdata: '10.0.0.5', protected: true })
    expect((await rows('select dirty from dns_zones where id = $1', [zoneId]))[0].dirty).toBe(true)
    expect((await rows("select action from dns_record_history where zone_id = $1 and after->>'name' = 'pki'", [zoneId])).map((x: any) => x.action)).toEqual(['create'])
    expect((await admin.get('/api/pki')).json.dns.records).toEqual([expect.objectContaining({ type: 'A', rdata: '10.0.0.5' })])
  })
  it('le nom existe déjà : pas de doublon ; un opérateur ne peut pas supprimer l\'enregistrement protégé', async () => {
    code(await admin.post('/api/pki/dns', { address: '10.0.0.6' }), 409, 'pki_dns_exists')
    const id = (await rows("select id from dns_records where zone_id = $1 and name = 'pki'", [zoneId]))[0].id
    code(await oper.delete(`/api/dns/records/${id}`), 403, 'protected_record')
    expect((await rows('select count(*)::int c from dns_records where id = $1', [id]))[0].c).toBe(1)
  })
})

describe('traçabilité', () => {
  it('chaque action est auditée, sans aucun secret', async () => {
    const a = (await rows("select action from audit_log where action like 'pki.%' order by id")).map((x: any) => x.action)
    expect(a).toEqual(expect.arrayContaining(['pki.apply', 'pki.status', 'pki.start', 'pki.stop', 'pki.restart', 'pki.uninstall', 'pki.dns_create']))
    expect(JSON.stringify(await rows("select detail from audit_log where action like 'pki.%'"))).not.toMatch(/PASSWORD|KEYSTORE|PRIVATE KEY|secret/i)
  })
})
