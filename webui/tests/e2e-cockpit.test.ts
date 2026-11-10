// Bout en bout du cockpit de filtrage (serveur CONSTRUIT, PostgreSQL réel, outils BIND/Kea réels, vrai fichier journal lu par le serveur).
import { spawn, type ChildProcess } from 'node:child_process'
import { appendFileSync, existsSync, mkdtempSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3397, BASE = `http://127.0.0.1:${PORT}`, DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-ck-')), GEN = join(TMP, 'gen'), LOG = join(TMP, 'query.log')
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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
const admin = new Client(), operator = new Client(), viewer = new Client(), anon = new Client()
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await sleep(150) } throw new Error('délai dépassé') }
const rows = async (sql: string, p: unknown[] = []) => (await db.query(sql, p)).rows
const ts = (offsetSec = 0) => new Date(Date.now() - offsetSec * 1000).toISOString()
const Q = (client: string, domain: string, type = 'A', off = 5) => `${ts(off)} client @0x7f ${client}#5000 (${domain}): query: ${domain} IN ${type} + (10.0.0.1)`
const RPZ = (client: string, domain: string, action = 'NXDOMAIN', off = 5) => `${ts(off)} rpz: info: client @0x7f ${client}#5001 (${domain}): rpz QNAME ${action} rewrite ${domain}/A/IN via ${domain}.rpz.ddibuntu.local`
const queries = async (qs = '') => (await admin.get(`/api/cockpit/queries${qs}`)).json

beforeAll(async () => {
  expect(existsSync('.output/server/index.mjs'), 'lancer « nuxt build » avant les tests').toBe(true)
  writeFileSync(LOG, '')
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_QUERY_LOG: LOG, DDI_QUERYLOG_INTERVAL_MS: '300' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW }); await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })
  expect((await operator.login('oper', PW)).status).toBe(200); expect((await viewer.login('lect', PW)).status).toBe(200)
  const l = (await admin.post('/api/filter/lists', { name: 'Pub', category: 'ads', format: 'domains', enabled: true })).json.id
  await admin.post(`/api/filter/lists/${l}/import`, { content: 'ads.example.net\ntracker.example.org\n' })
  await admin.post('/api/filter/rules', { domain: 'ok.example.net', action: 'allow' }); await admin.post('/api/filter/rules', { domain: 'bad.example.com', action: 'block' })
  // le blocage RPZ est désactivé par défaut : l'administrateur l'active
  expect((await admin.put('/api/filter/settings', { rpzEnabled: true, rpzAction: 'nxdomain', sinkhole4: '0.0.0.0', sinkhole6: '::' })).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })

describe('journal des requêtes : ingestion et explication', () => {
  it('une requête et sa réécriture RPZ forment une ligne ; la raison suit la précédence (liste, parent, règle, liste blanche)', async () => {
    const log = [Q('10.0.0.5', 'ads.example.net'), RPZ('10.0.0.5', 'ads.example.net'), Q('10.0.0.5', 'sub.tracker.example.org', 'AAAA'), RPZ('10.0.0.5', 'sub.tracker.example.org'),
      Q('10.0.0.6', 'bad.example.com'), RPZ('10.0.0.6', 'bad.example.com'), Q('10.0.0.6', 'ok.example.net'), RPZ('10.0.0.6', 'ok.example.net', 'PASSTHRU'),
      Q('10.0.0.6', 'www.example.com'), Q('10.0.0.7', 'www.example.com'), Q('10.0.0.7', 'mail.example.com', 'MX'), 'bruit sans rapport'].join('\n')
    const r = await admin.post('/api/filter/ingest-log', { content: log })
    expect(r.json).toMatchObject({ events: 11, stored: 7 })
    const by = Object.fromEntries((await rows('select domain, status, reason, category, qtype, client from dns_queries')).map((x) => [x.domain, x]))
    expect(by['ads.example.net']).toMatchObject({ status: 'blocked', reason: 'list:Pub', category: 'ads', qtype: 'A', client: '10.0.0.5' })
    expect(by['sub.tracker.example.org']).toMatchObject({ status: 'blocked', reason: 'list:Pub', qtype: 'AAAA' })      // bloqué par le domaine PARENT de la liste
    expect(by['bad.example.com']).toMatchObject({ status: 'blocked', reason: 'blacklist', category: '' })
    expect(by['ok.example.net']).toMatchObject({ status: 'allowed', reason: 'whitelist' })
    expect(by['www.example.com']).toMatchObject({ status: 'allowed', reason: '' }); expect(by['mail.example.com'].qtype).toBe('MX')
  })
  it('les statistiques agrégées existantes continuent d\'être alimentées (sans compter la liste blanche comme un blocage)', async () => {
    const s = (await admin.get('/api/filter/stats?range=1h')).json
    expect(s.byCategory.find((x: any) => x.category === 'ads')?.n).toBe('2'); expect(s.byCategory.find((x: any) => x.category === 'rule')?.n).toBe('1')
    expect((await rows("select coalesce(sum(count),0)::int n from dns_stats where kind not in ('query','blocked')"))[0].n).toBe(0)
  })
  it('la lecture ne fait pas confiance au contenu : droits, taille, corps invalide', async () => {
    code(await viewer.post('/api/filter/ingest-log', { content: 'x' }), 403, 'forbidden'); code(await admin.post('/api/filter/ingest-log', { content: '' }), 400, 'validation')
  })
})

describe('tableau de bord', () => {
  it('chiffres, pourcentage, tops, types, raisons, listes', async () => {
    const s = (await viewer.get('/api/cockpit/summary?range=24h')).json
    expect(s).toMatchObject({ range: '24h', total: 7, blocked: 3, percent: 42.9, uniqueDomains: 6, uniqueClients: 3 })
    expect(s.topBlocked.map((x: any) => x.domain).sort()).toEqual(['ads.example.net', 'bad.example.com', 'sub.tracker.example.org'])
    expect(s.topAllowed[0]).toEqual({ domain: 'www.example.com', n: 2 })
    expect(s.topClients.map((x: any) => [x.client, x.total, x.blocked])).toEqual([['10.0.0.6', 3, 1], ['10.0.0.5', 2, 2], ['10.0.0.7', 2, 0]])
    expect(s.byType.map((x: any) => x.qtype).sort()).toEqual(['A', 'AAAA', 'MX'])
    expect(s.byType.find((x: any) => x.qtype === 'A').n).toBe(5)
    expect(s.byReason).toEqual([{ reason: 'list:Pub', n: 2 }, { reason: 'blacklist', n: 1 }])
    expect(s.blocklist).toEqual({ domains: '2', lists: 1, allowRules: 1, blockRules: 1 })
    expect(s.blocking).toEqual({ enabled: true, pausedUntil: null }); expect(s.series.reduce((n: number, x: any) => n + x.n, 0)).toBe(7)
  })
  it('périodes : 15m, 1h, 6h, 24h, 7d ; une période inconnue est refusée', async () => {
    for (const r of ['15m', '1h', '6h', '24h', '7d']) expect((await admin.get(`/api/cockpit/summary?range=${r}`)).json.total).toBe(7)
    code(await admin.get('/api/cockpit/summary?range=2d'), 400, 'invalid_query'); code(await anon.get('/api/cockpit/summary'), 401, 'unauthenticated')
  })
  it('hors de la période : une requête ancienne n\'est pas comptée', async () => {
    await db.query("insert into dns_queries (at, client, domain, qtype, status) values (now() - interval '3 hours', '10.9.9.9', 'ancien.example.com', 'A', 'allowed')")
    expect((await admin.get('/api/cockpit/summary?range=1h')).json.total).toBe(7); expect((await admin.get('/api/cockpit/summary?range=6h')).json.total).toBe(8)
    await db.query("delete from dns_queries where domain = 'ancien.example.com'")
  })
})

describe('journal en direct : filtres et pages', () => {
  it('filtres : état, client, type, raison, domaine (sous-chaîne, sans joker SQL)', async () => {
    expect((await queries('?status=blocked')).items).toHaveLength(3); expect((await queries('?status=allowed')).items).toHaveLength(4)
    expect((await queries('?client=10.0.0.7')).items).toHaveLength(2); expect((await queries('?qtype=aaaa')).items.map((x: any) => x.domain)).toEqual(['sub.tracker.example.org'])
    expect((await queries('?reason=blacklist')).items).toHaveLength(1); expect((await queries('?domain=TRACKER')).items).toHaveLength(1)
    expect((await queries('?domain=%25')).items).toHaveLength(0); expect((await queries('?domain=_')).items).toHaveLength(0)   // « % » et « _ » sont des caractères, pas des jokers
    code(await admin.get('/api/cockpit/queries?status=x'), 400, 'invalid_query'); code(await admin.get('/api/cockpit/queries?limit=abc'), 400, 'invalid_query')
  })
  it('pagination par curseur : aucune ligne perdue ni répétée ; les nouveautés par after_id', async () => {
    const p1 = await queries('?limit=3'); expect(p1.items).toHaveLength(3); expect(p1.nextBefore).toBe(p1.items[2].id)
    const p2 = await queries(`?limit=3&before_id=${p1.nextBefore}`); const p3 = await queries(`?limit=3&before_id=${p2.nextBefore}`)
    const ids = [...p1.items, ...p2.items, ...p3.items].map((x: any) => x.id)
    expect(ids).toHaveLength(7); expect(new Set(ids).size).toBe(7); expect(ids).toEqual([...ids].sort((a, b) => b - a)); expect(p3.nextBefore).toBeNull()
    const last = p1.items[0].id; await admin.post('/api/filter/ingest-log', { content: Q('10.0.0.8', 'nouveau.example.com') })
    expect((await queries(`?after_id=${last}`)).items.map((x: any) => x.domain)).toEqual(['nouveau.example.com'])
    await db.query("delete from dns_queries where domain = 'nouveau.example.com'")
  })
})

describe('actions en un clic : liste blanche et noire', () => {
  it('droits ; domaine invalide', async () => {
    code(await viewer.post('/api/cockpit/action', { domain: 'x.example.com', action: 'allow' }), 403, 'forbidden')
    code(await operator.post('/api/cockpit/action', { domain: 'pas un domaine !', action: 'allow' }), 400, 'domain'); code(await operator.post('/api/cockpit/action', { domain: 'x.example.com', action: 'peut-etre' }), 400, 'validation')
  })
  it('« autoriser » un domaine bloqué par une liste ; « bloquer » remplace une autorisation ; idempotent ; retrait', async () => {
    let r = (await operator.post('/api/cockpit/action', { domain: 'ADS.example.net', action: 'allow' })).json
    expect(r).toMatchObject({ ok: true, domain: 'ads.example.net', result: 'created' })
    expect((await admin.get('/api/filter/check?domain=sub.ads.example.net')).json).toMatchObject({ blocked: false, reason: 'allow_rule' })
    r = (await operator.post('/api/cockpit/action', { domain: 'ok.example.net', action: 'block' })).json; expect(r.result).toBe('replaced')
    expect((await rows("select action from filter_rules where domain = 'ok.example.net'")).map((x) => x.action)).toEqual(['block'])
    expect((await operator.post('/api/cockpit/action', { domain: 'ok.example.net', action: 'block' })).json.result).toBe('exists')
    expect((await operator.post('/api/cockpit/action', { domain: 'ok.example.net', action: 'remove' })).json.result).toBe('removed'); expect((await operator.post('/api/cockpit/action', { domain: 'ok.example.net', action: 'remove' })).json.result).toBe('absent')
    expect((await rows("select action from audit_log where action = 'cockpit_action'")).length).toBeGreaterThanOrEqual(5)
  })
  it('ajout en masse : doublons et lignes invalides comptés, remplacement signalé', async () => {
    const d = ['a.example.com', 'b.example.com', 'b.example.com', 'pas valide !', 'c.example.com']
    expect((await operator.post('/api/filter/rules/bulk', { domains: d, action: 'block' })).json).toEqual({ added: 3, replaced: 0, existing: 0, invalid: 1 })
    expect((await operator.post('/api/filter/rules/bulk', { domains: d, action: 'block' })).json).toEqual({ added: 0, replaced: 0, existing: 3, invalid: 1 })
    expect((await operator.post('/api/filter/rules/bulk', { domains: ['a.example.com'], action: 'allow' })).json).toMatchObject({ added: 0, replaced: 1 })
    code(await viewer.post('/api/filter/rules/bulk', { domains: ['x.example.com'], action: 'block' }), 403, 'forbidden'); code(await operator.post('/api/filter/rules/bulk', { domains: [], action: 'block' }), 400, 'validation')
  })
  it('modifications en attente : comptées, puis remises à zéro par un déploiement validé', async () => {
    expect((await admin.get('/api/cockpit/summary')).json.pending).toBeGreaterThanOrEqual(5)
    const r = (await admin.post('/api/system/apply', { deploy: true })).json; expect(r).toMatchObject({ ok: true, deployed: true })
    expect((await admin.get('/api/cockpit/summary')).json.pending).toBe(0)
    expect(readFileSync(join(GEN, 'zones/db.rpz'), 'utf8')).toContain('b.example.com')   // la règle est bien dans la zone RPZ déployée
  })
})

describe('pause du blocage', () => {
  const opts = () => readFileSync(join(GEN, 'named.conf.options'), 'utf8')
  it('réservée aux administrateurs ; durée bornée', async () => {
    code(await operator.post('/api/cockpit/pause', { minutes: 5 }), 403, 'forbidden'); code(await admin.post('/api/cockpit/pause', { minutes: 5000 }), 400, 'validation'); code(await admin.post('/api/cockpit/pause', { minutes: -1 }), 400, 'validation')
  })
  it('pause : le RPZ est retiré ET déployé ; reprise : il revient', async () => {
    expect(opts()).toContain('response-policy')
    const r = (await admin.post('/api/cockpit/pause', { minutes: 5 })).json; expect(r).toMatchObject({ ok: true, blocking: false }); expect(Date.parse(r.until) - Date.now()).toBeGreaterThan(4 * 60_000)
    expect(opts()).not.toContain('response-policy'); expect((await admin.get('/api/filter/settings')).json.rpzEnabled).toBe(false)
    expect((await admin.get('/api/cockpit/summary')).json.blocking).toMatchObject({ enabled: false, pausedUntil: r.until })
    expect((await admin.post('/api/cockpit/pause', { minutes: 0 })).json).toMatchObject({ ok: true, blocking: true })
    expect(opts()).toContain('response-policy'); expect((await admin.get('/api/cockpit/summary')).json.blocking).toEqual({ enabled: true, pausedUntil: null })
  })
  it('fin de pause : le blocage est rétabli SEUL (lecture périodique du serveur)', async () => {
    await admin.post('/api/cockpit/pause', { minutes: 5 })
    await db.query("update settings set value = jsonb_build_object('until', (now() - interval '1 minute'), 'by', 'admin') where key = 'cockpit_pause'")
    await until(async () => opts().includes('response-policy'), 15000)    // on attend le fichier DÉPLOYÉ, pas seulement le réglage
    await until(async () => (await rows("select value from settings where key = 'cockpit_pause'"))[0].value === null, 5000)
    expect((await admin.get('/api/filter/settings')).json.rpzEnabled).toBe(true); expect((await admin.get('/api/cockpit/summary')).json.blocking).toEqual({ enabled: true, pausedUntil: null })
  })
  it('blocage coupé dans les réglages (sans pause) : la pause est refusée', async () => {
    await admin.put('/api/filter/settings', { rpzEnabled: false, rpzAction: 'nxdomain', sinkhole4: '0.0.0.0', sinkhole6: '::' })
    code(await admin.post('/api/cockpit/pause', { minutes: 5 }), 409, 'blocking_disabled')
    await admin.put('/api/filter/settings', { rpzEnabled: true, rpzAction: 'nxdomain', sinkhole4: '0.0.0.0', sinkhole6: '::' })
  })
})

describe('lecture automatique du fichier journal de BIND', () => {
  it('nouvelles lignes ingérées sans action de l\'utilisateur, une seule fois', async () => {
    appendFileSync(LOG, `${Q('10.1.1.1', 'tailed.example.com')}\n${Q('10.1.1.1', 'tailed.example.com')}\n${RPZ('10.1.1.1', 'tailed.example.com')}\n`)
    await until(async () => (await queries('?domain=tailed.example.com')).items.length === 2)
    await sleep(800); expect((await queries('?domain=tailed.example.com')).items).toHaveLength(2)   // pas de doublon aux passages suivants
    expect((await rows("select (value->>'off')::int as off from settings where key = 'querylog_pos'"))[0].off).toBeGreaterThan(0)
  })
  it('ligne incomplète : attendue (jamais coupée en deux)', async () => {
    const full = Q('10.1.1.2', 'partial.example.com')
    appendFileSync(LOG, full.slice(0, 60)); await sleep(1000); expect((await queries('?domain=partial.example.com')).items).toHaveLength(0)
    appendFileSync(LOG, full.slice(60) + '\n'); await until(async () => (await queries('?domain=partial.example.com')).items.length === 1)
    expect((await queries('?domain=partial.example.com')).items[0].client).toBe('10.1.1.2')
  })
  it('rotation du fichier : le nouveau fichier est lu depuis son début, l\'ancien n\'est pas relu', async () => {
    renameSync(LOG, LOG + '.1'); writeFileSync(LOG, `${Q('10.1.1.3', 'rotated.example.com')}\n`)
    await until(async () => (await queries('?domain=rotated.example.com')).items.length === 1)
    await sleep(800); expect((await queries('?domain=tailed.example.com')).items).toHaveLength(2)
  })
})

describe('confidentialité : conservation, anonymisation, purge', () => {
  it('réglages : valeurs par défaut, administrateur seul, bornes', async () => {
    expect((await viewer.get('/api/cockpit/settings')).json).toEqual({ retentionDays: 7, anonymize: 'none', autoDeploy: false, queryLog: true })
    code(await operator.put('/api/cockpit/settings', { retentionDays: 7, anonymize: 'none', autoDeploy: false }), 403, 'forbidden'); code(await admin.put('/api/cockpit/settings', { retentionDays: 91, anonymize: 'none', autoDeploy: false }), 400, 'validation')
    code(await admin.put('/api/cockpit/settings', { retentionDays: 7, anonymize: 'chiffre', autoDeploy: false }), 400, 'validation')
  })
  it('anonymisation : le dernier octet n\'est jamais stocké', async () => {
    await admin.put('/api/cockpit/settings', { retentionDays: 7, anonymize: 'mask', autoDeploy: false })
    await admin.post('/api/filter/ingest-log', { content: Q('192.168.7.9', 'masque.example.com') })
    expect((await rows("select client from dns_queries where domain = 'masque.example.com'"))[0].client).toBe('192.168.7.0')
  })
  it('conservation : réduire supprime les anciennes lignes ; 0 = rien n\'est stocké (les statistiques continuent)', async () => {
    await db.query("insert into dns_queries (at, client, domain, qtype, status) values (now() - interval '3 days', '10.9.9.9', 'vieux.example.com', 'A', 'allowed')")
    await admin.put('/api/cockpit/settings', { retentionDays: 1, anonymize: 'none', autoDeploy: false })
    expect((await rows("select count(*)::int n from dns_queries where domain = 'vieux.example.com'"))[0].n).toBe(0)
    const before = (await rows("select coalesce(sum(count),0)::int n from dns_stats where kind = 'query'"))[0].n
    await admin.put('/api/cockpit/settings', { retentionDays: 0, anonymize: 'none', autoDeploy: false })
    expect((await rows('select count(*)::int n from dns_queries'))[0].n).toBe(0)
    expect((await admin.post('/api/filter/ingest-log', { content: Q('10.2.2.2', 'zero.example.com') })).json).toMatchObject({ events: 1, stored: 0 })
    expect((await rows("select coalesce(sum(count),0)::int n from dns_stats where kind = 'query'"))[0].n).toBe(before + 1)
    await admin.put('/api/cockpit/settings', { retentionDays: 7, anonymize: 'none', autoDeploy: false })
  })
  it('purge : administrateur seul ; efface tout l\'historique', async () => {
    await admin.post('/api/filter/ingest-log', { content: Q('10.2.2.3', 'purge.example.com') })
    code(await operator.post('/api/cockpit/purge', {}), 403, 'forbidden')
    expect((await admin.post('/api/cockpit/purge', {})).json.deleted).toBeGreaterThanOrEqual(1); expect((await queries()).items).toHaveLength(0)
  })
})

describe('déploiement automatique (option)', () => {
  it('désactivé par défaut ; activé : une règle ajoutée est déployée SEULE, puis plus rien en attente', async () => {
    const n0 = (await rows('select count(*)::int n from deployments'))[0].n
    await operator.post('/api/cockpit/action', { domain: 'pas-auto.example.com', action: 'block' }); await sleep(4500)
    expect((await rows('select count(*)::int n from deployments'))[0].n).toBe(n0)       // défaut : aucun déploiement sans demande
    await admin.put('/api/cockpit/settings', { retentionDays: 7, anonymize: 'none', autoDeploy: true })
    await operator.post('/api/cockpit/action', { domain: 'auto.example.com', action: 'block' })
    await until(async () => (await rows('select count(*)::int n from deployments'))[0].n > n0, 15000)
    expect((await rows('select username, ok from deployments order by id desc limit 1'))[0]).toEqual({ username: 'cockpit (déploiement automatique)', ok: true })
    expect((await admin.get('/api/cockpit/summary')).json).toMatchObject({ pending: 0, autoDeploy: true }); expect(readFileSync(join(GEN, 'zones/db.rpz'), 'utf8')).toContain('auto.example.com')
    await admin.put('/api/cockpit/settings', { retentionDays: 7, anonymize: 'none', autoDeploy: false })
  })
})
