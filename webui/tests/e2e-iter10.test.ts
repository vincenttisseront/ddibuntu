// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : alertes et supervision — règles, cycle de vie, silences, notifications (faux webhook, faux SMTP STARTTLS),
// export Prometheus à jeton, tableau de bord. L'état du cluster, la santé des nœuds et des sauvegardes sont des fichiers que root publie : le test les écrit.
import { spawn, type ChildProcess } from 'node:child_process'
import { createHmac } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { decode, startFakeSmtp, subjectOf } from './helpers/fake-smtp'

const PORT = 3393, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s11-')); mkdirSync(join(TMP, 'gen'))
const CL = join(TMP, 'cluster-status.json'), HL = join(TMP, 'health.json'), BK = join(TMP, 'bk-status.json'), BR = join(TMP, 'bk-result.json')
let srv: ChildProcess, db: pg.Client, srvLog = ''

class Client {
  cookie = ''; csrf = ''; lang = ''
  async req(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
    const h: Record<string, string> = { cookie: this.cookie + (this.lang ? `; ddi_lang=${this.lang}` : ''), ...headers }
    if (body !== undefined) h['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) h['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* HTML ou texte */ }
    return { status: r.status, json, text, headers: r.headers }
  }
  get = (p: string, h?: Record<string, string>) => this.req('GET', p, undefined, h); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b); del = (p: string) => this.req('DELETE', p, undefined)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
const admin = new Client(), viewer = new Client(), operator = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 250)) } throw new Error('délai dépassé') }

// ---- faux webhook : enregistre les requêtes ; le code de réponse se règle
const hooks: Array<{ headers: http.IncomingHttpHeaders; body: any; raw: string }> = []
let hookStatus = 200
const hookServer = http.createServer((req, res) => { let raw = ''; req.on('data', (d) => { raw += d }); req.on('end', () => { try { hooks.push({ headers: req.headers, body: JSON.parse(raw), raw }) } catch { /* ignoré */ } res.statusCode = hookStatus; res.end('ok') }) })
let hookPort = 0
let smtp: Awaited<ReturnType<typeof startFakeSmtp>>

const now = () => Math.floor(Date.now() / 1000)
const hlth = (node: string, over: Record<string, unknown> = {}) => ({
  at: now() - 5, node, cluster: 'lab', role: 'data', hostname: node, uptimeSeconds: 9000, load1: 0.3, memory: { totalKb: 8_000_000, availKb: 6_000_000 },
  services: [{ name: 'console', state: 'active', expected: true }, { name: 'dns', state: 'active', expected: true }, { name: 'patroni', state: 'active', expected: true }],
  postgres: true, disks: [{ mount: '/', sizeBytes: 100e9, availBytes: 70e9 }], certs: [{ name: 'console', notAfter: now() + 300 * 86400 }], timeSynced: true, ...over })
const members = (over: Record<string, unknown> = {}) => [
  { name: 'n1', ip: '10.9.0.1', role: 'data', reachable: true, healthy: true, learner: false, isLeader: true, version: '3.5', raftIndex: 9, raftTerm: 2, dbSize: 1, latencyMs: 1 },
  { name: 'n2', ip: '10.9.0.2', role: 'data', reachable: true, healthy: true, learner: false, isLeader: false, version: '3.5', raftIndex: 9, raftTerm: 2, dbSize: 1, latencyMs: 1, ...over },
  { name: 'n3', ip: '10.9.0.3', role: 'witness', reachable: true, healthy: true, learner: false, isLeader: false, version: '3.5', raftIndex: 9, raftTerm: 2, dbSize: 1, latencyMs: 1 }]
const cluster = (o: { leader?: string; quorum?: boolean; tolerance?: number; healthy?: number; at?: number; n2?: Record<string, unknown>; health?: Record<string, unknown> } = {}) => ({
  cluster: 'lab', node: 'n1', role: 'data', local_role: 'leader', at: o.at ?? now() - 3, bind: 'primary',
  etcd: { healthy: true, members: 3, quorum: { voters: 3, needed: 2, healthy: o.healthy ?? 3, hasQuorum: o.quorum ?? true, tolerance: o.tolerance ?? 1, leader: 'n1', members: members() } },
  peers: [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }],
  patroni: { members: [{ name: 'n1', role: (o.leader ?? 'n1') === 'n1' ? 'leader' : 'replica', state: 'running' }, { name: 'n2', role: (o.leader ?? 'n1') === 'n2' ? 'leader' : 'replica', state: 'streaming', lag: 512 }] },
  vip: { address: '192.0.2.10/24', iface: 'ens192', held: true },
  health: o.health ?? { n1: hlth('n1'), n2: hlth('n2', o.n2 ?? {}), n3: hlth('n3', { role: 'witness', services: [{ name: 'etcd', state: 'active', expected: true }], postgres: null }) } })
const publish = (o?: Parameters<typeof cluster>[0]) => writeFileSync(CL, JSON.stringify(cluster(o)))
const evaluate = async () => { const r = await admin.post('/api/alerts/evaluate'); expect(r.status, r.text).toBe(200); return r.json }
const alerts = async () => (await admin.get('/api/alerts')).json
const keys = async () => (await alerts()).active.map((a: any) => `${a.rule}|${a.node}|${a.subject}`).sort()
const cfgBody = (over: Record<string, any> = {}) => ({
  minSeverity: 'warning', repeatHours: 0, lang: 'fr',
  thresholds: { diskWarn: 85, diskCrit: 95, certWarnDays: 30, certCritDays: 7, lagMiB: 64, backupMaxAgeHours: 0, subnetWarn: 90, subnetCrit: 98 },
  webhook: { enabled: false, url: '' }, email: { enabled: false, host: '', port: 587, security: 'starttls', verifyCert: true, user: '', from: '', to: [] }, ...over })

beforeAll(async () => {
  await new Promise<void>((r) => hookServer.listen(0, '127.0.0.1', r)); hookPort = (hookServer.address() as any).port
  smtp = await startFakeSmtp({ starttls: true, auth: { user: 'robot', pass: 'Mot-de-passe-SMTP-42' } })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  await boot(0)
}, 120000)
async function boot(interval: number) {
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RELOAD_STATUS: join(TMP, 'rs'),
    DDI_CLUSTER_STATUS: CL, DDI_HEALTH_STATUS: HL, DDI_BACKUP_STATUS: BK, DDI_BACKUP_RESULT: BR, DDI_BACKUP_RESTORE: join(TMP, 'bk-restore.json'),
    DDI_ALERT_INTERVAL_MS: String(interval), DDI_ALERT_RESOLVE_MISSES: '1' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  if (interval === 0) {
    const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
    expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  }
  expect((await admin.login('admin', PW)).status).toBe(200)
  if (interval === 0) {
    expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
    expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  }
  expect((await viewer.login('lect', PW)).status).toBe(200); expect((await operator.login('oper', PW)).status).toBe(200)
}
afterAll(async () => { srv?.kill('SIGTERM'); hookServer.close(); await smtp?.close(); await db?.end() })

describe('droits et état initial', () => {
  it('opérateur : alertes ; administrateur : réglages ; lecteur et anonyme : rien', async () => {
    expect((await operator.get('/api/alerts')).status).toBe(200); code(await viewer.get('/api/alerts'), 403, 'forbidden'); code(await anon.get('/api/alerts'), 401, 'unauthenticated')
    code(await operator.get('/api/alerts/config'), 403, 'forbidden'); expect((await admin.get('/api/alerts/config')).status).toBe(200)
    code(await operator.put('/api/alerts/config', cfgBody()), 403, 'forbidden'); code(await operator.post('/api/alerts/metrics-token'), 403, 'forbidden'); code(await viewer.post('/api/alerts/evaluate'), 403, 'forbidden')
    code(await viewer.post('/api/alerts/silences', { hours: 1 }), 403, 'forbidden')
  })
  it('rien de publié (serveur neuf) : aucune alerte inventée', async () => {
    rmSync(CL, { force: true }); rmSync(HL, { force: true }); rmSync(BK, { force: true })
    const r = await evaluate(); expect(r).toMatchObject({ ok: true, findings: 0 }); expect(await keys()).toEqual([])
    const a = await alerts(); expect(a.summary).toEqual({ critical: 0, warning: 0, info: 0, silenced: 0 }); expect(a.engine.runsHere).toBe(true); expect(a.rules.length).toBeGreaterThan(15)
  })
  it('réglages par défaut : aucun canal, rien de secret', async () => {
    const c = (await admin.get('/api/alerts/config')).json
    expect(c).toMatchObject({ minSeverity: 'warning', repeatHours: 0, lang: 'fr', metricsToken: false, webhook: { enabled: false, hasSecret: false }, email: { enabled: false, hasPassword: false } })
    expect(c.thresholds).toMatchObject({ diskWarn: 85, diskCrit: 95, certWarnDays: 30, certCritDays: 7, subnetWarn: 90, subnetCrit: 98 })
  })
})

describe('cycle de vie : ouverture, aggravation, résolution', () => {
  it('cluster sain : aucune alerte', async () => { publish(); await evaluate(); expect(await keys()).toEqual([]) })
  it('quorum perdu et service DNS arrêté sur n2 : deux alertes critiques', async () => {
    publish({ quorum: false, healthy: 1, tolerance: 0, n2: { services: [{ name: 'dns', state: 'failed', expected: true }] } })
    const r = await evaluate(); expect(r.opened).toBeGreaterThanOrEqual(2)
    expect(await keys()).toEqual(expect.arrayContaining(['cluster.quorum_lost||', 'node.service_down|n2|dns']))
    const a = await alerts(); expect(a.active.find((x: any) => x.rule === 'cluster.quorum_lost')).toMatchObject({ severity: 'critical', silenced: false, params: { healthy: 1, needed: 2, voters: 3 } })
    expect(a.summary.critical).toBeGreaterThanOrEqual(2)
  })
  it('une alerte déjà ouverte n’est pas dupliquée', async () => {
    const before = (await alerts()).active.length; await evaluate(); await evaluate(); expect((await alerts()).active.length).toBe(before)
    const { rows } = await db.query("select count(*)::int as n from alert_events where key = 'cluster.quorum_lost||' and state = 'firing'"); expect(rows[0].n).toBe(1)
  })
  it('retour à la normale : résolues d’elles-mêmes, conservées dans l’historique', async () => {
    publish(); const r = await evaluate(); expect(r.resolved).toBeGreaterThanOrEqual(2); expect(await keys()).toEqual([])
    const h = (await alerts()).history.map((x: any) => x.rule); expect(h).toEqual(expect.arrayContaining(['cluster.quorum_lost', 'node.service_down']))
  })
  it('bascule de leader : événement d’information, première observation sans alerte', async () => {
    publish({ leader: 'n1' }); await evaluate(); expect(await keys()).toEqual([])
    publish({ leader: 'n2' }); await evaluate()
    const a = (await alerts()).active.find((x: any) => x.rule === 'cluster.leader_changed'); expect(a).toMatchObject({ severity: 'info', node: 'n2', params: { from: 'n1', to: 'n2' } })
    publish({ leader: 'n1' }); await evaluate()
    // l'événement reste actif une heure (c'est voulu) : on le retire pour ne pas gêner la suite
    await db.query("delete from alert_events where rule = 'cluster.leader_changed'"); await db.query("update settings set value = '{\"leader\":\"n1\",\"leaderChangedAt\":null}'::jsonb where key = 'alert_memory'")
  })
  it('état du cluster périmé : une seule alerte critique, pas de faux constats', async () => {
    publish({ at: now() - 900, quorum: false }); await evaluate()
    expect((await keys()).filter((k: string) => k.startsWith('cluster.'))).toEqual(['cluster.state_stale|n1|'])
    publish(); await evaluate(); expect(await keys()).toEqual([])
  })
  it('nœud silencieux (santé périmée relayée par etcd) : critique ; l’arbitre : avertissement', async () => {
    publish({ health: { n1: hlth('n1'), n2: hlth('n2', { at: now() - 700 }), n3: hlth('n3', { role: 'witness', at: now() - 700, services: [], postgres: null }) } }); await evaluate()
    const a = (await alerts()).active.filter((x: any) => x.rule === 'node.health_stale'); expect(a.map((x: any) => [x.node, x.severity]).sort()).toEqual([['n2', 'critical'], ['n3', 'warning']])
    publish(); await evaluate(); expect(await keys()).toEqual([])
  })
  it('santé locale illisible ou hostile : ignorée, aucune erreur', async () => {
    writeFileSync(HL, '{pas du json'); const r = await evaluate(); expect(r.ok).toBe(true)
    writeFileSync(HL, JSON.stringify({ node: '<img onerror=1>', services: 7 })); expect((await evaluate()).ok).toBe(true)
    rmSync(HL, { force: true })
  })
  it('sauvegardes : archivage en échec = critique ; sous-réseau presque plein = avertissement (base réelle)', async () => {
    writeFileSync(BK, JSON.stringify({ at: now() - 30, enabled: true, role: 'primary', node: 'n1', hostname: 'h', cluster: 'lab', repo: '/r', keepFull: 3, intervalHours: 24, startHour: 2, mirrorDir: null, archiveMode: 'on',
      archiver: { archived_count: 5, last_archived_wal: 'A', last_archived_at: now() - 900, failed_count: 4, last_failed_wal: '00000001000000000000000B', last_failed_at: now() - 20 },
      diskFreeBytes: 1e9, preRestoreDirs: 0, walFiles: 1, walBytes: 1, lastWalAt: now(), pitrFrom: now() - 7200,
      backups: [{ id: '20261111T080000Z', node: 'n1', startedAt: now() - 400, finishedAt: now() - 300, sizeBytes: 5, timeline: 1, walArchived: true }] }))
    const s = await db.query("insert into subnets (cidr, name) values ('10.50.0.0/24', 'Serveurs') returning id")
    await db.query("insert into addresses (subnet_id, ip, status) select $1, ('10.50.0.0'::inet + g), 'used' from generate_series(1, 240) g", [s.rows[0].id])
    await evaluate()
    const a = (await alerts()).active
    expect(a.find((x: any) => x.rule === 'backup.archiver_failing')).toMatchObject({ severity: 'critical', params: { failed: 4, wal: '00000001000000000000000B' } })
    expect(a.find((x: any) => x.rule === 'ipam.subnet_full')).toMatchObject({ severity: 'warning', subject: '10.50.0.0/24', params: { used: 240, capacity: 254 } })
    rmSync(BK); await db.query('delete from subnets'); await evaluate(); expect(await keys()).toEqual([])
  })
})

describe('silences', () => {
  it('validation : règle inconnue, durée hors bornes, champs inconnus', async () => {
    code(await operator.post('/api/alerts/silences', { rule: 'inconnue', hours: 1 }), 400, 'validation')
    code(await operator.post('/api/alerts/silences', { hours: 0 }), 400, 'validation'); code(await operator.post('/api/alerts/silences', { hours: 9999 }), 400, 'validation')
    code(await operator.post('/api/alerts/silences', { hours: 1, extra: 1 }), 400, 'validation'); code(await operator.post('/api/alerts/silences', { hours: 1, node: 'N X!' }), 400, 'validation')
  })
  it('une alerte réduite au silence reste visible mais n’est plus comptée ; levée, elle l’est de nouveau', async () => {
    publish({ n2: { services: [{ name: 'dns', state: 'failed', expected: true }] } }); await evaluate()
    const s = await operator.post('/api/alerts/silences', { rule: 'node.service_down', node: 'n2', hours: 2, comment: 'maintenance' }); expect(s.status).toBe(200)
    let a = await alerts(); expect(a.active.find((x: any) => x.rule === 'node.service_down')).toMatchObject({ silenced: true }); expect(a.summary).toMatchObject({ critical: 0, silenced: 1 })
    expect(a.silences[0]).toMatchObject({ rule: 'node.service_down', node: 'n2', subject: null, comment: 'maintenance', created_by: 'oper' })
    expect((await admin.get('/api/dashboard')).json.alerts.summary).toMatchObject({ critical: 0, silenced: 1 })
    expect((await operator.del(`/api/alerts/silences/${s.json.id}`)).status).toBe(200); code(await operator.del(`/api/alerts/silences/${s.json.id}`), 404, 'not_found')
    a = await alerts(); expect(a.summary.critical).toBe(1); expect(a.silences).toEqual([])
    publish(); await evaluate()
  })
})

describe('réglages et canaux', () => {
  it('refus : adresse de webhook piégée, métadonnées des nuages, authentification en clair, seuils incohérents, champs inconnus', async () => {
    code(await admin.put('/api/alerts/config', cfgBody({ webhook: { enabled: true, url: 'ftp://x/y' } })), 400, 'webhook_url_invalid')
    code(await admin.put('/api/alerts/config', cfgBody({ webhook: { enabled: true, url: 'http://169.254.169.254/latest' } })), 400, 'webhook_url_forbidden')
    code(await admin.put('/api/alerts/config', cfgBody({ webhook: { enabled: true, url: 'https://u:p@example.com/' } })), 400, 'webhook_url_credentials')
    code(await admin.put('/api/alerts/config', cfgBody({ email: { enabled: true, host: 'smtp.example.com', port: 25, security: 'none', verifyCert: true, user: 'u', from: 'a@example.com', to: ['b@example.com'] } })), 400, 'email_auth_requires_tls')
    code(await admin.put('/api/alerts/config', cfgBody({ email: { enabled: true, host: 'smtp.example.com', port: 25, security: 'tls', verifyCert: true, user: '', from: 'pas-une-adresse', to: ['b@example.com'] } })), 400, 'email_from_invalid')
    code(await admin.put('/api/alerts/config', cfgBody({ thresholds: { diskWarn: 90, diskCrit: 80, certWarnDays: 30, certCritDays: 7, lagMiB: 64, backupMaxAgeHours: 0, subnetWarn: 90, subnetCrit: 98 } })), 400, 'validation')
    code(await admin.put('/api/alerts/config', { ...cfgBody(), extra: 1 }), 400, 'validation')
    code(await admin.post('/api/alerts/test/webhook'), 409, 'channel_disabled'); code(await admin.post('/api/alerts/test/email'), 409, 'channel_disabled'); code(await admin.post('/api/alerts/test/sms'), 404, 'not_found')
  })
  it('webhook : enregistré (secret chiffré, jamais renvoyé), essai réussi, signature HMAC valide', async () => {
    const url = `http://127.0.0.1:${hookPort}/hook`
    const r = await admin.put('/api/alerts/config', cfgBody({ webhook: { enabled: true, url, secret: 'secret-de-signature-123' } })); expect(r.status, r.text).toBe(200)
    expect(r.json.webhook).toEqual({ enabled: true, url, hasSecret: true }); expect(JSON.stringify(r.json)).not.toContain('secret-de-signature')
    const { rows } = await db.query("select value::text as v from settings where key = 'alerts_config'"); expect(rows[0].v).not.toContain('secret-de-signature-123'); expect(rows[0].v).toContain('"secretEnc"')
    hooks.length = 0; const t = await admin.post('/api/alerts/test/webhook'); expect(t.json).toMatchObject({ channel: 'webhook', ok: true, detail: 'http 200' })
    expect(hooks).toHaveLength(1); expect(hooks[0]!.body).toMatchObject({ version: 1, source: 'ddibuntu', kind: 'test' }); expect(hooks[0]!.body.text).toContain('[TEST]')
    expect(hooks[0]!.headers['x-ddibuntu-signature']).toBe('sha256=' + createHmac('sha256', 'secret-de-signature-123').update(hooks[0]!.raw).digest('hex'))
    // sans nouveau secret fourni, l'ancien est conservé ; avec null il est supprimé
    await admin.put('/api/alerts/config', cfgBody({ webhook: { enabled: true, url } })); expect((await admin.get('/api/alerts/config')).json.webhook.hasSecret).toBe(true)
    await admin.put('/api/alerts/config', cfgBody({ webhook: { enabled: true, url, secret: null } })); expect((await admin.get('/api/alerts/config')).json.webhook.hasSecret).toBe(false)
  })
  it('journal d’audit : la modification est tracée SANS adresse ni secret', async () => {
    const log = (await admin.get('/api/audit')).json; const rows = (log.items ?? log).filter((r: any) => r.action === 'alerts.configure')
    expect(rows.length).toBeGreaterThan(0); const det = JSON.stringify(rows.map((r: any) => r.detail)); expect(det).not.toContain('127.0.0.1'); expect(det).not.toContain('/hook'); expect(det).not.toContain('secret-de-signature')
  })
  it('ouverture puis résolution notifiées (une fois chacune), texte français', async () => {
    hooks.length = 0
    publish({ quorum: false, healthy: 1, tolerance: 0 }); const r = await evaluate(); expect(r.notified).toBeGreaterThanOrEqual(1)
    const opened = hooks.filter((h) => h.body.kind === 'firing'); expect(opened.length).toBeGreaterThanOrEqual(1)
    const q = opened.find((h) => h.body.alert.rule === 'cluster.quorum_lost')!
    expect(q.body.alert).toMatchObject({ severity: 'critical', params: { healthy: 1, needed: 2, voters: 3 } }); expect(q.body.text).toContain('[CRITIQUE] lab'); expect(q.body.text).toContain('Quorum etcd PERDU'); expect(q.body.alert.resolvedAt).toBeNull()
    const n = hooks.length; await evaluate(); await evaluate(); expect(hooks.length).toBe(n)   // pas de doublon tant que l'alerte est ouverte
    publish(); await evaluate()
    const res = hooks.filter((h) => h.body.kind === 'resolved'); expect(res.some((h) => h.body.alert.rule === 'cluster.quorum_lost' && h.body.alert.resolvedAt)).toBe(true)
    const d = (await alerts()).deliveries; expect(d.length).toBeGreaterThan(0); expect(d.every((x: any) => x.ok)).toBe(true)
  })
  it('gravité minimale : un avertissement n’est pas notifié si le seuil est « critique »', async () => {
    const url = `http://127.0.0.1:${hookPort}/hook`
    await admin.put('/api/alerts/config', cfgBody({ minSeverity: 'critical', webhook: { enabled: true, url } })); hooks.length = 0
    publish({ quorum: true, tolerance: 0, healthy: 2 }); await evaluate()   // marge nulle : avertissement
    expect(await keys()).toContain('cluster.quorum_margin||'); expect(hooks).toHaveLength(0)
    publish({ quorum: false, healthy: 1, tolerance: 0 }); await evaluate(); expect(hooks.some((h) => h.body.alert.rule === 'cluster.quorum_lost')).toBe(true)
    expect(hooks.some((h) => h.body.alert.rule === 'cluster.quorum_margin')).toBe(false)
    publish(); await evaluate()
    await admin.put('/api/alerts/config', cfgBody({ webhook: { enabled: true, url } }))
  })
  it('silence : aucune notification ; levée alors que le problème dure, l’alerte est notifiée', async () => {
    hooks.length = 0
    const s = await operator.post('/api/alerts/silences', { rule: 'node.postgres_down', hours: 1 })
    publish({ n2: { postgres: false } }); await evaluate(); expect(await keys()).toContain('node.postgres_down|n2|'); expect(hooks).toHaveLength(0)
    await operator.del(`/api/alerts/silences/${s.json.id}`); await evaluate(); expect(hooks.some((h) => h.body.kind === 'firing' && h.body.alert.rule === 'node.postgres_down')).toBe(true)
    publish(); await evaluate()
  })
  it('rappel : un problème durable est rappelé après l’intervalle choisi', async () => {
    const url = `http://127.0.0.1:${hookPort}/hook`
    await admin.put('/api/alerts/config', cfgBody({ repeatHours: 1, webhook: { enabled: true, url } }))
    publish({ n2: { timeSynced: false } }); await evaluate(); hooks.length = 0; await evaluate(); expect(hooks).toHaveLength(0)
    await db.query("update alert_events set notified_at = now() - interval '2 hours' where state = 'firing' and rule = 'node.time_unsynced'"); await evaluate()
    expect(hooks.filter((h) => h.body.kind === 'repeat' && h.body.alert.rule === 'node.time_unsynced')).toHaveLength(1)
    publish(); await evaluate(); await admin.put('/api/alerts/config', cfgBody({ webhook: { enabled: true, url } }))
  })
  it('webhook en échec : échec journalisé, nouvelle tentative à l’évaluation suivante, abandon après 5 essais', async () => {
    hookStatus = 500; hooks.length = 0
    publish({ n2: { memory: { totalKb: 1000, availKb: 10 } } })
    for (let i = 0; i < 7; i++) await evaluate()
    const d = (await alerts()).deliveries.filter((x: any) => !x.ok); expect(d.length).toBe(5); expect(d[0].detail).toBe('http 500')
    const { rows } = await db.query("select notified_at, notify_attempts from alert_events where state = 'firing' and rule = 'node.memory_low'"); expect(rows[0]).toMatchObject({ notified_at: null, notify_attempts: 5 })
    hookStatus = 200; publish(); await evaluate()
  })
  it('anglais : texte des notifications dans la langue choisie', async () => {
    const url = `http://127.0.0.1:${hookPort}/hook`
    await admin.put('/api/alerts/config', cfgBody({ lang: 'en', webhook: { enabled: true, url } })); hooks.length = 0
    publish({ quorum: false, healthy: 1, tolerance: 0 }); await evaluate()
    const q = hooks.find((h) => h.body.alert.rule === 'cluster.quorum_lost')!; expect(q.body.text).toContain('[CRITICAL] lab'); expect(q.body.text).toContain('etcd quorum LOST')
    publish(); await evaluate(); await admin.put('/api/alerts/config', cfgBody({ webhook: { enabled: true, url } }))
  })
  it('e-mail : STARTTLS, certificat auto-signé accepté sur demande, authentification, alerte et résolution reçues ; mot de passe chiffré en base', async () => {
    const r = await admin.put('/api/alerts/config', cfgBody({ lang: 'en', email: { enabled: true, host: '127.0.0.1', port: smtp.port, security: 'starttls', verifyCert: false, user: 'robot', password: 'Mot-de-passe-SMTP-42', from: 'ddibuntu@example.com', to: ['ops@example.com', 'astreinte@example.com'] } }))
    expect(r.status, r.text).toBe(200); expect(r.json.email).toMatchObject({ enabled: true, hasPassword: true, user: 'robot', to: ['ops@example.com', 'astreinte@example.com'] }); expect(JSON.stringify(r.json)).not.toContain('Mot-de-passe-SMTP')
    const { rows } = await db.query("select value::text as v from settings where key = 'alerts_config'"); expect(rows[0].v).not.toContain('Mot-de-passe-SMTP-42')
    const t = await admin.post('/api/alerts/test/email'); expect(t.json).toMatchObject({ channel: 'email', ok: true }); expect(smtp.mails).toHaveLength(1); expect(smtp.mails[0]).toMatchObject({ secure: true, auth: 'robot:Mot-de-passe-SMTP-42', from: 'ddibuntu@example.com', to: ['ops@example.com', 'astreinte@example.com'] })
    expect(subjectOf(smtp.mails[0]!)).toContain('[TEST]')
    smtp.mails.length = 0
    publish({ quorum: false, healthy: 1, tolerance: 0 }); await evaluate()
    const m = smtp.mails.find((x) => subjectOf(x).includes('etcd quorum LOST') || subjectOf(x).includes('Quorum etcd PERDU'))!; expect(m).toBeDefined()
    expect(subjectOf(m)).toContain('[CRITICAL] lab'); expect(decode(m).body).toContain('cluster.quorum_lost')
    smtp.mails.length = 0; publish(); await evaluate(); expect(smtp.mails.some((x) => subjectOf(x).includes('RESOLVED'))).toBe(true)
  })
  it('e-mail : mauvais mot de passe = échec journalisé, jamais de fuite dans le détail', async () => {
    await admin.put('/api/alerts/config', cfgBody({ email: { enabled: true, host: '127.0.0.1', port: smtp.port, security: 'starttls', verifyCert: false, user: 'robot', password: 'faux-mot-de-passe', from: 'ddibuntu@example.com', to: ['ops@example.com'] } }))
    const t = await admin.post('/api/alerts/test/email'); expect(t.json.ok).toBe(false); expect(t.json.detail).toMatch(/smtp_535/); expect(t.text).not.toContain('faux-mot-de-passe')
    await admin.put('/api/alerts/config', cfgBody())
  })
})

describe('export Prometheus', () => {
  let token = ''
  it('sans jeton : fermé (anonyme, session, jeton absent ou mal formé, jeton dans l’adresse)', async () => {
    code(await anon.get('/api/metrics'), 401, 'unauthenticated'); code(await admin.get('/api/metrics'), 401, 'unauthenticated')
    code(await anon.get('/api/metrics', { authorization: 'Bearer ddm_' + 'a'.repeat(43) }), 401, 'unauthenticated'); code(await anon.get('/api/metrics', { authorization: 'Basic abc' }), 401, 'unauthenticated')
    code(await anon.get('/api/metrics?token=ddm_' + 'a'.repeat(43)), 401, 'unauthenticated')
  })
  it('création : le jeton n’est montré qu’une fois, seule son empreinte est en base', async () => {
    const r = await admin.post('/api/alerts/metrics-token'); expect(r.status).toBe(200); token = r.json.token; expect(token).toMatch(/^ddm_[A-Za-z0-9_-]{43}$/)
    expect((await admin.get('/api/alerts/config')).json.metricsToken).toBe(true)
    const { rows } = await db.query("select value::text as v from settings where key = 'metrics_token_hash'"); expect(rows[0].v).not.toContain(token); expect(rows[0].v).toMatch(/[0-9a-f]{64}/)
  })
  it('avec le jeton : texte Prometheus (cluster, quorum, santé des nœuds, alertes)', async () => {
    publish({ quorum: false, healthy: 1, tolerance: 0 }); await evaluate()
    const r = await anon.get('/api/metrics', { authorization: `Bearer ${token}` }); expect(r.status, r.text.slice(0, 300)).toBe(200)
    expect(r.headers.get('content-type')).toContain('text/plain'); expect(r.headers.get('cache-control')).toContain('no-store')
    for (const l of r.text.trim().split('\n')) expect(l).toMatch(/^(# (HELP|TYPE) [a-z0-9_]+ .+|[a-z0-9_]+(\{.*\})? -?\d+(\.\d+)?)$/)
    expect(r.text).toContain('ddibuntu_cluster_quorum 0'); expect(r.text).toContain('ddibuntu_cluster_is_leader{node="n1"} 1'); expect(r.text).toContain('ddibuntu_node_service_up{node="n2",service="dns",expected="true"} 1')
    expect(r.text).toMatch(/ddibuntu_alerts_firing\{severity="critical"\} [1-9]/); expect(r.text).toContain('ddibuntu_info{version=')
    publish(); await evaluate()
  })
  it('remplacement : l’ancien jeton cesse de fonctionner ; révocation : l’export se ferme', async () => {
    const old = token; token = (await admin.post('/api/alerts/metrics-token')).json.token; expect(token).not.toBe(old)
    code(await anon.get('/api/metrics', { authorization: `Bearer ${old}` }), 401, 'unauthenticated'); expect((await anon.get('/api/metrics', { authorization: `Bearer ${token}` })).status).toBe(200)
    expect((await admin.del('/api/alerts/metrics-token')).status).toBe(200); code(await anon.get('/api/metrics', { authorization: `Bearer ${token}` }), 401, 'unauthenticated')
    expect((await admin.get('/api/alerts/config')).json.metricsToken).toBe(false)
  })
})

describe('tableau de bord', () => {
  it('serveur sans collecte : pas de cluster, pas de services, pas d’alerte', async () => {
    rmSync(CL, { force: true }); rmSync(HL, { force: true }); await evaluate()
    const d = (await viewer.get('/api/dashboard')).json
    expect(d.cluster).toBeNull(); expect(d.node).toBeNull(); expect(d.backup).toBeNull(); expect(d.alerts.summary).toEqual({ critical: 0, warning: 0, info: 0, silenced: 0 }); expect(d.alerts.thresholds).toEqual({ subnetWarn: 90 })
  })
  it('services de ce nœud, certificats, disques : lus du fichier de root', async () => {
    writeFileSync(HL, JSON.stringify(hlth('solo', { cluster: null, role: 'standalone', services: [{ name: 'console', state: 'active', expected: true }, { name: 'dns', state: 'failed', expected: true }, { name: 'dhcp', state: 'inactive', expected: false }], certs: [{ name: 'console', notAfter: now() + 12 * 86400 }] })))
    const d = (await viewer.get('/api/dashboard')).json
    expect(d.node).toMatchObject({ name: 'solo', stale: false, postgres: true, timeSynced: true })
    expect(d.node.services).toEqual([{ name: 'console', state: 'active', expected: true }, { name: 'dns', state: 'failed', expected: true }, { name: 'dhcp', state: 'inactive', expected: false }])
    expect(d.node.certs).toEqual([{ name: 'console', days: 12 }]); expect(d.node.disks[0]).toMatchObject({ mount: '/', percent: 30 })
    await evaluate(); expect(await keys()).toEqual(['node.service_down|solo|dns', 'node.cert_expiry|solo|console'].sort())
    expect((await viewer.get('/api/dashboard')).json.alerts.top.map((a: any) => a.rule).sort()).toEqual(['node.cert_expiry', 'node.service_down'])
    rmSync(HL); await evaluate()   // la santé locale disparue : plus de constat sur ce nœud
  })
  it('cluster, quorum, nœuds (santé de l’arbitre comprise), adresse de service', async () => {
    publish({ n2: { services: [{ name: 'dns', state: 'failed', expected: true }] } })
    const d = (await viewer.get('/api/dashboard')).json
    expect(d.cluster).toMatchObject({ name: 'lab', node: 'n1', leader: 'n1', stale: false, localRole: 'leader', quorum: { hasQuorum: true, healthy: 3, voters: 3, needed: 2, tolerance: 1 }, vip: { address: '192.0.2.10/24', held: true } })
    expect(d.cluster.nodes.map((n: any) => [n.name, n.role, n.isLeader])).toEqual([['n1', 'data', true], ['n2', 'data', false], ['n3', 'witness', false]])
    expect(d.cluster.nodes[1].health).toMatchObject({ stale: false, servicesDown: 1 }); expect(d.cluster.nodes[2].health).toMatchObject({ stale: false, servicesDown: 0 })
    expect(JSON.stringify(d.cluster)).not.toContain('10.9.0.')   // aucune adresse de nœud sur le tableau de bord
    publish()
  })
  it('sauvegardes : résumé', async () => {
    writeFileSync(BK, JSON.stringify({ at: now() - 30, enabled: true, role: 'primary', node: 'n1', hostname: 'h', cluster: 'lab', repo: '/r', keepFull: 3, intervalHours: 24, startHour: 2, mirrorDir: null, archiveMode: 'on', archiver: null,
      diskFreeBytes: 1e9, preRestoreDirs: 0, walFiles: 1, walBytes: 1, lastWalAt: now(), pitrFrom: now() - 7200, backups: [{ id: '20261111T080000Z', node: 'n1', startedAt: now() - 400, finishedAt: now() - 300, sizeBytes: 5, timeline: 1, walArchived: true }] }))
    const d = (await viewer.get('/api/dashboard')).json; expect(d.backup).toMatchObject({ node: 'n1', count: 1, stale: false, archiverFailing: false }); expect(d.backup.lastAt).toBeGreaterThan(now() - 400); rmSync(BK)
  })
  it('pages rendues côté serveur : tableau de bord et Système, en français puis en anglais, sans clé de traduction brute', async () => {
    for (const lang of ['fr', 'en']) {
      admin.lang = lang
      for (const p of ['/', '/system', '/cluster']) { const r = await admin.get(p); expect(r.status, p).toBe(200); expect(r.text, `${p} ${lang}`).not.toMatch(/\b(dash|alerts)\.[a-z_.]+\b(?![^<]*<\/script>)/) }
    }
    admin.lang = ''
  })
  it('catalogue : chaque règle a son texte et son nom court en français ET en anglais ; mêmes clés dans les deux langues', async () => {
    const fr = (await import('../app/i18n/fr')).default as any, en = (await import('../app/i18n/en')).default as any
    expect(Object.keys(fr).sort()).toEqual(Object.keys(en).sort())
    const { RULE_IDS } = await import('../server/utils/alert-rules')
    for (const id of RULE_IDS) for (const d of [fr, en]) { expect(d[`alerts.rule.${id}`], id).toBeTruthy(); expect(d[`alerts.rn.${id}`], id).toBeTruthy() }
  })
})

describe('évaluation automatique (minuteur)', () => {
  it('sans aucune action, le moteur ouvre l’alerte puis la résout seul', async () => {
    srv.kill('SIGTERM'); await new Promise((r) => setTimeout(r, 800))
    await boot(1000)
    publish({ quorum: false, healthy: 1, tolerance: 0 })
    await until(async () => (await keys()).includes('cluster.quorum_lost||'), 20000)
    publish(); await until(async () => !(await keys()).includes('cluster.quorum_lost||'), 20000)
  }, 90000)
})
