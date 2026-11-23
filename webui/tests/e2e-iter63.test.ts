// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.23.0 — assistant IA branché sur un faux serveur de modèles (API Ollama puis compatible OpenAI).
// Droits, réglages (clé chiffrée, jamais rendue), test de connexion, état public sans adresse, explications (journal d'audit, ligne RADIUS, synthèse),
// contexte relu côté serveur et SANS SECRET, pseudonymisation rétablie dans la réponse, mémoire, débit, audit sans question ni réponse.
import { spawn, type ChildProcess } from 'node:child_process'
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3491, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s63-')), LOGDIR = join(TMP, 'authlog'), AL = join(LOGDIR, 'radius-auth.log')
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
    return { status: r.status, json, text }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any; text?: string }, status: number, c: string) => expect([r.status, r.json?.data?.code], r.text).toEqual([status, c])
const admin = new Client(), viewer = new Client(), oper = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 200)) } throw new Error('délai dépassé') }
const rows = async (q: string, p: unknown[] = []) => (await db.query(q, p)).rows

// Faux serveur de modèles : note chaque demande ; la réponse cite les jetons reçus pour vérifier qu'ils sont rétablis
let fake: http.Server, FAKE = ''
const got: Array<{ url: string; auth?: string; body: any }> = []
let slow = 0
beforeAll(async () => {
  fake = http.createServer((req, res) => {
    let raw = ''
    req.on('data', (d) => { raw += d })
    req.on('end', () => {
      const body = raw ? JSON.parse(raw) : null
      got.push({ url: req.url!, auth: req.headers.authorization, body })
      const send = (j: unknown) => setTimeout(() => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(j)) }, slow)
      if (req.url === '/api/version') return send({ version: '0.12.3' })
      if (req.url === '/api/tags') return send({ models: [{ name: 'qwen2.5:7b' }] })
      if (req.url === '/v1/models') return send({ data: [{ id: 'mistral-small' }] })
      const user = body?.messages?.[1]?.content ?? ''
      const toks = [...new Set(String(user).match(/\[(?:IP|MAC|COMPTE)\d+\]/g) ?? [])].join(' ')
      if (req.url === '/api/chat') return send({ message: { content: `<think>brouillon</think>Cause probable : voir ${toks || 'rien'}.` } })
      if (req.url === '/v1/chat/completions') return send({ choices: [{ message: { content: 'Réponse compatible.' } }] })
      res.writeHead(404); res.end('{}')
    })
  })
  await new Promise<void>((r) => fake.listen(0, '127.0.0.1', () => r()))
  FAKE = `http://127.0.0.1:${(fake.address() as AddressInfo).port}`

  mkdirSync(LOGDIR, { recursive: true })
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RADIUS_AUTHLOG_DIR: LOGDIR, DDI_ALLOW_PRIVATE_FETCH: '1' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  for (const [u, ro, c] of [['lect', 'viewer', viewer], ['oper', 'operator', oper]] as const) { expect((await admin.post('/api/users', { username: u, role: ro, password: PW })).status).toBe(200); expect((await c.login(u, PW)).status).toBe(200) }
}, 300000)
afterAll(async () => { srv?.kill('SIGTERM'); fake?.close(); await db?.end(); rmSync(TMP, { recursive: true, force: true }) })

const base = () => ({ enabled: true, api: 'ollama', url: FAKE, model: 'qwen2.5:7b', tlsVerify: true, allowHttp: true, timeoutSec: 30, pseudonymize: false, perHour: 30, uses: { audit: true, radius: true, radius_summary: true } })

describe('assistant IA', () => {
  it('éteint par défaut : état public sans adresse, explication refusée', async () => {
    expect((await viewer.get('/api/ai/status')).json).toEqual({ enabled: false, model: null, uses: { audit: false, radius: false, radius_summary: false } })
    code(await anon.get('/api/ai/status'), 401, 'unauthenticated')
    code(await oper.post('/api/ai/explain', { use: 'radius_summary', minutes: 60 }), 409, 'ai_disabled')
  })
  it('droits : réglages et test réservés aux administrateurs, explication interdite au lecteur', async () => {
    code(await oper.get('/api/ai/settings'), 403, 'forbidden')
    code(await oper.put('/api/ai/settings', base()), 403, 'forbidden')
    code(await oper.post('/api/ai/test', { api: 'ollama', url: FAKE, tlsVerify: true, allowHttp: true }), 403, 'forbidden')
    code(await viewer.post('/api/ai/explain', { use: 'radius_summary', minutes: 60 }), 403, 'forbidden')
  })
  it('validation : HTTP sans acceptation, boucle locale hors test, champs inconnus, activation incomplète', async () => {
    code(await admin.put('/api/ai/settings', { ...base(), allowHttp: false }), 400, 'ai_https_required')
    code(await admin.put('/api/ai/settings', { ...base(), url: 'ftp://x' }), 400, 'ai_url_invalid')
    code(await admin.put('/api/ai/settings', { ...base(), model: '' }), 400, 'ai_incomplete')
    expect((await admin.put('/api/ai/settings', { ...base(), extra: 1 })).status).toBe(400)
    expect((await admin.put('/api/ai/settings', { ...base(), model: 'a b' })).status).toBe(400)
  })
  it('test de connexion : version et modèles, modèle absent signalé', async () => {
    const r = await admin.post('/api/ai/test', { api: 'ollama', url: FAKE + '/api', tlsVerify: true, allowHttp: true, model: 'absent' })
    expect(r.json).toEqual({ ok: true, version: '0.12.3', models: ['qwen2.5:7b'], modelFound: false })
    expect((await admin.post('/api/ai/test', { api: 'openai', url: FAKE + '/v1', tlsVerify: true, allowHttp: true })).json.models).toEqual(['mistral-small'])
    code(await admin.post('/api/ai/test', { api: 'ollama', url: 'http://127.0.0.1:9', tlsVerify: true, allowHttp: true }), 502, 'ai_unreachable')
  })
  it('réglages : clé chiffrée en base, jamais rendue, effacée sur demande ; audit sans clé', async () => {
    expect((await admin.put('/api/ai/settings', { ...base(), key: 'sk-cle-tres-secrete' })).status).toBe(200)
    const s = (await admin.get('/api/ai/settings')).json
    expect(s).toMatchObject({ enabled: true, keySet: true, model: 'qwen2.5:7b' }); expect(JSON.stringify(s)).not.toContain('sk-cle')
    const [row] = await rows("select value::text as v from settings where key = 'ai'")
    expect(row.v).not.toContain('sk-cle'); expect(row.v).toContain('keyEnc')
    expect(JSON.stringify(await rows("select detail from audit_log where action = 'ai.settings'"))).not.toContain('sk-cle')
    expect((await viewer.get('/api/ai/status')).json).toEqual({ enabled: true, model: 'qwen2.5:7b', uses: { audit: true, radius: true, radius_summary: true } })
  })
  it('journal d\'audit : contexte relu en base, secrets retirés, clé envoyée en Bearer, réponse nettoyée ; réservé aux administrateurs', async () => {
    const [ev] = await rows(`insert into audit_log (username, action, entity, detail, ip) values ('admin', 'enroll.refused', 'enroll', $1::jsonb, '10.9.8.7') returning id`,
      [JSON.stringify({ reason: 'enroll_not_in_group', host: 'WINPC01', password: 'mot-de-passe-fuite', keytab: 'BQIAAABV', note: 'jeton eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U' })])
    got.length = 0
    const r = await admin.post('/api/ai/explain', { use: 'audit', id: ev.id, lang: 'fr' })
    expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ text: 'Cause probable : voir rien.', model: 'qwen2.5:7b', cached: false, pseudonymized: false })
    const sent = got.find((g) => g.url === '/api/chat')!
    expect(sent.auth).toBe('Bearer sk-cle-tres-secrete')
    const txt = JSON.stringify(sent.body)
    expect(txt).toContain('enroll_not_in_group'); expect(txt).toContain('WINPC01'); expect(txt).toContain('10.9.8.7')
    for (const s of ['mot-de-passe-fuite', 'BQIAAABV', 'eyJhbGci']) expect(txt, s).not.toContain(s)
    expect(sent.body.messages[0].role).toBe('system'); expect(sent.body.stream).toBe(false)
    // 0.23.1 : sens de l'action, événements proches, aucune règle de jetons sans pseudonymisation
    expect(txt).toContain('enrolment'); expect(txt).toContain('related_events')
    expect(sent.body.messages[0].content).not.toContain('[COMPTE1]')
    code(await oper.post('/api/ai/explain', { use: 'audit', id: ev.id }), 403, 'forbidden')
    code(await admin.post('/api/ai/explain', { use: 'audit', id: 999999 }), 404, 'not_found')
    // même question : réponse gardée, aucun nouvel appel ; « refresh » redemande
    got.length = 0
    expect((await admin.post('/api/ai/explain', { use: 'audit', id: ev.id, lang: 'fr' })).json.cached).toBe(true); expect(got).toHaveLength(0)
    expect((await admin.post('/api/ai/explain', { use: 'audit', id: ev.id, lang: 'fr', refresh: true })).json.cached).toBe(false); expect(got).toHaveLength(1)
    // un nouvel événement proche change le contexte : la réponse gardée ne sert plus
    const [lf] = await rows(`insert into audit_log (action, entity, detail, ip) values ('login_failed', 'user', $1::jsonb, '10.9.8.7') returning id`,
      [JSON.stringify({ username: 'CORP\\jdupont', reason: 'not_found', source: null, tried: [{ via: 'ad', result: 'not_found' }] })])
    got.length = 0
    expect((await admin.post('/api/ai/explain', { use: 'audit', id: lf.id, lang: 'fr' })).status).toBe(200)
    const lfData = JSON.parse(String(got[0]!.body.messages[1].content).replace(/^[^\n]*\n<<<\n/, '').replace(/\n>>>$/, ''))
    expect(lfData.meaning).toMatch(/not RADIUS/); expect(lfData.reason_meaning).toMatch(/DOMAIN\\user/); expect(lfData.tried[0].meaning).toMatch(/did not find/)
    expect(lfData.auth_config).toMatchObject({ local_accounts: true, active_directory: { enabled: false }, sso_oidc: { enabled: false } })
    expect(lfData.related_events.some((e: any) => e.action === 'enroll.refused' && e.ip === '10.9.8.7')).toBe(true)
  })
  it('audit des demandes : usage, modèle, durée ; ni la question ni la réponse', async () => {
    const a = await rows("select entity_id, detail from audit_log where action = 'ai.explain' order by id")
    expect(a.length).toBeGreaterThanOrEqual(2)
    expect(a[0].entity_id).toBe('audit'); expect(a[0].detail).toMatchObject({ ok: true, model: 'qwen2.5:7b' }); expect(typeof a[0].detail.ms).toBe('number')
    expect(JSON.stringify(a)).not.toContain('Cause probable'); expect(JSON.stringify(a)).not.toContain('WINPC01')
  })
  it('ligne RADIUS et synthèse, pseudonymisées : jetons envoyés, valeurs rétablies dans la réponse', async () => {
    const n = Math.floor(Date.now() / 1000)
    const F = ['v1', String(n - 60), 'reject', 'alice@lab.test', 'wifi-hq', '10.0.0.5', 'aa-bb-cc-dd-ee-ff', 'AA-BB-CC-00-11-22:Corp', 'ap-hq', '/CN=3Dpc001', '/CN=3DLab Issuing CA', '1001', '271119151329Z', '', 'pc001.lab.test', 'computer:pc001.lab.test', '', 'eap_tls: (TLS) OpenSSL says error 23 : certificate revoked']
    writeFileSync(AL, [F.join('|'), F.map((v, i) => (i === 1 ? String(n - 30) : i === 3 ? 'bob' : v)).join('|')].join('\n') + '\n')
    expect((await admin.put('/api/ai/settings', { ...base(), pseudonymize: true })).status).toBe(200)
    const ev = (await viewer.get('/api/radius/events')).json.events.find((e: any) => e.user === 'alice@lab.test')
    got.length = 0
    const r = await oper.post('/api/ai/explain', { use: 'radius', at: ev.at, kind: ev.kind, mac: ev.mac, user: ev.user, lang: 'en' })
    expect(r.status, r.text).toBe(200); expect(r.json.pseudonymized).toBe(true)
    const txt = JSON.stringify(got[0]!.body)
    for (const s of ['alice@lab.test', '10.0.0.5', 'aa-bb-cc-dd-ee-ff', 'pc001.lab.test']) expect(txt, s).not.toContain(s)
    expect(txt).toContain('revoked'); expect(txt).toContain('DATA (JSON)')
    for (const s of ['alice@lab.test', '10.0.0.5', 'aa-bb-cc-dd-ee-ff']) expect(r.json.text, s).toContain(s)   // rétablies pour l'opérateur
    // la ligne doit exister vraiment : une référence inventée est refusée
    code(await oper.post('/api/ai/explain', { use: 'radius', at: ev.at + 1, kind: ev.kind, mac: ev.mac, user: ev.user }), 404, 'ai_event_gone')
    const s = await oper.post('/api/ai/explain', { use: 'radius_summary', minutes: 60, lang: 'fr' })
    expect(s.status, s.text).toBe(200)
    const sum = JSON.parse(String(got.at(-1)!.body.messages[1].content).replace(/^[^\n]*\n<<<\n/, '').replace(/\n>>>$/, ''))
    expect(sum).toMatchObject({ period_minutes: 60, events_read: 2, counts: { accept: 0, reject: 2, diag: 0 }, reject_reasons: [{ why: 'revoked', n: 2 }], rejects_by_identity: [{ identity: '[COMPTE1]', n: 2 }] })
    expect(JSON.stringify(sum)).not.toContain('pc001')
    expect(sum.rejects_by_device[0].n).toBe(2)
  })
  it('usage désactivé, débit atteint, autre API', async () => {
    expect((await admin.put('/api/ai/settings', { ...base(), uses: { audit: true, radius: false, radius_summary: true }, perHour: 1 })).status).toBe(200)
    code(await oper.post('/api/ai/explain', { use: 'radius', at: 1, kind: 'reject', mac: '', user: '' }), 409, 'ai_use_disabled')
    expect((await oper.post('/api/ai/explain', { use: 'radius_summary', minutes: 120 })).status).toBe(200)
    code(await oper.post('/api/ai/explain', { use: 'radius_summary', minutes: 180 }), 429, 'ai_quota')
    expect((await admin.put('/api/ai/settings', { ...base(), api: 'openai', model: 'mistral-small' })).status).toBe(200)
    expect((await oper.post('/api/ai/explain', { use: 'radius_summary', minutes: 60 })).json.text).toBe('Réponse compatible.')
  })
  it('délai dépassé : erreur classée, audit de l\'échec, la console reste disponible', async () => {
    expect((await admin.put('/api/ai/settings', { ...base(), timeoutSec: 10 })).status).toBe(200)
    slow = 11_000
    try { code(await oper.post('/api/ai/explain', { use: 'radius_summary', minutes: 90 }), 504, 'ai_timeout') } finally { slow = 0 }
    expect((await fetch(BASE + '/api/health')).status).toBe(200)
    const [last] = await rows("select detail from audit_log where action = 'ai.explain' order by id desc limit 1")
    expect(last.detail).toMatchObject({ ok: false, error: 'ai_timeout' })
  }, 30000)
  it('désactivation : boutons masqués, plus rien n\'est envoyé', async () => {
    expect((await admin.put('/api/ai/settings', { ...base(), enabled: false })).status).toBe(200)
    expect((await viewer.get('/api/ai/status')).json.enabled).toBe(false)
    got.length = 0
    code(await oper.post('/api/ai/explain', { use: 'radius_summary', minutes: 60 }), 409, 'ai_disabled'); expect(got).toHaveLength(0)
  })
})
