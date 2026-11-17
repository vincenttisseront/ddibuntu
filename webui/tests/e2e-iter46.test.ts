// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.13.9 — export des journaux vers un SIEM (formats, flux choisis, curseurs, reprise après échec)
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import dgram from 'node:dgram'
import http from 'node:http'
import net from 'node:net'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3447, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s46-')); mkdirSync(join(TMP, 'gen'))
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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b); delete = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client(), oper = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }

beforeAll(async () => {
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_DIG: join(TMP, 'dig.sh'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json'),  DDI_OIDC_ALLOW_HTTP: '1', DDI_SIEM_INTERVAL_MS: '0' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  expect((await oper.login('oper', PW)).status).toBe(200)
}, 120000)

afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })

// destinations d'écoute locales
function tcpSink(): Promise<{ port: number; lines: string[]; close: () => void }> {
  return new Promise((res) => {
    const lines: string[] = [], socks = new Set<net.Socket>()
    const s = net.createServer((c) => { socks.add(c); let buf = ''; c.on('data', (d) => { buf += d; const p = buf.split('\n'); buf = p.pop()!; lines.push(...p.filter(Boolean)) }); c.on('error', () => undefined) })
    s.listen(0, '127.0.0.1', () => res({ port: (s.address() as net.AddressInfo).port, lines, close: () => { s.close(); socks.forEach((x) => x.destroy()) } }))
  })
}
function udpSink(): Promise<{ port: number; msgs: string[]; close: () => void }> {
  return new Promise((res) => { const msgs: string[] = [], s = dgram.createSocket('udp4'); s.on('message', (m) => msgs.push(m.toString())); s.bind(0, '127.0.0.1', () => res({ port: s.address().port, msgs, close: () => s.close() })) })
}
function httpSink(port = 0): Promise<{ port: number; posts: Array<{ auth?: string; ctype?: string; body: string }>; close: () => void }> {
  return new Promise((res) => {
    const posts: Array<{ auth?: string; ctype?: string; body: string }> = []
    const s = http.createServer((rq, rs) => { let b = ''; rq.on('data', (d) => { b += d }); rq.on('end', () => { posts.push({ auth: rq.headers.authorization, ctype: rq.headers['content-type'], body: b }); rs.statusCode = 200; rs.end('ok') }) })
    s.listen(port, '127.0.0.1', () => res({ port: (s.address() as net.AddressInfo).port, posts, close: () => { s.close(); s.closeAllConnections?.() } }))
  })
}
const base = { enabled: true, host: '127.0.0.1', url: '', framing: 'newline', facility: 16, tls_verify: true, auth_prefix: 'Bearer' }
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))

describe('droits et validation', () => {
  it('réservé aux administrateurs', async () => {
    for (const c of [viewer, oper]) { code(await c.get('/api/siem/targets'), 403, 'forbidden') }
    expect((await anon.get('/api/siem/targets')).status).toBe(401)
  })
  it('refuse les destinations invalides', async () => {
    const ok = { ...base, name: 'x', protocol: 'tcp', port: 514, format: 'json', sources: ['audit'] }
    expect((await admin.post('/api/siem/targets', { ...ok, sources: [] })).status).toBe(400)
    expect((await admin.post('/api/siem/targets', { ...ok, sources: ['inconnu'] })).status).toBe(400)
    code(await admin.post('/api/siem/targets', { ...ok, port: null }), 422, 'siem_host_required')
    code(await admin.post('/api/siem/targets', { ...ok, host: '169.254.169.254' }), 422, 'siem_host_forbidden')
    code(await admin.post('/api/siem/targets', { ...ok, protocol: 'https', url: '' }), 422, 'siem_url_required')
    code(await admin.post('/api/siem/targets', { ...ok, protocol: 'https', url: 'ftp://x' }), 422, 'webhook_url_invalid')
    expect((await admin.post('/api/siem/targets', { ...ok, format: 'xml' })).status).toBe(400)
  })
})

describe('envoi TCP (JSON) : flux choisis, pas d\'historique, pas de doublon', () => {
  let sink: Awaited<ReturnType<typeof tcpSink>>, id = 0
  it('n\'envoie que ce qui arrive après la création', async () => {
    expect((await admin.post('/api/ipam/vlans', { vlan_id: 41, name: 'avant' })).status).toBe(200)   // historique : ne doit PAS partir
    sink = await tcpSink()
    const r = await admin.post('/api/siem/targets', { ...base, name: 'tcp-json', protocol: 'tcp', port: sink.port, format: 'json', sources: ['audit', 'deployments'] })
    expect(r.status).toBe(200); id = r.json.id
    expect((await admin.post('/api/ipam/vlans', { vlan_id: 42, name: 'apres' })).status).toBe(200)
    const run = await admin.post('/api/siem/run'); expect(run.json.failed).toBe(0)
    await until(async () => sink.lines.length > 0)
    const evs = sink.lines.map((l) => JSON.parse(l))
    expect(evs.every((e) => e.app === 'ddibuntu' && e.source === 'audit')).toBe(true)
    const vl = (await admin.get('/api/ipam/vlans')).json.items, idOf = (n: string) => String(vl.find((v: any) => v.name === n).id)
    const created = evs.filter((e) => e.event === 'audit.vlan_create').map((e) => e.entity_id)
    expect(created).toContain(idOf('apres'))
    expect(created).not.toContain(idOf('avant'))   // l'historique n'est pas renvoyé
    expect(evs.some((e) => e.event.startsWith('audit.') && e.user === 'admin')).toBe(true)
  })
  it('un second passage n\'envoie rien de plus', async () => {
    await admin.post('/api/siem/run')   // l'audit du passage lui-même peut apparaître (siem.create…) : on vérifie l'absence de doublons exacts
    await wait(300)
    const key = sink.lines.map((l) => { const e = JSON.parse(l); return `${e.event}|${e.timestamp}|${e.message}|${e.detail ?? ''}` })
    expect(new Set(key).size).toBe(key.length)
    const n = sink.lines.length
    await admin.post('/api/siem/run'); await admin.post('/api/siem/run'); await wait(300)
    expect(sink.lines.length).toBe(n)
  })
  it('le flux « déploiements » suit la sélection', async () => {
    expect((await admin.post('/api/system/apply', { deploy: false })).status).toBe(200)
    await db.query("insert into deployments (username, ok) values ('t', false)")
    await admin.post('/api/siem/run'); await until(async () => sink.lines.some((l) => JSON.parse(l).source === 'deployments'))
    const d = sink.lines.map((l) => JSON.parse(l)).find((e) => e.source === 'deployments' && e.event === 'deploy.failed')
    expect(d.severity).toBe(3)
  })
  it('liste sans secret, mise à jour, suppression', async () => {
    const l = await admin.get('/api/siem/targets'); expect(l.json.items.find((x: any) => x.id === id).sources).toEqual(['audit', 'deployments'])
    expect((await admin.put(`/api/siem/targets/${id}`, { ...base, name: 'tcp-json', protocol: 'tcp', port: sink.port, format: 'json', sources: ['audit'], enabled: false })).status).toBe(200)
    code(await admin.post('/api/siem/targets', { ...base, name: 'TCP-JSON', protocol: 'tcp', port: 514, format: 'json', sources: ['audit'] }), 409, 'siem_exists')
    const before = sink.lines.length
    await admin.post('/api/ipam/vlans', { vlan_id: 43, name: 'desactive' }); await admin.post('/api/siem/run'); await wait(300)
    expect(sink.lines.length).toBe(before)   // destination désactivée : rien ne part
    expect((await admin.delete(`/api/siem/targets/${id}`)).status).toBe(200)
    sink.close()
  })
})

describe('formats syslog / CEF / LEEF', () => {
  it('RFC 5424 en UDP', async () => {
    const u = await udpSink()
    const r = await admin.post('/api/siem/targets', { ...base, name: 'udp-5424', protocol: 'udp', port: u.port, format: 'rfc5424', facility: 20, sources: ['audit'] }); expect(r.status).toBe(200)
    await admin.post('/api/ipam/vlans', { vlan_id: 51, name: 'udp' }); await admin.post('/api/siem/run'); await until(async () => u.msgs.length > 0)
    expect(u.msgs[0]).toMatch(/^<(166|164)>1 \d{4}-\d\d-\d\dT[\d:.]+Z \S+ ddibuntu - audit_\S+ \[ddibuntu@32473 source="audit"/)
    u.close(); await admin.delete(`/api/siem/targets/${r.json.id}`)
  })
  it('CEF et LEEF en TCP, requêtes DNS bloquées seulement', async () => {
    const s = await tcpSink(), s2 = await tcpSink()
    const a = await admin.post('/api/siem/targets', { ...base, name: 'cef', protocol: 'tcp', port: s.port, format: 'cef', sources: ['dns_blocked'] })
    const b = await admin.post('/api/siem/targets', { ...base, name: 'leef', protocol: 'tcp', port: s2.port, format: 'leef', sources: ['dns_queries'] })
    expect([a.status, b.status]).toEqual([200, 200])
    await db.query("insert into dns_queries (at, client, domain, qtype, status, reason, category) values (now(), '10.0.0.5', 'ok.example', 'A', 'allowed', '', ''), (now(), '10.0.0.6', 'pub|ad.test', 'A', 'blocked', 'liste', 'ads')")
    await admin.post('/api/siem/run'); await until(async () => s.lines.length > 0 && s2.lines.length >= 2)
    expect(s.lines).toHaveLength(1)
    expect(s.lines[0]).toMatch(/^CEF:0\|DDI-Buntu\|DDI-Buntu\|[^|]*\|dns\.blocked\|/)
    expect(s.lines[0]).toMatch(/[^\\]\|4\|rt=\d+ /)   // gravité syslog 5 (notice) → CEF 4
    expect(s.lines[0]).toContain('src=10.0.0.6'); expect(s.lines[0]).toContain('request=pub|ad.test')   // « | » n'est échappé que dans l'en-tête
    expect(s2.lines.filter((l) => l.startsWith('LEEF:2.0|DDI-Buntu|DDI-Buntu|')).length).toBe(2)
    expect(s2.lines.some((l) => l.includes('^domain=ok.example^'))).toBe(true)
    s.close(); s2.close(); await admin.delete(`/api/siem/targets/${a.json.id}`); await admin.delete(`/api/siem/targets/${b.json.id}`)
  })
})

describe('HTTPS (webhook SIEM), secret et reprise après échec', () => {
  it('envoie un lot avec l\'en-tête d\'autorisation, sans jamais renvoyer le secret', async () => {
    const h = await httpSink()
    const r = await admin.post('/api/siem/targets', { ...base, name: 'hec', protocol: 'https', url: `http://127.0.0.1:${h.port}/ingest`, format: 'json', auth_prefix: 'Splunk', secret: 'jeton-siem-123', sources: ['audit'] })
    expect(r.status).toBe(200)
    await admin.post('/api/ipam/vlans', { vlan_id: 61, name: 'hec' }); await admin.post('/api/siem/run'); await until(async () => h.posts.length > 0)
    expect(h.posts[0]!.auth).toBe('Splunk jeton-siem-123'); expect(h.posts[0]!.ctype).toBe('application/x-ndjson')
    expect(h.posts[0]!.body.trim().split('\n').every((l) => JSON.parse(l).app === 'ddibuntu')).toBe(true)
    const l = await admin.get('/api/siem/targets'); expect(JSON.stringify(l.json)).not.toContain('jeton-siem-123'); expect(l.json.items.find((x: any) => x.name === 'hec').has_secret).toBe(true)
    h.close(); await admin.delete(`/api/siem/targets/${r.json.id}`)
  })
  it('un échec ne perd rien : reprise au même curseur', async () => {
    const h0 = await httpSink(); const port = h0.port; h0.close(); await wait(200)   // port fermé
    const r = await admin.post('/api/siem/targets', { ...base, name: 'reprise', protocol: 'https', url: `http://127.0.0.1:${port}/x`, format: 'json', sources: ['audit'] }); expect(r.status).toBe(200)
    await admin.post('/api/ipam/vlans', { vlan_id: 62, name: 'reprise' })
    const run = await admin.post('/api/siem/run'); expect(run.json.failed).toBeGreaterThan(0)
    const st = (await admin.get('/api/siem/targets')).json.items.find((x: any) => x.name === 'reprise')
    expect(st.last_ok).toBe(false); expect(st.last_error).not.toBe(''); expect(Number(st.sent)).toBe(0)
    const h = await httpSink(port)
    await admin.post('/api/siem/run'); await until(async () => h.posts.length > 0)
    expect(h.posts.map((p) => p.body).join('\n')).toContain('reprise')
    const ok = (await admin.get('/api/siem/targets')).json.items.find((x: any) => x.name === 'reprise'); expect(ok.last_ok).toBe(true); expect(ok.last_error).toBe(''); expect(Number(ok.sent)).toBeGreaterThan(0)
    h.close(); await admin.delete(`/api/siem/targets/${r.json.id}`)
  })
  it('test d\'envoi : succès et échec rapportés', async () => {
    const s = await tcpSink()
    const a = await admin.post('/api/siem/targets', { ...base, name: 't-ok', protocol: 'tcp', port: s.port, format: 'rfc3164', sources: ['audit'] })
    const t1 = await admin.post(`/api/siem/targets/${a.json.id}/test`); expect(t1.json.ok).toBe(true)
    await until(async () => s.lines.length > 0); expect(s.lines[0]).toMatch(/^<134>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ ddibuntu: Événement de test/)
    s.close(); await wait(200)
    const t2 = await admin.post(`/api/siem/targets/${a.json.id}/test`); expect(t2.json.ok).toBe(false); expect(t2.json.detail).not.toBe('')
    await admin.delete(`/api/siem/targets/${a.json.id}`)
  })
})
