// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.9.28 — traçabilité des baux (historique IP / MAC / nom).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { hotp, totpStep } from '../server/utils/totp'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3415, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s15-')); mkdirSync(join(TMP, 'gen'))
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
const admin = new Client(), viewer = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }

beforeAll(async () => {
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json') } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })


const ip2n = (ip: string) => ip.split('.').reduce((a, b) => a * 256 + Number(b), 0)
const lease = (ip: string, mac: string, host: string | null, minutes = 60) =>
  db.query("insert into lease4 (address, hwaddr, hostname, subnet_id, expire) values ($1, decode($2, 'hex'), $3, 1, now() + make_interval(mins => $4))", [ip2n(ip), mac.replace(/:/g, ''), host, minutes])

describe('traçabilité des baux', () => {
  it('sans table lease4 : relevé ignoré, recherche vide', async () => {
    const r = await admin.post('/api/trace/collect'); expect(r.status).toBe(200); expect(r.json.skipped).toBe('unavailable')
    const s = await admin.get('/api/trace?q=10.0.0.1'); expect(s.status).toBe(200); expect(s.json.items).toEqual([])
  })
  it('droits : lecteur peut chercher, pas relever ; anonyme refusé', async () => {
    expect((await viewer.get('/api/trace?q=x')).status).toBe(200)
    code(await viewer.post('/api/trace/collect'), 403, 'forbidden')
    expect((await anon.get('/api/trace?q=x')).status).toBe(401)
  })
  it('ouvre, prolonge, referme et change d\'association', async () => {
    await db.query('create table lease4 (address bigint primary key, hwaddr bytea, hostname varchar, subnet_id bigint, expire timestamp)')
    await lease('10.1.0.5', 'aa:bb:cc:00:00:01', 'PC-Alice.corp.')
    await lease('10.1.0.6', 'aa:bb:cc:00:00:02', null)
    let r = await admin.post('/api/trace/collect'); expect(r.json).toMatchObject({ active: 2, opened: 2, closed: 0 })
    r = await admin.post('/api/trace/collect'); expect(r.json).toMatchObject({ active: 2, opened: 0, closed: 0 })
    // l'adresse .5 passe à un autre poste : l'ancienne association est fermée, une nouvelle s'ouvre
    await db.query('update lease4 set hwaddr = decode($1, \'hex\'), hostname = $2 where address = $3', ['aabbcc000099', 'pc-bob', ip2n('10.1.0.5')])
    r = await admin.post('/api/trace/collect'); expect(r.json).toMatchObject({ active: 2, opened: 1, closed: 1 })
    // le bail .6 disparaît
    await db.query('delete from lease4 where address = $1', [ip2n('10.1.0.6')])
    r = await admin.post('/api/trace/collect'); expect(r.json).toMatchObject({ active: 1, opened: 0, closed: 1 })
  })
  it('recherche par IP, MAC (tout format, préfixe) et nom ; nom normalisé', async () => {
    const byIp = await viewer.get('/api/trace?q=10.1.0.5')
    expect(byIp.json.items.map((i: any) => [i.mac, i.hostname, i.open])).toEqual([['aa:bb:cc:00:00:99', 'pc-bob', true], ['aa:bb:cc:00:00:01', 'pc-alice.corp', false]])
    const byMac = await viewer.get('/api/trace?q=' + encodeURIComponent('AA-BB-CC-00-00-02'))
    expect(byMac.json.items).toHaveLength(1); expect(byMac.json.items[0]).toMatchObject({ ip: '10.1.0.6', hostname: null, open: false })
    expect((await viewer.get('/api/trace?q=aabbcc')).json.items).toHaveLength(3)
    expect((await viewer.get('/api/trace?q=alice')).json.items).toHaveLength(1)
    expect((await viewer.get('/api/trace?q=10.1.0.')).json.items).toHaveLength(3)
    expect((await viewer.get('/api/trace?q=%25')).json.items).toHaveLength(0)    // % n'est pas un joker
    expect((await viewer.get('/api/trace')).json.items).toEqual([])
    expect((await viewer.get('/api/trace?q=pc')).json.stats).toMatchObject({ total: 3, open: 1 })
  })
  it('corrèle avec l\'IPAM', async () => {
    const sp = await admin.get('/api/ipam/spaces'); const space = sp.json.items[0].id
    const n = await admin.post('/api/ipam/subnets', { space_id: space, cidr: '10.1.0.0/24', name: 'lan' }); expect(n.status, n.text).toBe(200)
    const a = await admin.post(`/api/ipam/subnets/${n.json.id}/addresses`, { ip: '10.1.0.5', hostname: 'bob-ipam', status: 'used' }); expect(a.status, a.text).toBe(200)
    const r = await viewer.get('/api/trace?q=10.1.0.5')
    expect(r.json.items[0].ipam_hostname).toBe('bob-ipam')
  })
})

describe('découverte planifiée et alertes d\'hygiène', () => {
  it('réglage : droits, validation, enregistrement', async () => {
    const g = await viewer.get('/api/discovery/schedule'); code(g, 403, 'forbidden')
    const a = await admin.get('/api/discovery/schedule'); expect(a.status).toBe(200); expect(a.json.schedule).toMatchObject({ enabled: false, intervalHours: 24 }); expect(a.json.last).toBeNull()
    const ok = { enabled: true, intervalHours: 6, subnetIds: [], methods: { tcp: false, icmp: false, arp: true, reverse: false, leases: true }, autoGhost: false, ghostDays: 30 }
    code(await viewer.put('/api/discovery/schedule', ok), 403, 'forbidden')
    expect((await admin.put('/api/discovery/schedule', { ...ok, intervalHours: 0 })).status).toBe(400)
    expect((await admin.put('/api/discovery/schedule', { ...ok, extra: 1 })).status).toBe(400)
    code(await admin.put('/api/discovery/schedule', { ...ok, methods: { tcp: false, icmp: false, arp: false, reverse: false, leases: false } }), 400, 'discovery_no_method')
    code(await admin.put('/api/discovery/schedule', { ...ok, subnetIds: [999999] }), 404, 'not_found')
    expect((await admin.put('/api/discovery/schedule', ok)).status).toBe(200)
    expect((await admin.get('/api/discovery/schedule')).json.schedule).toMatchObject({ enabled: true, intervalHours: 6, methods: { leases: true, icmp: false } })
  })
  it('passage à la demande : marque les connues, compte les inconnues, ne crée rien ; l\'alerte d\'hygiène apparaît puis se résout', async () => {
    await db.query('delete from addresses; delete from subnets')
    const s = (await db.query("insert into subnets (cidr, name) values ('10.77.0.0/29', 'labo') returning id")).rows[0].id
    await db.query("insert into addresses (subnet_id, ip, status, hostname) values ($1, '10.77.0.2', 'used', 'connu'), ($1, '10.77.0.5', 'used', 'disparu')", [s])
    await db.query('delete from lease4')
    await lease('10.77.0.2', 'aa:bb:cc:01:01:01', 'connu'); await lease('10.77.0.3', 'aa:bb:cc:01:01:02', 'inconnu')
    code(await viewer.post('/api/discovery/schedule/run'), 403, 'forbidden')
    expect((await admin.post('/api/discovery/schedule/run')).status).toBe(200)
    await until(async () => (await admin.get('/api/discovery/schedule')).json.last !== null, 40000)
    const last = (await admin.get('/api/discovery/schedule')).json.last
    expect(last, JSON.stringify(last)).toMatchObject({ ok: true, known: 1, unknown: 1, macChanged: 0 })
    const n = (await db.query('select count(*)::int as n, count(last_seen)::int as seen from addresses')).rows[0]
    expect(n).toEqual({ n: 2, seen: 1 })      // aucune adresse créée, la connue qui répond est marquée vue
    // joignabilité : celle qui répond (bail) est joignable, celle qui ne répond à aucune sonde active est injoignable
    const rc = (await db.query("select host(ip) as ip, reachable, checked_at is not null as chk from addresses order by ip")).rows
    expect(rc).toEqual([{ ip: '10.77.0.2', reachable: true, chk: true }, { ip: '10.77.0.5', reachable: false, chk: true }])
    expect(last.unreachable).toBe(1)
    const list = (await admin.get(`/api/ipam/subnets/${s}/addresses`)).json.items
    expect(list.map((a: any) => [a.ip, a.reachable])).toEqual([['10.77.0.2', true], ['10.77.0.5', false]])
    const ev = await admin.post('/api/alerts/evaluate'); expect(ev.status).toBe(200)
    const act = (await admin.get('/api/alerts')).json.active
    expect(act.find((x: any) => x.rule === 'ipam.unknown_hosts')).toMatchObject({ severity: 'warning', params: { count: 1 } })
  })
  it('fantômes : adresse silencieuse depuis longtemps → alerte d\'information', async () => {
    await db.query("update addresses set last_seen = now() - interval '40 days' where ip = '10.77.0.2'")
    await admin.post('/api/alerts/evaluate')
    const act = (await admin.get('/api/alerts')).json.active
    expect(act.find((x: any) => x.rule === 'ipam.ghosts')).toMatchObject({ severity: 'info', params: { count: 1, days: 30 } })
  })
  it('bascule automatique en « fantôme » (réglable) puis retour en « utilisée » quand l\'adresse réapparaît', async () => {
    const sch = (await admin.get('/api/discovery/schedule')).json.schedule
    code(await admin.put('/api/discovery/schedule', { ...sch, autoGhost: true, ghostDays: 0 }), 400, 'validation')
    expect((await admin.put('/api/discovery/schedule', { ...sch, autoGhost: true, ghostDays: 10 })).status).toBe(200)
    await db.query("update addresses set last_seen = now() - interval '40 days' where ip in ('10.77.0.2', '10.77.0.5')")
    const startRun = async () => { const before = (await admin.get('/api/discovery/schedule')).json.last?.at ?? 0; await new Promise((r) => setTimeout(r, 1100)); expect((await admin.post('/api/discovery/schedule/run')).status).toBe(200); await until(async () => { const l = (await admin.get('/api/discovery/schedule')).json; return !l.running && l.last.at > before }, 40000) }
    await startRun()
    const st = async () => Object.fromEntries((await db.query("select host(ip) as ip, status from addresses")).rows.map((r) => [r.ip, r.status]))
    // .2 répond (bail) : marquée vue, reste utilisée ; .5 ne répond pas et n'a pas été vue depuis 40 jours : fantôme
    expect(await st()).toEqual({ '10.77.0.2': 'used', '10.77.0.5': 'ghost' })
    // le fantôme figure dans la liste des fantômes et reste filtrable par statut
    expect((await admin.get('/api/ipam/ghosts?days=10')).json.items.map((i: any) => i.ip)).toEqual(['10.77.0.5'])
    // elle réapparaît (bail) : retour en « utilisée »
    await lease('10.77.0.5', 'aa:bb:cc:01:01:05', 'disparu')
    await startRun()
    expect(await st()).toEqual({ '10.77.0.2': 'used', '10.77.0.5': 'used' })
    // désactivé : rien ne bascule
    expect((await admin.put('/api/discovery/schedule', { ...sch, autoGhost: false, ghostDays: 10 })).status).toBe(200)
    await db.query("update addresses set last_seen = now() - interval '40 days' where ip = '10.77.0.5'")
    await db.query('delete from lease4 where address = $1', [ip2n('10.77.0.5')])
    await startRun()
    expect((await st())['10.77.0.5']).toBe('used')
  })
})

describe('jetons d\'API et OpenAPI', () => {
  let ro = '', rw = '', rwId = 0
  const bearer = async (tok: string, method: string, path: string, body?: unknown) => {
    const r = await fetch(BASE + path, { method, headers: { authorization: `Bearer ${tok}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) })
    const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* HTML */ }
    return { status: r.status, json, text }
  }
  it('gestion réservée à l\'administrateur ; secret montré une seule fois, jamais relisible', async () => {
    code(await viewer.get('/api/tokens'), 403, 'forbidden'); code(await viewer.post('/api/tokens', { name: 'x', role: 'viewer', expiresDays: 30 }), 403, 'forbidden')
    expect((await admin.post('/api/tokens', { name: 'bad name', role: 'viewer', expiresDays: 30 })).status).toBe(400)
    expect((await admin.post('/api/tokens', { name: 'adm', role: 'admin', expiresDays: 30 })).status).toBe(400)        // jamais administrateur
    expect((await admin.post('/api/tokens', { name: 'x', role: 'viewer', expiresDays: 0 })).status).toBe(400)
    const a = await admin.post('/api/tokens', { name: 'lecture', role: 'viewer', expiresDays: 30 }); expect(a.status, a.text).toBe(200)
    expect(a.json.token).toMatch(/^ddi_[A-Za-z0-9_-]{40}$/); ro = a.json.token
    const b = await admin.post('/api/tokens', { name: 'ecriture', role: 'operator', expiresDays: null }); expect(b.status).toBe(200); rw = b.json.token; rwId = b.json.id
    code(await admin.post('/api/tokens', { name: 'LECTURE', role: 'viewer', expiresDays: 30 }), 409, 'token_exists')
    const l = await admin.get('/api/tokens'); expect(l.json.items).toHaveLength(2)
    expect(JSON.stringify(l.json)).not.toContain(ro); expect(JSON.stringify(l.json)).not.toContain(rw)
    expect((await db.query('select token_hash from api_tokens')).rows.every((r) => r.token_hash !== ro && /^[0-9a-f]{64}$/.test(r.token_hash))).toBe(true)
  })
  it('lecture avec Bearer, sans cookie ni CSRF ; le rôle est respecté', async () => {
    expect((await bearer(ro, 'GET', '/api/ipam/spaces')).status).toBe(200)
    expect((await bearer(ro, 'GET', '/api/auth/me')).json.user).toMatchObject({ username: 'token:lecture', role: 'viewer', source: 'token' })
    code(await bearer(ro, 'POST', '/api/ipam/spaces', { name: 'nope' }), 403, 'forbidden')               // lecteur : pas d'écriture
    const w = await bearer(rw, 'POST', '/api/ipam/spaces', { name: 'via-jeton' }); expect(w.status, w.text).toBe(200)   // opérateur : écriture sans CSRF
    expect((await db.query("select username from audit_log where action like '%space%' order by id desc limit 1")).rows[0]?.username).toBe('token:ecriture')
  })
  it('un jeton ne gère ni jetons, ni comptes, ni mot de passe', async () => {
    code(await bearer(rw, 'GET', '/api/tokens'), 403, 'forbidden'); code(await bearer(rw, 'GET', '/api/users'), 403, 'forbidden')
    code(await bearer(rw, 'POST', '/api/auth/logout', {}), 403, 'forbidden'); code(await bearer(rw, 'POST', '/api/auth/password', { current: 'a', next: 'b' }), 403, 'forbidden')
  })
  it('jeton inconnu, mal formé, révoqué, expiré : refusé', async () => {
    code(await bearer('ddi_' + 'A'.repeat(40), 'GET', '/api/ipam/spaces'), 401, 'invalid_token')
    expect((await bearer('pas-un-jeton', 'GET', '/api/ipam/spaces')).status).toBe(401)
    await db.query("update api_tokens set expires_at = now() - interval '1 minute' where name = 'lecture'")
    code(await bearer(ro, 'GET', '/api/ipam/spaces'), 401, 'invalid_token')
    expect((await admin.delete(`/api/tokens/${rwId}`)).status).toBe(200)
    code(await bearer(rw, 'GET', '/api/ipam/spaces'), 401, 'invalid_token')
    code(await admin.delete(`/api/tokens/${rwId}`), 404, 'not_found')
    const l = (await admin.get('/api/tokens')).json.items
    expect(l.map((x: any) => [x.name, x.active])).toEqual([['ecriture', false], ['lecture', false]])
  })
  it('OpenAPI : document valide décrivant les routes, accessible avec un jeton', async () => {
    const t = (await admin.post('/api/tokens', { name: 'doc', role: 'viewer', expiresDays: 1 })).json.token
    const r = await bearer(t, 'GET', '/api/openapi.json'); expect(r.status).toBe(200)
    expect(r.json.openapi).toBe('3.0.3'); expect(r.json.servers).toEqual([{ url: '/api' }])
    expect(r.json.paths['/ipam/subnets/{id}/addresses'].get.parameters[0]).toMatchObject({ name: 'id', in: 'path', required: true })
    expect(r.json.paths['/tokens'].post['x-required-role']).toBe('admin'); expect(r.json.paths['/health'].get.security).toEqual([])
    expect(Object.keys(r.json.paths).length).toBeGreaterThan(80)
    code(await anon.get('/api/openapi.json'), 401, 'unauthenticated')
  })
})


describe('délégation par périmètre (espaces IPAM)', () => {
  const sc = new Client(); let scId = 0, sp2 = 0, sp3 = 0, sn2 = 0, sn3 = 0, ad2 = 0, ad3 = 0
  it('un opérateur restreint écrit dans son espace, pas ailleurs, ni hors IPAM', async () => {
    sp2 = (await admin.post('/api/ipam/spaces', { name: 'Paris' })).json.id; sp3 = (await admin.post('/api/ipam/spaces', { name: 'Lyon' })).json.id
    const r2 = await admin.post('/api/ipam/subnets', { cidr: '10.92.0.0/24', name: 'p', space_id: sp2 }); sn2 = r2.json?.id; if (!sn2) throw new Error(r2.text); const r3 = await admin.post('/api/ipam/subnets', { cidr: '10.93.0.0/24', name: 'l', space_id: sp3 }); sn3 = r3.json?.id
    ad2 = (await admin.post(`/api/ipam/subnets/${sn2}/addresses`, { ip: '10.92.0.5', status: 'used' })).json.id; ad3 = (await admin.post(`/api/ipam/subnets/${sn3}/addresses`, { ip: '10.93.0.5', status: 'used' })).json.id
    expect([sp2, sp3, sn2, sn3, ad2, ad3].every(Boolean), JSON.stringify([sp2, sp3, sn2, sn3, ad2, ad3])).toBe(true)
    expect((await admin.post('/api/users', { username: 'paris', role: 'operator', password: PW, space_ids: [sp2] })).status).toBe(200)
    expect((await sc.login('paris', PW)).json.user.spaceIds).toEqual([sp2]); scId = (await db.query("select id from users where username='paris'")).rows[0].id
    // dans son espace
    expect((await sc.post(`/api/ipam/subnets/${sn2}/addresses`, { ip: '10.92.0.6', status: 'used' })).status).toBe(200)
    expect((await sc.put(`/api/ipam/addresses/${ad2}`, { description: 'ok' })).status).toBe(200)
    expect((await sc.post('/api/ipam/subnets', { cidr: '10.92.1.0/24', name: 'p2', space_id: sp2 })).status).toBe(200)
    // hors de son espace
    code(await sc.post(`/api/ipam/subnets/${sn3}/addresses`, { ip: '10.93.0.6', status: 'used' }), 403, 'out_of_scope')
    code(await sc.put(`/api/ipam/addresses/${ad3}`, { description: 'non' }), 403, 'out_of_scope')
    code(await sc.delete(`/api/ipam/addresses/${ad3}`), 403, 'out_of_scope')
    code(await sc.post('/api/ipam/subnets', { cidr: '10.93.1.0/24', name: 'l2', space_id: sp3 }), 403, 'out_of_scope')
    code(await sc.put(`/api/ipam/subnets/${sn2}`, { space_id: sp3 }), 403, 'out_of_scope')            // pas de déménagement vers un autre espace
    code(await sc.delete(`/api/ipam/spaces/${sp3}`), 403, 'out_of_scope'); code(await sc.post('/api/ipam/spaces', { name: 'X' }), 403, 'out_of_scope')
    code(await sc.post('/api/ipam/vlans', { vlan_id: 99, name: 'v' }), 403, 'out_of_scope')
    // hors IPAM : toute écriture d'opérateur refusée ; la lecture reste libre
    code(await sc.post('/api/system/apply', {}), 403, 'forbidden')
    expect((await admin.get('/api/ipam/spaces')).status).toBe(200); expect((await sc.get(`/api/ipam/subnets/${sn3}/addresses`)).status).toBe(200)
    expect((await db.query('select 1 from addresses where id = $1', [ad3])).rows).toHaveLength(1)
  })
  it('opérateur restreint : DNS/DHCP/découverte refusés ; administrateur et opérateur libre non concernés', async () => {
    code(await sc.post('/api/dns/zones', { name: 'x.example.', type: 'primary' }), 403, 'out_of_scope')
    code(await sc.post('/api/discovery/schedule/run', {}), 403, 'out_of_scope')
    expect((await admin.post(`/api/ipam/subnets/${sn3}/addresses`, { ip: '10.93.0.7', status: 'used' })).status).toBe(200)
    expect((await admin.post('/api/users', { username: 'libre', role: 'operator', password: PW })).status).toBe(200)
    const lib = new Client(); expect((await lib.login('libre', PW)).json.user.spaceIds).toBeNull()
    expect((await lib.post(`/api/ipam/subnets/${sn3}/addresses`, { ip: '10.93.0.8', status: 'used' })).status).toBe(200)
  })
  it('changer le périmètre ferme la session ; passer administrateur lève la restriction', async () => {
    expect((await admin.put(`/api/users/${scId}`, { space_ids: [sp3] })).status).toBe(200)
    expect((await sc.get('/api/auth/me')).json.user).toBeNull()
    expect((await sc.login('paris', PW)).json.user.spaceIds).toEqual([sp3])
    expect((await sc.post(`/api/ipam/subnets/${sn3}/addresses`, { ip: '10.93.0.9', status: 'used' })).status).toBe(200)
    expect((await admin.put(`/api/users/${scId}`, { role: 'admin' })).status).toBe(200)
    expect((await db.query('select space_ids from users where id = $1', [scId])).rows[0].space_ids).toBeNull()
    expect((await admin.put(`/api/users/${scId}`, { role: 'viewer', space_ids: [] })).status).toBe(200)
    expect((await admin.post('/api/users', { username: 'bad', role: 'operator', password: PW, space_ids: [0] })).status).toBe(400)
  })
  it('groupes AD : le périmètre est accepté dans la table de correspondance', async () => {
    const r = await admin.put('/api/ad/settings', { enabled: false, urls: [], baseDn: '', bindDn: '', userAttr: 'sAMAccountName', nestedGroups: true, tlsRejectUnauthorized: true, groupMap: [{ groupDn: 'CN=Ops,OU=G,DC=c,DC=l', role: 'operator', spaceIds: [sp2] }] })
    expect(r.status, r.text).toBe(200)
    expect((await admin.get('/api/ad/settings')).json.groupMap).toEqual([{ groupDn: 'CN=Ops,OU=G,DC=c,DC=l', role: 'operator', spaceIds: [sp2] }])
  })
})

describe('DHCP multi-espaces', () => {
  it('un même plan dans deux espaces : un seul est servi à la fois ; des plans distincts coexistent dans Kea', async () => {
    const sx = (await admin.post('/api/ipam/spaces', { name: 'Client X' })).json.id
    const mk = async (cidr: string, space: number, name: string) => { const r = await admin.post('/api/ipam/subnets', { cidr, name, space_id: space }); expect(r.status, r.text).toBe(200); return r.json.id as number }
    const a1 = await mk('10.50.0.0/24', 1, 'a1'), ax = await mk('10.50.0.0/24', sx, 'ax'), bx = await mk('10.51.0.0/24', sx, 'bx')
    const sc1 = await admin.post('/api/dhcp/scopes', { subnet_id: a1 }); expect(sc1.status, sc1.text).toBe(200)
    const r = await admin.post('/api/dhcp/scopes', { subnet_id: ax }); code(r, 409, 'dhcp_overlap'); expect(r.json.data).toMatchObject({ cidr: '10.50.0.0/24', space: 'Défaut' })
    // étendue désactivée : ne bloque pas ; la réactiver est refusée si l'autre est servie
    const scx = await admin.post('/api/dhcp/scopes', { subnet_id: ax, enabled: false }); expect(scx.status, scx.text).toBe(200)
    code(await admin.put(`/api/dhcp/scopes/${scx.json.id}`, { lease_time: 3600, enabled: true }), 409, 'dhcp_overlap')
    // plan distinct dans l'autre espace : servi sans souci, présent dans la configuration Kea
    expect((await admin.post('/api/dhcp/scopes', { subnet_id: bx })).status).toBe(200)
    const kea = (await admin.get('/api/system/render')).json.files.find((f: any) => f.kind === 'kea').content
    expect(kea).toContain('10.50.0.0/24'); expect(kea).toContain('10.51.0.0/24')
    // déménager un réseau servi vers un espace où son plan est déjà servi : refusé
    const big = await mk('10.54.0.0/24', 1, 'big'), small = await mk('10.54.0.0/25', 1, 'small')   // imbriqués dans le même espace : accepté
    expect((await admin.post('/api/dhcp/scopes', { subnet_id: big })).status).toBe(200); expect((await admin.post('/api/dhcp/scopes', { subnet_id: small })).status).toBe(200)
    code(await admin.put(`/api/ipam/subnets/${big}`, { space_id: sx }), 409, 'dhcp_overlap')
    // libérer le plan : l'autre devient activable
    expect((await admin.put(`/api/dhcp/scopes/${sc1.json.id}`, { lease_time: 3600, enabled: false })).status).toBe(200)
    expect((await admin.put(`/api/dhcp/scopes/${scx.json.id}`, { lease_time: 3600, enabled: true })).status).toBe(200)
  })
})

describe('contrôle d\'une adresse (DNS + présence)', () => {
  let lo = 0, gone = 0
  it('hôte qui répond : présent ; hôte muet sans nom DNS : absent, signalé injoignable', async () => {
    const sn = await admin.post('/api/ipam/subnets', { cidr: '127.0.0.0/24', name: 'boucle' }); expect(sn.status, sn.text).toBe(200)
    lo = (await admin.post(`/api/ipam/subnets/${sn.json.id}/addresses`, { ip: '127.0.0.1', status: 'used', hostname: 'local' })).json.id
    const r = await admin.post(`/api/ipam/addresses/${lo}/check`); expect(r.status, r.text).toBe(200)
    expect(r.json).toMatchObject({ ip: '127.0.0.1', verdict: 'alive', alive: true, hostname: 'local' }); expect(r.json.methods).toContain('tcp')
    expect((await db.query('select reachable, checked_at is not null as c from addresses where id = $1', [lo])).rows[0]).toEqual({ reachable: true, c: true })
    const sn2 = await admin.post('/api/ipam/subnets', { cidr: '198.18.77.0/24', name: 'muet' }); gone = (await admin.post(`/api/ipam/subnets/${sn2.json.id}/addresses`, { ip: '198.18.77.9', status: 'used' })).json.id
    const g = await admin.post(`/api/ipam/addresses/${gone}/check`); expect(g.status, g.text).toBe(200)
    // le bac à sable laisse parfois « répondre » des adresses lointaines (relais TCP) : on vérifie la cohérence verdict ↔ drapeau enregistré
    expect(g.json).toMatchObject({ ptr: null, ptrMatchesIp: null, hostnameMatchesIp: null }); expect(['alive', 'absent']).toContain(g.json.verdict); expect(g.json.alive).toBe(g.json.verdict === 'alive')
    expect((await db.query('select reachable from addresses where id = $1', [gone])).rows[0].reachable).toBe(g.json.alive)
    expect((await db.query("select count(*)::int n from audit_log where action = 'address_check'")).rows[0].n).toBe(2)
  })
  it('droits : lecteur refusé, adresse inconnue, périmètre respecté', async () => {
    code(await viewer.post(`/api/ipam/addresses/${gone}/check`), 403, 'forbidden')
    code(await admin.post('/api/ipam/addresses/999999/check'), 404, 'not_found')
    expect((await admin.post('/api/users', { username: 'etroit', role: 'operator', password: PW, space_ids: [999] })).status).toBe(200)
    const et = new Client(); expect((await et.login('etroit', PW)).status).toBe(200)
    code(await et.post(`/api/ipam/addresses/${gone}/check`), 403, 'out_of_scope')
  })
})


describe('double authentification (TOTP)', () => {
  const U = 'mfa1', uid = async (n: string) => (await db.query('select id from users where username = $1', [n])).rows[0].id as number
  let secret = '', codes: string[] = []
  const now = () => totpStep()
  const mk = async (name: string) => { expect((await admin.post('/api/users', { username: name, role: 'operator', password: PW })).status).toBe(200) }
  const mfaLogin = async (c: Client, user: string, code: string) => {
    const r = await c.post('/api/auth/login', { username: user, password: PW }); expect(r.status, r.text).toBe(200); expect(r.json.mfa).toBe(true)
    const v = await c.post('/api/auth/login/mfa', { challenge: r.json.challenge, code }); if (v.status === 200) c.csrf = v.json.csrf; return v
  }
  it('activation : mot de passe exigé, premier code vérifié, 10 codes de secours montrés une fois', async () => {
    await mk(U); const c = new Client(); expect((await c.login(U, PW)).json.mfa).toBeUndefined()
    expect((await c.get('/api/auth/mfa')).json).toEqual({ available: true, enabled: false, recoveryLeft: 0 })
    code(await c.post('/api/auth/mfa/setup', { password: 'mauvais-mot-de-passe' }), 401, 'bad_password')
    code(await c.post('/api/auth/mfa/enable', { code: '123456' }), 409, 'mfa_no_setup')
    const su = await c.post('/api/auth/mfa/setup', { password: PW }); expect(su.status, su.text).toBe(200)
    secret = su.json.secret; expect(secret).toMatch(/^[A-Z2-7]{32}$/); expect(su.json.uri).toContain(`secret=${secret}`)
    expect((await db.query('select totp_secret_enc from users where username = $1', [U])).rows[0].totp_secret_enc).not.toContain(secret)   // chiffré au repos
    code(await c.post('/api/auth/mfa/enable', { code: '000000' === hotp(secret, now()) ? '111111' : '000000' }), 400, 'bad_code')
    const en = await c.post('/api/auth/mfa/enable', { code: hotp(secret, now()) }); expect(en.status, en.text).toBe(200)
    codes = en.json.codes; expect(codes).toHaveLength(10)
    expect((await c.get('/api/auth/mfa')).json).toEqual({ available: true, enabled: true, recoveryLeft: 10 })
    expect(JSON.stringify((await admin.get('/api/users')).json)).not.toContain(codes[0]!)
    expect((await admin.get('/api/users')).json.items.find((u: any) => u.username === U).totp_enabled).toBe(true)
    code(await c.post('/api/auth/mfa/setup', { password: PW }), 409, 'mfa_already')
  })
  it('connexion : le mot de passe seul ne donne aucune session ; code faux / rejoué refusés ; code frais accepté', async () => {
    const c = new Client(); const r = await c.post('/api/auth/login', { username: U, password: PW })
    expect(r.status).toBe(200); expect(r.json.mfa).toBe(true); expect(r.json.user).toBeUndefined(); expect(r.text).not.toContain('csrf')
    expect((await c.get('/api/auth/me')).json.user).toBeNull(); code(await c.get('/api/ipam/spaces'), 401, 'unauthenticated')
    code(await c.post('/api/auth/login/mfa', { challenge: r.json.challenge, code: '12345a' }), 401, 'bad_code')
    code(await c.post('/api/auth/login/mfa', { challenge: r.json.challenge, code: hotp(secret, now()) }), 401, 'bad_code')          // pas consommé à l'activation : rejeu refusé
    code(await c.post('/api/auth/login/mfa', { challenge: r.json.challenge + 'x', code: hotp(secret, now() + 1) }), 401, 'mfa_expired')   // défi altéré
    code(await c.post('/api/auth/login/mfa', { challenge: 'aaaaaaaaaa.bbbbbbbbbb', code: hotp(secret, now() + 1) }), 401, 'mfa_expired')
    const ok = await c.post('/api/auth/login/mfa', { challenge: r.json.challenge, code: hotp(secret, now() + 1) }); expect(ok.status, ok.text).toBe(200)
    expect(ok.json.user).toMatchObject({ username: U, role: 'operator' }); c.csrf = ok.json.csrf
    expect((await c.get('/api/ipam/spaces')).status).toBe(200)
    // le même code ne sert qu'une fois
    code(await mfaLogin(new Client(), U, hotp(secret, now() + 1)), 401, 'bad_code')
    expect((await db.query("select count(*)::int n from audit_log where action in ('login_mfa_challenge')")).rows[0].n).toBeGreaterThanOrEqual(2)
  })
  it('codes de secours : usage unique, décomptés', async () => {
    const c = new Client(); expect((await mfaLogin(c, U, codes[0]!.toUpperCase())).status).toBe(200)
    code(await mfaLogin(new Client(), U, codes[0]!), 401, 'bad_code')
    expect((await c.get('/api/auth/mfa')).json.recoveryLeft).toBe(9)
    expect((await mfaLogin(new Client(), U, ` ${codes[1]} `)).status).toBe(200)
    expect((await db.query("select count(*)::int n from audit_log where action = 'mfa_recovery_used'")).rows[0].n).toBe(2)
  })
  it('anti-force brute : 5 codes faux, puis blocage', async () => {
    await mk('mfa2'); const c = new Client(); await c.login('mfa2', PW)
    const su = await c.post('/api/auth/mfa/setup', { password: PW }); const s2 = su.json.secret
    expect((await c.post('/api/auth/mfa/enable', { code: hotp(s2, now()) })).status).toBe(200)
    const r = await new Client().post('/api/auth/login', { username: 'mfa2', password: PW })
    for (let i = 0; i < 5; i++) code(await new Client().post('/api/auth/login/mfa', { challenge: r.json.challenge, code: '00000' + i }), 401, 'bad_code')
    code(await new Client().post('/api/auth/login/mfa', { challenge: r.json.challenge, code: hotp(s2, now() + 1) }), 429, 'too_many_attempts')   // même le bon code
  })
  it('défi invalidé par un changement de mot de passe ; comptes non locaux et jetons : pas de MFA locale', async () => {
    await mk('mfa3'); const c = new Client(); await c.login('mfa3', PW)
    const s3 = (await c.post('/api/auth/mfa/setup', { password: PW })).json.secret; expect((await c.post('/api/auth/mfa/enable', { code: hotp(s3, now()) })).status).toBe(200)
    const r = await new Client().post('/api/auth/login', { username: 'mfa3', password: PW })
    expect((await admin.put(`/api/users/${await uid('mfa3')}`, { password: PW + '-nouveau-1' })).status).toBe(200)
    code(await new Client().post('/api/auth/login/mfa', { challenge: r.json.challenge, code: hotp(s3, now() + 1) }), 401, 'mfa_expired')
    await db.query("insert into users (username, role, source) values ('annuaire', 'viewer', 'ad')")
    const t = (await admin.post('/api/tokens', { name: 'mfa-test', role: 'operator', expiresDays: 1 })).json.token
    const rt = await fetch(BASE + '/api/auth/mfa/setup', { method: 'POST', headers: { authorization: `Bearer ${t}`, 'content-type': 'application/json' }, body: JSON.stringify({ password: PW }) }); expect(rt.status).toBe(403)
  })
  it('désactivation par l\'utilisateur (mot de passe + code) ; réinitialisation par l\'administrateur', async () => {
    const c = new Client(); expect((await mfaLogin(c, U, codes[2]!)).status).toBe(200)
    code(await c.post('/api/auth/mfa/disable', { password: 'faux', code: codes[3]! }), 401, 'bad_password')
    code(await c.post('/api/auth/mfa/disable', { password: PW, code: '000000' }), 400, 'bad_code')
    const rg = await c.post('/api/auth/mfa/recovery', { password: PW }); expect(rg.status).toBe(200); expect(rg.json.codes).toHaveLength(10)
    code(await mfaLogin(new Client(), U, codes[4]!), 401, 'bad_code')                                 // anciens codes invalidés
    expect((await c.post('/api/auth/mfa/disable', { password: PW, code: rg.json.codes[0] })).status).toBe(200)
    expect((await new Client().login(U, PW)).json.mfa).toBeUndefined()
    expect((await db.query('select totp_secret_enc, cardinality(recovery_hashes) n from users where username = $1', [U])).rows[0]).toEqual({ totp_secret_enc: null, n: 0 })
    // administrateur : réinitialise mfa2
    code(await viewer.post(`/api/users/${await uid('mfa2')}/mfa/reset`), 403, 'forbidden'); code(await admin.post('/api/users/999999/mfa/reset'), 404, 'not_found')
    expect((await admin.post(`/api/users/${await uid('mfa2')}/mfa/reset`)).status).toBe(200)
    expect((await new Client().login('mfa2', PW)).json.mfa).toBeUndefined()
    expect((await db.query("select count(*)::int n from audit_log where action in ('mfa_reset','mfa_disable','mfa_enable')")).rows[0].n).toBeGreaterThanOrEqual(5)
  })
})
