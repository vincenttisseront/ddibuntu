// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : audit de sécurité 0.24.1 — chaque correctif a son refus attendu ET son fonctionnement légitime.
//  - première configuration : un seul administrateur sous requêtes simultanées, compteur d'échecs par adresse ;
//  - délégation par espaces IPAM : un opérateur restreint n'écrit pas dans une zone DNS qu'il choisit ;
//  - pages rendues par le serveur jamais en cache (elles portent l'utilisateur et le jeton CSRF), fichiers de l'interface non touchés ;
//  - journal d'audit : bornes de pagination ; deux comptes : le second ne reçoit jamais les données du premier.
import { execFileSync, spawn, type ChildProcess } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3492, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-sec-')); mkdirSync(join(TMP, 'gen'))
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
    return { status: r.status, json, text, headers: r.headers }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b); delete = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
const admin = new Client(), anon = new Client(), anon2 = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }

beforeAll(async () => {
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_ALLOW_UNVERIFIED_AUTH: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json') } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })

describe('première configuration', () => {
  it('requêtes simultanées avec le bon jeton : un seul administrateur est créé', async () => {
    const [a, b] = await Promise.all([
      anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'premier', password: PW }),
      anon2.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'second', password: PW }),
    ])
    const statuses = [a.status, b.status].sort()
    expect(statuses, `${a.text} ${b.text}\n${srvLog.slice(-800)}`).toEqual([200, 409])
    const loser = a.status === 409 ? a : b; code(loser, 409, 'already_configured')
    expect(Number((await db.query("select count(*) n from users where role = 'admin'")).rows[0].n)).toBe(1)
  })
  it('après la configuration : refusée, même avec le bon jeton', async () => {
    code(await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'troisieme', password: PW }), 409, 'already_configured')
    expect(Number((await db.query('select count(*) n from users')).rows[0].n)).toBe(1)
  })
  it('le compteur d\'échecs est tenu par adresse (jamais un compteur commun qui bloquerait l\'installation de tous)', async () => {
    await db.query('delete from users')
    code(await anon.post('/api/setup/admin', { token: 'mauvais-jeton-0123456789', username: 'x', password: PW }), 403, 'bad_setup_token')
    const rows = (await db.query("select username from login_attempts where not success and username like 'setup%'")).rows.map((r) => r.username)
    expect(rows).toEqual(['setup:127.0.0.1'])
    // le bon jeton fonctionne encore, et crée l'administrateur de la suite
    expect((await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })).status).toBe(200)
  })
})

describe('pages rendues par le serveur et en-têtes', () => {
  it('la page HTML n\'est jamais mise en cache ; l\'API non plus', async () => {
    const p = await fetch(BASE + '/login'); expect(p.status).toBe(200)
    expect(p.headers.get('cache-control')).toBe('no-store')
    expect(p.headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
    expect(p.headers.get('x-content-type-options')).toBe('nosniff')
    const a = await fetch(BASE + '/api/health'); expect(a.headers.get('cache-control')).toBe('no-store')
  })
  it('les fichiers de l\'interface ne reçoivent pas « no-store » (le cache du navigateur reste utile)', async () => {
    const html = await (await fetch(BASE + '/login')).text()
    const asset = /(?:src|href)="(\/_nuxt\/[^"]+\.(?:js|css))"/.exec(html)?.[1]
    expect(asset, 'aucun fichier /_nuxt/ trouvé dans la page de connexion').toBeTruthy()
    const r = await fetch(BASE + asset!); expect(r.status).toBe(200)
    expect(r.headers.get('cache-control') ?? '').not.toContain('no-store')
    expect((await fetch(BASE + '/favicon.svg')).headers.get('cache-control') ?? '').not.toContain('no-store')
  })
  it('deux comptes : la page du second ne contient ni le nom ni le jeton CSRF du premier', async () => {
    expect((await admin.login('admin', PW)).status).toBe(200)
    expect((await admin.post('/api/users', { username: 'lecteur', role: 'viewer', password: PW })).status).toBe(200)
    const viewer = new Client(); expect((await viewer.login('lecteur', PW)).status).toBe(200)
    const page = async (c: Client) => (await fetch(BASE + '/', { headers: { cookie: c.cookie } })).text()
    const pa = await page(admin), pv = await page(viewer)
    expect(pa).toContain(admin.csrf); expect(pv).toContain(viewer.csrf)          // chaque page porte SON jeton…
    expect(pv).not.toContain(admin.csrf); expect(pa).not.toContain(viewer.csrf)   // …et jamais celui de l'autre, quel que soit l'ordre des requêtes
    expect(pv).not.toContain('"admin"')
    expect(await page(admin)).toContain(admin.csrf)                              // relecture après le passage du second : toujours le sien
    const anonPage = await (await fetch(BASE + '/')).text()
    expect(anonPage).not.toContain(admin.csrf); expect(anonPage).not.toContain(viewer.csrf)
  })
})

describe('journal d\'audit : bornes', () => {
  it('un décalage négatif ou non numérique est refusé (400), pas une erreur interne', async () => {
    code(await admin.get('/api/audit?offset=-5'), 400, 'invalid_query')
    code(await admin.get('/api/audit?limit=abc'), 400, 'invalid_query')
    expect(srvLog).not.toMatch(/erreur interne/)
  })
  it('usage normal : limite bornée à 500, décalage accepté', async () => {
    const r = await admin.get('/api/audit?limit=100000&offset=0'); expect(r.status).toBe(200); expect(r.json.items.length).toBeLessThanOrEqual(500)
    expect((await admin.get('/api/audit?limit=2&offset=1')).json.items.length).toBeLessThanOrEqual(2)
  })
})

describe('délégation par espaces IPAM : zone DNS imposée par le gabarit', () => {
  const sc = new Client()
  let spaceId = 0, subnetId = 0, tplZone = 0, otherZone = 0
  it('préparation : deux zones, un gabarit rattaché à la première, un opérateur restreint', async () => {
    tplZone = (await admin.post('/api/dns/zones', { name: 'delegue.exemple.test', type: 'primary' })).json.id
    otherZone = (await admin.post('/api/dns/zones', { name: 'central.exemple.test', type: 'primary' })).json.id
    expect([tplZone, otherZone].every(Boolean)).toBe(true)
    const tpl = await admin.post('/api/ipam/templates', { name: 'agence', create_scope: false, dns_zone_id: tplZone }); expect(tpl.status, tpl.text).toBe(200)
    spaceId = (await admin.post('/api/ipam/spaces', { name: 'Agence' })).json.id
    const sn = await admin.post('/api/ipam/subnets', { cidr: '10.77.0.0/24', name: 'agence', space_id: spaceId, template_id: tpl.json.id }); expect(sn.status, sn.text).toBe(200); subnetId = sn.json.id
    expect((await admin.post('/api/users', { username: 'agence', role: 'operator', password: PW, space_ids: [spaceId] })).status).toBe(200)
    expect((await sc.login('agence', PW)).json.user.spaceIds).toEqual([spaceId])
  })
  it('refus : l\'opérateur restreint ne peut pas écrire dans une zone qu\'il choisit (et rien n\'est créé)', async () => {
    code(await sc.post(`/api/ipam/subnets/${subnetId}/addresses`, { ip: '10.77.0.10', status: 'used', hostname: 'intrus', dns_zone_id: otherZone }), 403, 'out_of_scope')
    code(await sc.post(`/api/ipam/subnets/${subnetId}/next`, { hostname: 'intrus2', dns_zone_id: otherZone }), 403, 'out_of_scope')
    expect(Number((await db.query('select count(*) n from dns_records where zone_id = $1', [otherZone])).rows[0].n)).toBe(0)
    expect(Number((await db.query("select count(*) n from addresses where ip = '10.77.0.10'")).rows[0].n)).toBe(0)   // la transaction est annulée
  })
  it('légitime : sans choix, la zone du gabarit est utilisée ; la zone du gabarit demandée explicitement aussi ; « aucune zone » aussi', async () => {
    const a = await sc.post(`/api/ipam/subnets/${subnetId}/addresses`, { ip: '10.77.0.11', status: 'used', hostname: 'poste1' }); expect(a.status, a.text).toBe(200); expect(a.json.dns).toBe(true)
    const b = await sc.post(`/api/ipam/subnets/${subnetId}/addresses`, { ip: '10.77.0.12', status: 'used', hostname: 'poste2', dns_zone_id: tplZone }); expect(b.status, b.text).toBe(200); expect(b.json.dns).toBe(true)
    const c2 = await sc.post(`/api/ipam/subnets/${subnetId}/addresses`, { ip: '10.77.0.13', status: 'used', hostname: 'poste3', dns_zone_id: null }); expect(c2.status, c2.text).toBe(200); expect(c2.json.dns).toBe(false)
    const n = await sc.post(`/api/ipam/subnets/${subnetId}/next`, { hostname: 'poste4' }); expect(n.status, n.text).toBe(200); expect(n.json.dns).toBe(true)
    const names = (await db.query("select name from dns_records where zone_id = $1 and type = 'A' order by name", [tplZone])).rows.map((r) => r.name)
    expect(names).toEqual(['poste1', 'poste2', 'poste4'])
    expect(Number((await db.query('select count(*) n from dns_records where zone_id = $1', [otherZone])).rows[0].n)).toBe(0)
  })
  it('un administrateur (sans périmètre) choisit toujours la zone', async () => {
    const r = await admin.post(`/api/ipam/subnets/${subnetId}/addresses`, { ip: '10.77.0.20', status: 'used', hostname: 'central1', dns_zone_id: otherZone }); expect(r.status, r.text).toBe(200); expect(r.json.dns).toBe(true)
    expect(Number((await db.query("select count(*) n from dns_records where zone_id = $1 and name = 'central1'", [otherZone])).rows[0].n)).toBe(1)
  })
})

describe('démarrage de la console de production', () => {
  // même environnement que l'appliance (HTTPS fourni par console-start) avec un réglage « test » : la console refuse de démarrer, elle ne bascule pas en mode permissif
  // certificat auto-signé jetable (exemple.test) : Nitro lit le PEM à la création du serveur HTTPS, avant le plugin de garde
  beforeAll(() => { execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=console.exemple.test', '-keyout', join(TMP, 'tls.key'), '-out', join(TMP, 'tls.crt')], { stdio: 'ignore' }) })
  const boot = (extra: Record<string, string>) => new Promise<{ code: number | null; out: string }>((resolve) => {
    const p = spawn('node', ['.output/server/index.mjs'], { env: { PATH: process.env.PATH ?? '', NODE_ENV: 'production', PORT: '3493', NITRO_HOST: '127.0.0.1', NITRO_SSL_CERT: readFileSync(join(TMP, 'tls.crt'), 'utf8'), NITRO_SSL_KEY: readFileSync(join(TMP, 'tls.key'), 'utf8'), DDI_DATABASE_URL: DBURL, DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_GENERATED_DIR: join(TMP, 'gen'), ...extra } })
    let out = ''; p.stdout!.on('data', (d) => { out += d }); p.stderr!.on('data', (d) => { out += d })
    const t = setTimeout(() => { p.kill('SIGKILL') }, 20000)
    p.on('exit', (c) => { clearTimeout(t); resolve({ code: c, out }) })
  })
  it('DDI_TEST_MODE=1 avec le certificat du service : arrêt immédiat, message explicite', async () => {
    const r = await boot({ DDI_TEST_MODE: '1' })
    expect(r.code).not.toBe(0); expect(r.out).toContain('DDI_TEST_MODE=1 est réservé aux tests')
  }, 30000)
  it('DDI_OIDC_ALLOW_HTTP=1 avec le certificat du service : arrêt immédiat', async () => {
    const r = await boot({ DDI_OIDC_ALLOW_HTTP: '1' })
    expect(r.code).not.toBe(0); expect(r.out).toContain('DDI_OIDC_ALLOW_HTTP=1 est réservé aux tests')
  }, 30000)
})
