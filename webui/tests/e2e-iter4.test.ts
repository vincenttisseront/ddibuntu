// Bout en bout (serveur CONSTRUIT, PostgreSQL réel, outils BIND/Kea réels) : points de restauration, retour arrière,
// import NetBox, import AD (transfert de zone), découverte réseau.
import { spawn, type ChildProcess } from 'node:child_process'
import { chmodSync, mkdtempSync, existsSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3398, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-i4-')), GEN = join(TMP, 'gen'), STATUS = join(TMP, 'reload-status'), DIG = join(TMP, 'dig')
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
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b); del = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
const admin = new Client(), operator = new Client(), viewer = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 150)) } throw new Error('délai dépassé') }
const rows = async (sql: string, p: unknown[] = []) => (await db.query(sql, p)).rows

// ---- Faux NetBox (HTTP : autorisé en mode test) ----
let nb: http.Server, nbPort = 0
let NBDATA: { vlans: any[]; prefixes: any[]; addresses: any[] } = { vlans: [], prefixes: [], addresses: [] }
const NB_TOKEN = 'nb-jeton-secret-0123456789'
const nbBase = () => `http://127.0.0.1:${nbPort}`
// ---- Faux dig : renvoie un transfert de zone pour corp.example.com depuis dc1 ----
const AXFR = ['corp.example.com.\t3600\tIN\tSOA\tdc1.corp.example.com. hostmaster.corp.example.com. 77 900 600 86400 3600', 'corp.example.com.\t600\tIN\tNS\tdc1.corp.example.com.',
  'dc1.corp.example.com.\t3600\tIN\tA\t10.0.0.10', 'srv.corp.example.com.\t3600\tIN\tA\t10.0.0.20', '_ldap._tcp.dc._msdcs.corp.example.com.\t600\tIN\tSRV\t0 100 389 dc1.corp.example.com.',
  'corp.example.com.\t3600\tIN\tSOA\tdc1.corp.example.com. hostmaster.corp.example.com. 77 900 600 86400 3600']
// ---- Écouteur TCP pour la découverte ----
let lis: net.Server, lisPort = 0

beforeAll(async () => {
  expect(existsSync('.output/server/index.mjs'), 'lancer « nuxt build » avant les tests').toBe(true)
  writeFileSync(DIG, `#!/bin/bash\nif [ "$1" = "@dc1.corp.example.com" ] && [ "$2" = "corp.example.com" ]; then cat <<'EOF'\n${AXFR.join('\n')}\nEOF\nfi\nexit 0\n`); chmodSync(DIG, 0o755)
  nb = http.createServer((req, res) => {
    const send = (c: number, b: unknown) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)) }
    if (req.headers.authorization !== `Token ${NB_TOKEN}`) return send(403, { detail: 'refusé' })
    const u = new URL(req.url!, nbBase())
    if (u.pathname === '/api/status/') return send(200, { 'netbox-version': '4.2.1' })
    const key = ({ '/api/ipam/vlans/': 'vlans', '/api/ipam/prefixes/': 'prefixes', '/api/ipam/ip-addresses/': 'addresses' } as any)[u.pathname]
    if (!key) return send(404, {})
    const all = (NBDATA as any)[key] as any[], off = Number(u.searchParams.get('offset') ?? 0), lim = Number(u.searchParams.get('limit') ?? 1000)
    // petites pages pour exercer la pagination
    const size = Math.min(lim, 2), part = all.slice(off, off + size)
    send(200, { count: all.length, next: off + size < all.length ? `${nbBase()}${u.pathname}?limit=${lim}&offset=${off + size}` : null, results: part })
  })
  await new Promise<void>((r) => nb.listen(0, '127.0.0.1', r)); nbPort = (nb.address() as any).port
  lis = net.createServer((s) => s.destroy()); await new Promise<void>((r) => lis.listen(0, '127.0.0.2', r)); lisPort = (lis.address() as any).port
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_ALLOW_PRIVATE_FETCH: '1', DDI_DIG: DIG, DDI_RELOAD_STATUS: STATUS } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n--- journal du serveur ---\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await operator.login('oper', PW)).status).toBe(200); expect((await viewer.login('lect', PW)).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end(); nb?.close(); lis?.close() })

const mk = async () => {
  const vlan = (await admin.post('/api/ipam/vlans', { vlan_id: 30, name: 'Manuel' })).json
  const s1 = (await admin.post('/api/ipam/subnets', { cidr: '10.10.0.0/24', name: 'LAN A', site: 'Paris' })).json
  const s2 = (await admin.post('/api/ipam/subnets', { cidr: '10.20.0.0/24', name: 'LAN B' })).json
  await admin.post(`/api/ipam/subnets/${s1.id}/addresses`, { ip: '10.10.0.5', status: 'used', hostname: 'srv05' })
  const z = (await admin.post('/api/dns/zones', { name: 'lab.example.com', type: 'primary', soa_mname: 'ns1.lab.example.com.', soa_rname: 'hostmaster.lab.example.com.' })).json
  await admin.post('/api/dns/records', { zone_id: z.id, name: '@', type: 'NS', rdata: 'ns1.lab.example.com.' })
  await admin.post('/api/dns/records', { zone_id: z.id, name: 'ns1', type: 'A', rdata: '10.10.0.2' })
  await admin.post('/api/dns/records', { zone_id: z.id, name: 'www', type: 'A', rdata: '10.10.0.80' })
  return { vlan, s1, s2, z }
}
let W: Awaited<ReturnType<typeof mk>>

describe('points de restauration des données', () => {
  it('migration 2 appliquée, version 0.4.0', async () => {
    const i = (await admin.get('/api/system/info')).json
    expect([i.schema, i.version]).toEqual([4, '0.4.0'])   // 1 socle, 2 points de restauration/origine IPAM, 3 journal des requêtes, 4 espaces/conteneurs/pools IPAM
    expect((await rows("select column_name from information_schema.columns where table_name = 'addresses' and column_name in ('source','external_id','last_seen') order by 1")).map((r) => r.column_name)).toEqual(['external_id', 'last_seen', 'source'])
  })
  it('droits : lecteur refusé, opérateur peut créer un point, seul l\'administrateur restaure, supprime, épingle', async () => {
    W = await mk()
    code(await viewer.post('/api/snapshots', { label: 'x' }), 403, 'forbidden'); code(await viewer.get('/api/snapshots'), 403, 'forbidden')
    const id = (await operator.post('/api/snapshots', { label: 'par opérateur' })).json.id; expect(id).toBeGreaterThan(0)
    code(await operator.post(`/api/snapshots/${id}/restore`, {}), 403, 'forbidden'); code(await operator.del(`/api/snapshots/${id}`), 403, 'forbidden'); code(await operator.get(`/api/snapshots/${id}/diff`), 403, 'forbidden')
    code(await anon.get('/api/snapshots'), 401, 'unauthenticated')
  })
  let snapA = 0, snapB = 0
  it('un point contient les données ; jamais de secret ni de table sensible', async () => {
    snapA = (await admin.post('/api/snapshots', { label: 'état A' })).json.id
    const meta = (await admin.get('/api/snapshots')).json.items.find((s: any) => s.id === snapA)
    expect(meta).toMatchObject({ kind: 'manual', label: 'état A', username: 'admin', pinned: false })
    expect(meta.counts).toMatchObject({ vlans: 1, subnets: 2, addresses: 1, dns_zones: 1, dns_records: 3 })
    const raw = JSON.stringify((await rows('select data from config_snapshots where id = $1', [snapA]))[0].data)
    expect(raw).not.toMatch(/password_hash|token_hash|csrf|session/i)
    expect(Object.keys((await rows('select data from config_snapshots where id = $1', [snapA]))[0].data).sort()).toEqual(['addresses', 'dhcp_pools', 'dhcp_reservations', 'dhcp_scopes', 'dns_records', 'dns_zones', 'filter_rules', 'ipam_pools', 'ipam_spaces', 'settings', 'subnets', 'vlans'])
  })
  it('diff : annonce ce que fera la restauration (supprimé / rétabli / modifié)', async () => {
    await admin.del(`/api/ipam/subnets/${W.s2.id}`)                                  // sera rétabli
    await admin.post('/api/ipam/subnets', { cidr: '10.30.0.0/24', name: 'LAN C' })      // sera supprimé
    const rec = (await admin.get(`/api/dns/records?zone_id=${W.z.id}`)).json.items.find((r: any) => r.name === 'www')
    await admin.put(`/api/dns/records/${rec.id}`, { zone_id: W.z.id, name: 'www', type: 'A', rdata: '10.10.0.99' })   // sera modifié
    snapB = (await admin.post('/api/snapshots', { label: 'état B' })).json.id
    const d = (await admin.get(`/api/snapshots/${snapA}/diff`)).json.diff
    expect(d.subnets).toMatchObject({ removed: 1, restored: 1, changed: 0 }); expect(d.subnets.samples.removed).toEqual(['10.30.0.0/24']); expect(d.subnets.samples.restored).toEqual(['10.20.0.0/24'])
    expect(d.dns_records).toMatchObject({ changed: 1 }); expect(d.dns_records.samples.changed[0]).toContain('www')
    expect((await admin.get(`/api/snapshots/${snapB}/diff`)).json.diff).toEqual({})    // identique à l'état courant : rien à faire
    code(await admin.get('/api/snapshots/999999/diff'), 404, 'not_found')
  })
  it('restauration : les données reviennent, l\'état d\'avant est conservé, et c\'est réversible', async () => {
    const before = (await rows('select serial::text as s from dns_zones'))[0].s
    const r = await admin.post(`/api/snapshots/${snapA}/restore`, {}); expect(r.status).toBe(200)
    const subs = (await admin.get('/api/ipam/subnets')).json.items.map((s: any) => s.cidr).sort()
    expect(subs).toEqual(['10.10.0.0/24', '10.20.0.0/24'])
    const www = (await admin.get(`/api/dns/records?zone_id=${W.z.id}`)).json.items.find((x: any) => x.name === 'www'); expect(www.rdata).toBe('10.10.0.80')
    expect((await rows("select kind, label from config_snapshots where id = $1", [r.json.preSnapshot]))[0]).toMatchObject({ kind: 'pre-restore' })
    // le numéro de série de zone ne baisse JAMAIS (un secondaire ignorerait la zone) et la zone est à redéployer
    const z = (await rows('select serial::text as s, dirty from dns_zones'))[0]; expect(BigInt(z.s)).toBeGreaterThan(BigInt(before)); expect(z.dirty).toBe(true)
    // retour à l'état d'avant la restauration
    expect((await admin.post(`/api/snapshots/${r.json.preSnapshot}/restore`, {})).status).toBe(200)
    expect((await admin.get('/api/ipam/subnets')).json.items.map((s: any) => s.cidr).sort()).toEqual(['10.10.0.0/24', '10.30.0.0/24'])
    expect((await admin.get(`/api/dns/records?zone_id=${W.z.id}`)).json.items.find((x: any) => x.name === 'www').rdata).toBe('10.10.0.99')
    // les séquences repartent après le plus grand identifiant : une création ne doit pas entrer en collision
    expect((await admin.post('/api/ipam/subnets', { cidr: '10.40.0.0/24', name: 'après restauration' })).status).toBe(200)
  })
  it('restauration ATOMIQUE : un point corrompu est refusé et la base reste exactement comme avant', async () => {
    const bad = (await admin.post('/api/snapshots', { label: 'à corrompre' })).json.id
    await db.query(`update config_snapshots set data = jsonb_set(data, '{addresses}', '[{"id":999,"subnet_id":424242,"ip":"10.9.9.9","status":"used","source":"manual"}]'::jsonb) where id = $1`, [bad])
    const snapshot = JSON.stringify(await rows('select id, cidr::text from subnets order by id')), nBefore = (await rows('select count(*)::int as n from config_snapshots'))[0].n
    const r = await admin.post(`/api/snapshots/${bad}/restore`, {}); expect(r.status).toBeGreaterThanOrEqual(400)
    expect(JSON.stringify(await rows('select id, cidr::text from subnets order by id'))).toBe(snapshot)
    expect((await rows('select count(*)::int as n from config_snapshots'))[0].n).toBe(nBefore)   // même le point « avant restauration » a été annulé
  })
  it('un point d\'une autre version du schéma n\'est pas restauré', async () => {
    const id = (await admin.post('/api/snapshots', { label: 'ancien format' })).json.id
    await db.query('update config_snapshots set schema_version = 1 where id = $1', [id])
    code(await admin.post(`/api/snapshots/${id}/restore`, {}), 409, 'snapshot_schema_mismatch')
  })
  it('épingler, renommer, supprimer ; conservation limitée sans jamais perdre un point épinglé', async () => {
    const keep = (await admin.post('/api/snapshots', { label: 'à garder' })).json.id
    expect((await admin.put(`/api/snapshots/${keep}`, { pinned: true, label: 'épinglé' })).json).toMatchObject({ pinned: true, label: 'épinglé' })
    for (let i = 0; i < 45; i++) await operator.post('/api/snapshots', { label: `bulk ${i}` })
    const list = (await admin.get('/api/snapshots')).json.items
    expect(list.some((s: any) => s.id === keep && s.pinned)).toBe(true)
    expect((await rows('select count(*)::int as n from config_snapshots where not pinned'))[0].n).toBeLessThanOrEqual(61)
    expect((await rows("select count(*)::int as n from config_snapshots where label = 'bulk 44'"))[0].n).toBe(1)   // les plus récents sont gardés
    expect((await admin.del(`/api/snapshots/${keep}`)).status).toBe(200); code(await admin.del(`/api/snapshots/${keep}`), 404, 'not_found')
  })
})

describe('déploiement : point de restauration et résultat réel', () => {
  it('chaque déploiement prend un point de l\'état déployé, relié à l\'historique', async () => {
    const r = await admin.post('/api/system/apply', { deploy: true }); expect(r.json).toMatchObject({ ok: true, deployed: true })
    const d = (await admin.get('/api/system/deployments')).json.items[0]
    expect(d.snapshot_id).toBeGreaterThan(0); expect(d.applied).toBeNull()
    expect((await rows('select kind from config_snapshots where id = $1', [d.snapshot_id]))[0].kind).toBe('deploy')
  })
  it('résultat réel du rechargement privilégié : succès, puis échec avec retour arrière automatique', async () => {
    expect((await admin.get('/api/system/reload-status')).json.status).toBeNull()   // pas encore de fichier
    const at = Math.floor(Date.now() / 1000) + 5
    writeFileSync(STATUS, `at=${at}\nok=1\nmessage=configuration appliquée\n`)
    expect((await admin.get('/api/system/reload-status')).json.status).toMatchObject({ ok: true, message: 'configuration appliquée' })
    expect((await admin.get('/api/system/deployments')).json.items[0]).toMatchObject({ applied: true, apply_message: 'configuration appliquée' })
    await admin.post('/api/system/apply', { deploy: true })
    writeFileSync(STATUS, `at=${at + 10}\nok=0\nmessage=Kea ne démarre pas (retour arrière automatique effectué)\n`)
    await admin.get('/api/system/reload-status')
    expect((await admin.get('/api/system/deployments')).json.items[0]).toMatchObject({ applied: false })
    expect((await admin.get('/api/system/deployments')).json.items[0].apply_message).toContain('retour arrière automatique')
    writeFileSync(STATUS, 'n’importe quoi'); expect((await admin.get('/api/system/reload-status')).json.status).toBeNull()   // fichier illisible : pas de plantage
  })
  it('revenir à un déploiement précédent : restauration + redéploiement validé', async () => {
    const first = (await admin.get('/api/system/deployments')).json.items.at(-1)
    await admin.post('/api/ipam/subnets', { cidr: '10.77.0.0/24', name: 'après le déploiement' })
    const r = await admin.post(`/api/snapshots/${first.snapshot_id}/restore`, { deploy: true })
    expect(r.status).toBe(200); expect(r.json.applied).toMatchObject({ ok: true, deployed: true })
    expect((await admin.get('/api/ipam/subnets')).json.items.some((s: any) => s.cidr === '10.77.0.0/24')).toBe(false)
  })
})

describe('imports : point de restauration automatique et annulation', () => {
  it('import CSV : un point est pris AVANT l\'écriture ; « annuler » le restaure', async () => {
    const before = (await admin.get('/api/ipam/subnets')).json.items.length
    const r = await admin.post('/api/import/ipam-csv/commit', { kind: 'subnets', content: 'cidr,name\n10.55.0.0/24,Importé\n10.56.0.0/24,Importé 2\n', filename: 'sn.csv' })
    expect(r.json).toMatchObject({ created: 2 }); expect(r.json.snapshotId).toBeGreaterThan(0)
    expect((await admin.get('/api/import/runs')).json.items[0]).toMatchObject({ kind: 'csv-subnets', snapshot_id: r.json.snapshotId })
    expect((await admin.get('/api/ipam/subnets')).json.items.length).toBe(before + 2)
    expect((await admin.post(`/api/snapshots/${r.json.snapshotId}/restore`, {})).status).toBe(200)
    expect((await admin.get('/api/ipam/subnets')).json.items.length).toBe(before)
  })
  it('import DNS : même garantie', async () => {
    const z = (await admin.get('/api/dns/zones')).json.items[0]
    const r = await admin.post('/api/import/dns/commit', { zone_id: z.id, content: '$ORIGIN lab.example.com.\nnouveau 300 IN A 10.10.0.123\n', filename: 'z.txt' })
    expect(r.json).toMatchObject({ inserted: 1 }); expect(r.json.snapshotId).toBeGreaterThan(0)
    await admin.post(`/api/snapshots/${r.json.snapshotId}/restore`, {})
    expect((await admin.get(`/api/dns/records?zone_id=${z.id}`)).json.items.some((x: any) => x.name === 'nouveau')).toBe(false)
  })
  it('une erreur d\'import ne laisse pas de modification partielle (le point reste disponible)', async () => {
    const n = (await rows('select count(*)::int as n from subnets'))[0].n
    const r = await admin.post('/api/import/ipam-csv/commit', { kind: 'subnets', content: 'cidr,name\npas-un-cidr,X\n', filename: 'bad.csv' })
    expect(r.json.created).toBe(0); expect((await rows('select count(*)::int as n from subnets'))[0].n).toBe(n)
  })
})

describe('import NetBox', () => {
  const body = (over: object = {}) => ({ url: nbBase(), tlsVerify: true, include: { vlans: true, prefixes: true, addresses: true }, mode: 'add', prune: false, includeContainers: false, token: NB_TOKEN, ...over })
  const seed = () => {
    NBDATA = {
      vlans: [{ id: 1, vid: 100, name: 'NB-Serveurs' }, { id: 2, vid: 200, name: 'NB-Postes' }, { id: 3, vid: 300, name: 'NB-Voix' }],
      prefixes: [{ id: 11, prefix: '172.20.0.0/24', description: 'DC Paris', status: { value: 'active' }, vlan: { vid: 100 }, scope: { name: 'Paris' }, tags: [{ slug: 'prod' }] }, { id: 12, prefix: '172.21.0.0/24', description: 'Postes', status: { value: 'active' }, vlan: { vid: 200 } }, { id: 13, prefix: '172.16.0.0/12', status: { value: 'container' } }],
      addresses: [{ id: 21, address: '172.20.0.1/24', status: { value: 'active' }, role: { value: 'gateway' }, dns_name: 'gw.dc.example.com' }, { id: 22, address: '172.20.0.10/24', status: { value: 'active' }, dns_name: 'srv10.dc.example.com', description: 'Serveur 10' },
        { id: 23, address: '172.21.0.5/24', status: { value: 'dhcp' } }, { id: 24, address: '192.0.2.50/24', status: { value: 'active' } }],
    }
  }
  it('réservé aux administrateurs', async () => {
    for (const [m, p] of [['GET', '/api/netbox/settings'], ['PUT', '/api/netbox/settings'], ['POST', '/api/netbox/test'], ['POST', '/api/netbox/preview'], ['POST', '/api/netbox/commit']] as const) code(await operator.req(m, p, m === 'GET' ? undefined : {}), 403, 'forbidden')
    code(await anon.get('/api/netbox/settings'), 401, 'unauthenticated')
  })
  it('paramètres : URL contrôlée ; le jeton n\'est conservé que sur demande, chiffré, et jamais renvoyé', async () => {
    code(await admin.put('/api/netbox/settings', { ...body({ url: 'ftp://nb.example.com' }), rememberToken: false }), 400, 'netbox_url_invalid')
    code(await admin.put('/api/netbox/settings', { ...body({ url: 'http://169.254.169.254/' }), rememberToken: false }), 400, 'netbox_url_forbidden')
    expect((await admin.put('/api/netbox/settings', { ...body(), rememberToken: false })).status).toBe(200)
    expect((await admin.get('/api/netbox/settings')).json).toMatchObject({ url: nbBase(), tokenSet: false, mode: 'add' })
    expect((await admin.put('/api/netbox/settings', { ...body(), rememberToken: true })).status).toBe(200)
    const g = await admin.get('/api/netbox/settings'); expect(g.json.tokenSet).toBe(true); expect(g.text).not.toContain(NB_TOKEN)
    const stored = JSON.stringify((await rows("select value from settings where key = 'netbox'"))[0].value); expect(stored).not.toContain(NB_TOKEN); expect(stored).toContain('tokenEnc')
    expect((await admin.post('/api/netbox/test', { url: nbBase(), tlsVerify: true })).json).toMatchObject({ ok: true, version: '4.2.1' })   // jeton relu du coffre
    await admin.put('/api/netbox/settings', { ...body(), rememberToken: false })
    code(await admin.post('/api/netbox/test', { url: nbBase(), tlsVerify: true }), 400, 'netbox_token_missing')
  })
  it('test de connexion : mauvais jeton refusé, serveur injoignable signalé', async () => {
    code(await admin.post('/api/netbox/test', { url: nbBase(), tlsVerify: true, token: 'mauvais' }), 401, 'netbox_auth')
    expect((await admin.post('/api/netbox/test', { url: nbBase(), tlsVerify: true, token: NB_TOKEN })).json).toMatchObject({ ok: true })
    code(await admin.post('/api/netbox/test', { url: 'http://127.0.0.1:1/', tlsVerify: true, token: NB_TOKEN }), 502, 'netbox_unreachable')
  })
  let planId = ''
  it('aperçu : AUCUNE écriture ; pagination lue ; conteneur ignoré ; adresse sans sous-réseau comptée', async () => {
    seed(); const n = (await rows('select (select count(*) from subnets)::int s, (select count(*) from vlans)::int v, (select count(*) from addresses)::int a'))[0]
    const r = (await admin.post('/api/netbox/preview', body())).json
    expect(r.fetched).toEqual({ vlans: 3, prefixes: 3, addresses: 4 })
    expect(r.stats.vlans.created).toBe(3); expect(r.stats.subnets.created).toBe(2); expect(r.stats.skipped.containers).toBe(1); expect(r.stats.addresses).toMatchObject({ created: 3, no_subnet: 1 })
    expect(r.samples.subnets).toEqual(['172.20.0.0/24', '172.21.0.0/24'])
    expect((await rows('select (select count(*) from subnets)::int s, (select count(*) from vlans)::int v, (select count(*) from addresses)::int a'))[0]).toEqual(n)
    planId = r.planId; expect(planId).toMatch(/^[0-9a-f-]{36}$/)
  })
  it('import : écrit exactement ce qui a été prévisualisé, marque l\'origine, prend un point de restauration', async () => {
    const r = (await admin.post('/api/netbox/commit', { planId })).json
    expect(r.stats ?? r).toBeTruthy(); expect(r.snapshotId).toBeGreaterThan(0)
    expect(r.subnets.created).toBe(2); expect(r.addresses.created).toBe(3)
    const s = await rows("select text(cidr) as c, name, site, tags, source, external_id, (select vlan_id from vlans v where v.id = s.vlan_id) as vid from subnets s where source = 'netbox' order by cidr")
    expect(s).toEqual([{ c: '172.20.0.0/24', name: 'DC Paris', site: 'Paris', tags: ['prod'], source: 'netbox', external_id: '11', vid: 100 }, { c: '172.21.0.0/24', name: 'Postes', site: null, tags: [], source: 'netbox', external_id: '12', vid: 200 }])
    const a = await rows("select host(ip) as ip, status, hostname, description, source from addresses where source = 'netbox' order by ip")
    expect(a).toEqual([{ ip: '172.20.0.1', status: 'gateway', hostname: 'gw.dc.example.com', description: null, source: 'netbox' }, { ip: '172.20.0.10', status: 'used', hostname: 'srv10.dc.example.com', description: 'Serveur 10', source: 'netbox' }, { ip: '172.21.0.5', status: 'dhcp', hostname: null, description: null, source: 'netbox' }])
    expect((await admin.get('/api/import/runs')).json.items[0]).toMatchObject({ kind: 'netbox', snapshot_id: r.snapshotId })
    code(await admin.post('/api/netbox/commit', { planId }), 404, 'plan_expired')   // un aperçu ne sert qu'une fois
    code(await admin.post('/api/netbox/commit', { planId: 'pas-un-uuid' }), 400, 'validation')
  })
  it('le jeton n\'apparaît NULLE PART : ni journal d\'audit, ni historique, ni journal du serveur', async () => {
    expect(JSON.stringify(await rows('select detail from audit_log'))).not.toContain(NB_TOKEN)
    expect(JSON.stringify(await rows('select summary from import_runs'))).not.toContain(NB_TOKEN); expect(srvLog).not.toContain(NB_TOKEN)
  })
  it('synchronisation : modifie ce qui vient de NetBox, conserve le manuel, supprime les disparus seulement sur demande', async () => {
    await admin.post('/api/ipam/subnets', { cidr: '172.22.0.0/24', name: 'Manuel' })
    const manual = await admin.post('/api/ipam/subnets/' + (await rows("select id from subnets where cidr = '172.20.0.0/24'"))[0].id + '/addresses', { ip: '172.20.0.77', status: 'used', hostname: 'manuel77' })
    expect(manual.status).toBe(200)
    NBDATA.vlans[0].name = 'NB-Serveurs-V2'; NBDATA.prefixes[0].description = 'DC Paris v2'; NBDATA.addresses[1].dns_name = 'srv10-bis.dc.example.com'
    NBDATA.addresses = NBDATA.addresses.filter((x: any) => x.id !== 23)   // disparue de NetBox
    const p = (await admin.post('/api/netbox/preview', body({ mode: 'sync' }))).json
    expect(p.stats.vlans).toMatchObject({ updated: 1, unchanged: 2 }); expect(p.stats.subnets).toMatchObject({ updated: 1, unchanged: 1 }); expect(p.stats.addresses).toMatchObject({ updated: 1, unchanged: 1 })
    expect(p.stats.pruned).toEqual({ vlans: 0, addresses: 0 })
    await admin.post('/api/netbox/commit', { planId: p.planId })
    expect((await rows("select name from vlans where vlan_id = 100"))[0].name).toBe('NB-Serveurs-V2'); expect((await rows("select hostname from addresses where ip = '172.20.0.10'"))[0].hostname).toBe('srv10-bis.dc.example.com')
    expect((await rows("select count(*)::int n from addresses where ip = '172.21.0.5'"))[0].n).toBe(1)   // pas supprimée sans « prune »
    const p2 = (await admin.post('/api/netbox/preview', body({ mode: 'sync', prune: true }))).json
    expect(p2.stats.pruned).toEqual({ vlans: 0, addresses: 1 })
    await admin.post('/api/netbox/commit', { planId: p2.planId })
    expect((await rows("select count(*)::int n from addresses where ip = '172.21.0.5'"))[0].n).toBe(0)
    expect((await rows("select count(*)::int n from addresses where ip = '172.20.0.77'"))[0].n).toBe(1)   // l'adresse manuelle n'est JAMAIS supprimée
    expect((await rows("select count(*)::int n from subnets where cidr = '172.22.0.0/24'"))[0].n).toBe(1)
  })
  it('une ligne saisie à la main n\'est écrasée que par le mode « écraser »', async () => {
    await admin.post('/api/ipam/vlans', { vlan_id: 400, name: 'Mon VLAN' }); NBDATA.vlans.push({ id: 4, vid: 400, name: 'NB-400' })
    const keep = (await admin.post('/api/netbox/preview', body({ mode: 'sync' }))).json; expect(keep.stats.vlans.kept_manual).toBe(1)
    await admin.post('/api/netbox/commit', { planId: keep.planId }); expect((await rows('select name, source from vlans where vlan_id = 400'))[0]).toEqual({ name: 'Mon VLAN', source: 'manual' })
    const ow = (await admin.post('/api/netbox/preview', body({ mode: 'sync_overwrite' }))).json; await admin.post('/api/netbox/commit', { planId: ow.planId })
    expect((await rows('select name, source from vlans where vlan_id = 400'))[0]).toEqual({ name: 'NB-400', source: 'netbox' })
  })
  it('annuler l\'import : le point de restauration ramène l\'IPAM d\'avant', async () => {
    const snap = (await admin.get('/api/import/runs')).json.items.filter((r: any) => r.kind === 'netbox').at(-1).snapshot_id   // le PLUS ANCIEN : avant tout import NetBox
    expect((await admin.post(`/api/snapshots/${snap}/restore`, {})).status).toBe(200)
    expect((await rows("select count(*)::int n from subnets where source = 'netbox'"))[0].n).toBe(0)
  })
  it('erreurs : aperçu avec un mauvais jeton, URL interdite, serveur injoignable', async () => {
    code(await admin.post('/api/netbox/preview', body({ token: 'mauvais' })), 401, 'netbox_auth')
    code(await admin.post('/api/netbox/preview', body({ url: 'http://169.254.169.254/' })), 400, 'netbox_url_forbidden')
    code(await admin.post('/api/netbox/preview', body({ url: 'http://127.0.0.1:1/' })), 502, 'netbox_unreachable')
  })
})

describe('import Active Directory (lecture en direct)', () => {
  it('réservé aux administrateurs ; sans paramètres AD : refusé proprement', async () => {
    for (const p of ['/api/import/ad/discover', '/api/import/ad/subnets', '/api/import/ad/dns/preview', '/api/import/ad/dns/commit']) code(await operator.post(p, {}), 403, 'forbidden')
    code(await admin.post('/api/import/ad/discover', {}), 400, 'ad_incomplete')
  })
  it('transfert de zone : seuls les contrôleurs configurés ; zone invalide refusée', async () => {
    expect((await admin.put('/api/ad/settings', { enabled: true, urls: ['ldaps://dc1.corp.example.com'], baseDn: 'DC=corp,DC=example,DC=com', bindDn: 'CN=svc,DC=corp,DC=example,DC=com', bindPassword: 'x', userAttr: 'sAMAccountName', groupMap: [], nestedGroups: true, tlsRejectUnauthorized: true })).status).toBe(200)
    code(await admin.post('/api/import/ad/dns/preview', { server: 'evil.example.org', zone: 'corp.example.com' }), 400, 'axfr_server_not_allowed')
    code(await admin.post('/api/import/ad/dns/preview', { server: '127.0.0.1', zone: 'corp.example.com' }), 400, 'axfr_server_not_allowed')
    code(await admin.post('/api/import/ad/dns/preview', { server: 'dc1.corp.example.com', zone: 'zone invalide !' }), 400, 'invalid_input')
    code(await admin.post('/api/import/ad/dns/preview', { server: 'dc1.corp.example.com', zone: 'refuse.example.com' }), 502, 'axfr_failed')
  })
  it('aperçu (sans écriture) puis import : zone créée, enregistrements importés, point de restauration', async () => {
    const pv = (await admin.post('/api/import/ad/dns/preview', { server: 'dc1.corp.example.com', zone: 'corp.example.com' })).json
    expect(pv).toMatchObject({ zone: 'corp.example.com', zoneExists: false, total: 4 }); expect(pv.byType).toEqual({ NS: 1, A: 2, SRV: 1 }); expect(pv.adCritical).toBeGreaterThan(0)
    expect((await rows("select count(*)::int n from dns_zones where name = 'corp.example.com'"))[0].n).toBe(0)
    code(await admin.post('/api/import/ad/dns/commit', { server: 'dc1.corp.example.com', zone: 'corp.example.com' }), 404, 'zone_missing')
    const r = (await admin.post('/api/import/ad/dns/commit', { server: 'dc1.corp.example.com', zone: 'corp.example.com', create: true })).json
    expect(r.inserted).toBe(4); expect(r.snapshotId).toBeGreaterThan(0)
    expect((await rows("select ad_integrated, type, soa_mname from dns_zones where name = 'corp.example.com'"))[0]).toMatchObject({ ad_integrated: true, type: 'primary', soa_mname: 'dc1.corp.example.com.' })
    await admin.post(`/api/snapshots/${r.snapshotId}/restore`, {})
    expect((await rows("select count(*)::int n from dns_zones where name = 'corp.example.com'"))[0].n).toBe(0)   // annulé, zone comprise
  })
  it('lecture LDAP sans contrôleur joignable : erreur claire, aucune écriture', async () => {
    await admin.put('/api/ad/settings', { enabled: true, urls: ['ldaps://dc-inexistant.invalid'], baseDn: 'DC=corp,DC=example,DC=com', bindDn: 'CN=svc,DC=corp,DC=example,DC=com', bindPassword: 'x', userAttr: 'sAMAccountName', groupMap: [], nestedGroups: true, tlsRejectUnauthorized: true })
    const n = (await rows('select count(*)::int n from subnets'))[0].n
    expect((await admin.post('/api/import/ad/discover', {})).status).toBe(502)
    expect((await admin.post('/api/import/ad/subnets', { cidrs: ['10.1.0.0/24'] })).status).toBe(502)
    expect((await rows('select count(*)::int n from subnets'))[0].n).toBe(n)
  })
})

describe('découverte réseau', () => {
  let subId = 0
  it('capacités ; droits', async () => {
    const c = (await operator.get('/api/discovery/capabilities')).json; expect(c.maxTargets).toBe(4096); expect(c.presets.basic).toContain(443); expect(typeof c.icmp).toBe('boolean')
    code(await viewer.get('/api/discovery/capabilities'), 403, 'forbidden'); code(await viewer.post('/api/discovery/start', {}), 403, 'forbidden'); code(await anon.get('/api/discovery/capabilities'), 401, 'unauthenticated')
  })
  const M = { tcp: true, icmp: false, arp: false, reverse: false, leases: false }
  it('garde-fous : sous-réseau inconnu, plage interdite, trop grand, corps invalide', async () => {
    code(await operator.post('/api/discovery/start', { subnet_ids: [999999], methods: M }), 404, 'not_found')
    const bad = (await admin.post('/api/ipam/subnets', { cidr: '169.254.7.0/24', name: 'lien local' })).json
    code(await operator.post('/api/discovery/start', { subnet_ids: [bad.id], methods: M }), 400, 'discovery_forbidden_range')
    const big = (await admin.post('/api/ipam/subnets', { cidr: '10.64.0.0/19', name: 'trop grand' })).json
    code(await operator.post('/api/discovery/start', { subnet_ids: [big.id], methods: M }), 400, 'discovery_too_large')
    code(await operator.post('/api/discovery/start', { subnet_ids: [], methods: M }), 400, 'validation')
    code(await operator.post('/api/discovery/start', { subnet_ids: [bad.id], methods: M, ports: [0] }), 400, 'validation')
    code(await operator.post('/api/discovery/start', { subnet_ids: [bad.id], methods: M, ports: Array.from({ length: 21 }, (_, i) => i + 1) }), 400, 'validation')
    code(await operator.get('/api/discovery/00000000-0000-0000-0000-000000000000'), 404, 'not_found')
  })
  const run = async (opts: object = {}) => {
    const s = (await operator.post('/api/discovery/start', { subnet_ids: [subId], methods: M, ports: [lisPort], timeoutMs: 500, ...opts })).json
    expect(s.id, JSON.stringify(s)).toBeTruthy()
    let j: any; await until(async () => { j = (await operator.get(`/api/discovery/${s.id}`)).json; return j.state !== 'running' })
    return { id: s.id as string, job: j }
  }
  it('découverte réelle sur le réseau local : hôte avec port ouvert, hôtes qui répondent par RST', async () => {
    subId = (await admin.post('/api/ipam/subnets', { cidr: '127.0.0.0/29', name: 'boucle locale (test)' })).json.id
    await admin.post(`/api/ipam/subnets/${subId}/addresses`, { ip: '127.0.0.5', status: 'used', hostname: 'connu5', mac: 'aa:bb:cc:00:00:05' })
    await admin.post(`/api/ipam/subnets/${subId}/addresses`, { ip: '127.0.0.6', status: 'used', hostname: 'disparu' })
    const { job } = await run()
    expect(job.state).toBe('done'); expect(job.total).toBe(6); expect(job.done).toBe(6)
    const h = (ip: string) => job.result.hosts.find((x: any) => x.ip === ip)
    expect(h('127.0.0.2')).toMatchObject({ alive: true, ports: [lisPort], via: ['tcp'], status: 'new', subnetId: subId })
    expect(h('127.0.0.3').ports).toEqual([]); expect(h('127.0.0.3').alive).toBe(true)
    expect(h('127.0.0.5').status).toBe('known')
    expect(job.result.hosts.every((x: any) => x.ip !== '127.0.0.0' && x.ip !== '127.0.0.7')).toBe(true)   // ni réseau ni diffusion
  })
  it('import des hôtes choisis : créés avec leur origine ; les autres ne sont pas touchés ; point de restauration pris', async () => {
    const { id, job } = await run()
    const h = (ip: string) => job.result.hosts.find((x: any) => x.ip === ip)
    const before = (await rows('select count(*)::int n from addresses'))[0].n
    const r = (await operator.post(`/api/discovery/${id}/commit`, { ips: ['127.0.0.2', '127.0.0.3', '10.99.99.99'] })).json
    expect(r).toMatchObject({ created: 2, updated: 0 }); expect(r.snapshotId).toBeGreaterThan(0)
    expect((await rows('select count(*)::int n from addresses'))[0].n).toBe(before + 2)
    expect((await rows("select status, source, description, last_seen is not null as seen from addresses where ip = '127.0.0.2'"))[0]).toMatchObject({ status: 'used', source: 'discovery', seen: true })
    expect((await rows("select description from addresses where ip = '127.0.0.2'"))[0].description).toMatch(/^découvert le \d{4}-\d{2}-\d{2}$/)
    expect((await rows("select count(*)::int n from addresses where ip = '127.0.0.4'"))[0].n).toBe(0)
    // sur la boucle locale TOUT répond (RST) : aucune adresse obsolète ici ; le cas « dans l'IPAM mais muette » est couvert par les tests unitaires de classify
    expect(job.result.stale).toEqual([]); expect(h('127.0.0.6')).toMatchObject({ status: 'known' })
    await admin.post(`/api/snapshots/${r.snapshotId}/restore`, {}); expect((await rows('select count(*)::int n from addresses'))[0].n).toBe(before)   // annulable
  })
  it('hôtes connus : « mettre à jour » complète sans jamais remplacer ce qui est saisi', async () => {
    const { id } = await run()
    const r = (await operator.post(`/api/discovery/${id}/commit`, { ips: [], updateKnown: true })).json; expect(r.created).toBe(0); expect(r.updated).toBeGreaterThanOrEqual(1)
    const a = (await rows("select hostname, mac::text as mac, last_seen is not null as seen from addresses where ip = '127.0.0.5'"))[0]
    expect(a).toEqual({ hostname: 'connu5', mac: 'aa:bb:cc:00:00:05', seen: true })
  })
  it('méthodes passives seules (sans aucun paquet) ; annulation d\'un travail terminé sans effet', async () => {
    const { id, job } = await run({ methods: { tcp: false, icmp: false, arp: false, reverse: false, leases: true } })
    expect(job.state).toBe('done'); expect(job.result.hosts).toEqual([])   // aucun bail Kea ici
    expect((await operator.post(`/api/discovery/${id}/cancel`, {})).status).toBe(200)
  })
  it('un résultat inconnu ou une liste d\'adresses invalide est refusé', async () => {
    code(await operator.post('/api/discovery/00000000-0000-0000-0000-000000000000/commit', { ips: [] }), 404, 'not_found')
    const { id } = await run(); code(await operator.post(`/api/discovery/${id}/commit`, { ips: 'x' }), 400, 'validation')
  })
})

describe('traductions des nouveaux codes d\'erreur', () => {
  it('chaque code renvoyé par l\'API a une traduction française ET anglaise', async () => {
    const fr = (await import('../app/i18n/fr')).default, en = (await import('../app/i18n/en')).default
    const codes = ['netbox_url_invalid', 'netbox_url_forbidden', 'netbox_https_required', 'netbox_token_missing', 'netbox_auth', 'netbox_tls', 'netbox_unreachable', 'netbox_timeout', 'netbox_redirect', 'netbox_bad_next', 'netbox_bad_response', 'netbox_too_large', 'netbox_not_found', 'netbox_http', 'plan_expired',
      'ad_incomplete', 'ad_unreachable', 'ad_search_failed', 'axfr_server_not_allowed', 'axfr_failed', 'axfr_unavailable', 'zone_missing', 'snapshot_schema_mismatch', 'discovery_running', 'discovery_too_large', 'discovery_forbidden_range', 'discovery_empty']
    for (const c of codes) { expect((fr as any)[`err.${c}`], `fr err.${c}`).toBeTruthy(); expect((en as any)[`err.${c}`], `en err.${c}`).toBeTruthy() }
  })
})
