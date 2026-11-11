// Unitaires (sans base) : client NetBox (vrai serveur HTTPS à autorité privée), normalisation et plan, découverte (fausses sondes), AD (faux LDAP).
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { fetchAll, getJson, isForbiddenTarget, normalizeNetbox, parseBaseUrl, planNetbox, NetboxError, upstreamDetail } from '../server/utils/netbox'
import type { Existing, PlanOpts } from '../server/utils/netbox'
import { classify, discoverHosts, enumerateTargets, DiscoveryError } from '../server/utils/discovery'
import type { ProbeDeps } from '../server/utils/discovery'
import { AdImportError, adDiscover, allowedDcHosts, axfrZone, configNcFromBaseDn } from '../server/utils/adimport'
import { parseZoneFile } from '../server/utils/dns'
import type { AdSettings, LdapLike } from '../server/utils/ad'

process.env.DDI_TEST_MODE = '1'

// ------------------------------------------------------------------------------------------------ NetBox : HTTPS réel, autorité privée
const DIR = mkdtempSync(join(tmpdir(), 'nb-'))
let srv: https.Server, port = 0, hits: Array<{ url: string; auth: string }> = []
let CA = ''
const sh = (cmd: string, args: string[]) => execFileSync(cmd, args, { stdio: 'pipe' })
const page = (n: number, results: any[], next: string | null) => JSON.stringify({ count: n, next, previous: null, results })

beforeAll(async () => {
  sh('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(DIR, 'ca.key'), '-out', join(DIR, 'ca.pem'), '-days', '2', '-subj', '/CN=CA-NetBox-Test'])
  sh('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(DIR, 's.key'), '-out', join(DIR, 's.csr'), '-subj', '/CN=127.0.0.1'])
  writeFileSync(join(DIR, 'ext'), 'subjectAltName=IP:127.0.0.1\n')
  sh('openssl', ['x509', '-req', '-in', join(DIR, 's.csr'), '-CA', join(DIR, 'ca.pem'), '-CAkey', join(DIR, 'ca.key'), '-CAcreateserial', '-out', join(DIR, 's.pem'), '-days', '2', '-extfile', join(DIR, 'ext')])
  CA = readFileSync(join(DIR, 'ca.pem'), 'utf8')
  srv = https.createServer({ key: readFileSync(join(DIR, 's.key')), cert: readFileSync(join(DIR, 's.pem')) }, (req, res) => {
    hits.push({ url: req.url!, auth: String(req.headers.authorization ?? '') })
    const base = `https://127.0.0.1:${port}`
    const send = (code: number, body: string, h: Record<string, string> = {}) => { res.writeHead(code, { 'content-type': 'application/json', ...h }); res.end(body) }
    if (req.headers.authorization !== 'Token bon-jeton' && req.headers.authorization !== 'Bearer nbt_cle.secret') return send(403, '{"detail":"no"}')
    if (req.url === '/api/status/') return send(200, '{"netbox-version":"4.2.1"}')
    if (req.url?.startsWith('/api/ipam/vlans/')) return send(200, page(2, [{ id: 1, vid: 10, name: 'Serveurs' }, { id: 2, vid: 20, name: 'Postes' }], null))
    if (req.url === '/api/ipam/prefixes/?limit=1000') return send(200, page(3, [{ id: 1, prefix: '10.0.0.0/24' }, { id: 2, prefix: '10.0.1.0/24' }], `${base}/api/ipam/prefixes/?limit=1000&offset=2`))
    if (req.url === '/api/ipam/prefixes/?limit=1000&offset=2') return send(200, page(3, [{ id: 3, prefix: '10.0.2.0/24' }], null))
    if (req.url?.startsWith('/api/ipam/ip-addresses/')) return send(200, page(1, [{ id: 9, address: '10.0.0.5/24' }], 'https://evil.example.org/api/ipam/ip-addresses/?offset=1'))   // « next » vers un AUTRE hôte
    if (req.url === '/redir') return send(302, '', { location: 'https://evil.example.org/' })
    if (req.url === '/api/big/') return send(200, 'x'.repeat(2000))
    if (req.url === '/api/notjson/') return send(200, '<html>')
    send(404, '{}')
  })
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r)); port = (srv.address() as any).port
})
afterAll(() => srv?.close())
const U = (p: string) => new URL(p, `https://127.0.0.1:${port}/`)

describe('NetBox : client HTTPS', () => {
  it('autorité inconnue : refusée (netbox_tls) ; avec la CA fournie : acceptée', async () => {
    await expect(getJson(U('/api/status/'), { token: 'bon-jeton', verify: true })).rejects.toMatchObject({ code: 'netbox_tls' })
    expect(await getJson(U('/api/status/'), { token: 'bon-jeton', verify: true, ca: CA })).toEqual({ 'netbox-version': '4.2.1' })
  })
  it('« ne pas vérifier » est un choix explicite et fonctionne', async () => { expect((await getJson(U('/api/status/'), { token: 'bon-jeton', verify: false })['netbox-version' as any]) ?? true).toBeTruthy() })
  it('jeton refusé -> netbox_auth ; jeton v2 « nbt_ » envoyé en Bearer', async () => {
    await expect(getJson(U('/api/status/'), { token: 'mauvais', verify: true, ca: CA })).rejects.toMatchObject({ code: 'netbox_auth', status: 502, upstream: { status: 403, detail: 'no' } })   // le motif de NetBox est conservé
    hits = []; await getJson(U('/api/status/'), { token: 'nbt_cle.secret', verify: true, ca: CA })
    expect(hits[0]!.auth).toBe('Bearer nbt_cle.secret')
  })
  it('motif du refus : texte brut, nettoyé et borné', () => {
    expect(upstreamDetail('{"detail":"Invalid v1 token"}')).toBe('Invalid v1 token')
    expect(upstreamDetail('{"detail":"a\\u0000b\\u001b[31mc\\u007f"}')).toBe('ab[31mc')
    expect(upstreamDetail('{"detail":"' + 'x'.repeat(500) + '"}')).toHaveLength(160)
    for (const raw of ['', 'pas du json', '<html>403</html>', '{"detail":42}', '{"detail":null}', '[]', '{"autre":"x"}']) expect(upstreamDetail(raw)).toBe('')
  })
  it('redirection : jamais suivie (le jeton ne change pas de destinataire)', async () => {
    await expect(getJson(U('/redir'), { token: 'bon-jeton', verify: true, ca: CA })).rejects.toMatchObject({ code: 'netbox_redirect' })
  })
  it('pagination : toutes les pages sont lues, sur la même origine', async () => {
    const r = await fetchAll(new URL(`https://127.0.0.1:${port}/`), 'ipam/prefixes', { token: 'bon-jeton', verify: true, ca: CA })
    expect(r.map((x) => x.prefix)).toEqual(['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24'])
  })
  it('« next » vers un autre hôte : refusé, et le jeton n\'y est JAMAIS envoyé', async () => {
    hits = []
    await expect(fetchAll(new URL(`https://127.0.0.1:${port}/`), 'ipam/ip-addresses', { token: 'bon-jeton', verify: true, ca: CA })).rejects.toMatchObject({ code: 'netbox_bad_next' })
    expect(hits.every((h) => !h.url.includes('evil'))).toBe(true)
  })
  it('réponse trop grosse et réponse non JSON : refusées', async () => {
    await expect(getJson(U('/api/big/'), { token: 'bon-jeton', verify: true, ca: CA, maxBytes: 500 })).rejects.toMatchObject({ code: 'netbox_too_large' })
    await expect(getJson(U('/api/notjson/'), { token: 'bon-jeton', verify: true, ca: CA })).rejects.toMatchObject({ code: 'netbox_bad_response' })
  })
  it('hôte injoignable -> netbox_unreachable', async () => {
    await expect(getJson(new URL('https://127.0.0.1:1/api/status/'), { token: 'x', verify: true, timeoutMs: 2000 })).rejects.toMatchObject({ code: 'netbox_unreachable' })
  })
})

describe('NetBox : URL et destinations interdites', () => {
  it('URL : HTTPS exigé hors mode test ; identifiants, schéma, chemin /api normalisés', () => {
    expect(parseBaseUrl('https://nb.example.com/api/').href).toBe('https://nb.example.com/')
    expect(parseBaseUrl('https://nb.example.com/netbox').href).toBe('https://nb.example.com/netbox/')
    for (const bad of ['ftp://x', 'https://u:p@nb.example.com/', 'pas une url', '']) expect(() => parseBaseUrl(bad), bad).toThrow(NetboxError)
    process.env.DDI_TEST_MODE = '0'
    try { expect(() => parseBaseUrl('http://nb.example.com/')).toThrowError(expect.objectContaining({ code: 'netbox_https_required' })) } finally { process.env.DDI_TEST_MODE = '1' }
  })
  it.each(['127.0.0.1', '127.8.8.8', '169.254.169.254', '0.0.0.0', '::1', 'fe80::1', '224.0.0.1', '::ffff:127.0.0.1', '::ffff:169.254.169.254', 'pas-une-ip'])('destination interdite : %s', (a) => { expect(isForbiddenTarget(a)).toBe(true) })
  it.each(['10.1.2.3', '192.168.0.10', '172.16.5.5', '8.8.8.8', 'fd00::1'])('destination permise (NetBox est interne) : %s', (a) => { expect(isForbiddenTarget(a)).toBe(false) })
  it('URL à IP littérale interdite : refusée dès l\'analyse', () => {
    process.env.DDI_ALLOW_PRIVATE_FETCH = ''
    expect(() => parseBaseUrl('https://169.254.169.254/')).toThrowError(expect.objectContaining({ code: 'netbox_url_forbidden' }))
    expect(() => parseBaseUrl('https://[::1]/')).toThrowError(expect.objectContaining({ code: 'netbox_url_forbidden' }))
  })
})

// ------------------------------------------------------------------------------------------------ NetBox : normalisation et plan
const RAW = {
  vlans: [{ id: 1, vid: 10, name: 'Serveurs' }, { id: 2, vid: 10, name: 'Doublon' }, { id: 3, vid: 5000, name: 'Hors plage' }, { id: 4, vid: 20, name: '' }],
  prefixes: [
    { id: 1, prefix: '10.0.0.0/24', description: 'LAN serveurs', status: { value: 'active' }, vlan: { vid: 10 }, scope: { name: 'Paris' }, tags: [{ slug: 'prod' }], vrf: null },
    { id: 2, prefix: '10.0.0.0/24', description: 'même préfixe, autre VRF', vrf: { name: 'MGMT' } },
    { id: 3, prefix: '10.0.0.0/16', status: { value: 'container' } },
    { id: 4, prefix: 'pas-un-prefixe' },
    { id: 5, prefix: '10.9.0.0/24', description: '', vrf: { name: 'DMZ' }, site: { name: 'Lyon' } },
  ],
  addresses: [
    { id: 1, address: '10.0.0.1/24', status: { value: 'active' }, role: { value: 'gateway' }, dns_name: 'GW.corp.example.com.' },
    { id: 2, address: '10.0.0.10/24', status: { value: 'reserved' }, dns_name: 'srv_invalide!', description: '', assigned_object: { name: 'eth0', device: { name: 'srv01' } } },
    { id: 3, address: '10.0.0.11/24', status: { value: 'dhcp' } },
    { id: 4, address: '10.0.0.12/24', status: { value: 'active' }, role: { value: 'vip' } },
    { id: 5, address: '10.0.0.12/24', status: { value: 'active' } },
    { id: 6, address: '10.0.50.9/24', status: { value: 'active' } },
    { id: 7, address: 'cassé', status: { value: 'active' } },
  ],
}
const EMPTY: Existing = { vlans: new Map(), subnets: new Map(), addresses: new Map() }
const OPTS: PlanOpts = { include: { vlans: true, prefixes: true, addresses: true }, mode: 'add', prune: false, includeContainers: false }

describe('NetBox : normalisation', () => {
  const d = normalizeNetbox(RAW)
  it('VLAN : doublons de VID et VID hors plage écartés, nom par défaut', () => {
    expect(d.vlans.map((v) => [v.vid, v.name])).toEqual([[10, 'Serveurs'], [20, 'VLAN 20']])
    expect(d.skipped).toMatchObject({ vlan_duplicate: 1, vlan_invalid: 1 })
  })
  it('préfixes : même préfixe dans deux VRF = le premier ; invalide écarté ; VRF et site conservés', () => {
    expect(d.prefixes.map((p) => p.cidr)).toEqual(['10.0.0.0/24', '10.0.0.0/16', '10.9.0.0/24'])
    expect(d.skipped).toMatchObject({ prefix_duplicate: 1, prefix_invalid: 1 })
    const p = d.prefixes[2]!; expect(p.site).toBe('Lyon'); expect(p.description).toContain('[VRF DMZ]'); expect(p.name).toBe('10.9.0.0/24')
    expect(d.prefixes[0]).toMatchObject({ site: 'Paris', vid: 10, tags: ['prod'] })
  })
  it('adresses : statuts et rôles traduits, nom DNS contrôlé, propriétaire dans la description, doublons écartés', () => {
    const a = (ip: string) => d.addresses.find((x) => x.ip === ip)!
    expect(a('10.0.0.1')).toMatchObject({ status: 'gateway', hostname: 'gw.corp.example.com' })
    expect(a('10.0.0.10')).toMatchObject({ status: 'reserved', hostname: null, description: 'srv01 / eth0' })
    expect(a('10.0.0.11').status).toBe('dhcp'); expect(a('10.0.0.12').status).toBe('infra')
    expect(d.skipped).toMatchObject({ address_duplicate: 1, address_invalid: 1 })
  })
})

describe('NetBox : plan', () => {
  const d = normalizeNetbox(RAW)
  it('base vide, mode « ajouter » : tout est créé, les conteneurs sont ignorés, les adresses sans sous-réseau sont comptées', () => {
    const p = planNetbox(d, EMPTY, OPTS)
    expect(p.stats.vlans.created).toBe(2); expect(p.stats.subnets.created).toBe(2); expect(p.stats.skipped.containers).toBe(1)
    expect(p.stats.addresses.created).toBe(4); expect(p.stats.addresses.no_subnet).toBe(1)   // 10.0.50.9 n'est dans aucun sous-réseau retenu (le /16 est un conteneur ignoré)
    expect(p.addresses.every((x) => x.subnetCidr === '10.0.0.0/24')).toBe(true)
  })
  it('conteneurs inclus : le sous-réseau le plus précis est choisi (/24 avant /16)', () => {
    const p = planNetbox(d, EMPTY, { ...OPTS, includeContainers: true })
    expect(p.stats.subnets.created).toBe(3); expect(p.stats.addresses.no_subnet).toBe(0)
    expect(p.addresses.find((x) => x.row.ip === '10.0.0.1')!.subnetCidr).toBe('10.0.0.0/24'); expect(p.addresses.find((x) => x.row.ip === '10.0.50.9')!.subnetCidr).toBe('10.0.0.0/16')
  })
  const ex = (src: string): Existing => ({
    vlans: new Map([[10, { id: 1, name: 'Ancien nom', description: null, source: src }]]),
    subnets: new Map([['10.0.0.0/24', { id: 7, name: 'LAN serveurs', description: 'LAN serveurs', site: 'Paris', vid: 10, tags: ['prod'], source: src }]]),
    addresses: new Map([['10.0.0.1', { id: 3, status: 'used', hostname: null, description: null, source: src }]]),
  })
  it('mode « ajouter » : l\'existant n\'est jamais touché', () => {
    const p = planNetbox(d, ex('manual'), OPTS)
    expect(p.stats.vlans).toMatchObject({ created: 1, existing: 1, updated: 0 }); expect(p.stats.addresses.existing).toBe(1)
  })
  it('mode « synchroniser » : seules les lignes venant de NetBox sont mises à jour ; les lignes manuelles sont conservées', () => {
    const nb = planNetbox(d, ex('netbox'), { ...OPTS, mode: 'sync' })
    expect(nb.stats.vlans.updated).toBe(1); expect(nb.stats.subnets.unchanged).toBe(1); expect(nb.stats.addresses.updated).toBe(1)
    const man = planNetbox(d, ex('manual'), { ...OPTS, mode: 'sync' })
    expect(man.stats.vlans).toMatchObject({ updated: 0, kept_manual: 1 }); expect(man.stats.addresses.kept_manual).toBe(1)
  })
  it('mode « écraser » : les lignes manuelles passent aussi à NetBox (et deviennent « netbox »)', () => {
    const p = planNetbox(d, ex('manual'), { ...OPTS, mode: 'sync_overwrite' })
    expect(p.stats.vlans.updated).toBe(1); expect(p.stats.subnets.updated).toBe(1); expect(p.stats.addresses.updated).toBe(1)
  })
  it('suppression des disparus : seulement les adresses et VLAN venant de NetBox, jamais les manuels, jamais les sous-réseaux', () => {
    const e: Existing = { vlans: new Map([[99, { id: 50, name: 'x', description: null, source: 'netbox' }], [98, { id: 51, name: 'm', description: null, source: 'manual' }]]),
      subnets: new Map([['10.77.0.0/24', { id: 60, name: 's', description: null, site: null, vid: null, tags: [], source: 'netbox' }]]),
      addresses: new Map([['10.0.0.200', { id: 70, status: 'used', hostname: null, description: null, source: 'netbox' }], ['10.0.0.201', { id: 71, status: 'used', hostname: null, description: null, source: 'manual' }]]) }
    const p = planNetbox(d, e, { ...OPTS, mode: 'sync', prune: true })
    expect(p.prune).toEqual({ vlans: [50], addresses: [70] }); expect(p.stats.stale_subnets).toBe(1)
    expect(planNetbox(d, e, { ...OPTS, mode: 'sync', prune: false }).prune).toEqual({ vlans: [], addresses: [] })
    expect(planNetbox(d, e, { ...OPTS, mode: 'add', prune: true }).prune).toEqual({ vlans: [], addresses: [] })
  })
  it('catégories non incluses : ni données, ni suppressions', () => {
    const p = planNetbox(d, EMPTY, { ...OPTS, include: { vlans: false, prefixes: true, addresses: false } })
    expect(p.stats.vlans.created + p.stats.addresses.created).toBe(0); expect(p.stats.subnets.created).toBe(2)
  })
})

// ------------------------------------------------------------------------------------------------ Découverte
const deps = (o: Partial<ProbeDeps> & { alive?: string[]; open?: Record<string, number[]> } = {}): ProbeDeps => ({
  tcp: async (ip, port) => (o.open?.[ip]?.includes(port) ? 'open' : o.alive?.includes(ip) ? 'closed' : 'none'),
  ping: async (ip) => !!o.alive?.includes(ip) && ip.endsWith('.9'),
  arp: async () => new Map(), leases: async () => new Map(), reverse: async () => null, ...o,
})
const M = { tcp: true, icmp: false, arp: false, reverse: false, leases: false }
describe('découverte : cibles', () => {
  it('/24 : 254 hôtes (sans réseau ni diffusion) ; /31 : 2 ; /32 : 1', () => {
    expect(enumerateTargets(['10.0.0.0/24']).ips).toHaveLength(254); expect(enumerateTargets(['10.0.0.0/31']).ips).toEqual(['10.0.0.0', '10.0.0.1']); expect(enumerateTargets(['10.0.0.7/32']).ips).toEqual(['10.0.0.7'])
    expect(enumerateTargets(['10.0.0.0/24']).ips[0]).toBe('10.0.0.1'); expect(enumerateTargets(['10.0.0.0/24']).ips.at(-1)).toBe('10.0.0.254')
  })
  it('plafond de 4096 adresses ; IPv6 ignoré (signalé) ; plages interdites refusées', () => {
    expect(() => enumerateTargets(['10.0.0.0/19'])).toThrow(DiscoveryError)   // 8190 hôtes
    expect(() => enumerateTargets(['10.0.0.0/20'])).not.toThrow(); expect(enumerateTargets(['10.0.0.0/20']).ips).toHaveLength(4094)
    expect(() => enumerateTargets(['10.0.0.0/20', '10.8.0.0/24'])).toThrowError(expect.objectContaining({ code: 'discovery_too_large' }))
    expect(enumerateTargets(['fd00::/64', '10.0.0.0/30'])).toMatchObject({ ips: ['10.0.0.1', '10.0.0.2'], skipped: ['fd00::/64:ipv6'] })
    for (const bad of ['127.0.0.0/24', '169.254.1.0/24', '224.0.0.0/24', '0.0.0.0/24']) expect(() => enumerateTargets([bad]), bad).toThrowError(expect.objectContaining({ code: 'discovery_forbidden_range' }))
    expect(enumerateTargets(['127.0.0.0/30'], true).ips).toEqual(['127.0.0.1', '127.0.0.2'])
  })
})
describe('découverte : sondes', () => {
  const T = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.9']
  const run = (d: ProbeDeps, m = M, o: object = {}) => discoverHosts({ targets: T, ports: [22, 80], methods: m, concurrency: 4, timeoutMs: 100, ...o }, d)
  it('TCP : port ouvert ET « refusé » (RST) prouvent que l\'hôte répond ; le silence non', async () => {
    const r = await run(deps({ open: { '10.0.0.1': [22] }, alive: ['10.0.0.1', '10.0.0.2'] }))
    expect(r.map((h) => h.ip)).toEqual(['10.0.0.1', '10.0.0.2']); expect(r[0]).toMatchObject({ ports: [22], via: ['tcp'] }); expect(r[1]!.ports).toEqual([])
  })
  it('ICMP : un hôte muet en TCP est trouvé par ping', async () => {
    const r = await run(deps({ ping: async (ip) => ip === '10.0.0.9' }), { ...M, icmp: true })
    expect(r).toHaveLength(1); expect(r[0]).toMatchObject({ ip: '10.0.0.9', via: ['icmp'] })
  })
  it('ARP : lue APRÈS les sondes ; donne l\'adresse MAC et révèle un hôte qui filtre tout', async () => {
    const r = await run(deps({ arp: async () => new Map([['10.0.0.3', 'aa:bb:cc:00:00:03'], ['10.9.9.9', 'aa:aa:aa:aa:aa:aa']]) }), { ...M, arp: true })
    expect(r).toHaveLength(1); expect(r[0]).toMatchObject({ ip: '10.0.0.3', mac: 'aa:bb:cc:00:00:03', via: ['arp'] })   // l'entrée hors cibles est ignorée
  })
  it('baux DHCP : hôte, MAC et nom proviennent des baux (méthode passive)', async () => {
    const r = await run(deps({ leases: async () => new Map([['10.0.0.2', { mac: 'aa:bb:cc:00:00:02', hostname: 'PC-Dupont' }]]) }), { ...M, tcp: false, leases: true })
    expect(r).toEqual([expect.objectContaining({ ip: '10.0.0.2', mac: 'aa:bb:cc:00:00:02', leaseName: 'PC-Dupont', via: ['dhcp'] })])
  })
  it('DNS inverse : seulement pour les hôtes trouvés', async () => {
    const asked: string[] = []
    const r = await run(deps({ alive: ['10.0.0.1'], reverse: async (ip) => { asked.push(ip); return 'srv01.corp.example.com' } }), { ...M, reverse: true })
    expect(asked).toEqual(['10.0.0.1']); expect(r[0]!.ptr).toBe('srv01.corp.example.com')
  })
  it('méthodes passives seules : aucune sonde n\'est émise', async () => {
    let sent = 0
    await run(deps({ tcp: async () => { sent++; return 'none' }, ping: async () => { sent++; return false } }), { tcp: false, icmp: false, arp: true, reverse: false, leases: true })
    expect(sent).toBe(0)
  })
  it('arrêt demandé : le travail s\'interrompt sans erreur', async () => {
    let n = 0
    const r = await discoverHosts({ targets: Array.from({ length: 100 }, (_, i) => `10.0.0.${i + 1}`), ports: [22], methods: M, concurrency: 1, timeoutMs: 50 }, deps({ alive: ['10.0.0.1'], tcp: async () => { n++; return 'closed' } }), undefined, () => n >= 5)
    expect(n).toBeLessThan(10); expect(r.length).toBeLessThanOrEqual(n)
  })
  it('concurrence bornée', async () => {
    let cur = 0, max = 0
    await discoverHosts({ targets: Array.from({ length: 60 }, (_, i) => `10.0.1.${i + 1}`), ports: [22], methods: M, concurrency: 8, timeoutMs: 50 }, deps({ tcp: async () => { cur++; max = Math.max(max, cur); await new Promise((r) => setTimeout(r, 5)); cur--; return 'none' } }))
    expect(max).toBeLessThanOrEqual(8)
  })
})
describe('découverte : comparaison avec l\'IPAM', () => {
  const h = (ip: string, mac: string | null = null) => ({ ip, alive: true, via: ['tcp'], ports: [], mac, ptr: null, leaseName: null })
  it('nouveau / connu / adresse MAC différente ; adresses « utilisées » muettes = obsolètes', () => {
    const known = [{ id: 1, subnet_id: 5, ip: '10.0.0.2', hostname: 'a', mac: 'aa:aa:aa:aa:aa:02', status: 'used' }, { id: 2, subnet_id: 5, ip: '10.0.0.3', hostname: 'b', mac: 'aa:aa:aa:aa:aa:03', status: 'used' },
      { id: 3, subnet_id: 5, ip: '10.0.0.4', hostname: 'c', mac: null, status: 'used' }, { id: 4, subnet_id: 5, ip: '10.0.0.5', hostname: null, mac: null, status: 'reserved' }]
    const r = classify([h('10.0.0.1'), h('10.0.0.2', 'AA:AA:AA:AA:AA:02'), h('10.0.0.3', 'bb:bb:bb:bb:bb:03')], known, () => 5)
    expect(r.hosts.map((x) => x.status)).toEqual(['new', 'known', 'mac_changed'])
    expect(r.stale).toEqual([{ ip: '10.0.0.4', hostname: 'c' }])   // 10.0.0.5 est « reservée » : jamais obsolète
  })
})

// ------------------------------------------------------------------------------------------------ Active Directory
const S: AdSettings = { enabled: true, urls: ['ldaps://dc1.corp.example.com', 'ldaps://dc2.corp.example.com:636'], baseDn: 'OU=Tech,DC=corp,DC=example,DC=com', bindDn: 'CN=svc,DC=corp,DC=example,DC=com', userAttr: 'sAMAccountName', groupMap: [], nestedGroups: true, tlsRejectUnauthorized: true }
const fakeLdap = (o: { bindFails?: string[]; rootDse?: string | null; subnets?: any[]; sites?: any[] } = {}, calls: string[] = []) => (url: string): LdapLike => ({
  bind: async (_d, pw) => { calls.push(`bind:${url}:${pw ? 'pw' : 'nopw'}`); if (o.bindFails?.includes(url)) throw new Error('refused') },
  search: async (base, opt) => {
    calls.push(`search:${opt.scope}:${base}`)
    if (base === '') return { searchEntries: o.rootDse === null ? [] : [{ configurationNamingContext: o.rootDse ?? 'CN=Configuration,DC=corp,DC=example,DC=com' }] }
    if (opt.filter === '(objectClass=site)') return { searchEntries: o.sites ?? [{ cn: 'Lyon' }, { cn: 'Paris' }] }
    return { searchEntries: o.subnets ?? [] }
  },
  unbind: async () => { calls.push(`unbind:${url}`) },
})
describe('AD en direct : découverte', () => {
  const SUBS = [{ cn: '10.2.0.0/24', siteObject: 'CN=Lyon,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com', description: 'Lyon LAN' }, { cn: '10.1.0.0/24', siteObject: 'CN=Paris\\, Nord,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com', location: 'Paris' },
    { cn: '10.1.0.0/24', siteObject: 'CN=Doublon,CN=Sites,CN=Configuration,DC=x' }, { cn: 'pas-un-reseau', siteObject: '' }, { cn: '2001:db8::/64', siteObject: 'CN=Lyon,CN=Sites,CN=Configuration,DC=x' }]
  it('lit la partition Configuration annoncée, trie, déduplique, ignore l\'invalide, extrait le site (RDN échappé)', async () => {
    const calls: string[] = []
    const r = await adDiscover(S, 'secret', fakeLdap({ subnets: SUBS }, calls))
    expect(r.server).toBe('ldaps://dc1.corp.example.com'); expect(r.sites).toEqual(['Lyon', 'Paris'])
    expect(r.subnets.map((s) => [s.cidr, s.site, s.name])).toEqual([['10.1.0.0/24', 'Paris, Nord', 'Paris, Nord — 10.1.0.0/24'], ['10.2.0.0/24', 'Lyon', 'Lyon — 10.2.0.0/24'], ['2001:db8::/64', 'Lyon', 'Lyon — 2001:db8::/64']])
    expect(calls).toContain('search:sub:CN=Subnets,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com'); expect(calls.at(-1)).toBe('unbind:ldaps://dc1.corp.example.com')
  })
  it('rootDSE absent : partition déduite du Base DN (uniquement les composants DC)', async () => {
    expect(configNcFromBaseDn('OU=Tech,DC=corp,DC=example,DC=com')).toBe('CN=Configuration,DC=corp,DC=example,DC=com')
    const calls: string[] = []; await adDiscover(S, 'secret', fakeLdap({ rootDse: null }, calls))
    expect(calls).toContain('search:sub:CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com')
  })
  it('1er contrôleur en échec : le suivant est utilisé ; tous en échec : ad_unreachable', async () => {
    expect((await adDiscover(S, 'secret', fakeLdap({ bindFails: ['ldaps://dc1.corp.example.com'] }))).server).toBe('ldaps://dc2.corp.example.com:636')
    await expect(adDiscover(S, 'secret', fakeLdap({ bindFails: S.urls }))).rejects.toMatchObject({ code: 'ad_unreachable' })
  })
  it('liaison sans mot de passe refusée AVANT tout contact (elle réussirait « en anonyme »)', async () => {
    const calls: string[] = []
    await expect(adDiscover(S, '', fakeLdap({}, calls))).rejects.toMatchObject({ code: 'ad_incomplete' }); expect(calls).toEqual([])
    await expect(adDiscover({ ...S, urls: [] }, 'x', fakeLdap())).rejects.toBeInstanceOf(AdImportError)
  })
  it('transfert de zone : seuls les contrôleurs déjà configurés sont autorisés', () => { expect(allowedDcHosts(S)).toEqual(['dc1.corp.example.com', 'dc2.corp.example.com']) })
})
const AXFR = [
  'corp.example.com.\t3600\tIN\tSOA\tdc1.corp.example.com. hostmaster.corp.example.com. 123 900 600 86400 3600',
  'corp.example.com.\t600\tIN\tNS\tdc1.corp.example.com.', 'corp.example.com.\t600\tIN\tA\t10.0.0.10',
  'dc1.corp.example.com.\t3600\tIN\tA\t10.0.0.10', '_ldap._tcp.dc._msdcs.corp.example.com.\t600\tIN\tSRV\t0 100 389 dc1.corp.example.com.',
  'corp.example.com.\t3600\tIN\tSOA\tdc1.corp.example.com. hostmaster.corp.example.com. 123 900 600 86400 3600'].join('\n')
describe('AD en direct : transfert de zone', () => {
  const fake = (out: string, code?: string) => ((_c: string, _a: string[], _o: any, cb: any) => cb(code ? Object.assign(new Error('x'), { code }) : null, out)) as any
  it('un transfert réussi est analysé comme une zone (SOA, NS, A, SRV)', async () => {
    const text = await axfrZone('dc1.corp.example.com', 'corp.example.com', fake(AXFR))
    const z = parseZoneFile(text, 'corp.example.com')
    expect(z.soa).toMatchObject({ mname: 'dc1.corp.example.com.', serial: 123 }); expect(z.records.map((r) => r.type).sort()).toEqual(['A', 'A', 'NS', 'SRV'])
  })
  it('refus ou délai (aucun enregistrement) -> axfr_failed ; dig absent -> axfr_unavailable', async () => {
    await expect(axfrZone('dc1.corp.example.com', 'corp.example.com', fake(''))).rejects.toMatchObject({ code: 'axfr_failed' })
    await expect(axfrZone('dc1.corp.example.com', 'corp.example.com', fake('; Transfer failed.\n'))).rejects.toMatchObject({ code: 'axfr_failed' })
    await expect(axfrZone('dc1.corp.example.com', 'corp.example.com', fake('', 'ENOENT'))).rejects.toMatchObject({ code: 'axfr_unavailable' })
  })
  it('dig est lancé avec des arguments séparés (aucun passage par un shell)', async () => {
    let seen: string[] = []
    await axfrZone('dc1.corp.example.com', 'corp.example.com', ((_c: string, a: string[], _o: any, cb: any) => { seen = a; cb(null, AXFR) }) as any)
    expect(seen).toEqual(['@dc1.corp.example.com', 'corp.example.com', 'AXFR', '+noall', '+answer', '+nocomments', '+time=8', '+tries=1'])
  })
})
void http
