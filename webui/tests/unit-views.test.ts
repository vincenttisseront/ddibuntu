// Vues DNS : listes de clients, ordre d'évaluation, couverture locale, rendu de named.conf.zones validé par named-checkconf.
import { describe, expect, it } from 'vitest'
import { DNS_DEFAULTS, renderNamedOptions, renderNamedZones, rpzBase, validateFiles, zoneBase, zoneFile } from '~~/server/utils/render'
import type { OutFile, ZoneRow } from '~~/server/utils/render'
import { aclDecision, normalizeAcl, normalizeAclToken, shadowedViews, uncoveredLocal, viewForClient } from '~~/server/utils/views'
import type { ViewInfo } from '~~/server/utils/views'
import { parseIp } from '~~/server/utils/net'

process.env.DDI_TEST_MODE = '1'
const ip = (s: string) => parseIp(s)!
const view = (o: Partial<ViewInfo> & { name: string; position: number }): ViewInfo => ({ id: o.position + 1, match_clients: ['any'], match_destinations: [], recursion: true, ...o })
const zone = (o: Partial<ZoneRow>): ZoneRow => ({ name: 'example.com', type: 'primary', default_ttl: 3600, serial: 2026110901, soa_mname: null, soa_rname: null, soa_refresh: 3600, soa_retry: 600, soa_expire: 1209600, soa_minimum: 3600,
  masters: [], forwarders: [], allow_transfer: [], ddns_enabled: false, disabled: false, ...o })

describe('listes de clients', () => {
  it('éléments valides normalisés ; invalides refusés', () => {
    expect(normalizeAclToken(' ANY ')).toBe('any')
    expect(normalizeAclToken('!10.0.0.0/8')).toBe('!10.0.0.0/8')
    expect(normalizeAclToken('192.168.1.7')).toBe('192.168.1.7')
    expect(normalizeAclToken('localnets')).toBe('localnets')
    for (const bad of ['!any', '!none', '', 'tout', '10.0.0.0/33', '999.1.1.1', 'key foo', '10.0.0.1; };', '{ any; }']) expect(normalizeAclToken(bad), bad).toBeNull()
    expect(normalizeAcl(['10.0.0.0/8', '!10.1.0.0/16'])).toEqual(['10.0.0.0/8', '!10.1.0.0/16'])
    expect(normalizeAcl(['10.0.0.0/8', 'oups'])).toBeNull()
    expect(normalizeAcl(Array.from({ length: 51 }, () => 'any'))).toBeNull()
  })
  it('première correspondance gagne ; « ! » exclut', () => {
    const acl = ['!10.1.0.0/16', '10.0.0.0/8']
    expect(aclDecision(acl, ip('10.1.2.3'))).toBe(false)
    expect(aclDecision(acl, ip('10.2.2.3'))).toBe(true)
    expect(aclDecision(acl, ip('192.168.0.1'))).toBeNull()
    expect(aclDecision(['none'], ip('10.0.0.1'))).toBeNull()
    expect(aclDecision(['localhost'], ip('127.0.0.1'))).toBe(true)
    expect(aclDecision(['localhost'], ip('::1'))).toBe(true)
    expect(aclDecision(['192.0.2.7'], ip('192.0.2.7'))).toBe(true)   // adresse seule
    expect(aclDecision(['192.0.2.7'], ip('192.0.2.8'))).toBeNull()
    expect(aclDecision(['2001:db8::/32'], ip('2001:db8::5'))).toBe(true)
    expect(aclDecision(['2001:db8::/32'], ip('10.0.0.1'))).toBeNull()
  })
})

describe('ordre des vues et couverture', () => {
  const internal = view({ name: 'interne', position: 0, match_clients: ['10.0.0.0/8', 'localhost'] })
  const external = view({ name: 'externe', position: 1, recursion: false })
  it('la première vue dont la liste correspond répond ; l\'ordre des positions prime sur l\'ordre du tableau', () => {
    expect(viewForClient([external, internal], ip('10.1.1.1'))?.name).toBe('interne')
    expect(viewForClient([external, internal], ip('8.8.8.8'))?.name).toBe('externe')
    expect(viewForClient([internal], ip('8.8.8.8'))).toBeNull()
  })
  it('le serveur doit se couvrir lui-même (127.0.0.1 et ::1)', () => {
    expect(uncoveredLocal([internal, external])).toEqual([])
    expect(uncoveredLocal([view({ name: 'lan', position: 0, match_clients: ['10.0.0.0/8'] })])).toEqual(['127.0.0.1', '::1'])
    expect(uncoveredLocal([view({ name: 'v4', position: 0, match_clients: ['127.0.0.0/8'] })])).toEqual(['::1'])
    expect(uncoveredLocal([view({ name: 'ext', position: 0, match_clients: ['!127.0.0.1', 'any'] })])).toEqual(['127.0.0.1'])
  })
  it('une vue placée après une vue « any » est inatteignable', () => {
    expect(shadowedViews([internal, external])).toEqual([])
    expect(shadowedViews([{ ...external, position: 0 }, { ...internal, position: 1 }])).toEqual(['interne'])
    expect(shadowedViews([view({ name: 'a', position: 0, match_destinations: ['10.0.0.1'] }), view({ name: 'b', position: 1 })])).toEqual([])   // « any » restreint par destination ne masque rien
  })
})

describe('noms de fichiers', () => {
  it('une zone par vue, un fichier RPZ par vue', () => {
    expect(zoneBase(zone({}))).toBe('db.example.com')
    expect(zoneBase(zone({ view: 'interne' }))).toBe('db.interne.example.com')
    expect(zoneBase(zone({ name: 'example.com.', view: 'externe' }))).toBe('db.externe.example.com')
    expect(rpzBase()).toBe('db.rpz')
    expect(rpzBase('interne')).toBe('db.rpz-interne')
    expect(zoneFile(zone({ view: 'interne' }), []).path).toBe('zones/db.interne.example.com')
  })
})

describe('rendu de named.conf.zones', () => {
  const dns = { ...DNS_DEFAULTS, rpzEnabled: true }
  it('sans vue : configuration inchangée (aucun bloc « view », RPZ unique)', () => {
    const c = renderNamedZones([zone({})], dns)
    expect(c).not.toContain('view ')
    expect(c).toMatch(/file "[^"]*\/db\.example\.com"/)
    expect(c.match(/db\.rpz"/g)).toHaveLength(1)
  })
  const views = [view({ name: 'interne', position: 0, match_clients: ['10.0.0.0/8', 'localhost'], match_destinations: ['10.0.0.53'] }), view({ name: 'externe', position: 1, recursion: false })]
  const zones = [zone({ view: 'interne' }), zone({ view: 'externe', ddns_enabled: true }), zone({ name: 'seul.example.org', view: 'interne' }), zone({ name: 'off.example.org', view: 'externe', disabled: true })]
  it('un bloc par vue dans l\'ordre ; zones et RPZ de chaque vue ; format ligne à ligne', () => {
    const lines = renderNamedZones(zones, dns, views).split('\n')
    const i = lines.indexOf('view "interne" {'), e = lines.indexOf('view "externe" {')
    expect(i).toBeGreaterThan(-1); expect(e).toBeGreaterThan(i)
    expect(lines[i + 1]).toBe('  match-clients { 10.0.0.0/8; localhost; };')
    expect(lines.slice(i, e).some((l) => l === '  match-destinations { 10.0.0.53; };')).toBe(true)
    expect(lines.slice(i, e)).toContain('  recursion yes;')
    expect(lines.slice(e)).toContain('  recursion no;')
    expect(lines.slice(e)).toContain('  allow-recursion { none; };')
    // les zones restent une par ligne, à la marge
    const z = lines.filter((l) => l.startsWith('zone "'))
    expect(z.filter((l) => l.includes('db.interne.example.com'))).toHaveLength(1)
    expect(z.filter((l) => l.includes('db.externe.example.com'))).toHaveLength(1)
    expect(z.filter((l) => l.includes('off.example.org'))).toHaveLength(0)   // zone désactivée : absente
    expect(z.filter((l) => l.includes('db.rpz-interne'))).toHaveLength(1)
    expect(z.filter((l) => l.includes('db.rpz-externe'))).toHaveLength(1)
    expect(lines.filter((l) => l === '};')).toHaveLength(2)
  })
  it('sans RPZ activée : aucune zone de politique, quelle que soit la vue', () => {
    expect(renderNamedZones(zones, { ...DNS_DEFAULTS, rpzEnabled: false }, views)).not.toContain('rpz')
  })
  it('liste de clients vide : « none » (aucun client), jamais une liste vide invalide', () => {
    expect(renderNamedZones([], dns, [view({ name: 'vide', position: 0, match_clients: [] })])).toContain('match-clients { none; };')
  })
  it('named-checkconf accepte la configuration à vues (zones, RPZ par vue, destinations)', async (ctx) => {
    const sorted = [...views]
    const files: OutFile[] = [
      ...zones.filter((z) => !z.disabled).map((z) => zoneFile(z, [{ name: '@', type: 'NS', ttl: null, rdata: 'ns1' }, { name: 'ns1', type: 'A', ttl: null, rdata: '192.0.2.1' }])),
      { path: 'named.conf.options', kind: 'named', mode: 0o644, content: renderNamedOptions(dns, true) },
      { path: 'named.conf.zones', kind: 'named', mode: 0o644, content: renderNamedZones(zones, dns, sorted) },
    ]
    for (const v of sorted) files.push({ path: `zones/${rpzBase(v.name)}`, kind: 'rpz', mode: 0o644, content: `$ORIGIN ${dns.rpzZone}.\n$TTL 300\n@ IN SOA localhost. root.localhost. ( 1 3600 600 86400 300 )\n@ IN NS localhost.\n` })
    const r = await validateFiles(files)
    const conf = r.find((c) => c.name === 'named-checkconf')
    if (!conf || conf.ok === null) return ctx.skip()
    expect(conf.output, conf.output).toBe(''); expect(conf.ok).toBe(true)
  })
})

import { parseBindLog } from '~~/server/utils/querylog'
describe('journal des requêtes avec vues', () => {
  it('BIND préfixe « view <nom>: » : requêtes et réécritures RPZ restent comptées', () => {
    const t = '2026-11-11T10:00:00.000Z client @0x7f01 10.1.2.3#5353 (www.example.com): view interne: query: www.example.com IN A +E(0)K (10.0.0.53)\n'
      + '2026-11-11T10:00:01.000Z client @0x7f02 10.1.2.3#5354 (ads.example.net): view interne: rpz QNAME NXDOMAIN rewrite ads.example.net/A/IN via ads.example.net.rpz.ddibuntu.local\n'
      + '2026-11-11T10:00:02.000Z client @0x7f03 10.1.2.3#5355 (a.test): query: a.test IN AAAA +E(0)K (10.0.0.53)\n'
    const r = parseBindLog(t)
    expect(r.map((e) => [e.kind, e.domain, e.client])).toEqual([['query', 'www.example.com', '10.1.2.3'], ['blocked', 'ads.example.net', '10.1.2.3'], ['query', 'a.test', '10.1.2.3']])
  })
})
