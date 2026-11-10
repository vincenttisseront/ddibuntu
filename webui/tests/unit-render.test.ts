// Génération de configuration validée par les OUTILS OFFICIELS : named-checkzone, named-checkconf, kea-dhcp4 -t.
import { describe, expect, it } from 'vitest'
import { DNS_DEFAULTS, KEA_DEFAULTS, renderKea, renderNamedOptions, renderNamedZones, renderRpz, validateFiles, zoneFile } from '~~/server/utils/render'
import type { KeaScope, OutFile, ZoneRow } from '~~/server/utils/render'

process.env.DDI_TEST_MODE = '1'
const zone = (o: Partial<ZoneRow>): ZoneRow => ({ name: 'example.com', type: 'primary', default_ttl: 3600, serial: 2026110901, soa_mname: null, soa_rname: null, soa_refresh: 3600, soa_retry: 600, soa_expire: 1209600, soa_minimum: 3600,
  masters: [], forwarders: [], allow_transfer: [], ddns_enabled: false, disabled: false, ...o })

// Un enregistrement de CHAQUE type pris en charge
const ALL = [
  { name: '@', type: 'NS', ttl: null, rdata: 'ns1' }, { name: 'ns1', type: 'A', ttl: 300, rdata: '192.0.2.1' }, { name: 'ns1', type: 'AAAA', ttl: null, rdata: '2001:db8::1' },
  { name: 'www', type: 'CNAME', ttl: null, rdata: 'ns1' }, { name: '@', type: 'MX', ttl: null, rdata: '10 mail.example.com.' }, { name: 'mail', type: 'A', ttl: null, rdata: '192.0.2.25' },
  { name: '@', type: 'TXT', ttl: null, rdata: 'v=spf1 mx -all' }, { name: 'long', type: 'TXT', ttl: null, rdata: 'x'.repeat(700) + ' "guillemets" \\ é' },
  { name: '_sip._tcp', type: 'SRV', ttl: null, rdata: '0 5 5060 sip.example.com.' }, { name: '@', type: 'CAA', ttl: null, rdata: '0 issue letsencrypt.org' },
  { name: 'tel', type: 'NAPTR', ttl: null, rdata: '100 10 "S" "SIP+D2U" "" _sip._udp.example.com.' },
  { name: 'ssh', type: 'SSHFP', ttl: null, rdata: '4 2 ' + 'ab'.repeat(32) }, { name: '_443._tcp.www', type: 'TLSA', ttl: null, rdata: '3 1 1 ' + 'cd'.repeat(32) },
  { name: 'svc', type: 'HTTPS', ttl: null, rdata: '1 . alpn=h2,h3' }, { name: 'svc2', type: 'SVCB', ttl: null, rdata: '1 svc.example.com. port=8443' },
  { name: 'box', type: 'HINFO', ttl: null, rdata: '"AMD64" "Linux"' }, { name: 'resp', type: 'RP', ttl: null, rdata: 'admin.example.com. info.example.com.' },
  { name: 'child', type: 'NS', ttl: null, rdata: 'ns.child.example.com.' }, { name: 'child', type: 'DS', ttl: null, rdata: '12345 13 2 ' + 'ef'.repeat(32) },
  { name: 'ns.child', type: 'A', ttl: null, rdata: '192.0.2.50' }, { name: 'old', type: 'DNAME', ttl: null, rdata: 'new.example.org.' },
]
const REV = [{ name: '@', type: 'NS', ttl: null, rdata: 'ns1.example.com.' }, { name: '1', type: 'PTR', ttl: null, rdata: 'ns1.example.com.' }]

const scopes: KeaScope[] = [
  { id: 1, cidr: '192.168.10.0/24', enabled: true, leaseTime: 3600, options: { routers: ['192.168.10.1'], dnsServers: ['192.168.10.2', '192.168.10.3'], domainName: 'corp.local', domainSearch: ['corp.local', 'ad.corp.local'], ntpServers: ['192.168.10.5'], tftpServer: 'tftp.corp.local', bootFile: 'pxelinux.0', custom: [{ code: 224, name: 'site-code', type: 'string', value: 'PARIS-01' }] },
    pools: [{ start: '192.168.10.100', end: '192.168.10.150' }, { start: '192.168.10.200', end: '192.168.10.220' }], reservations: [{ mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.10.50', hostname: 'printer1' }, { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.10.51', hostname: null }] },
  { id: 2, cidr: '10.20.0.0/16', enabled: true, leaseTime: 86400, options: {}, pools: [{ start: '10.20.1.10', end: '10.20.1.250' }], reservations: [] },
  { id: 3, cidr: '10.30.0.0/24', enabled: false, leaseTime: 86400, options: {}, pools: [], reservations: [] },
]

function files(extra: OutFile[] = []): OutFile[] {
  const dns = { ...DNS_DEFAULTS, forwarders: ['9.9.9.9'], rpzEnabled: true }
  const zs: ZoneRow[] = [zone({ ddns_enabled: true }), zone({ name: '2.0.192.in-addr.arpa' }), zone({ name: 'sec.example.org', type: 'secondary', masters: ['192.0.2.7'] }), zone({ name: 'ad.corp.local', type: 'forward', forwarders: ['10.0.0.10', '10.0.0.11'] })]
  return [
    zoneFile(zs[0]!, ALL), zoneFile(zs[1]!, REV),
    { path: 'zones/db.rpz', kind: 'rpz', mode: 0o644, content: renderRpz({ zone: dns.rpzZone, serial: 1700000000, action: 'nxdomain' }, ['ads.example.net', 'tracker.example.org'], ['ok.example.net']) },
    { path: 'named.conf.options', kind: 'named', mode: 0o644, content: renderNamedOptions(dns, true) },
    { path: 'named.conf.zones', kind: 'named', mode: 0o644, content: renderNamedZones(zs, dns) },
    { path: 'kea-dhcp4.conf', kind: 'kea', mode: 0o640, content: renderKea({ ...KEA_DEFAULTS, ddns: true, globalOptions: { ntpServers: ['192.168.10.5'] } }, scopes) },
    ...extra,
  ]
}

describe('validation par les outils officiels', () => {
  it('toute la configuration générée est acceptée (zones, named.conf, RPZ, Kea)', async () => {
    const r = await validateFiles(files())
    for (const c of r) console.log(`    ${c.ok === true ? 'OK ' : 'KO '} ${c.name}${c.ok === true ? '' : ' : ' + c.output}`)
    expect(r.map((c) => c.name).sort()).toEqual(['kea-dhcp4 -t', 'named-checkconf', 'named-checkzone 2.0.192.in-addr.arpa', 'named-checkzone example.com', 'named-checkzone rpz.ddibuntu.local'].sort())
    expect(r.every((c) => c.ok === true)).toBe(true)
  })
  it('RRL : désactivée par défaut ; activée, une seule ligne acceptée par named-checkconf (essai à blanc, exemptions, valeurs extrêmes)', async () => {
    expect(renderNamedOptions(DNS_DEFAULTS, false)).not.toContain('rate-limit')
    const on = { ...DNS_DEFAULTS, rrlEnabled: true }
    const o = renderNamedOptions(on, false)
    expect(o).toContain('  rate-limit { responses-per-second 20; window 15; slip 2; log-only yes; exempt-clients { 127.0.0.0/8; ::1; }; };')
    expect(o.split('\n').filter((l) => l.includes('rate-limit'))).toHaveLength(1)
    expect(renderNamedOptions({ ...on, rrlLogOnly: false, rrlExempt: [] }, false)).toContain('rate-limit { responses-per-second 20; window 15; slip 2; log-only no; };')
    for (const v of [{ rrlResponsesPerSecond: 1, rrlWindow: 5, rrlSlip: 0 }, { rrlResponsesPerSecond: 1000, rrlWindow: 3600, rrlSlip: 10, rrlExempt: ['10.0.0.0/8', '192.0.2.7', '2001:db8::/32'], rrlLogOnly: false }]) {
      const r = await validateFiles([{ path: 'named.conf.options', kind: 'named', mode: 0o644, content: renderNamedOptions({ ...on, ...v }, false) }])
      expect(r[0]!.ok, r[0]!.output).toBe(true)
    }
  })
  it('un fichier de zone invalide est refusé par named-checkzone', async () => {
    const bad = zoneFile(zone({ name: 'bad.test' }), [{ name: 'x', type: 'A', ttl: null, rdata: '10.0.0.1' }])   // sans NS
    const r = await validateFiles([bad])
    expect(r[0]!.ok).toBe(false)
    expect(r[0]!.output).toMatch(/no NS/i)
  })
  it('un named.conf corrompu est refusé par named-checkconf', async () => {
    const r = await validateFiles([{ path: 'named.conf.options', kind: 'named', mode: 0o644, content: 'options { directory "/x" ; recursion maybe; };' }])
    expect(r[0]!.ok).toBe(false)
  })
  it('une configuration Kea invalide est refusée par kea-dhcp4 -t', async () => {
    const bad = JSON.parse(renderKea(KEA_DEFAULTS, scopes)); bad.Dhcp4.subnet4[0].pools = [{ pool: '192.168.99.1 - 192.168.99.9' }]   // pool hors du sous-réseau
    const r = await validateFiles([{ path: 'kea-dhcp4.conf', kind: 'kea', mode: 0o640, content: JSON.stringify(bad) }])
    expect(r[0]!.ok).toBe(false)
  })
})

describe('contenu généré', () => {
  it('Kea : options, réservations, pools, scope désactivé exclu', () => {
    const k = JSON.parse(renderKea({ ...KEA_DEFAULTS, ddns: true }, scopes)).Dhcp4
    expect(k.subnet4.map((s: any) => s.subnet)).toEqual(['192.168.10.0/24', '10.20.0.0/16'])
    const o = Object.fromEntries(k.subnet4[0]['option-data'].map((x: any) => [x.name, x.data]))
    expect(o['domain-name-servers']).toBe('192.168.10.2, 192.168.10.3'); expect(o.routers).toBe('192.168.10.1'); expect(o['site-code']).toBe('PARIS-01')
    expect(k.subnet4[0].pools).toEqual([{ pool: '192.168.10.100 - 192.168.10.150' }, { pool: '192.168.10.200 - 192.168.10.220' }])
    expect(k.subnet4[0].reservations[0]).toEqual({ 'hw-address': 'aa:bb:cc:dd:ee:01', 'ip-address': '192.168.10.50', hostname: 'printer1' })
    expect(k.subnet4[0].reservations[1]).not.toHaveProperty('hostname')
    expect(k['option-def']).toEqual([{ name: 'site-code', code: 224, type: 'string', space: 'dhcp4' }])
    expect(k['dhcp-ddns']).toEqual({ 'enable-updates': true })
  })
  it('Kea : les options globales sont héritées et surchargées par scope', () => {
    const k = JSON.parse(renderKea({ ...KEA_DEFAULTS, globalOptions: { ntpServers: ['1.1.1.1'], routers: ['9.9.9.9'] } }, scopes)).Dhcp4
    const o1 = Object.fromEntries(k.subnet4[0]['option-data'].map((x: any) => [x.name, x.data]))
    const o2 = Object.fromEntries(k.subnet4[1]['option-data'].map((x: any) => [x.name, x.data]))
    expect(o1.routers).toBe('192.168.10.1'); expect(o1['ntp-servers']).toBe('192.168.10.5'); expect(o2.routers).toBe('9.9.9.9'); expect(o2['ntp-servers']).toBe('1.1.1.1')
  })
  it('RPZ : un domaine autorisé l’emporte sur un blocage, jamais de doublon de propriétaire', () => {
    const t = renderRpz({ zone: 'rpz.test', serial: 1, action: 'nxdomain' }, ['a.example.net', 'b.example.net', 'ok.example.net'], ['ok.example.net'])
    expect(t).toContain('a.example.net IN CNAME .'); expect(t).toContain('*.a.example.net IN CNAME .')
    expect(t).toContain('ok.example.net IN CNAME rpz-passthru.')
    expect(t).not.toContain('ok.example.net IN CNAME .')
    expect(renderRpz({ zone: 'rpz.test', serial: 1, action: 'nodata' }, ['x.test'], [])).toContain('x.test IN CNAME *.')
    expect(renderRpz({ zone: 'rpz.test', serial: 1, action: 'sinkhole', sinkhole4: '10.9.9.9' }, ['x.test'], [])).toContain('x.test IN A 10.9.9.9')
  })
  it('named.conf : DDNS, secondaire, redirecteur, RPZ', () => {
    const dns = { ...DNS_DEFAULTS, rpzEnabled: true }
    const z = renderNamedZones([zone({ ddns_enabled: true, allow_transfer: ['10.0.0.0/8'] }), zone({ name: 's.org', type: 'secondary', masters: ['1.2.3.4'] }), zone({ name: 'f.org', type: 'forward', forwarders: ['5.6.7.8'] }), zone({ name: 'off.org', disabled: true })], dns)
    expect(z).toContain('allow-update { key "ddi-ddns"; }'); expect(z).toContain('allow-transfer { 10.0.0.0/8; }'); expect(z).toContain('primaries { 1.2.3.4; }')
    expect(z).toContain('type forward; forward only; forwarders { 5.6.7.8; }'); expect(z).not.toContain('off.org'); expect(z).toContain('zone "rpz.ddibuntu.local"')
    expect(renderNamedOptions(dns, true)).toContain('response-policy { zone "rpz.ddibuntu.local" policy given; }')
    expect(renderNamedOptions({ ...dns, rpzEnabled: false }, false)).not.toContain('response-policy')
  })
  it('named.conf : formats exacts relus par root pour le secondaire du cluster', () => {
    const dns = { ...DNS_DEFAULTS, rpzEnabled: true }
    const lines = renderNamedOptions(dns, true).split('\n')
    expect(lines).toContain('options {'); expect(lines.filter((l) => l.trim() === 'allow-transfer { none; };')).toHaveLength(1)   // root remplace cette ligne, une seule fois
    const z = renderNamedZones([zone({ ddns_enabled: true, allow_transfer: ['10.0.0.0/8'] }), zone({ name: 'q.org' }), zone({ name: 's.org', type: 'secondary', masters: ['1.2.3.4'] }), zone({ name: 'f.org', type: 'forward', forwarders: ['5.6.7.8'] })], dns).split('\n')
    for (const l of z.filter((x) => x && !x.startsWith('//'))) expect(l, l).toMatch(/^zone "[^"]+" \{ type (primary; file "[^"]+";.*|secondary;.*|forward;.*) \};$/)
    expect(z.some((l) => /allow-update \{ key "ddi-ddns"; \}/.test(l))).toBe(true)
  })
})

// Défauts découverts sur un vrai BIND : sans « querylog yes » AUCUNE requête n'est écrite dans le journal, et sans la catégorie
// rpz-passthru les domaines autorisés par une règle ne sont pas tracés (le cockpit ne pourrait pas dire « liste blanche »).
describe('journal des requêtes : configuration BIND', () => {
  it('querylog activé et catégories requêtes + rpz + rpz-passthru vers le même canal ; désactivé proprement', async () => {
    const { DNS_DEFAULTS, renderNamedOptions } = await import('../server/utils/render')
    const on = renderNamedOptions({ ...DNS_DEFAULTS, queryLog: true, rpzEnabled: true } as any, false)
    expect(on).toContain('querylog yes;')
    for (const c of ['queries', 'rpz', 'rpz-passthru']) expect(on).toContain(`category ${c} { ddi_queries; };`)
    expect(on).toContain('print-time iso8601-utc')   // l'analyseur lit l'horodatage ISO
    const off = renderNamedOptions({ ...DNS_DEFAULTS, queryLog: false } as any, false)
    expect(off).toContain('querylog no;'); expect(off).not.toContain('ddi_queries')
  })
})
