import { describe, expect, it } from 'vitest'
import { conflictError, isAdCritical, nextSerial, normalizeRdata, parseTtl, parseZoneFile, renderRdata, renderZone, toRelativeName, tokenize } from '~~/server/utils/dns'
import type { RecordType } from '~~/server/utils/dns'

const ok = (t: RecordType, s: string) => { const r = normalizeRdata(t, s); if (!r.ok) throw new Error(`${t} ${s} : ${r.error}`); return r.value }
const ko = (t: RecordType, s: string) => expect(normalizeRdata(t, s).ok).toBe(false)

describe('validation par type', () => {
  it('A / AAAA', () => {
    expect(ok('A', ' 10.0.0.1 ')).toBe('10.0.0.1'); ko('A', '2001:db8::1'); ko('A', '10.0.0'); ko('A', '999.1.1.1')
    expect(ok('AAAA', '2001:0db8::0001')).toBe('2001:db8::1'); ko('AAAA', '10.0.0.1')
  })
  it('cibles de nom : relatives, absolues, « @ »', () => {
    expect(ok('CNAME', 'Web')).toBe('web'); expect(ok('CNAME', 'web.example.com')).toBe('web.example.com.'); expect(ok('CNAME', 'web.example.com.')).toBe('web.example.com.')
    expect(ok('CNAME', '@')).toBe('@'); ko('CNAME', 'bad name'); ko('NS', '10.0.0.1')
    expect(ok('PTR', 'host.example.com')).toBe('host.example.com.'); expect(ok('DNAME', 'other.example.')).toBe('other.example.')
  })
  it('MX, SRV', () => {
    expect(ok('MX', '10 mail.example.com')).toBe('10 mail.example.com.'); ok('MX', '0 .'); ko('MX', 'mail.example.com'); ko('MX', '70000 mail'); ko('MX', '10 a b')
    expect(ok('SRV', '0 5 5060 sip.example.com')).toBe('0 5 5060 sip.example.com.'); ko('SRV', '0 5 sip'); ko('SRV', '0 5 70000 sip')
  })
  it('TXT : texte libre, limites', () => {
    expect(ok('TXT', 'v=spf1 include:_spf.example.com ~all')).toBe('v=spf1 include:_spf.example.com ~all')
    ko('TXT', 'ligne\nbrisée'); ko('TXT', 'x'.repeat(61000))
  })
  it('CAA, NAPTR, SSHFP, TLSA, HTTPS, HINFO, RP, DS', () => {
    expect(ok('CAA', '0 issue "letsencrypt.org"')).toBe('0 issue letsencrypt.org'); expect(ok('CAA', '128 iodef mailto:sec@example.com')).toBe('128 iodef mailto:sec@example.com'); ko('CAA', 'issue x'); ko('CAA', '300 issue x')
    expect(ok('NAPTR', '100 10 "S" "SIP+D2U" "" _sip._udp.example.com')).toBe('100 10 "S" "SIP+D2U" "" _sip._udp.example.com.'); ko('NAPTR', '100 10 "S" "x"')
    expect(ok('SSHFP', '4 2 ' + 'a'.repeat(64))).toBe('4 2 ' + 'a'.repeat(64)); ko('SSHFP', '4 2 abcd'); ko('SSHFP', '4 1 ' + 'a'.repeat(64))
    expect(ok('TLSA', '3 1 1 ' + 'AB'.repeat(32))).toBe('3 1 1 ' + 'ab'.repeat(32)); ko('TLSA', '4 1 1 aa'); ko('TLSA', '3 1 1 abc')
    expect(ok('HTTPS', '1 . alpn=h2,h3')).toBe('1 . alpn=h2,h3'); ko('HTTPS', 'x . alpn=h2'); ko('HTTPS', '1 . "quoted"')
    expect(ok('HINFO', '"AMD64" "Linux"')).toBe('"AMD64" "Linux"'); expect(ok('HINFO', 'AMD64 Linux')).toBe('"AMD64" "Linux"'); ko('HINFO', 'seul')
    expect(ok('RP', 'admin.example.com. txt.example.com.')).toBe('admin.example.com. txt.example.com.')
    expect(ok('DS', '12345 13 2 ' + 'AB'.repeat(32))).toBe('12345 13 2 ' + 'ab'.repeat(32)); ko('DS', '1 2 3')
  })
})

describe('noms et conflits', () => {
  it('nom relatif à la zone', () => {
    expect(toRelativeName('www.Example.com.', 'example.com')).toBe('www'); expect(toRelativeName('example.com', 'example.com')).toBe('@')
    expect(toRelativeName('@', 'example.com')).toBe('@'); expect(toRelativeName('a.b', 'example.com')).toBe('a.b')
    expect(toRelativeName('www.other.org.', 'example.com')).toBeNull(); expect(toRelativeName('bad name', 'example.com')).toBeNull()
    expect(toRelativeName('*.apps', 'example.com')).toBe('*.apps')
  })
  it('un CNAME est seul à son nom et jamais au sommet', () => {
    const ex = [{ id: 1, name: 'www', type: 'A' }, { id: 2, name: 'alias', type: 'CNAME' }]
    expect(conflictError(ex, { name: 'www', type: 'CNAME' })).toBe('cname_conflict')
    expect(conflictError(ex, { name: 'alias', type: 'A' })).toBe('cname_conflict')
    expect(conflictError(ex, { name: 'alias', type: 'CNAME' }, 2)).toBeNull()
    expect(conflictError(ex, { name: '@', type: 'CNAME' })).toBe('cname_apex')
    expect(conflictError(ex, { name: 'WWW', type: 'MX' })).toBeNull()
    expect(conflictError(ex, { name: 'ALIAS', type: 'TXT' })).toBe('cname_conflict')
  })
  it('enregistrements critiques Active Directory', () => {
    expect(isAdCritical('_ldap._tcp.dc._msdcs', 'SRV')).toBe(true); expect(isAdCritical('_kerberos._tcp', 'SRV')).toBe(true)
    expect(isAdCritical('gc._msdcs', 'A')).toBe(true); expect(isAdCritical('DomainDnsZones', 'A')).toBe(true)
    expect(isAdCritical('www', 'A')).toBe(false); expect(isAdCritical('_sip._tcp', 'SRV')).toBe(false)
  })
  it('numéro de série et TTL', () => {
    expect(nextSerial(1, new Date('2026-11-09T10:00:00Z'))).toBe(2026110900)
    expect(nextSerial(2026110900, new Date('2026-11-09T10:00:00Z'))).toBe(2026110901)
    expect(nextSerial(2026110950, new Date('2026-11-09T10:00:00Z'))).toBe(2026110951)
    expect([parseTtl('300'), parseTtl('1h'), parseTtl('1h30m'), parseTtl('2d'), parseTtl('x')]).toEqual([300, 3600, 5400, 172800, null])
  })
  it('jetons : guillemets et échappements', () => {
    expect(tokenize('a "b c" "d\\"e" f')!.map((t) => t.v)).toEqual(['a', 'b c', 'd"e', 'f'])
    expect(tokenize('"non fermé')).toBeNull()
  })
  it('TXT : découpe en blocs de 255 octets, échappements sûrs', () => {
    const long = 'a'.repeat(600)
    const r = renderRdata('TXT', long)
    expect(r.split('" "').length).toBe(3)
    expect(renderRdata('TXT', 'dit "oui" \\ é')).toBe('"dit \\034oui\\034 \\092 \\195\\169"')
  })
})

// Export d'un contrôleur de domaine Windows (« dnscmd /ZoneExport »), reconstitué : jetons [Aging:…], parenthèses, TTL
const WINDOWS_ZONE = `;
;  Database file ad.corp.local.dns for ad.corp.local zone.
;      Zone version:  42
;
@                       IN  SOA dc01.ad.corp.local. hostmaster.ad.corp.local. (
                        42          ; serial number
                        900         ; refresh
                        600         ; retry
                        86400       ; expire
                        3600 )      ; default TTL
;
;  Zone NS records
;
@                       NS  dc01.ad.corp.local.
@                       NS  dc02.ad.corp.local.
;
;  Zone records
;
@ [Aging:3631234] 600   A   10.0.0.10
@ [Aging:3631234] 600   A   10.0.0.11
_msdcs                  NS  dc01.ad.corp.local.
dc01 [Aging:3631200] 1200 A 10.0.0.10
dc02 1200 A 10.0.0.11
www                     CNAME   dc01
printer 3600 IN A 10.0.5.20
_ldap._tcp              600 SRV 0 100 389 dc01.ad.corp.local.
_kerberos._tcp.Default-First-Site-Name._sites 600 SRV 0 100 88 dc01.ad.corp.local.
gc._msdcs 600 A 10.0.0.10
txt1 TXT "v=spf1 mx" " ~all"
host.autre.org. A 1.2.3.4
wins 900 WINS 10.0.0.9
bad A 999.0.0.1
`

describe('analyse d’un export de zone Windows', () => {
  const p = parseZoneFile(WINDOWS_ZONE, 'ad.corp.local')
  it('SOA et enregistrements', () => {
    expect(p.soa).toMatchObject({ mname: 'dc01.ad.corp.local.', serial: 42, refresh: 900, retry: 600, expire: 86400, minimum: 3600 })
    const key = (r: { name: string; type: string; rdata: string }) => `${r.name} ${r.type} ${r.rdata}`
    const have = p.records.map(key)
    expect(have).toContain('@ NS dc01.ad.corp.local.')
    expect(have).toContain('@ A 10.0.0.10'); expect(have).toContain('@ A 10.0.0.11')
    expect(have).toContain('www CNAME dc01.ad.corp.local.')      // « dc01 » relatif dans un fichier de zone -> absolu
    expect(have).toContain('_ldap._tcp SRV 0 100 389 dc01.ad.corp.local.')
    expect(have).toContain('_kerberos._tcp.default-first-site-name._sites SRV 0 100 88 dc01.ad.corp.local.')
    expect(have).toContain('txt1 TXT v=spf1 mx ~all')
    expect(p.records.find((r) => r.name === 'dc01')!.ttl).toBe(1200)
    expect(p.records.find((r) => r.name === 'printer')!.ttl).toBe(3600)
  })
  it('doublons, hors zone, types non pris en charge, valeurs invalides : signalés, jamais importés', () => {
    expect(p.records.filter((r) => r.name === 'dc01' && r.type === 'A').length).toBe(1)
    const codes = p.warnings.map((w) => w.code)
    expect(codes).toContain('out_of_zone'); expect(codes).toContain('unsupported_type'); expect(codes.some((c) => c.startsWith('rdata_invalid'))).toBe(true)
    expect(p.skipped).toBe(3)
    expect(p.records.some((r) => r.name.includes('autre'))).toBe(false)
  })
  it('détection des enregistrements critiques', () => {
    const crit = p.records.filter((r) => isAdCritical(r.name, r.type)).map((r) => r.name)
    expect(crit).toEqual(expect.arrayContaining(['_msdcs', 'gc._msdcs', '_ldap._tcp', '_kerberos._tcp.default-first-site-name._sites']))
  })
  it('$ORIGIN, $TTL, propriétaire hérité, parenthèses sur plusieurs lignes', () => {
    const z = parseZoneFile('$ORIGIN example.com.\n$TTL 1h\n@ IN SOA ns1 admin ( 1 2 3 4 5 )\n  IN NS ns1\nns1 IN A 192.0.2.1\n    IN AAAA 2001:db8::1\nmail 2h IN MX 10 mx\nsub.example.com. CNAME ns1.example.com.\n$GENERATE 1-3 h$ A 10.0.0.$\n', 'example.com')
    expect(z.records.map((r) => `${r.name} ${r.type} ${r.rdata}`)).toEqual(['@ NS ns1.example.com.', 'ns1 A 192.0.2.1', 'ns1 AAAA 2001:db8::1', 'mail MX 10 mx.example.com.', 'sub CNAME ns1.example.com.'])
    expect(z.defaultTtl).toBe(3600); expect(z.records[3]!.ttl).toBe(7200)
    expect(z.warnings.some((w) => w.code === 'unsupported_directive')).toBe(true)
  })
})

describe('rendu de zone', () => {
  it('produit un fichier de zone relisible : rendu -> analyse -> mêmes enregistrements', () => {
    const recs = [
      { name: '@', type: 'NS', ttl: null, rdata: 'ns1' }, { name: 'ns1', type: 'A', ttl: 300, rdata: '192.0.2.1' }, { name: 'www', type: 'CNAME', ttl: null, rdata: 'ns1' },
      { name: '@', type: 'MX', ttl: null, rdata: '10 mail.example.com.' }, { name: '@', type: 'TXT', ttl: null, rdata: 'v=spf1 -all' },
      { name: '_sip._tcp', type: 'SRV', ttl: null, rdata: '0 5 5060 sip.example.com.' }, { name: '@', type: 'CAA', ttl: null, rdata: '0 issue letsencrypt.org' },
      { name: 'off', type: 'A', ttl: null, rdata: '192.0.2.99', disabled: true },
    ]
    const text = renderZone({ name: 'example.com', default_ttl: 3600, serial: 2026110901, soa_mname: null, soa_rname: null, soa_refresh: 3600, soa_retry: 600, soa_expire: 1209600, soa_minimum: 3600 }, recs)
    expect(text).toContain('@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026110901 3600 600 1209600 3600 )')
    expect(text).not.toContain('192.0.2.99')
    const back = parseZoneFile(text, 'example.com')
    expect(back.skipped).toBe(0)
    const norm = (r: { name: string; type: string; rdata: string }) => `${r.name} ${r.type} ${r.rdata}`
    expect(back.records.map(norm).sort()).toEqual([
      '@ CAA 0 issue letsencrypt.org', '@ MX 10 mail.example.com.', '@ NS ns1.example.com.', '@ TXT v=spf1 -all', '_sip._tcp SRV 0 5 5060 sip.example.com.', 'ns1 A 192.0.2.1', 'www CNAME ns1.example.com.',
    ].sort())
  })
})
