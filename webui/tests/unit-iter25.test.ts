import { describe, expect, it } from 'vitest'
import { assess } from '../server/utils/migration-assess'

const DHCP = `<?xml version="1.0"?><DHCPServer><IPv4>
<Classes><Class><Name>Cisco</Name></Class><Class><Name>Win</Name></Class></Classes>
<Policies><Policy><Name>p1</Name></Policy></Policies>
<Filters><Filter><List>Allow</List></Filter><Filter><List>Deny</List></Filter></Filters>
<Scopes><Scope><ScopeId>192.168.1.0</ScopeId><Name>LAN</Name><SubnetMask>255.255.255.0</SubnetMask><StartRange>192.168.1.100</StartRange><EndRange>192.168.1.200</EndRange><LeaseDuration>8.00:00:00</LeaseDuration><State>Active</State>
<OptionValues><OptionValue><OptionId>3</OptionId><Value>192.168.1.1</Value></OptionValue><OptionValue><OptionId>200</OptionId><Value>x</Value></OptionValue></OptionValues>
<Reservations><Reservation><IPAddress>192.168.1.50</IPAddress><ClientId>AA-BB-CC-DD-EE-01</ClientId></Reservation></Reservations></Scope></Scopes>
<Superscopes><Superscope><Name>ss</Name></Superscope></Superscopes></IPv4>
<IPv6><Scopes><Scope><Prefix>2001:db8::</Prefix></Scope></Scopes></IPv6></DHCPServer>`
const ZONES = `"ZoneName","ZoneType","IsDsIntegrated","IsReverseLookupZone","DynamicUpdate","IsSigned"
"corp.local","Primary","True","False","Secure","False"
"web.corp.local","Primary","False","False","None","False"
"_msdcs.corp.local","Primary","True","False","Secure","False"
"1.168.192.in-addr.arpa","Primary","False","True","None","False"
"sec.corp.local","Secondary","False","False","None","False"
"stub.corp.local","Stub","False","False","None","False"
"partner.net","Forwarder","False","False","None","False"
"signed.corp.local","Primary","False","False","None","True"
"TrustAnchors","Primary","True","False","None","False"`
const by = (a: ReturnType<typeof assess>, code: string) => a.findings.find((f) => f.code === code)

describe('évaluation de compatibilité Windows', () => {
  it('DHCP : repris, adapté, non pris en charge', () => {
    const a = assess({ dhcp: DHCP })
    expect(by(a, 'dhcp_scopes')).toMatchObject({ level: 'ok', count: 1 }); expect(by(a, 'dhcp_reservations')).toMatchObject({ level: 'ok', count: 1 })
    expect(by(a, 'dhcp_options')).toMatchObject({ level: 'adapted', count: 1, detail: '200' })
    expect(by(a, 'dhcp_policies')?.count).toBe(1); expect(by(a, 'dhcp_classes')?.count).toBe(2); expect(by(a, 'dhcp_filters')?.count).toBe(2); expect(by(a, 'dhcp_superscopes')?.count).toBe(1)
    expect(by(a, 'dhcp_ipv6')?.level).toBe('unsupported'); expect(a.verdict).toBe('review')
  })
  it('DNS : zones classées, zones automatiques ignorées', () => {
    const a = assess({ zones: ZONES })
    expect(by(a, 'dns_primary')?.count).toBe(2)   // corp.local est intégrée à AD ; _msdcs aussi
    expect(by(a, 'dns_reverse')?.count).toBe(1); expect(by(a, 'dns_ds')?.count).toBe(2)   // TrustAnchors ignorée
    expect(by(a, 'dns_secondary')?.count).toBe(1); expect(by(a, 'dns_stub')?.level).toBe('unsupported'); expect(by(a, 'dns_forwarder')?.count).toBe(1)
    expect(by(a, 'dns_signed')?.count).toBe(1); expect(by(a, 'dns_secure_update')?.count).toBe(2); expect(by(a, 'dns_ad_critical')?.count).toBe(1)
  })
  it('configuration simple : prêt à migrer', () => {
    const a = assess({ dhcp: '<DHCPServer><IPv4><Scopes><Scope><ScopeId>10.0.0.0</ScopeId><Name>n</Name><SubnetMask>255.255.255.0</SubnetMask><StartRange>10.0.0.10</StartRange><EndRange>10.0.0.20</EndRange></Scope></Scopes></IPv4></DHCPServer>', zones: '"ZoneName","ZoneType"\n"a.test","Primary"' })
    expect(a.verdict).toBe('ready'); expect(a.summary.unsupported).toBe(0)
  })
  it('entrées invalides : erreurs claires, jamais d’exception', () => {
    expect(assess({ dhcp: '<pas du xml' }).errors).toEqual(['dhcp_xml_invalid'])
    expect(assess({ dhcp: '<a></a>' }).errors).toEqual(['dhcp_no_ipv4'])
    expect(assess({ zones: 'foo,bar\n1,2' }).errors).toEqual(['dns_csv_invalid'])
    expect(assess({ dhcp: '<pas du xml' }).verdict).toBe('blocked'); expect(assess({}).findings).toEqual([])
  })
})
