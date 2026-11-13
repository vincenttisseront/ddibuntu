import { describe, expect, it } from 'vitest'
import { parseServers, planZones } from '../server/utils/zone-inventory'
import { axfrArgs, validServer } from '../server/utils/axfr'
import { parseZoneFile } from '../server/utils/dns'

const CSV = `"ZoneName","ZoneType","IsDsIntegrated","IsSigned","MasterServers"
"corp.local","Primary","True","False",""
"Web.Corp.Local.","Primary","False","True",""
"0.168.192.in-addr.arpa","Primary","False","False",""
"sec.corp.local","Secondary","False","False","10.0.0.5 10.0.0.6"
"nomaster.corp.local","Secondary","False","False",""
"partner.net","Forwarder","False","False","203.0.113.7;203.0.113.8"
"stub.corp.local","Stub","False","False","10.0.0.9"
"TrustAnchors","Primary","True","False",""
"bad_name!","Primary","False","False",""
"corp.local","Primary","False","False",""`
const DIG = `corp.local.\t3600\tIN\tSOA\tdc1.corp.local. hostmaster.corp.local. 12 900 600 86400 3600
corp.local.\t600\tIN\tNS\tdc1.corp.local.
dc1.corp.local.\t3600\tIN\tA\t10.0.0.10
_ldap._tcp.corp.local.\t600\tIN\tSRV\t0 100 389 dc1.corp.local.
www.corp.local.\t3600\tIN\tCNAME\tdc1.corp.local.
corp.local.\t3600\tIN\tSOA\tdc1.corp.local. hostmaster.corp.local. 12 900 600 86400 3600`

describe('zones Windows : inventaire et transfert', () => {
  it('plan : type repris, maîtres / redirecteurs lus, stub et anomalies ignorés, existant reconnu', () => {
    const p = planZones(CSV, new Set(['web.corp.local']))
    const by = Object.fromEntries([...p.items].reverse().map((i) => [i.name, i]))   // la première occurrence l'emporte
    expect(by['corp.local']).toMatchObject({ type: 'primary', action: 'create', adIntegrated: true })
    expect(by['web.corp.local']).toMatchObject({ action: 'exists', signed: true })
    expect(by['sec.corp.local']).toMatchObject({ type: 'secondary', action: 'create', masters: ['10.0.0.5', '10.0.0.6'] })
    expect(by['partner.net']).toMatchObject({ type: 'forward', forwarders: ['203.0.113.7', '203.0.113.8'] })
    expect(by['nomaster.corp.local']).toMatchObject({ action: 'skip', reason: 'no_masters' }); expect(by['stub.corp.local']).toMatchObject({ action: 'skip', reason: 'stub' })
    expect(by['trustanchors']).toBeUndefined(); expect(by['bad_name!']).toMatchObject({ reason: 'invalid_name' })
    expect(p.items.filter((i) => i.reason === 'duplicate').length).toBe(1)
  })
  it('CSV sans ZoneName : erreur ; adresses de serveurs tolérantes', () => {
    expect(planZones('a,b\n1,2', new Set()).errors).toEqual(['dns_csv_invalid'])
    expect(parseServers('10.0.0.1, 10.0.0.1;fe80::1 pas-une-ip')).toEqual(['10.0.0.1', 'fe80::1'])
  })
  it('serveur de transfert : IP ou nom valide, jamais une option ; arguments sans shell', () => {
    expect(validServer('10.0.0.10')).toBe(true); expect(validServer('dc1.corp.local')).toBe(true)
    for (const bad of ['-f /etc/passwd', '; rm -rf /', 'a b', '', '$(id)']) expect(validServer(bad)).toBe(false)
    expect(axfrArgs('corp.local', '10.0.0.10')).toEqual(['+noall', '+answer', '+nocomments', '+time=10', '+tries=1', '+tcp', '@10.0.0.10', 'corp.local', 'AXFR'])
  })
  it('la sortie de dig AXFR est lue par l’import de zone (SOA en double, SRV, CNAME)', () => {
    const z = parseZoneFile(DIG, 'corp.local')
    expect(z.soa).not.toBeNull(); expect(z.records.map((r) => `${r.name}/${r.type}`).sort()).toEqual(['@/NS', '_ldap._tcp/SRV', 'dc1/A', 'www/CNAME'])
  })

  it('coexistence : les primaires deviennent secondaires derrière le serveur Windows, le reste est inchangé', () => {
    const p = planZones(CSV, new Set(), '192.0.2.1')
    const by = Object.fromEntries([...p.items].reverse().map((i) => [i.name, i]))
    expect(by['corp.local']).toMatchObject({ type: 'secondary', masters: ['192.0.2.1'] })
    expect(by['sec.corp.local'].masters).toEqual(['10.0.0.5', '10.0.0.6'])
    expect(by['partner.net'].type).toBe('forward')
  })
})
