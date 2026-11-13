import { describe, expect, it } from 'vitest'
import { parseCidr } from '../server/utils/net'
import { classlessRange, reverseZonesFor } from '../server/utils/reverse'

const z = (c: string) => reverseZonesFor(parseCidr(c)!)
describe('zones inverses automatiques', () => {
  it('préfixes alignés et regroupés', () => {
    expect(z('10.1.2.0/24').zones).toEqual([{ name: '2.1.10.in-addr.arpa', kind: 'standard' }])
    expect(z('10.1.0.0/16').zones[0]!.name).toBe('1.10.in-addr.arpa'); expect(z('10.4.0.0/22').zones[0]!.name).toBe('4.10.in-addr.arpa'); expect(z('10.0.0.0/8').zones[0]!.name).toBe('10.in-addr.arpa')
    expect(z('4.0.0.0/6').error).toBe('reverse_too_large')
  })
  it('classless RFC 2317 : zone fille, CNAME de la zone parente', () => {
    const p = z('192.168.1.64/26')
    expect(p.zones).toEqual([{ name: '1.168.192.in-addr.arpa', kind: 'standard' }, { name: '64-26.1.168.192.in-addr.arpa', kind: 'classless' }])
    expect(p.cnames).toHaveLength(64); expect(p.cnames[0]).toEqual({ zone: '1.168.192.in-addr.arpa', name: '64', target: '64.64-26.1.168.192.in-addr.arpa' }); expect(p.cnames[63]!.name).toBe('127')
    expect(z('192.168.1.5/32').cnames).toEqual([{ zone: '1.168.192.in-addr.arpa', name: '5', target: '5.5-32.1.168.192.in-addr.arpa' }])
  })
  it('IPv6 : zone au nibble', () => {
    expect(z('2001:db8::/32').zones[0]!.name).toBe('8.b.d.0.1.0.0.2.ip6.arpa'); expect(z('2001:db8::/62').zones[0]!.name).toBe('0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
    expect(z('::/2').error).toBe('reverse_too_large')
  })
  it('plage d\'une zone classless : alignement exigé', () => {
    expect(classlessRange('64-26.1.168.192.in-addr.arpa')).toEqual({ parent: '1.168.192.in-addr.arpa', first: '192.168.1.64', last: '192.168.1.127' })
    expect(classlessRange('65-26.1.168.192.in-addr.arpa')).toBeNull(); expect(classlessRange('1.168.192.in-addr.arpa')).toBeNull(); expect(classlessRange('0-24.1.168.192.in-addr.arpa')).toBeNull()
  })
})
