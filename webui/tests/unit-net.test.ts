import { describe, expect, it } from 'vitest'
import { capacity, cidrContainsCidr, cidrContainsIp, cidrToString, isHostname, isValidDnsName, nextFree, normCidr, normDomain, normIp, normMac, parseCidr, parseIp, ptrName, reverseZoneName } from '~~/server/utils/net'

describe('adresses IPv4 / IPv6', () => {
  it('normalise et compresse selon la RFC 5952', () => {
    expect(normIp('2001:0DB8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8::1')
    expect(normIp('2001:db8:0:0:1:0:0:1')).toBe('2001:db8::1:0:0:1')
    expect(normIp('0:0:0:0:0:0:0:0')).toBe('::')
    expect(normIp('::1')).toBe('::1')
    expect(normIp('::ffff:192.0.2.1')).toBe('::ffff:c000:201')
    expect(normIp('10.0.0.1')).toBe('10.0.0.1')
  })
  it.each(['256.1.1.1', '1.2.3', '01.2.3.4', 'fe80::1%eth0', '2001:db8::g', '1:2:3:4:5:6:7:8:9', 'abc', '', '::1::2'])('refuse %s', (s) => {
    expect(parseIp(s)).toBeNull()
  })
  it('CIDR : normalise les bits hôte, refuse les préfixes hors limites', () => {
    expect(normCidr('10.1.2.3/24')).toBe('10.1.2.0/24')
    expect(normCidr('2001:db8::5/32')).toBe('2001:db8::/32')
    expect(parseCidr('10.0.0.0/33')).toBeNull()
    expect(parseCidr('10.0.0.0')).toBeNull()
    expect(parseCidr('10.1.2.3/24', true)).toBeNull()
    expect(parseCidr('::/129')).toBeNull()
  })
  it('appartenance et capacité', () => {
    const c = parseCidr('192.168.1.0/24')!
    expect(cidrContainsIp(c, parseIp('192.168.1.200')!)).toBe(true)
    expect(cidrContainsIp(c, parseIp('192.168.2.1')!)).toBe(false)
    expect(cidrContainsIp(c, parseIp('::1')!)).toBe(false)
    expect(cidrContainsCidr(parseCidr('10.0.0.0/8')!, parseCidr('10.5.0.0/16')!)).toBe(true)
    expect(cidrContainsCidr(parseCidr('10.5.0.0/16')!, parseCidr('10.0.0.0/8')!)).toBe(false)
    expect(capacity(c)).toBe(254n)
    expect(capacity(parseCidr('10.0.0.0/31')!)).toBe(2n)
    expect(capacity(parseCidr('10.0.0.1/32')!)).toBe(1n)
    expect(capacity(parseCidr('2001:db8::/64')!)).toBe(1n << 64n)
  })
  it('prochaine adresse libre : évite prises, plages exclues, réseau et diffusion', () => {
    const c = parseCidr('10.0.0.0/29')!   // .1 à .6 utilisables
    const taken = new Set([parseIp('10.0.0.1')!.n, parseIp('10.0.0.2')!.n])
    expect(nextFree(c, taken, [[parseIp('10.0.0.3')!.n, parseIp('10.0.0.4')!.n]])).toBe('10.0.0.5')
    expect(nextFree(c, new Set([1n, 2n, 3n, 4n, 5n, 6n].map((x) => parseIp('10.0.0.0')!.n + x)))).toBeNull()
    expect(cidrToString(parseCidr('10.0.0.8/29')!)).toBe('10.0.0.8/29')
  })
  it('noms inverses', () => {
    expect(ptrName(parseIp('192.0.2.10')!)).toBe('10.2.0.192.in-addr.arpa')
    expect(ptrName(parseIp('2001:db8::1')!)).toBe('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa')
    expect(reverseZoneName(parseCidr('192.168.1.0/24')!)).toBe('1.168.192.in-addr.arpa')
    expect(reverseZoneName(parseCidr('10.0.0.0/8')!)).toBe('10.in-addr.arpa')
    expect(reverseZoneName(parseCidr('10.0.0.0/25')!)).toBeNull()
    expect(reverseZoneName(parseCidr('2001:db8::/32')!)).toBe('8.b.d.0.1.0.0.2.ip6.arpa')
  })
  it('MAC et noms', () => {
    for (const m of ['AA:BB:CC:DD:EE:FF', 'aa-bb-cc-dd-ee-ff', 'aabb.ccdd.eeff', 'aabbccddeeff']) expect(normMac(m)).toBe('aa:bb:cc:dd:ee:ff')
    expect(normMac('aa:bb:cc:dd:ee')).toBeNull()
    expect(normMac('zz:bb:cc:dd:ee:ff')).toBeNull()
    expect(normDomain('Ads.Example.COM.')).toBe('ads.example.com')
    expect(normDomain('localhost')).toBeNull()
    expect(normDomain('bad domain.com')).toBeNull()
    expect(isValidDnsName('*.example.com')).toBe(true)
    expect(isValidDnsName('a.*.example.com')).toBe(false)
    expect(isValidDnsName('-bad.example.com')).toBe(false)
    expect(isValidDnsName('a'.repeat(64) + '.com')).toBe(false)
    expect(isValidDnsName('_sip._tcp')).toBe(true)
    expect(isHostname('srv-01')).toBe(true)
    expect(isHostname('srv_01')).toBe(false)
  })
})
