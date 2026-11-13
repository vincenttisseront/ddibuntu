import { describe, expect, it } from 'vitest'
import { covers, normNets, splitNets } from '../server/utils/firewall'

describe('pare-feu : réseaux d\'administration', () => {
  it('normalise : CIDR, adresse seule, IPv6, doublons ; refuse /0 et le reste', () => {
    expect(normNets(['192.168.1.0/24', '10.20.0.15', '10.20.0.15/32', '2001:db8::1', ' '])).toEqual(['192.168.1.0/24', '10.20.0.15/32', '2001:db8::1/128'])
    expect(normNets(['10.0.0.5/24'])).toEqual(['10.0.0.0/24'])
    for (const bad of ['0.0.0.0/0', '::/0', 'x', '10.0.0.0/33', '10.0.0.1; rm']) expect(normNets([bad])).toBeNull()
  })
  it('covers : le poste d\'administration est-il couvert ?', () => {
    expect(covers(['10.20.0.0/24'], '10.20.0.7')).toBe(true)
    expect(covers(['10.20.0.0/24'], '::ffff:10.20.0.7')).toBe(true)
    expect(covers(['10.20.0.0/24'], '10.21.0.7')).toBe(false)
    expect(covers(['2001:db8::/32'], '10.20.0.7')).toBe(false)
    expect(covers([], '10.20.0.7')).toBe(false); expect(covers(['10.0.0.0/8'], null)).toBe(false)
  })
  it('splitNets accepte virgules, espaces, retours à la ligne', () => { expect(splitNets('a, b\nc;d')).toEqual(['a', 'b', 'c', 'd']) })
})
