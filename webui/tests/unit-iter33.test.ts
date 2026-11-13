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

import { checkHints, validateFiles } from '../server/utils/render'
describe('diagnostic des NS sans adresse', () => {
  it('extrait les noms (dédoublonnés) de la sortie de named-checkzone', () => {
    const out = "zone a.b/IN: NS 'x.a.b' has no address records (A or AAAA)\nzone a.b/IN: NS 'x.a.b' has no address records (A or AAAA)\nzone a.b/IN: NS 'y.a.b' has no address records (A or AAAA)\nzone a.b/IN: not loaded due to errors."
    expect(checkHints(out)).toEqual([{ code: 'ns_no_address', names: ['x.a.b', 'y.a.b'] }]); expect(checkHints('zone a.b/IN: loaded serial 1\nOK')).toEqual([])
  })
  it('validateFiles joint le diagnostic au résultat refusé', async () => {
    const zone = { path: 'zones/db.ex.test', kind: 'zone' as const, content: '$ORIGIN ex.test.\n$TTL 300\n@ IN SOA ns1.ex.test. h.ex.test. ( 1 900 600 86400 300 )\n@ IN NS ns1.ex.test.\n@ IN NS stale.ex.test.\nns1 IN A 192.0.2.1\n' }
    const r = (await validateFiles([zone]))[0]!
    if (r.ok === null) return   // named-checkzone absent
    expect(r.ok).toBe(false); expect(r.hints).toEqual([{ code: 'ns_no_address', names: ['stale.ex.test'] }])
  })
})
