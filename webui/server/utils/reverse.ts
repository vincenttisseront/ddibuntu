// Zones inverses automatiques (0.10.4) : quelles zones un sous-réseau demande, y compris la délégation « classless » de la RFC 2317 pour les /25 à /32.
import { ipToString, type Cidr } from './net'

export interface RevZone { name: string; kind: 'standard' | 'classless' }
export interface RevCname { zone: string; name: string; target: string }
export interface RevPlan { zones: RevZone[]; cnames: RevCname[]; error?: 'reverse_too_large' }

const nib = (c: Cidr, n: number) => c.n.toString(16).padStart(32, '0').slice(0, n).split('').reverse().join('.')

export function reverseZonesFor(c: Cidr): RevPlan {
  if (c.v === 6) {
    const n = Math.floor(c.prefix / 4)
    return n === 0 ? { zones: [], cnames: [], error: 'reverse_too_large' } : { zones: [{ name: `${nib(c, n)}.ip6.arpa`, kind: 'standard' }], cnames: [] }
  }
  const o = ipToString({ v: 4, n: c.n }).split('.')
  if (c.prefix < 8) return { zones: [], cnames: [], error: 'reverse_too_large' }
  if (c.prefix <= 24) {
    const k = Math.floor(c.prefix / 8)   // un /22 est servi par la zone du /16 qui le contient
    return { zones: [{ name: `${o.slice(0, k).reverse().join('.')}.in-addr.arpa`, kind: 'standard' }], cnames: [] }
  }
  const parent = `${o.slice(0, 3).reverse().join('.')}.in-addr.arpa`
  const child = `${o[3]}-${c.prefix}.${parent}`
  const size = 2 ** (32 - c.prefix), first = Number(o[3])
  return { zones: [{ name: parent, kind: 'standard' }, { name: child, kind: 'classless' }], cnames: Array.from({ length: size }, (_, i) => ({ zone: parent, name: String(first + i), target: `${first + i}.${child}` })) }
}

/** « 64-26.1.168.192.in-addr.arpa » → plage couverte, sinon null. */
export function classlessRange(zone: string): { parent: string; first: string; last: string } | null {
  const m = zone.toLowerCase().match(/^(\d{1,3})-(\d{1,2})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa$/)
  if (!m) return null
  const f = Number(m[1]), p = Number(m[2])
  if (p < 25 || p > 32 || f > 255 || f % 2 ** (32 - p) !== 0) return null
  return { parent: `${m[3]}.${m[4]}.${m[5]}.in-addr.arpa`, first: `${m[5]}.${m[4]}.${m[3]}.${f}`, last: `${m[5]}.${m[4]}.${m[3]}.${f + 2 ** (32 - p) - 1}` }
}
