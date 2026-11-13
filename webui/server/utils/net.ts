// Calcul réseau IPv4/IPv6 et validations de noms. Aucune dépendance : BigInt + node:net.
import { isIPv4, isIPv6 } from 'node:net'

export type IpVersion = 4 | 6
export interface Ip { v: IpVersion; n: bigint }
export interface Cidr { v: IpVersion; n: bigint; prefix: number }

const BITS: Record<IpVersion, number> = { 4: 32, 6: 128 }

function parseV6(t: string): bigint | null {
  if (t.includes('%')) return null
  let s = t
  const m = s.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/)
  if (m) {
    const v4 = parseIp(m[1]!)
    if (!v4 || v4.v !== 4) return null
    s = s.slice(0, s.length - m[1]!.length) + (v4.n >> 16n).toString(16) + ':' + (v4.n & 0xffffn).toString(16)
  }
  const parts = s.split('::')
  if (parts.length > 2) return null
  const head = parts[0] ? parts[0].split(':') : []
  const rest = parts.length === 2 && parts[1] ? parts[1]!.split(':') : []
  if (parts.length === 1 && head.length !== 8) return null
  if (parts.length === 2 && head.length + rest.length > 7) return null
  const groups = parts.length === 2 ? [...head, ...Array(8 - head.length - rest.length).fill('0'), ...rest] : head
  let n = 0n
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null
    n = (n << 16n) | BigInt(Number.parseInt(g, 16))
  }
  return n
}

export function parseIp(input: string): Ip | null {
  const t = input.trim()
  if (isIPv4(t)) {
    const p = t.split('.').map(Number)
    return { v: 4, n: (BigInt(p[0]!) << 24n) | (BigInt(p[1]!) << 16n) | (BigInt(p[2]!) << 8n) | BigInt(p[3]!) }
  }
  if (isIPv6(t)) {
    const n = parseV6(t)
    return n === null ? null : { v: 6, n }
  }
  return null
}

export function ipToString(ip: Ip): string {
  if (ip.v === 4) return [24n, 16n, 8n, 0n].map((s) => ((ip.n >> s) & 0xffn).toString()).join('.')
  const g: number[] = []
  for (let i = 7; i >= 0; i--) g.push(Number((ip.n >> BigInt(i * 16)) & 0xffffn))
  // RFC 5952 : on compresse la plus longue suite (>= 2) de groupes nuls, la première en cas d'égalité
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
  g.forEach((x, i) => {
    if (x === 0) { if (curStart < 0) { curStart = i; curLen = 0 } curLen++; if (curLen > bestLen) { bestLen = curLen; bestStart = curStart } }
    else { curStart = -1; curLen = 0 }
  })
  const hex = g.map((x) => x.toString(16))
  if (bestLen < 2) return hex.join(':')
  const left = hex.slice(0, bestStart).join(':')
  const right = hex.slice(bestStart + bestLen).join(':')
  return `${left}::${right}`
}

export function normIp(input: string): string | null {
  const ip = parseIp(input)
  return ip ? ipToString(ip) : null
}

/** Réseau CIDR. Les bits hôte sont ignorés (normalisés) sauf si strict=true. Préfixe obligatoire. */
export function parseCidr(input: string, strict = false): Cidr | null {
  const m = input.trim().match(/^([^/]+)\/(\d{1,3})$/)
  if (!m) return null
  const ip = parseIp(m[1]!)
  if (!ip) return null
  const prefix = Number(m[2])
  if (prefix > BITS[ip.v]) return null
  const host = BITS[ip.v] - prefix
  const mask = ((1n << BigInt(BITS[ip.v])) - 1n) ^ ((1n << BigInt(host)) - 1n)
  const net = ip.n & mask
  if (strict && net !== ip.n) return null
  return { v: ip.v, n: net, prefix }
}

export function cidrToString(c: Cidr): string {
  return `${ipToString({ v: c.v, n: c.n })}/${c.prefix}`
}
export function normCidr(input: string): string | null {
  const c = parseCidr(input)
  return c ? cidrToString(c) : null
}

export function cidrRange(c: Cidr): { first: bigint; last: bigint } {
  const host = BigInt(BITS[c.v] - c.prefix)
  return { first: c.n, last: c.n | ((1n << host) - 1n) }
}
export function cidrContainsIp(c: Cidr, ip: Ip): boolean {
  if (c.v !== ip.v) return false
  const r = cidrRange(c)
  return ip.n >= r.first && ip.n <= r.last
}
export function cidrContainsCidr(outer: Cidr, inner: Cidr): boolean {
  return outer.v === inner.v && outer.prefix <= inner.prefix && cidrContainsIp(outer, { v: inner.v, n: inner.n })
}
/** Nombre d'adresses utilisables (IPv4 : hors réseau et diffusion, sauf /31 et /32). */
export function capacity(c: Cidr): bigint {
  const total = 1n << BigInt(BITS[c.v] - c.prefix)
  if (c.v === 4) {
    if (c.prefix >= 31) return total
    return total - 2n
  }
  return total
}
/** Première adresse libre d'un réseau IPv4 hors adresses prises et plages exclues. */
export function nextFree(c: Cidr, taken: Set<bigint>, excluded: Array<[bigint, bigint]> = []): string | null {
  if (c.v !== 4) return null
  const r = cidrRange(c)
  const first = c.prefix >= 31 ? r.first : r.first + 1n
  const last = c.prefix >= 31 ? r.last : r.last - 1n
  for (let n = first; n <= last; n++) {
    if (taken.has(n)) continue
    if (excluded.some(([a, b]) => n >= a && n <= b)) continue
    return ipToString({ v: 4, n })
  }
  return null
}

/** Première adresse IPv4 libre d'une plage [lo, hi] (bornes incluses), hors adresses prises et plages exclues. */
export function nextFreeInRange(lo: bigint, hi: bigint, taken: Set<bigint>, excluded: Array<[bigint, bigint]> = []): string | null {
  for (let n = lo; n <= hi; n++) {
    if (taken.has(n)) continue
    if (excluded.some(([a, b]) => n >= a && n <= b)) continue
    return ipToString({ v: 4, n })
  }
  return null
}

/** Nom PTR d'une adresse (in-addr.arpa / ip6.arpa), sans point final. */
export function ptrName(ip: Ip): string {
  if (ip.v === 4) return ipToString(ip).split('.').reverse().join('.') + '.in-addr.arpa'
  const hex = ip.n.toString(16).padStart(32, '0')
  return hex.split('').reverse().join('.') + '.ip6.arpa'
}
/** Zone inverse d'un réseau : seulement pour les préfixes alignés (IPv4 multiple de 8, IPv6 multiple de 4). */
export function reverseZoneName(c: Cidr): string | null {
  if (c.v === 4) {
    if (c.prefix % 8 !== 0 || c.prefix === 0) return null
    const o = ipToString({ v: 4, n: c.n }).split('.').slice(0, c.prefix / 8)
    return o.reverse().join('.') + '.in-addr.arpa'
  }
  if (c.prefix % 4 !== 0 || c.prefix === 0) return null
  const hex = c.n.toString(16).padStart(32, '0').slice(0, c.prefix / 4)
  return hex.split('').reverse().join('.') + '.ip6.arpa'
}

export function normMac(input: string): string | null {
  const h = input.trim().toLowerCase().replace(/[:\-.]/g, '')
  if (!/^[0-9a-f]{12}$/.test(h)) return null
  return h.match(/.{2}/g)!.join(':')
}

// ---- Noms DNS ----
const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/i
export function isValidLabel(l: string): boolean { return LABEL.test(l) }
/** Nom d'hôte absolu ou relatif, sans point final. Le joker « * » n'est admis qu'en première étiquette. */
export function isValidDnsName(name: string, allowWildcard = true): boolean {
  if (!name || name.length > 253) return false
  const labels = name.split('.')
  return labels.every((l, i) => (allowWildcard && i === 0 && l === '*') || isValidLabel(l))
}
export function normDomain(input: string): string | null {
  const d = input.trim().toLowerCase().replace(/\.$/, '')
  return isValidDnsName(d, false) && d.includes('.') ? d : null
}
export function isHostname(name: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(name)
}
