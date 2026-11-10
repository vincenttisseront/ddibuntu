// Listes de blocage : analyse des formats usuels, domaines normalisés, téléchargement protégé (SSRF).
import http from 'node:http'
import https from 'node:https'
import dns from 'node:dns'
import { createHash } from 'node:crypto'
import { isIP } from 'node:net'
import { cidrContainsIp, normDomain, parseCidr, parseIp } from './net'

export type ListFormat = 'hosts' | 'domains' | 'adblock'
export const CATEGORIES = ['adult', 'malware', 'phishing', 'ads', 'tracking', 'gambling', 'social', 'custom'] as const

const HOSTS_SKIP = new Set(['localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix', 'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts', '0.0.0.0'])

export function parseBlocklist(text: string, format: ListFormat, max = 5_000_000): { domains: string[]; skipped: number } {
  const out = new Set<string>()
  let skipped = 0
  for (const raw of text.replace(/\r/g, '').split('\n')) {
    let line = raw.trim()
    if (!line || line.startsWith('#') || line.startsWith('!') || line.startsWith('[')) continue
    let cand: string | null = null
    if (format === 'hosts') {
      line = line.replace(/\s+#.*$/, '')
      const p = line.split(/\s+/)
      if (p.length < 2 || !['0.0.0.0', '127.0.0.1', '::', '::1'].includes(p[0]!)) { skipped++; continue }
      for (const h of p.slice(1)) { if (HOSTS_SKIP.has(h)) continue; const d = normDomain(h); if (d) out.add(d); else skipped++ }
      if (out.size >= max) break
      continue
    }
    if (format === 'adblock') {
      if (line.startsWith('@@')) { skipped++; continue }
      const m = line.match(/^\|\|([a-z0-9._*-]+)\^$/i)
      if (!m) { skipped++; continue }
      cand = m[1]!
    } else {
      cand = line.split(/\s+/)[0]!.replace(/^\*\./, '')
    }
    const d = normDomain(cand.replace(/^\*\./, ''))
    if (d) out.add(d); else skipped++
    if (out.size >= max) break
  }
  return { domains: [...out], skipped }
}

// ---- Téléchargement : http(s) seulement, adresses publiques seulement, plafond de taille ----
const PRIVATE = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']
export function isPrivateAddress(addr: string): boolean {
  const ip = parseIp(addr)
  if (!ip) return true
  if (ip.v === 6 && (ip.n >> 32n) === 0xffffn) return isPrivateAddress(`${(ip.n >> 24n) & 255n}.${(ip.n >> 16n) & 255n}.${(ip.n >> 8n) & 255n}.${ip.n & 255n}`)
  return PRIVATE.some((c) => cidrContainsIp(parseCidr(c)!, ip))
}

export interface FetchOpts { allowPrivate: boolean; maxBytes: number; timeoutMs: number; maxRedirects?: number }
export async function fetchList(url: string, opts: FetchOpts, depth = 0): Promise<{ text: string; sha256: string }> {
  let u: URL
  try { u = new URL(url) } catch { throw Object.assign(new Error('url_invalid'), { code: 'url_invalid' }) }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw Object.assign(new Error('url_scheme'), { code: 'url_scheme' })
  if (u.username || u.password) throw Object.assign(new Error('url_credentials'), { code: 'url_credentials' })
  const lib = u.protocol === 'https:' ? https : http
  // une IP littérale ne passe pas par « lookup » : contrôle explicite (crochets IPv6 retirés)
  const literal = u.hostname.replace(/^\[|\]$/g, '')
  if (isIP(literal) && !opts.allowPrivate && isPrivateAddress(literal)) throw Object.assign(new Error('url_private'), { code: 'url_private' })
  // le contrôle d'adresse a lieu à la connexion (lookup) : pas de fenêtre pour un « DNS rebinding »
  const lookup: any = (host: string, options: any, cb: any) => {
    dns.lookup(host, { all: true, ...(typeof options === 'object' ? options : {}) }, (err, addrs: any) => {
      if (err) return cb(err)
      const list = Array.isArray(addrs) ? addrs : [{ address: addrs, family: 4 }]
      if (!opts.allowPrivate && list.some((a: any) => isPrivateAddress(a.address))) return cb(Object.assign(new Error('url_private'), { code: 'url_private' }))
      if (options?.all) return cb(null, list)
      cb(null, list[0].address, list[0].family)
    })
  }
  return await new Promise((resolve, reject) => {
    let settled = false
    const fin = <T,>(fn: (v: T) => void) => (v: T) => { if (!settled) { settled = true; fn(v) } }
    const ok = fin(resolve as (v: { text: string; sha256: string }) => void), ko = fin(reject)
    const req = lib.request(u, { method: 'GET', lookup, timeout: opts.timeoutMs, headers: { 'user-agent': 'ddibuntu-console', accept: 'text/plain,*/*' } }, (res) => {
      const status = res.statusCode ?? 0
      res.on('error', (e) => ko(e))
      if ([301, 302, 303, 307, 308].includes(status) && res.headers.location) {
        res.resume()
        if (depth >= (opts.maxRedirects ?? 3)) return ko(Object.assign(new Error('too_many_redirects'), { code: 'too_many_redirects' }))
        return fetchList(new URL(res.headers.location, u).toString(), opts, depth + 1).then(ok, ko)
      }
      if (status !== 200) { res.resume(); return ko(Object.assign(new Error('http_status'), { code: 'http_status', status })) }
      const chunks: Buffer[] = []
      let size = 0
      res.on('data', (d: Buffer) => {
        size += d.length
        if (size > opts.maxBytes) { ko(Object.assign(new Error('too_large'), { code: 'too_large' })); res.destroy(); req.destroy(); return }
        chunks.push(d)
      })
      res.on('end', () => { const b = Buffer.concat(chunks); ok({ text: b.toString('utf8'), sha256: createHash('sha256').update(b).digest('hex') }) })
    })
    req.on('timeout', () => { ko(Object.assign(new Error('timeout'), { code: 'timeout' })); req.destroy() })
    req.on('error', (e) => ko(e))
    req.end()
  })
}
