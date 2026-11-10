// Découverte réseau des adresses des sous-réseaux DÉJÀ déclarés dans l'IPAM. Sans privilège : sondes TCP, ping (si disponible),
// table ARP lue dans /proc/net/arp (le service n'a pas le droit d'ouvrir une socket netlink), baux DHCP et DNS inverse locaux.
import net from 'node:net'
import { execFile } from 'node:child_process'
import { promises as fs } from 'node:fs'
import { Resolver } from 'node:dns/promises'
import { cidrRange, ipToString, normMac, parseCidr } from './net'

export const MAX_TARGETS = 4096
export const PORT_PRESETS: Record<string, number[]> = { basic: [22, 80, 443, 445, 3389], windows: [135, 139, 445, 3389, 5985], web: [80, 443, 8080, 8443], infra: [22, 53, 161, 389, 636, 3306, 5432] }
export class DiscoveryError extends Error { constructor(public code: string) { super(code) } }
const BLOCKED = ['0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4'].map((c) => parseCidr(c)!)

/** Adresses à sonder : hôtes des sous-réseaux IPv4 donnés (sans réseau ni diffusion). Plafonné ; ni boucle locale, ni lien local, ni multicast. */
export function enumerateTargets(cidrs: string[], allowLoopback = false): { ips: string[]; subnetOf: Map<string, string>; skipped: string[] } {
  const ips: string[] = [], subnetOf = new Map<string, string>(), skipped: string[] = []
  for (const text of cidrs) {
    const c = parseCidr(text, false)
    if (!c) continue
    if (c.v !== 4) { skipped.push(`${text}:ipv6`); continue }
    const { first, last } = cidrRange(c)
    // la boucle locale n'est permise que pour les tests ; lien local, multicast et plages réservées restent TOUJOURS interdits
    if (BLOCKED.some((b) => first >= cidrRange(b).first && first <= cidrRange(b).last && !(allowLoopback && b.n === parseCidr('127.0.0.0/8')!.n))) throw new DiscoveryError('discovery_forbidden_range')
    const lo = c.prefix <= 30 ? first + 1n : first, hi = c.prefix <= 30 ? last - 1n : last
    if (BigInt(ips.length) + (hi - lo + 1n) > BigInt(MAX_TARGETS)) throw new DiscoveryError('discovery_too_large')
    for (let n = lo; n <= hi; n++) { const ip = ipToString({ v: 4, n }); ips.push(ip); subnetOf.set(ip, text) }
  }
  return { ips, subnetOf, skipped }
}

export interface ProbeDeps {
  tcp(ip: string, port: number, timeoutMs: number): Promise<'open' | 'closed' | 'none'>   // closed = RST reçu : l'hôte répond
  ping(ip: string, timeoutMs: number): Promise<boolean>
  arp(): Promise<Map<string, string>>                                                     // ip -> mac (entrées complètes)
  leases(): Promise<Map<string, { mac: string; hostname: string | null }>>
  reverse(ip: string): Promise<string | null>
}
export interface DiscoverOpts { targets: string[]; ports: number[]; methods: { tcp: boolean; icmp: boolean; arp: boolean; reverse: boolean; leases: boolean }; concurrency: number; timeoutMs: number }
export interface Host { ip: string; alive: boolean; via: string[]; ports: number[]; mac: string | null; ptr: string | null; leaseName: string | null }

export async function discoverHosts(o: DiscoverOpts, deps: ProbeDeps, onProgress?: (done: number, alive: number) => void, shouldStop?: () => boolean): Promise<Host[]> {
  const hosts = new Map<string, Host>(), queue = [...o.targets]
  let done = 0, alive = 0
  const mark = (h: Host, how: string) => { if (!h.alive) { h.alive = true; alive++ } if (!h.via.includes(how)) h.via.push(how) }
  const probe = async (ip: string) => {
    const h: Host = { ip, alive: false, via: [], ports: [], mac: null, ptr: null, leaseName: null }
    const jobs: Array<Promise<void>> = []
    if (o.methods.tcp) for (const p of o.ports) jobs.push(deps.tcp(ip, p, o.timeoutMs).then((r) => { if (r === 'open') { h.ports.push(p); mark(h, 'tcp') } else if (r === 'closed') mark(h, 'tcp') }))
    if (o.methods.icmp) jobs.push(deps.ping(ip, o.timeoutMs).then((r) => { if (r) mark(h, 'icmp') }))
    await Promise.all(jobs)
    h.ports.sort((a, b) => a - b); hosts.set(ip, h); done++
    onProgress?.(done, alive)
  }
  const worker = async () => { while (queue.length && !shouldStop?.()) await probe(queue.shift()!) }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(o.concurrency, queue.length)) }, worker))
  for (const ip of o.targets) if (!hosts.has(ip)) hosts.set(ip, { ip, alive: false, via: [], ports: [], mac: null, ptr: null, leaseName: null })   // passif seul ou arrêt demandé
  // lecture passive APRÈS les sondes : les paquets envoyés ont rempli la table ARP des voisins directs
  if (o.methods.arp) for (const [ip, mac] of await deps.arp()) { const h = hosts.get(ip); if (h) { h.mac = mac; mark(h, 'arp') } }
  if (o.methods.leases) for (const [ip, l] of await deps.leases()) { const h = hosts.get(ip); if (h) { h.mac = h.mac ?? l.mac; h.leaseName = l.hostname; mark(h, 'dhcp') } }
  const found = [...hosts.values()].filter((h) => h.alive)
  if (o.methods.reverse) {
    const q = [...found]
    await Promise.all(Array.from({ length: Math.min(16, q.length) }, async () => { while (q.length) { const h = q.shift()!; h.ptr = await deps.reverse(h.ip) } }))
  }
  return found.sort((a, b) => (a.ip.split('.').reduce((n, x) => n * 256 + Number(x), 0)) - (b.ip.split('.').reduce((n, x) => n * 256 + Number(x), 0)))
}

// ---------------------------------------------------------------------------------------------
export const realDeps = (leases: ProbeDeps['leases']): ProbeDeps => ({
  tcp: (ip, port, timeoutMs) => new Promise((resolve) => {
    const s = net.connect({ host: ip, port }); let fin = false
    const end = (r: 'open' | 'closed' | 'none') => { if (!fin) { fin = true; s.destroy(); resolve(r) } }
    s.setTimeout(timeoutMs, () => end('none')); s.once('connect', () => end('open'))
    s.once('error', (e: any) => end(e?.code === 'ECONNREFUSED' || e?.code === 'ECONNRESET' ? 'closed' : 'none'))
  }),
  ping: (ip, timeoutMs) => new Promise((resolve) => { execFile('ping', ['-c', '1', '-W', String(Math.max(1, Math.ceil(timeoutMs / 1000))), ip], { timeout: timeoutMs + 2000 }, (err) => resolve(!err)) }),
  arp: async () => {
    const out = new Map<string, string>()
    try {
      for (const l of (await fs.readFile('/proc/net/arp', 'utf8')).split('\n').slice(1)) {
        const f = l.trim().split(/\s+/)
        if (f.length >= 6 && f[2] === '0x2') { const mac = normMac(f[3]!); if (mac && mac !== '00:00:00:00:00:00') out.set(f[0]!, mac) }
      }
    } catch { /* table illisible : méthode sans effet */ }
    return out
  },
  leases,
  reverse: async (ip) => {
    try { const r = new Resolver({ timeout: 1500, tries: 1 }); r.setServers(['127.0.0.1']); const n = (await r.reverse(ip))[0]; return n ? n.toLowerCase().replace(/\.$/, '') : null } catch { return null }
  },
})
/** Le ping n'est utilisable que si le système laisse un service sans privilège émettre des échos ICMP. */
let pingCache: { at: number; ok: boolean } | null = null
export async function pingWorks(): Promise<boolean> {
  if (pingCache && Date.now() - pingCache.at < 300_000) return pingCache.ok
  const ok = await new Promise<boolean>((res) => execFile('ping', ['-c', '1', '-W', '1', '127.0.0.1'], { timeout: 4000 }, (e) => res(!e)))
  pingCache = { at: Date.now(), ok }
  return ok
}

// ---------------------------------------------------------------------------------------------
export type HostStatus = 'new' | 'known' | 'mac_changed'
export interface KnownAddr { id: number; subnet_id: number; ip: string; hostname: string | null; mac: string | null; status: string }
export interface ResultHost extends Host { subnetId: number; status: HostStatus; known: KnownAddr | null }
export interface JobResult { hosts: ResultHost[]; stale: Array<{ ip: string; hostname: string | null }> }
export interface Job { id: string; user: string; state: 'running' | 'done' | 'cancelled' | 'error'; startedAt: number; total: number; done: number; alive: number; warnings: string[]; error?: string; stop: boolean; result?: JobResult }
export const jobs = new Map<string, Job>()
export const runningJob = () => [...jobs.values()].find((j) => j.state === 'running')
export function sweepJobs() { const lim = Date.now() - 3600_000; for (const [k, j] of jobs) if (j.state !== 'running' && j.startedAt < lim) jobs.delete(k); while (jobs.size > 3) { const k = [...jobs.entries()].find(([, j]) => j.state !== 'running')?.[0]; if (!k) break; jobs.delete(k) } }

/** Compare les hôtes trouvés à l'IPAM : nouveaux, connus, adresse MAC différente ; et les adresses « utilisées » qui n'ont pas répondu. */
export function classify(found: Host[], known: KnownAddr[], subnetIdOfIp: (ip: string) => number): JobResult {
  const byIp = new Map(known.map((k) => [k.ip, k])), seen = new Set(found.map((h) => h.ip))
  const hosts: ResultHost[] = found.map((h) => {
    const k = byIp.get(h.ip) ?? null
    const status: HostStatus = !k ? 'new' : (k.mac && h.mac && k.mac.toLowerCase() !== h.mac.toLowerCase() ? 'mac_changed' : 'known')
    return { ...h, subnetId: k?.subnet_id ?? subnetIdOfIp(h.ip), status, known: k }
  })
  const stale = known.filter((k) => k.status === 'used' && !seen.has(k.ip)).slice(0, 500).map((k) => ({ ip: k.ip, hostname: k.hostname }))
  return { hosts, stale }
}
