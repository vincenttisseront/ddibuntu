// Vérification avant bascule (0.12.5) : compare ce que répond (DNS) ou décrit (DHCP) le serveur Windows avec ce que porte la console.
// Lecture seule. Le DNS passe par « dig » (jamais par un shell) ; la comparaison est pure et testable.
import { execFile } from 'node:child_process'
import type { DhcpPlan } from './ad'
import { validServer } from './axfr'

export interface Finding { scope: string; kind: string; detail: string }
export interface DbScope {
  cidr: string; lease_time: number; enabled: boolean; options: Record<string, any>
  pools: Array<{ start: string; end: string }>; reservations: Array<{ mac: string; ip: string; hostname: string | null }>
}
const mac = (m: string) => m.toLowerCase().replace(/[^0-9a-f]/g, '')
const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null)
const OPTS = ['routers', 'dnsServers', 'domainName', 'ntpServers', 'domainSearch', 'tftpServer', 'bootFile'] as const

/** Étendues Windows (export XML analysé) contre étendues de la console. Une plage Windows est comparée après retrait des exclusions. */
export function compareDhcp(plan: DhcpPlan, db: DbScope[]): Finding[] {
  const out: Finding[] = [], mine = new Map(db.map((s) => [s.cidr, s])), seen = new Set<string>()
  for (const w of plan.scopes) {
    const s = mine.get(w.cidr); seen.add(w.cidr)
    if (!s) { out.push({ scope: w.cidr, kind: 'scope_missing', detail: w.name }); continue }
    if (s.lease_time !== w.leaseTime) out.push({ scope: w.cidr, kind: 'lease_differs', detail: `${w.leaseTime} → ${s.lease_time}` })
    if (s.enabled !== w.enabled) out.push({ scope: w.cidr, kind: 'state_differs', detail: `${w.enabled} → ${s.enabled}` })
    const pk = (p: { start: string; end: string }) => `${p.start}-${p.end}`
    const wp = new Set(w.pools.map(pk)), mp = new Set(s.pools.map(pk))
    for (const p of wp) if (!mp.has(p)) out.push({ scope: w.cidr, kind: 'pool_missing', detail: p })
    for (const p of mp) if (!wp.has(p)) out.push({ scope: w.cidr, kind: 'pool_extra', detail: p })
    const wr = new Map(w.reservations.map((r) => [mac(r.mac), r])), mr = new Map(s.reservations.map((r) => [mac(r.mac), r]))
    for (const [k, r] of wr) {
      const m = mr.get(k)
      if (!m) out.push({ scope: w.cidr, kind: 'reservation_missing', detail: `${r.mac} ${r.ip}` })
      else if (m.ip !== r.ip) out.push({ scope: w.cidr, kind: 'reservation_differs', detail: `${r.mac} ${r.ip} → ${m.ip}` })
    }
    for (const [k, r] of mr) if (!wr.has(k)) out.push({ scope: w.cidr, kind: 'reservation_extra', detail: `${r.mac} ${r.ip}` })
    for (const o of OPTS) {
      const a = (w.options as any)[o], b = s.options?.[o]
      if (!same(a ?? null, b ?? null)) out.push({ scope: w.cidr, kind: 'option_differs', detail: `${o}: ${JSON.stringify(a ?? null)} → ${JSON.stringify(b ?? null)}` })
    }
  }
  for (const s of db) if (!seen.has(s.cidr)) out.push({ scope: s.cidr, kind: 'scope_extra', detail: '' })
  return out
}

// ---- DNS ----
export const normAnswer = (lines: string[]): string[] =>
  [...new Set(lines.map((l) => l.trim().toLowerCase().replace(/\s+/g, ' ').replace(/\.$/, '')).filter((l) => l && !l.startsWith(';')))].sort()

/** TXT : les « chaînes » d'un même enregistrement sont concaténées par les clients (DKIM, SPF) ; Windows et BIND les découpent à des endroits différents (limite de 255 octets). On compare donc le texte joint. */
export const joinTxt = (line: string): string => line.replace(/(?<!\\)"\s+"/g, '')

export type Runner = (server: string, name: string, type: string) => Promise<string[] | null>
export const digRunner: Runner = (server, name, type) => new Promise((resolve) => {
  execFile(process.env.DDI_DIG || 'dig', ['+short', '+time=3', '+tries=1', `@${server}`, name, type], { timeout: 15_000, maxBuffer: 1024 * 1024 }, (err, stdout) => {
    if (err) return resolve(null)
    resolve(String(stdout).split('\n'))
  })
})

export interface DnsProbe { name: string; type: string }
export interface DnsDiff { name: string; type: string; windows: string[] | null; ddi: string[] | null }

/** Interroge les deux serveurs pour chaque (nom, type) ; retourne les écarts (réponse différente, ou serveur muet). */
export async function compareDns(probes: DnsProbe[], windows: string, ddi: string, run: Runner = digRunner, conc = 8): Promise<{ checked: number; diffs: DnsDiff[] }> {
  const diffs: DnsDiff[] = []; let i = 0
  const worker = async () => {
    for (;;) {
      const p = probes[i++]; if (!p) return
      const [w, d] = await Promise.all([run(windows, p.name, p.type), run(ddi, p.name, p.type)])
      const nrm = (x: string[]) => normAnswer(p.type.toUpperCase() === 'TXT' ? x.map(joinTxt) : x)
      const nw = w && nrm(w), nd = d && nrm(d)
      if (!nw || !nd || !same(nw, nd)) diffs.push({ name: p.name, type: p.type, windows: nw, ddi: nd })
    }
  }
  await Promise.all(Array.from({ length: Math.min(conc, Math.max(1, probes.length)) }, worker))
  diffs.sort((a, b) => a.name.localeCompare(b.name) || a.type.localeCompare(b.type))
  return { checked: probes.length, diffs }
}
export const validProbeServer = validServer
