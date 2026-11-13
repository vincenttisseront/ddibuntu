// Reprise des baux DHCP actifs d'un serveur Windows dans la base de baux de Kea (0.12.2), pour que les clients gardent leur adresse à la bascule.
// Source : CSV du script « Get-DhcpServerv4Lease » (IPAddress, ClientId, HostName, ExpiryUtc, AddressState). Analyse PURE ici ; l'écriture est dans le gestionnaire.
import { csvObjects } from './ad'
import { cidrContainsIp, normMac, parseCidr, parseIp } from './net'

export type LeaseSkip = 'invalid' | 'not_active' | 'expired' | 'no_scope'
export interface WinLease { ip: string; n: number; mac: string; hostname: string | null; expire: Date; scopeId: number; lifetime: number }
export interface LeasePlan { import: WinLease[]; skipped: Record<LeaseSkip, number>; total: number; errors: string[] }
export interface ScopeRef { id: number; cidr: string; leaseTime: number }

export function planLeases(csv: string, scopes: ScopeRef[], now = new Date()): LeasePlan {
  const plan: LeasePlan = { import: [], skipped: { invalid: 0, not_active: 0, expired: 0, no_scope: 0 }, total: 0, errors: [] }
  const rows = csvObjects(csv)
  if (!rows.length || !('ipaddress' in rows[0]!) || !('clientid' in rows[0]!)) { plan.errors.push('leases_csv_invalid'); return plan }
  const nets = scopes.map((s) => ({ s, c: parseCidr(s.cidr) })).filter((x) => x.c && x.c.v === 4) as Array<{ s: ScopeRef; c: NonNullable<ReturnType<typeof parseCidr>> }>
  const seen = new Set<string>()
  for (const r of rows) {
    plan.total++
    const ip = parseIp(r.ipaddress ?? ''), mac = normMac((r.clientid ?? '').replace(/-/g, ':')), exp = r.expiryutc ? new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(r.expiryutc) ? r.expiryutc : r.expiryutc + 'Z') : null
    if (!ip || ip.v !== 4 || !mac || !exp || Number.isNaN(exp.getTime()) || seen.has(r.ipaddress!)) { plan.skipped.invalid++; continue }
    seen.add(r.ipaddress!)
    if ((r.addressstate ?? 'Active').toLowerCase() !== 'active') { plan.skipped.not_active++; continue }
    if (exp.getTime() <= now.getTime()) { plan.skipped.expired++; continue }
    const hit = nets.find((x) => cidrContainsIp(x.c, ip))
    if (!hit) { plan.skipped.no_scope++; continue }
    const host = (r.hostname ?? '').trim().toLowerCase().split('.')[0] ?? ''
    plan.import.push({ ip: r.ipaddress!, n: Number(ip.n), mac, hostname: /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(host) ? host : null, expire: exp, scopeId: hit.s.id, lifetime: hit.s.leaseTime })
  }
  return plan
}
