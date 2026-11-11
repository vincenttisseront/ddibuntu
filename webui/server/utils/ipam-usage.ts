// Taux d'occupation des sous-réseaux (tableau de bord, alertes, export Prometheus).
import { query } from './db'
import { capacity, parseCidr } from './net'
import type { SubnetUsage } from './alert-rules'

export async function subnetUsage(): Promise<SubnetUsage[]> {
  const subs = await query<any>('select s.id, text(s.cidr) as cidr, s.name, (select count(*)::int from addresses a where a.subnet_id = s.id) as used from subnets s')
  const out: SubnetUsage[] = []
  for (const s of subs) {
    const c = parseCidr(s.cidr); if (!c) continue
    const cap = capacity(c)
    if (cap > BigInt(1_000_000_000)) continue   // IPv6 : l'occupation n'a pas de sens
    out.push({ cidr: s.cidr, name: s.name ?? '', used: s.used, capacity: Number(cap), percent: Math.round((s.used / Number(cap)) * 1000) / 10 })
  }
  return out
}
