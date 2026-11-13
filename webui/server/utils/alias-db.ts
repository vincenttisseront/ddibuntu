// Lecture en base des noms et alias d'adresses (voir aliases.ts). Un seul passage sur les CNAME pour toute une page d'adresses.
import { query } from './db'
import { normIp } from './net'
import { collectAliases, fqdnOf } from './aliases'
import type { Alias, AliasRec } from './aliases'

export interface HostRow { id: number; ip: string; type: string; name: string; zoneId: number; zone: string; view: number | null; viewName: string | null; ttl: number | null; fqdn: string }

const toRec = (r: any): AliasRec => ({ id: r.id, zoneId: r.zone_id, zone: r.zone, view: r.view_id ?? null, name: r.name, rdata: r.rdata, ttl: r.ttl ?? null, comment: r.comment ?? null, disabled: !!r.disabled, protected: !!r.protected })

export async function loadCnames(): Promise<AliasRec[]> {
  return (await query<any>("select r.id, r.zone_id, z.name as zone, z.view_id, r.name, r.rdata, r.ttl, r.comment, r.disabled, r.protected from dns_records r join dns_zones z on z.id = r.zone_id where r.type = 'CNAME' and z.type = 'primary'")).map(toRec)
}
/** Enregistrements A/AAAA actifs qui portent ces adresses (zones primaires, toutes vues). */
export async function loadHosts(ips: string[]): Promise<HostRow[]> {
  const norm = [...new Set(ips.map((i) => normIp(i)).filter((x): x is string => !!x))]
  if (!norm.length) return []
  const rows = await query<any>(`select r.id, r.type, r.name, r.ttl, r.rdata, z.id as zone_id, z.name as zone, z.view_id, v.name as view_name
    from dns_records r join dns_zones z on z.id = r.zone_id left join dns_views v on v.id = z.view_id
    where r.type in ('A','AAAA') and not r.disabled and z.type = 'primary' and r.rdata = any($1::text[]) order by z.name, r.name`, [norm])
  return rows.map((r) => ({ id: r.id, ip: r.rdata, type: r.type, name: r.name, zoneId: r.zone_id, zone: r.zone, view: r.view_id ?? null, viewName: r.view_name ?? null, ttl: r.ttl ?? null, fqdn: fqdnOf(r.name, r.zone) }))
}
/** Alias (toutes profondeurs) d'une adresse, vue par vue. */
export function aliasesOf(hosts: HostRow[], cnames: AliasRec[]): Alias[] {
  const views = [...new Set(hosts.map((h) => h.view))], out: Alias[] = []
  for (const v of views) out.push(...collectAliases(hosts.filter((h) => h.view === v).map((h) => h.fqdn), v, cnames.filter((c) => c.view === v)))
  return out
}
/** Alias (noms complets) pour chaque adresse d'une page : colonne « Alias » des listes. */
export async function aliasNames(ips: string[]): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>()
  const hosts = await loadHosts(ips); if (!hosts.length) return out
  const cnames = await loadCnames(); if (!cnames.length) return out
  const byIp = new Map<string, HostRow[]>()
  for (const h of hosts) byIp.set(h.ip, [...(byIp.get(h.ip) ?? []), h])
  for (const [ip, hs] of byIp) {
    const names = [...new Set(aliasesOf(hs, cnames).map((a) => a.fqdn))]
    if (names.length) out.set(ip, names)
  }
  return out
}
