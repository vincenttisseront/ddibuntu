// Recherche globale (palette de la console) et carte d'occupation d'un réseau.
// Lecture seule, rôle « viewer ». Toutes les valeurs passent en paramètres liés ; les jokers LIKE saisis sont neutralisés.
import { fail, intParam, qint, qstr, route } from '../utils/router'
import { one, query } from '../utils/db'
import { cidrRange, cidrToString, normIp, parseCidr, parseIp } from '../utils/net'

export const registered = true

type Item = { id: number; title: string; subtitle: string; to: string }
type Group = { kind: string; items: Item[]; more: boolean }

const like = (s: string) => `%${s.replace(/[%_\\]/g, '\\$&')}%`

/** Interprétation de la saisie : adresse IP exacte, réseau CIDR, fragment d'adresse MAC. */
export function interpret(q: string): { ip: string | null; cidr: string | null; mac: string | null } {
  let ip: string | null = null, cidr: string | null = null, mac: string | null = null
  if (q.includes('/')) { const c = parseCidr(q); if (c) cidr = cidrToString(c) } else ip = normIp(q)
  const hex = q.toLowerCase().replace(/[:.\-]/g, '')
  if (/^[0-9a-f]{4,12}$/.test(hex) && (/[:.\-]/.test(q) || hex.length === 12)) mac = hex
  return { ip, cidr, mac }
}

route('GET', '/search', 'viewer', async (c) => {
  const q = (qstr(c, 'q', 100) ?? '').trim()
  const per = qint(c, 'limit', 8, 1, 50)
  if (q.length < 2) return { q, total: 0, groups: [] as Group[] }
  const lk = like(q), { ip, cidr, mac } = interpret(q)
  const n = per + 1
  const take = (rows: any[], f: (r: any) => Item): { items: Item[]; more: boolean } => ({ items: rows.slice(0, per).map(f), more: rows.length > per })
  const groups: Group[] = []
  const add = (kind: string, g: { items: Item[]; more: boolean }) => { if (g.items.length) groups.push({ kind, ...g }) }

  const nets = await query<any>(`select s.id, text(s.cidr) as cidr, s.name, s.site, s.kind, sp.name as space
    from subnets s join ipam_spaces sp on sp.id = s.space_id
    where text(s.cidr) ilike $1 or s.name ilike $1 or coalesce(s.site, '') ilike $1 or coalesce(s.description, '') ilike $1 or array_to_string(s.tags, ' ') ilike $1
       or ($2::inet is not null and s.cidr >>= $2::inet) or ($3::cidr is not null and s.cidr && $3::cidr)
    order by coalesce(s.cidr >>= $2::inet, false) desc, case when $2::inet is not null then -masklen(s.cidr) else 0 end, s.space_id, s.cidr limit ${n}`, [lk, ip, cidr])
  add('network', take(nets, (r) => ({ id: r.id, title: r.cidr, subtitle: [r.name, r.space, r.site].filter(Boolean).join(' · '), to: `/ipam?subnet=${r.id}#addresses` })))

  const addrs = await query<any>(`select a.id, a.subnet_id, host(a.ip) as ip, a.status, a.hostname, a.mac::text as mac, text(s.cidr) as cidr
    from addresses a join subnets s on s.id = a.subnet_id
    where host(a.ip) ilike $1 or coalesce(a.hostname, '') ilike $1 or a.mac::text ilike $1 or ($4::text is not null and replace(a.mac::text, ':', '') like $4)
       or coalesce(a.description, '') ilike $1 or coalesce(a.owner, '') ilike $1 or ($3::cidr is not null and a.ip <<= $3::cidr)
    order by (a.ip = $2::inet) desc nulls last, a.ip limit ${n}`, [lk, ip, cidr, mac ? `%${mac}%` : null])
  add('address', take(addrs, (r) => ({ id: r.id, title: r.ip, subtitle: [r.hostname, r.mac, r.status, r.cidr].filter(Boolean).join(' · '), to: `/ipam?subnet=${r.subnet_id}#addresses` })))

  const zones = await query<any>(`select id, name, type from dns_zones where name ilike $1 or coalesce(comment, '') ilike $1 order by lower(name) limit ${n}`, [lk])
  add('zone', take(zones, (r) => ({ id: r.id, title: r.name, subtitle: r.type, to: `/dns?zone=${r.id}#records` })))

  const recs = await query<any>(`select r.id, r.zone_id, r.name, r.type, r.rdata, z.name as zone
    from dns_records r join dns_zones z on z.id = r.zone_id
    where r.name ilike $1 or r.rdata ilike $1 or (r.name || '.' || z.name) ilike $1 or coalesce(r.comment, '') ilike $1
    order by z.name, r.name, r.type limit ${n}`, [lk])
  add('record', take(recs, (r) => ({ id: r.id, title: r.name === '@' ? r.zone : `${r.name}.${r.zone}`, subtitle: `${r.type} ${r.rdata}`.slice(0, 160), to: `/dns?zone=${r.zone_id}#records` })))

  const scopes = await query<any>(`select d.id, coalesce(d.name, text(s.cidr)) as name, text(s.cidr) as cidr, d.enabled
    from dhcp_scopes d join subnets s on s.id = d.subnet_id
    where coalesce(d.name, '') ilike $1 or text(s.cidr) ilike $1 or s.name ilike $1 or ($2::inet is not null and s.cidr >>= $2::inet)
    order by s.cidr limit ${n}`, [lk, ip])
  add('scope', take(scopes, (r) => ({ id: r.id, title: r.name, subtitle: `${r.cidr}${r.enabled ? '' : ' · off'}`, to: `/dhcp?scope=${r.id}#ranges` })))

  const resv = await query<any>(`select r.id, d.id as scope_id, host(r.ip) as ip, r.mac::text as mac, r.hostname, text(s.cidr) as cidr
    from dhcp_reservations r join dhcp_scopes d on d.id = r.scope_id join subnets s on s.id = d.subnet_id
    where host(r.ip) ilike $1 or r.mac::text ilike $1 or ($3::text is not null and replace(r.mac::text, ':', '') like $3)
       or coalesce(r.hostname, '') ilike $1 or coalesce(r.description, '') ilike $1 or ($2::cidr is not null and r.ip <<= $2::cidr)
    order by r.ip limit ${n}`, [lk, cidr, mac ? `%${mac}%` : null])
  add('reservation', take(resv, (r) => ({ id: r.id, title: r.ip, subtitle: [r.mac, r.hostname, r.cidr].filter(Boolean).join(' · '), to: `/dhcp?scope=${r.scope_id}#ranges` })))

  const vlans = await query<any>(`select id, vlan_id, name from vlans where vlan_id::text = $2 or name ilike $1 or coalesce(description, '') ilike $1 order by vlan_id limit ${n}`, [lk, q])
  add('vlan', take(vlans, (r) => ({ id: r.id, title: `VLAN ${r.vlan_id}`, subtitle: r.name, to: '/ipam#vlans' })))

  // Les listes de blocage peuvent compter des millions de noms : correspondance exacte (index) uniquement.
  const dom = q.toLowerCase().replace(/\.$/, '')
  const filt = await query<any>(`select 'rule' as src, r.id, r.domain as title, r.action as sub from filter_rules r where r.domain ilike $1 or coalesce(r.comment, '') ilike $1
    union all select 'list', l.id, l.name, l.category from block_lists l where l.name ilike $1 or l.category ilike $1
    union all select 'entry', e.list_id, e.domain, l.name from block_entries e join block_lists l on l.id = e.list_id where e.domain = $2
    limit ${n}`, [lk, dom])
  add('filter', take(filt, (r) => ({ id: r.id, title: r.title, subtitle: `${r.src} · ${r.sub}`, to: '/filtering' })))

  return { q, total: groups.reduce((s, g) => s + g.items.length, 0), groups }
})

// ---- Carte d'occupation ----
// Un caractère par adresse du réseau (IPv4, jusqu'à /16) : n réseau, b diffusion, u utilisée, r réservée, g passerelle, i infrastructure,
// d adresse DHCP, v réservation DHCP, o plage DHCP dynamique libre, p plage IPAM libre, '.' libre.
const MAP_MAX = 65536
route('GET', '/ipam/subnets/:id/map', 'viewer', async (c) => {
  const id = intParam(c, 'id')
  const s = await one<any>('select id, text(cidr) as cidr, name, kind, host(gateway) as gateway from subnets where id = $1', [id])
  if (!s) fail(404, 'not_found')
  const cd = parseCidr(s.cidr)!
  if (cd.v !== 4) fail(400, 'map_unsupported_family')
  const size = 1 << (32 - cd.prefix)
  if (size > MAP_MAX) fail(400, 'map_too_large')
  const base = cidrRange(cd).first
  const cells = new Array<string>(size).fill('.')
  const off = (ipText: string): number => { const p = parseIp(ipText); if (!p || p.v !== 4) return -1; const o = p.n - base; return o >= 0n && o < BigInt(size) ? Number(o) : -1 }
  const range = (a: string, b: string, ch: string) => {
    const lo = off(a), hi = off(b)
    if (lo < 0 || hi < lo) return
    for (let i = lo; i <= hi; i++) if (cells[i] === '.') cells[i] = ch
  }
  // du moins prioritaire au plus prioritaire : les plages ne recouvrent que les cases encore libres, les occupants écrasent
  for (const r of await query<any>('select host(start_ip) a, host(end_ip) b from dhcp_pools p join dhcp_scopes d on d.id = p.scope_id where d.subnet_id = $1', [id])) range(r.a, r.b, 'o')
  for (const r of await query<any>('select host(start_ip) a, host(end_ip) b from ipam_pools where subnet_id = $1', [id])) range(r.a, r.b, 'p')
  for (const r of await query<any>('select host(r.ip) ip from dhcp_reservations r join dhcp_scopes d on d.id = r.scope_id where d.subnet_id = $1', [id])) { const o = off(r.ip); if (o >= 0) cells[o] = 'v' }
  if (s.gateway) { const o = off(s.gateway); if (o >= 0) cells[o] = 'g' }
  const items: Array<[number, string | null, string | null, string | null]> = []
  const code: Record<string, string> = { used: 'u', reserved: 'r', dhcp: 'd', gateway: 'g', infra: 'i' }
  for (const r of await query<any>('select host(ip) ip, status, hostname, mac::text mac, description from addresses where subnet_id = $1', [id])) {
    const o = off(r.ip); if (o < 0) continue
    cells[o] = code[r.status] ?? 'u'
    items.push([o, r.hostname, r.mac, r.description])
  }
  if (cd.prefix < 31) { cells[0] = 'n'; cells[size - 1] = 'b' }
  const counts: Record<string, number> = {}
  for (const ch of cells) counts[ch] = (counts[ch] ?? 0) + 1
  return { id, cidr: s.cidr, name: s.name, base: cidrToString({ v: 4, n: base, prefix: 32 }).replace(/\/32$/, ''), prefix: cd.prefix, size, cells: cells.join(''), counts, items }
})
