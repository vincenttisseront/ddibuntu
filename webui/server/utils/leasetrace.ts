// Traçabilité des baux : instantané périodique des baux actifs de Kea (table lease4) dans lease_history, et recherche de l'historique.
import { inRecovery, query, tx } from './db'

export interface ActiveLease { ip: string; mac: string; hostname: string | null; subnet_id: number | null }

export const fmtMac = (hex: string): string => hex.match(/.{2}/g)?.join(':') ?? ''

/** Baux actifs lus dans lease4 ; null si Kea n'a pas (encore) de base de baux PostgreSQL. */
export async function activeLeases(): Promise<ActiveLease[] | null> {
  const t = await query<any>("select to_regclass('public.lease4') is not null as ok")
  if (!t[0]?.ok) return null
  const rows = await query<any>(`select ((address >> 24) & 255) || '.' || ((address >> 16) & 255) || '.' || ((address >> 8) & 255) || '.' || (address & 255) as ip,
    encode(hwaddr, 'hex') as mac, nullif(trim(hostname), '') as hostname, subnet_id from lease4 where expire > now() and hwaddr is not null and length(hwaddr) = 6`)
  return rows.map((r) => ({ ip: r.ip, mac: fmtMac(r.mac), hostname: r.hostname ? String(r.hostname).replace(/\.$/, '').toLowerCase() : null, subnet_id: r.subnet_id ?? null }))
}

/** Met l'historique à jour (primaire uniquement). Retourne les compteurs du passage. */
export async function snapshotLeases(): Promise<{ active: number; opened: number; closed: number; skipped?: string }> {
  if (await inRecovery()) return { active: 0, opened: 0, closed: 0, skipped: 'replica' }
  const act = await activeLeases().catch(() => null)
  if (act === null) return { active: 0, opened: 0, closed: 0, skipped: 'unavailable' }
  return tx(async (cl) => {
    await cl.query(`create temporary table if not exists _act (ip inet, mac macaddr, hostname text, subnet_id int) on commit drop`)
    await cl.query('truncate _act')
    if (act.length) await cl.query('insert into _act select * from unnest($1::inet[], $2::macaddr[], $3::text[], $4::int[])', [act.map((a) => a.ip), act.map((a) => a.mac), act.map((a) => a.hostname), act.map((a) => a.subnet_id)])
    await cl.query(`update lease_history h set last_seen = now(), subnet_id = a.subnet_id from _act a where h.open and h.ip = a.ip and h.mac = a.mac and h.hostname is not distinct from a.hostname`)
    const closed = (await cl.query(`update lease_history h set open = false where h.open and not exists
      (select 1 from _act a where h.ip = a.ip and h.mac = a.mac and h.hostname is not distinct from a.hostname)`)).rowCount ?? 0
    const opened = (await cl.query(`insert into lease_history (ip, mac, hostname, subnet_id)
      select a.ip, a.mac, a.hostname, a.subnet_id from _act a where not exists
      (select 1 from lease_history h where h.open and h.ip = a.ip and h.mac = a.mac and h.hostname is not distinct from a.hostname)`)).rowCount ?? 0
    return { active: act.length, opened, closed }
  })
}

export async function pruneTrace(days: number): Promise<number> {
  return (await query("delete from lease_history where not open and last_seen < now() - make_interval(days => $1) returning 1", [days])).length
}

const likeEsc = (s: string) => s.replace(/[\\%_]/g, (m) => '\\' + m)

/** Recherche par IP (entière ou début), MAC (tout format, début accepté) ou nom (fragment). */
export async function searchTrace(q: string, limit: number) {
  const term = q.trim().toLowerCase()
  const conds: string[] = [], args: unknown[] = []
  const add = (sql: string, v: unknown) => { args.push(v); conds.push(sql.replace('$#', '$' + args.length)) }
  if (/^[0-9.]+$/.test(term)) add("host(h.ip) like $# escape '\\'", likeEsc(term) + '%')
  const hex = term.replace(/[:.-]/g, '')
  if (/^[0-9a-f:.-]+$/.test(term) && /^[0-9a-f]{2,12}$/.test(hex)) add("replace(h.mac::text, ':', '') like $#", hex + '%')
  if (term) add("lower(h.hostname) like $# escape '\\'", '%' + likeEsc(term) + '%')
  if (!conds.length) return []
  args.push(limit)
  return query<any>(`select h.id, host(h.ip) as ip, h.mac::text as mac, h.hostname, h.subnet_id, h.first_seen, h.last_seen, h.open,
      a.hostname as ipam_hostname, a.description as ipam_description, a.status as ipam_status
    from lease_history h left join addresses a on a.ip = h.ip
    where ${conds.join(' or ')} order by h.last_seen desc, h.id desc limit $${args.length}`, args)
}
