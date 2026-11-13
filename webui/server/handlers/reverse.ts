// Zones inverses automatiques (0.10.4) : plan par sous-réseau, création des zones manquantes et des CNAME de délégation classless (RFC 2317).
import { z } from 'zod'
import { audit, fail, qint, route } from '../utils/router'
import { one, query, tx } from '../utils/db'
import { parseCidr } from '../utils/net'
import { reverseZonesFor } from '../utils/reverse'

export const registered = true

async function plan(subnetId: number, viewId: number | null) {
  const s = await one<any>('select id, text(cidr) as cidr, kind from subnets where id = $1', [subnetId])
  if (!s) fail(404, 'not_found')
  const p = reverseZonesFor(parseCidr(s.cidr)!)
  if (p.error) return { subnet: s.cidr, zones: [], cnames: [], error: p.error }
  const have = await query<any>('select id, lower(name) as name, type from dns_zones where view_id is not distinct from $1', [viewId])
  const byName = new Map(have.map((h) => [h.name as string, h]))
  const zones = p.zones.map((zn) => ({ ...zn, exists: byName.has(zn.name), id: byName.get(zn.name)?.id ?? null, type: byName.get(zn.name)?.type ?? null }))
  const parent = p.cnames[0] && byName.get(p.cnames[0].zone)
  const existing = parent ? new Set((await query<any>("select lower(name) as n from dns_records where zone_id = $1 and type = 'CNAME'", [parent.id])).map((r) => r.n as string)) : new Set<string>()
  return { subnet: s.cidr, zones, cnames: p.cnames.map((c) => ({ ...c, exists: existing.has(c.name) })) }
}

const q = (c: any) => ({ subnet: qint(c, 'subnet_id', 0), view: qint(c, 'view_id', 0) || null })
route('GET', '/dns/reverse/plan', 'viewer', async (c) => { const { subnet, view } = q(c); if (!subnet) fail(400, 'invalid_query'); return plan(subnet, view) })

// Sous-réseaux dont la zone inverse manque (vue donnée ou sans vue)
route('GET', '/dns/reverse/missing', 'viewer', async (c) => {
  const view = qint(c, 'view_id', 0) || null
  const subs = await query<any>("select id, text(cidr) as cidr, name from subnets where kind <> 'container' order by cidr limit 1000")
  const have = new Set((await query<any>('select lower(name) as n from dns_zones where view_id is not distinct from $1', [view])).map((r) => r.n as string))
  const items = []
  for (const s of subs) {
    const p = reverseZonesFor(parseCidr(s.cidr)!)
    if (p.error) continue
    const missing = p.zones.filter((zn) => !have.has(zn.name)).map((zn) => zn.name)
    if (missing.length) items.push({ id: s.id, cidr: s.cidr, name: s.name, missing })
  }
  return { items }
})

const createBody = z.object({ subnet_id: z.number().int(), view_id: z.number().int().nullable().optional(), from_zone_id: z.number().int().nullable().optional() })
route('POST', '/dns/reverse/create', 'operator', async (c) => {
  const b = await c.body(createBody)
  const viewId = b.view_id ?? null
  const pl = await plan(b.subnet_id, viewId)
  if ('error' in pl && pl.error) fail(400, pl.error)
  if (viewId && !(await one('select 1 from dns_views where id = $1', [viewId]))) fail(400, 'view_not_found')
  if (!viewId && (await one('select 1 from dns_views limit 1'))) fail(400, 'zones_without_view')
  const model = b.from_zone_id ? await one<any>("select id, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_minimum, default_ttl from dns_zones where id = $1 and type = 'primary'", [b.from_zone_id]) : null
  if (b.from_zone_id && !model) fail(400, 'zone_not_primary')
  const out = await tx(async (cl) => {
    let zones = 0, cnames = 0
    const ids = new Map<string, number>()
    for (const zn of pl.zones) {
      if (zn.exists) { ids.set(zn.name, zn.id); continue }
      const r = (await cl.query(`insert into dns_zones (name, type, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_minimum, default_ttl, view_id, comment)
        values ($1,'primary',$2,$3,coalesce($4,3600),coalesce($5,600),coalesce($6,1209600),coalesce($7,3600),coalesce($8,3600),$9,$10) returning id`,
        [zn.name, model?.soa_mname ?? null, model?.soa_rname ?? null, model?.soa_refresh ?? null, model?.soa_retry ?? null, model?.soa_expire ?? null, model?.soa_minimum ?? null, model?.default_ttl ?? null, viewId, `Zone inverse automatique (${pl.subnet})`])).rows[0].id as number
      ids.set(zn.name, r); zones++
      if (model) await cl.query("insert into dns_records (zone_id, name, type, ttl, rdata) select $1, name, type, ttl, rdata from dns_records where zone_id = $2 and type = 'NS' and name = '@'", [r, model.id])
    }
    // délégation classless : un CNAME par adresse du bloc, dans la zone parente (un PTR au même nom serait en conflit : il est retiré)
    for (const cn of pl.cnames) {
      const zid = ids.get(cn.zone)!
      await cl.query("delete from dns_records where zone_id = $1 and name = $2 and type = 'PTR'", [zid, cn.name])
      const r = await cl.query("insert into dns_records (zone_id, name, type, rdata, comment) select $1,$2,'CNAME',$3,'RFC 2317' where not exists (select 1 from dns_records where zone_id = $1 and lower(name) = lower($2))", [zid, cn.name, `${cn.target}.`])
      cnames += r.rowCount ?? 0
    }
    if (ids.size) await cl.query('update dns_zones set dirty = true, updated_at = now() where id = any($1)', [[...ids.values()]])
    return { zones, cnames }
  })
  await audit(c, 'reverse_create', 'subnet', b.subnet_id, out)
  return out
})
