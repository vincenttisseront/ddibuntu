import { z } from 'zod'
import { setResponseHeader } from 'h3'
import { audit, fail, intParam, qint, qstr, route } from '../utils/router'
import { one, query, tx } from '../utils/db'
import { capacity, nextFree, nextFreeInRange, isHostname, normIp, normMac, parseCidr, cidrToString, cidrContainsIp, parseIp, ptrName } from '../utils/net'
import type { PoolClient } from 'pg'
import { cleanOptions, optionsS } from '../utils/dhcpopts'
import { checkHostnameRule, patternError, resolveDnsZone, syncReservation } from '../utils/smartddi'

const cidrS = z.string().trim().refine((v) => !!parseCidr(v), 'cidr')
const ipS = z.string().trim().refine((v) => !!normIp(v), 'ip')
const status = z.enum(['used', 'reserved', 'dhcp', 'gateway', 'infra', 'ghost'])
const host = z.string().trim().toLowerCase().refine(isHostname, 'hostname')
const mac = z.string().trim().refine((v) => !!normMac(v), 'mac')

const SUBNET_SQL = `select s.id, s.space_id, sp.name as space, s.kind, text(s.cidr) as cidr, family(s.cidr) as family, s.name, s.description, s.vlan_id, v.vlan_id as vlan, s.site,
  host(s.gateway) as gateway, s.tags,
  (select count(*)::int from addresses a where a.subnet_id = s.id) as used,
  (select p.id from subnets p where p.space_id = s.space_id and p.cidr >> s.cidr order by masklen(p.cidr) desc limit 1) as parent_id,
  (select coalesce(sum(case when family(q.start_ip) = 4 then q.end_ip - q.start_ip + 1 else 0 end), 0)::float8 from ipam_pools q where q.subnet_id = s.id) as pooled,
  (select count(*)::int from ipam_pools q where q.subnet_id = s.id) as pools,
  exists (select 1 from dhcp_scopes d where d.subnet_id = s.id) as has_dhcp, s.template_id, t.name as template
  from subnets s join ipam_spaces sp on sp.id = s.space_id left join vlans v on v.id = s.vlan_id left join network_templates t on t.id = s.template_id`

const pct = (num: bigint, den: bigint) => (den <= 0n ? null : Math.min(100, Number((num * 1000n) / den) / 10))

/** Liste plate triée en ordre de parcours de l'arbre (un parent précède ses enfants), avec profondeur et agrégats. */
async function networkTree(spaceId?: number, family?: number) {
  const rows = await query<any>(`${SUBNET_SQL} ${spaceId ? 'where s.space_id = ' + Math.trunc(spaceId) : ''} order by s.space_id, s.cidr`)
  const byId = new Map<number, any>()
  const items = rows.map((r) => {
    const c = parseCidr(r.cidr)!, cap = capacity(c)
    const o = { ...r, _cap: cap, depth: 0, children: 0, parent: null as any, used_total: r.used as number }
    byId.set(r.id, o)
    return o
  })
  const childCap = new Map<number, bigint>()
  for (const o of items) {
    const p = o.parent_id ? byId.get(o.parent_id) : null
    if (p) { o.parent = { id: p.id, cidr: p.cidr, name: p.name }; p.children++; childCap.set(p.id, (childCap.get(p.id) ?? 0n) + BigInt(o._cap)) }
  }
  for (const o of items) { let d = 0, p = o.parent_id ? byId.get(o.parent_id) : null; while (p && d < 64) { d++; p = p.parent_id ? byId.get(p.parent_id) : null }; o.depth = d }
  // utilisation d'un conteneur = adresses de tous ses descendants
  for (const o of items) { let p = o.parent_id ? byId.get(o.parent_id) : null; let g = 0; while (p && g++ < 64) { p.used_total += o.used; p = p.parent_id ? byId.get(p.parent_id) : null } }
  const out = items.map((o) => {
    const cap: bigint = o._cap, huge = cap > 1_000_000_000n
    const allocNum = o.kind === 'container' || o.children ? (childCap.get(o.id) ?? 0n) : BigInt(Math.round(o.pooled))
    const { _cap, pooled, ...rest } = o; void _cap; void pooled
    return { ...rest, capacity: huge ? null : Number(cap), size_label: huge ? `2^${(o.family === 6 ? 128 : 32) - Number(String(o.cidr).split('/')[1])}` : String(cap),
      percent: huge ? null : Math.min(100, Math.round((o.used_total / Number(cap)) * 1000) / 10), allocated: pct(allocNum, cap) }
  })
  return family ? out.filter((o) => o.family === family) : out
}

route('GET', '/ipam/subnets', 'viewer', async (c) => {
  const sp = qint(c, 'space_id', 0), fam = qint(c, 'family', 0)
  return { items: await networkTree(sp || undefined, fam === 4 || fam === 6 ? fam : undefined) }
})

// ---- Espaces ----
import { allowAddress, allowPool, allowSpace, allowSubnet, denyScoped } from '../utils/scope'
const spaceBody = z.object({ name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional() })
route('GET', '/ipam/spaces', 'viewer', async () => ({ items: await query(`select sp.id, sp.name, sp.description,
  (select count(*)::int from subnets s where s.space_id = sp.id) as subnets,
  (select count(*)::int from addresses a join subnets s on s.id = a.subnet_id where s.space_id = sp.id) as addresses from ipam_spaces sp order by sp.id`) }))
route('POST', '/ipam/spaces', 'operator', async (c) => {
  denyScoped(c)
  const b = await c.body(spaceBody)
  const r = await one<any>('insert into ipam_spaces (name, description) values ($1,$2) returning id', [b.name, b.description ?? null])
  await audit(c, 'space_create', 'space', r.id, { name: b.name })
  return { id: r.id }
})
route('PUT', '/ipam/spaces/:id', 'operator', async (c) => {
  allowSpace(c, Number(c.params.id))
  const id = intParam(c, 'id')
  const b = await c.body(spaceBody.partial())
  const r = await query('update ipam_spaces set name = coalesce($2, name), description = coalesce($3, description), updated_at = now() where id = $1 returning id', [id, b.name ?? null, b.description ?? null])
  if (!r.length) fail(404, 'not_found')
  await audit(c, 'space_update', 'space', id)
  return { ok: true }
})
route('DELETE', '/ipam/spaces/:id', 'operator', async (c) => {
  allowSpace(c, Number(c.params.id))
  const id = intParam(c, 'id')
  if (id === 1) fail(409, 'space_default')
  const n = await one<any>('select count(*)::int as n from subnets where space_id = $1', [id])
  if (n.n > 0) fail(409, 'space_not_empty', 'space_not_empty', { subnets: n.n })
  await query('delete from ipam_spaces where id = $1', [id])
  await audit(c, 'space_delete', 'space', id)
  return { ok: true }
})

const subnetBody = z.object({
  cidr: cidrS, name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional(),
  vlan_id: z.number().int().nullable().optional(), site: z.string().max(100).nullable().optional(),
  gateway: ipS.nullable().optional(), tags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
  space_id: z.number().int().min(1).optional(), kind: z.enum(['network', 'container']).optional(), template_id: z.number().int().min(1).nullable().optional(),
})
async function checkSpace(id: number) { if (!(await one('select 1 from ipam_spaces where id = $1', [id]))) fail(400, 'space_not_found') }
function checkGateway(cidr: string, gw: string | null | undefined) {
  if (!gw) return
  const c = parseCidr(cidr)!, ip = parseIp(gw)!
  if (!cidrContainsIp(c, ip)) fail(400, 'gateway_outside')
}

route('POST', '/ipam/subnets', 'operator', async (c) => {
  const b = await c.body(subnetBody)
  const cidr = cidrToString(parseCidr(b.cidr)!)
  checkGateway(cidr, b.gateway)
  const spaceId = b.space_id ?? 1
  allowSpace(c, spaceId)
  await checkSpace(spaceId)
  if (b.kind === 'container' && b.gateway) fail(400, 'container_no_addresses')
  const kind = b.kind ?? 'network'
  const out = await tx(async (cl) => {
    const tpl = b.template_id ? (await cl.query('select id, create_scope, lease_time, dhcp_options from network_templates where id = $1', [b.template_id])).rows[0] : null
    if (b.template_id && !tpl) fail(400, 'template_not_found')
    const r = (await cl.query('insert into subnets (cidr, name, description, vlan_id, site, gateway, tags, space_id, kind, template_id) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning id',
      [cidr, b.name, b.description ?? null, b.vlan_id ?? null, b.site ?? null, b.gateway ? normIp(b.gateway) : null, b.tags ?? [], spaceId, kind, b.template_id ?? null])).rows[0].id as number
    if (b.gateway) await cl.query("insert into addresses (subnet_id, ip, status, hostname, description) values ($1,$2,'gateway','gateway','Passerelle') on conflict do nothing", [r, normIp(b.gateway)])
    // gabarit : l'étendue DHCP naît avec le réseau, dans la même transaction (IPv4, réseau, espace par défaut : Kea ne distingue pas les espaces)
    let dhcp: 'scope_created' | 'scope_skipped' | null = null
    if (tpl?.create_scope) {
      if (parseCidr(cidr)!.v === 4 && kind === 'network' && spaceId === 1) {
        const opts = { ...cleanOptions(tpl.dhcp_options) }
        if (!opts.routers && b.gateway) opts.routers = [normIp(b.gateway)]
        await cl.query('insert into dhcp_scopes (subnet_id, name, lease_time, enabled, options) values ($1,$2,$3,true,$4::jsonb)', [r, b.name, tpl.lease_time, JSON.stringify(opts)])
        dhcp = 'scope_created'
      } else dhcp = 'scope_skipped'
    }
    return { id: r, dhcp }
  })
  await audit(c, 'subnet_create', 'subnet', out.id, { cidr, space_id: spaceId, template_id: b.template_id ?? null })
  return out
})
route('PUT', '/ipam/subnets/:id', 'operator', async (c) => {
  await allowSubnet(c, Number(c.params.id))
  const id = intParam(c, 'id')
  const b = await c.body(subnetBody.partial())
  const cur = await one<any>('select text(cidr) as cidr, (select count(*)::int from addresses where subnet_id = $1) as n from subnets where id = $1', [id])
  if (!cur) fail(404, 'not_found')
  if (b.space_id !== undefined) { allowSpace(c, b.space_id); await checkSpace(b.space_id) }
  if (b.kind === 'container' && cur.n > 0) fail(409, 'container_no_addresses')
  if (b.template_id && !(await one('select 1 from network_templates where id = $1', [b.template_id]))) fail(400, 'template_not_found')
  if (b.cidr && cidrToString(parseCidr(b.cidr)!) !== cur.cidr) fail(400, 'cidr_immutable')
  checkGateway(cur.cidr, b.gateway)
  await query(`update subnets set name = coalesce($2, name), description = coalesce($3, description), vlan_id = $4, site = coalesce($5, site),
    gateway = coalesce($6, gateway), tags = coalesce($7, tags), space_id = coalesce($8, space_id), kind = coalesce($9, kind), template_id = case when $10::boolean then $11::int else template_id end, updated_at = now() where id = $1`,
    [id, b.name ?? null, b.description ?? null, b.vlan_id === undefined ? (await one<any>('select vlan_id from subnets where id = $1', [id]))?.vlan_id ?? null : b.vlan_id, b.site ?? null, b.gateway ? normIp(b.gateway) : null, b.tags ?? null, b.space_id ?? null, b.kind ?? null, b.template_id !== undefined, b.template_id ?? null])
  await audit(c, 'subnet_update', 'subnet', id)
  return { ok: true }
})
route('DELETE', '/ipam/subnets/:id', 'operator', async (c) => {
  await allowSubnet(c, Number(c.params.id))
  const id = intParam(c, 'id')
  const n = await one<any>('select (select count(*) from addresses where subnet_id = $1)::int a, (select count(*) from dhcp_scopes where subnet_id = $1)::int d', [id])
  if ((n.a > 1 || n.d > 0) && qstr(c, 'force') !== '1') fail(409, 'subnet_not_empty', 'subnet_not_empty', { addresses: n.a, dhcp: n.d })
  await query('delete from subnets where id = $1', [id])
  await audit(c, 'subnet_delete', 'subnet', id)
  return { ok: true }
})

// ---- Adresses ----
route('GET', '/ipam/subnets/:id/addresses', 'viewer', async (c) => {
  const id = intParam(c, 'id'), q = qstr(c, 'q'), st = qstr(c, 'status')
  const items = await query(`select id, host(ip) as ip, status, hostname, mac::text as mac, description, owner, reachable, checked_at from addresses
    where subnet_id = $1 and ($2::text is null or hostname ilike $2 or host(ip) like $2 or mac::text ilike $2 or description ilike $2)
      and ($3::text is null or status = $3) order by ip`, [id, q ? `%${q}%` : null, st ?? null])
  return { items }
})

const addrBody = z.object({ ip: ipS, status: status.default('used'), hostname: host.nullable().optional(), mac: mac.nullable().optional(), description: z.string().max(500).nullable().optional(), owner: z.string().max(100).nullable().optional(), dns_zone_id: z.number().int().nullable().optional() })

/** Crée les enregistrements A/AAAA et PTR correspondant à une adresse (si une zone inverse primaire existe). */
async function syncDns(cl: PoolClient, ip: string, hostname: string, zoneId: number): Promise<void> {
  const z = (await cl.query("select id, name, view_id from dns_zones where id = $1 and type = 'primary'", [zoneId])).rows[0]
  if (!z) fail(400, 'zone_not_primary')
  const addr = parseIp(ip)!
  await cl.query("insert into dns_records (zone_id, name, type, rdata) values ($1,$2,$3,$4) on conflict do nothing", [z.id, hostname, addr.v === 4 ? 'A' : 'AAAA', ip])
  await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [z.id])
  const ptr = ptrName(addr)
  const rz = (await cl.query("select id, name from dns_zones where type = 'primary' and $1 like '%.' || lower(name) order by (view_id is not distinct from $2) desc, length(name) desc limit 1", [ptr, z.view_id])).rows[0]
  if (rz) {
    await cl.query('insert into dns_records (zone_id, name, type, rdata) values ($1,$2,$3,$4) on conflict do nothing', [rz.id, ptr.slice(0, -(rz.name.length + 1)), 'PTR', `${hostname}.${z.name}.`])
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [rz.id])
  }
}

route('POST', '/ipam/subnets/:id/addresses', 'operator', async (c) => {
  await allowSubnet(c, Number(c.params.id))
  const sid = intParam(c, 'id')
  const b = await c.body(addrBody)
  const ip = normIp(b.ip)!
  if ((await one<any>('select kind from subnets where id = $1', [sid]))?.kind === 'container') fail(400, 'container_no_addresses')
  const out = await tx(async (cl) => {
    await checkHostnameRule(cl, sid, b.hostname)
    const r = (await cl.query('insert into addresses (subnet_id, ip, status, hostname, mac, description, owner) values ($1,$2,$3,$4,$5,$6,$7) returning id',
      [sid, ip, b.status, b.hostname ?? null, b.mac ? normMac(b.mac) : null, b.description ?? null, b.owner ?? null])).rows[0].id as number
    const zone = b.hostname ? await resolveDnsZone(cl, sid, b.dns_zone_id) : null
    if (zone && b.hostname) await syncDns(cl, ip, b.hostname, zone)
    return { id: r, dhcp: await syncReservation(cl, r), dns: !!zone }
  })
  await audit(c, 'address_create', 'address', out.id, { ip })
  return out
})

// Prochaine adresse libre : hors adresses prises, passerelle, réseau/diffusion et plages DHCP
route('POST', '/ipam/subnets/:id/next', 'operator', async (c) => {
  await allowSubnet(c, Number(c.params.id))
  const sid = intParam(c, 'id')
  const b = await c.body(z.object({ status: status.default('used'), hostname: host.nullable().optional(), description: z.string().max(500).nullable().optional(), dns_zone_id: z.number().int().nullable().optional(), pool_id: z.number().int().optional() }))
  const out = await tx(async (cl) => {
    await cl.query('select 1 from subnets where id = $1 for update', [sid])
    const s = (await cl.query('select text(cidr) as cidr, kind from subnets where id = $1', [sid])).rows[0]
    if (!s) fail(404, 'not_found')
    if (s.kind === 'container') fail(400, 'container_no_addresses')
    const cidr = parseCidr(s.cidr)!
    if (cidr.v !== 4) fail(400, 'ipv4_only')
    await checkHostnameRule(cl, sid, b.hostname)
    const taken = new Set<bigint>((await cl.query('select host(ip) as ip from addresses where subnet_id = $1', [sid])).rows.map((r) => parseIp(r.ip)!.n))
    const pools = (await cl.query('select host(p.start_ip) s, host(p.end_ip) e from dhcp_pools p join dhcp_scopes d on d.id = p.scope_id where d.subnet_id = $1', [sid])).rows
    const excl = pools.map((p) => [parseIp(p.s)!.n, parseIp(p.e)!.n] as [bigint, bigint])
    let ip: string | null
    if (b.pool_id) {
      const pl = (await cl.query('select host(start_ip) s, host(end_ip) e from ipam_pools where id = $1 and subnet_id = $2', [b.pool_id, sid])).rows[0]
      if (!pl) fail(404, 'pool_not_found')
      ip = nextFreeInRange(parseIp(pl.s)!.n, parseIp(pl.e)!.n, taken, excl)
      if (!ip) fail(409, 'pool_full')
    } else {
      ip = nextFree(cidr, taken, excl)
      if (!ip) fail(409, 'subnet_full')
    }
    const id = (await cl.query('insert into addresses (subnet_id, ip, status, hostname, description) values ($1,$2,$3,$4,$5) returning id', [sid, ip, b.status, b.hostname ?? null, b.description ?? null])).rows[0].id
    const zone = b.hostname ? await resolveDnsZone(cl, sid, b.dns_zone_id) : null
    if (zone && b.hostname) await syncDns(cl, ip, b.hostname, zone)
    return { id: id as number, ip, dhcp: await syncReservation(cl, id as number), dns: !!zone }
  })
  await audit(c, 'address_allocate', 'address', out.id, { ip: out.ip })
  return out
})

route('PUT', '/ipam/addresses/:id', 'operator', async (c) => {
  await allowAddress(c, Number(c.params.id))
  const id = intParam(c, 'id')
  const b = await c.body(addrBody.omit({ ip: true, dns_zone_id: true }).partial())
  const dhcp = await tx(async (cl) => {
    const cur = (await cl.query('select subnet_id from addresses where id = $1 for update', [id])).rows[0]
    if (!cur) fail(404, 'not_found')
    if (b.hostname) await checkHostnameRule(cl, cur.subnet_id, b.hostname)
    await cl.query(`update addresses set status = coalesce($2, status), hostname = case when $3::boolean then $4 else hostname end, mac = case when $5::boolean then $6::macaddr else mac end,
      description = coalesce($7, description), owner = coalesce($8, owner), updated_at = now() where id = $1`,
      [id, b.status ?? null, b.hostname !== undefined, b.hostname ?? null, b.mac !== undefined, b.mac ? normMac(b.mac) : null, b.description ?? null, b.owner ?? null])
    return syncReservation(cl, id)
  })
  await audit(c, 'address_update', 'address', id)
  return { ok: true, dhcp }
})
route('DELETE', '/ipam/addresses/:id', 'operator', async (c) => {
  await allowAddress(c, Number(c.params.id))
  const id = intParam(c, 'id')
  await query('delete from addresses where id = $1', [id])
  await audit(c, 'address_delete', 'address', id)
  return { ok: true }
})

// ---- Pools d'adresses (plages nommées dans un réseau) ----
const poolBody = z.object({ name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional(), start_ip: ipS, end_ip: ipS })
const POOL_SQL = `select q.id, q.subnet_id, q.name, q.description, host(q.start_ip) as start_ip, host(q.end_ip) as end_ip, text(s.cidr) as cidr, s.name as network, s.space_id, sp.name as space, family(q.start_ip) as family,
  case when family(q.start_ip) = 4 then (q.end_ip - q.start_ip + 1)::float8 else null end as size,
  (select count(*)::int from addresses a where a.subnet_id = q.subnet_id and a.ip between q.start_ip and q.end_ip) as used
  from ipam_pools q join subnets s on s.id = q.subnet_id join ipam_spaces sp on sp.id = s.space_id`
const withPct = (r: any) => ({ ...r, percent: r.size ? Math.min(100, Math.round((r.used / r.size) * 1000) / 10) : null })
route('GET', '/ipam/pools', 'viewer', async (c) => {
  const sp = qint(c, 'space_id', 0), sid = qint(c, 'subnet_id', 0), q = qstr(c, 'q', 100)
  const rows = await query<any>(`${POOL_SQL} where ($1::int = 0 or s.space_id = $1) and ($2::int = 0 or q.subnet_id = $2)
    and ($3::text is null or q.name ilike $3 or host(q.start_ip) like $3 or text(s.cidr) like $3) order by s.space_id, s.cidr, q.start_ip limit 2000`, [sp, sid, q ? `%${q.replace(/[%_\\]/g, '\\$&')}%` : null])
  return { items: rows.map(withPct) }
})
route('POST', '/ipam/subnets/:id/pools', 'operator', async (c) => {
  await allowSubnet(c, Number(c.params.id))
  const sid = intParam(c, 'id')
  const b = await c.body(poolBody)
  const sub = await one<any>('select kind from subnets where id = $1', [sid])
  if (!sub) fail(404, 'not_found')
  if (sub.kind === 'container') fail(400, 'container_no_addresses')
  const r = await one<any>('insert into ipam_pools (subnet_id, name, description, start_ip, end_ip) values ($1,$2,$3,$4,$5) returning id', [sid, b.name, b.description ?? null, normIp(b.start_ip), normIp(b.end_ip)])
  await audit(c, 'pool_create', 'pool', r.id, { start: b.start_ip, end: b.end_ip })
  return { id: r.id }
})
route('PUT', '/ipam/pools/:id', 'operator', async (c) => {
  await allowPool(c, Number(c.params.id))
  const id = intParam(c, 'id')
  const b = await c.body(poolBody.partial())
  const r = await query('update ipam_pools set name = coalesce($2, name), description = coalesce($3, description), start_ip = coalesce($4, start_ip), end_ip = coalesce($5, end_ip), updated_at = now() where id = $1 returning id',
    [id, b.name ?? null, b.description ?? null, b.start_ip ? normIp(b.start_ip) : null, b.end_ip ? normIp(b.end_ip) : null])
  if (!r.length) fail(404, 'not_found')
  await audit(c, 'pool_update', 'pool', id)
  return { ok: true }
})
route('DELETE', '/ipam/pools/:id', 'operator', async (c) => {
  await allowPool(c, Number(c.params.id))
  const id = intParam(c, 'id')
  await query('delete from ipam_pools where id = $1', [id])
  await audit(c, 'pool_delete', 'pool', id)
  return { ok: true }
})

// ---- Toutes les adresses (vue transverse, pagination côté serveur) ----
route('GET', '/ipam/addresses', 'viewer', async (c) => {
  const sp = qint(c, 'space_id', 0), sid = qint(c, 'subnet_id', 0), fam = qint(c, 'family', 0), q = qstr(c, 'q', 100), st = qstr(c, 'status')
  const limit = qint(c, 'limit', 100, 1, 500), offset = qint(c, 'offset', 0, 0, 10_000_000)
  const args = [sp, sid, fam, q ? `%${q.replace(/[%_\\]/g, '\\$&')}%` : null, st ?? null]
  const where = `where ($1::int = 0 or s.space_id = $1) and ($2::int = 0 or a.subnet_id = $2) and ($3::int = 0 or family(a.ip) = $3)
    and ($4::text is null or a.hostname ilike $4 or host(a.ip) like $4 or a.mac::text ilike $4 or a.description ilike $4 or a.owner ilike $4) and ($5::text is null or a.status = $5)`
  const total = (await one<any>(`select count(*)::int as n from addresses a join subnets s on s.id = a.subnet_id ${where}`, args)).n
  const items = await query(`select a.id, a.subnet_id, host(a.ip) as ip, a.status, a.hostname, a.mac::text as mac, a.description, a.owner, a.reachable, a.checked_at, text(s.cidr) as cidr, s.name as network, sp.name as space
    from addresses a join subnets s on s.id = a.subnet_id join ipam_spaces sp on sp.id = s.space_id ${where} order by s.space_id, a.ip limit ${limit} offset ${offset}`, args)
  return { items, total }
})

// ---- Gabarits de réseau : règles héritées à la création d'un réseau ----
const templateBody = z.object({
  name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional(),
  create_scope: z.boolean().default(true), lease_time: z.number().int().min(60).max(31536000).default(86400),
  dhcp_options: optionsS.default({}), dns_zone_id: z.number().int().nullable().optional(),
  hostname_pattern: z.string().trim().nullable().optional(),
})
async function checkTemplate(b: z.infer<typeof templateBody> | Partial<z.infer<typeof templateBody>>) {
  if (b.hostname_pattern) { const e = patternError(b.hostname_pattern); if (e) fail(400, e) }
  if (b.dns_zone_id && !(await one("select 1 from dns_zones where id = $1 and type = 'primary'", [b.dns_zone_id]))) fail(400, 'zone_not_primary')
}
route('GET', '/ipam/templates', 'viewer', async () => ({ items: await query(`select t.id, t.name, t.description, t.create_scope, t.lease_time, t.dhcp_options, t.dns_zone_id, z.name as dns_zone, t.hostname_pattern,
  (select count(*)::int from subnets s where s.template_id = t.id) as subnets from network_templates t left join dns_zones z on z.id = t.dns_zone_id order by lower(t.name)`) }))
route('POST', '/ipam/templates', 'operator', async (c) => {
  denyScoped(c)
  const b = await c.body(templateBody)
  await checkTemplate(b)
  const r = await one<any>('insert into network_templates (name, description, create_scope, lease_time, dhcp_options, dns_zone_id, hostname_pattern) values ($1,$2,$3,$4,$5::jsonb,$6,$7) returning id',
    [b.name, b.description ?? null, b.create_scope, b.lease_time, JSON.stringify(cleanOptions(b.dhcp_options)), b.dns_zone_id ?? null, b.hostname_pattern || null])
  await audit(c, 'template_create', 'template', r.id, { name: b.name })
  return { id: r.id }
})
route('PUT', '/ipam/templates/:id', 'operator', async (c) => {
  denyScoped(c)
  const id = intParam(c, 'id')
  const b = await c.body(templateBody)
  await checkTemplate(b)
  const r = await query('update network_templates set name = $2, description = $3, create_scope = $4, lease_time = $5, dhcp_options = $6::jsonb, dns_zone_id = $7, hostname_pattern = $8, updated_at = now() where id = $1 returning id',
    [id, b.name, b.description ?? null, b.create_scope, b.lease_time, JSON.stringify(cleanOptions(b.dhcp_options)), b.dns_zone_id ?? null, b.hostname_pattern || null])
  if (!r.length) fail(404, 'not_found')
  await audit(c, 'template_update', 'template', id)
  return { ok: true }
})
route('DELETE', '/ipam/templates/:id', 'operator', async (c) => {
  denyScoped(c)
  const id = intParam(c, 'id')
  await query('delete from network_templates where id = $1', [id])
  await audit(c, 'template_delete', 'template', id)
  return { ok: true }
})

// ---- VLAN ----
const vlanBody = z.object({ vlan_id: z.number().int().min(1).max(4094), name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional() })
route('GET', '/ipam/vlans', 'viewer', async () => ({ items: await query('select v.id, v.vlan_id, v.name, v.description, (select count(*)::int from subnets s where s.vlan_id = v.id) as subnets from vlans v order by v.vlan_id') }))
route('POST', '/ipam/vlans', 'operator', async (c) => {
  denyScoped(c)
  const b = await c.body(vlanBody)
  const r = await one<any>('insert into vlans (vlan_id, name, description) values ($1,$2,$3) returning id', [b.vlan_id, b.name, b.description ?? null])
  await audit(c, 'vlan_create', 'vlan', r.id)
  return { id: r.id }
})
route('PUT', '/ipam/vlans/:id', 'operator', async (c) => {
  denyScoped(c)
  const id = intParam(c, 'id')
  const b = await c.body(vlanBody.partial())
  await query('update vlans set vlan_id = coalesce($2, vlan_id), name = coalesce($3, name), description = coalesce($4, description) where id = $1', [id, b.vlan_id ?? null, b.name ?? null, b.description ?? null])
  await audit(c, 'vlan_update', 'vlan', id)
  return { ok: true }
})
route('DELETE', '/ipam/vlans/:id', 'operator', async (c) => {
  denyScoped(c)
  const id = intParam(c, 'id')
  await query('delete from vlans where id = $1', [id])
  await audit(c, 'vlan_delete', 'vlan', id)
  return { ok: true }
})

// ---- Recherche et export ----
route('GET', '/ipam/search', 'viewer', async (c) => {
  const q = qstr(c, 'q', 100)
  if (!q || q.length < 2) return { subnets: [], addresses: [] }
  const like = `%${q.replace(/[%_\\]/g, '\\$&')}%`
  const subnets = await query('select id, text(cidr) as cidr, name, site from subnets where text(cidr) ilike $1 or name ilike $1 or coalesce(site, \'\') ilike $1 order by cidr limit 50', [like])
  const addresses = await query(`select a.id, a.subnet_id, host(a.ip) as ip, a.status, a.hostname, a.mac::text as mac, a.description, text(s.cidr) as cidr from addresses a join subnets s on s.id = a.subnet_id
    where host(a.ip) ilike $1 or a.hostname ilike $1 or a.mac::text ilike $1 or a.description ilike $1 order by a.ip limit 100`, [like])
  return { subnets, addresses }
})
const csvq = (v: unknown) => { const s = v === null || v === undefined ? '' : String(v); return /^[=+\-@]/.test(s) ? `"'${s.replace(/"/g, '""')}"` : /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s }
route('GET', '/ipam/export/addresses', 'viewer', async (c) => {
  const rows = await query<any>(`select text(s.cidr) as cidr, host(a.ip) as ip, a.status, a.hostname, a.mac::text as mac, a.description from addresses a join subnets s on s.id = a.subnet_id order by s.cidr, a.ip`)
  setResponseHeader(c.event, 'Content-Type', 'text/csv; charset=utf-8')
  setResponseHeader(c.event, 'Content-Disposition', 'attachment; filename="ipam-addresses.csv"')
  return ['cidr,ip,status,hostname,mac,description', ...rows.map((r) => [r.cidr, r.ip, r.status, r.hostname, r.mac, r.description].map(csvq).join(','))].join('\n') + '\n'
})

// Valeur exportée et lue par le point d'entrée : empêche l'élimination du module par l'optimiseur
export const registered = true
