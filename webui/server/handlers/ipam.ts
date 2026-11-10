import { z } from 'zod'
import { setResponseHeader } from 'h3'
import { audit, fail, intParam, qint, qstr, route } from '../utils/router'
import { one, query, tx } from '../utils/db'
import { capacity, nextFree, isHostname, normIp, normMac, parseCidr, cidrToString, cidrContainsIp, parseIp, ptrName } from '../utils/net'
import type { PoolClient } from 'pg'

const cidrS = z.string().trim().refine((v) => !!parseCidr(v), 'cidr')
const ipS = z.string().trim().refine((v) => !!normIp(v), 'ip')
const status = z.enum(['used', 'reserved', 'dhcp', 'gateway', 'infra'])
const host = z.string().trim().toLowerCase().refine(isHostname, 'hostname')
const mac = z.string().trim().refine((v) => !!normMac(v), 'mac')

const SUBNET_SQL = `select s.id, text(s.cidr) as cidr, family(s.cidr) as family, s.name, s.description, s.vlan_id, v.vlan_id as vlan, s.site,
  host(s.gateway) as gateway, s.tags,
  (select count(*)::int from addresses a where a.subnet_id = s.id) as used,
  (select p.id from subnets p where p.cidr >> s.cidr order by masklen(p.cidr) desc limit 1) as parent_id,
  exists (select 1 from dhcp_scopes d where d.subnet_id = s.id) as has_dhcp
  from subnets s left join vlans v on v.id = s.vlan_id`

route('GET', '/ipam/subnets', 'viewer', async () => {
  const rows = await query<any>(`${SUBNET_SQL} order by s.cidr`)
  return { items: rows.map((r) => { const c = parseCidr(r.cidr)!; const cap = capacity(c); return { ...r, capacity: cap > 1_000_000_000n ? null : Number(cap), percent: cap > 1_000_000_000n ? null : Math.min(100, Math.round((r.used / Number(cap)) * 1000) / 10) } }) }
})

const subnetBody = z.object({
  cidr: cidrS, name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional(),
  vlan_id: z.number().int().nullable().optional(), site: z.string().max(100).nullable().optional(),
  gateway: ipS.nullable().optional(), tags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
})
function checkGateway(cidr: string, gw: string | null | undefined) {
  if (!gw) return
  const c = parseCidr(cidr)!, ip = parseIp(gw)!
  if (!cidrContainsIp(c, ip)) fail(400, 'gateway_outside')
}

route('POST', '/ipam/subnets', 'operator', async (c) => {
  const b = await c.body(subnetBody)
  const cidr = cidrToString(parseCidr(b.cidr)!)
  checkGateway(cidr, b.gateway)
  const id = await tx(async (cl) => {
    const r = (await cl.query('insert into subnets (cidr, name, description, vlan_id, site, gateway, tags) values ($1,$2,$3,$4,$5,$6,$7) returning id',
      [cidr, b.name, b.description ?? null, b.vlan_id ?? null, b.site ?? null, b.gateway ? normIp(b.gateway) : null, b.tags ?? []])).rows[0].id
    if (b.gateway) await cl.query("insert into addresses (subnet_id, ip, status, hostname, description) values ($1,$2,'gateway','gateway','Passerelle') on conflict do nothing", [r, normIp(b.gateway)])
    return r as number
  })
  await audit(c, 'subnet_create', 'subnet', id, { cidr })
  return { id }
})
route('PUT', '/ipam/subnets/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const b = await c.body(subnetBody.partial())
  const cur = await one<any>('select text(cidr) as cidr from subnets where id = $1', [id])
  if (!cur) fail(404, 'not_found')
  if (b.cidr && cidrToString(parseCidr(b.cidr)!) !== cur.cidr) fail(400, 'cidr_immutable')
  checkGateway(cur.cidr, b.gateway)
  await query(`update subnets set name = coalesce($2, name), description = coalesce($3, description), vlan_id = $4, site = coalesce($5, site),
    gateway = coalesce($6, gateway), tags = coalesce($7, tags), updated_at = now() where id = $1`,
    [id, b.name ?? null, b.description ?? null, b.vlan_id === undefined ? (await one<any>('select vlan_id from subnets where id = $1', [id]))?.vlan_id ?? null : b.vlan_id, b.site ?? null, b.gateway ? normIp(b.gateway) : null, b.tags ?? null])
  await audit(c, 'subnet_update', 'subnet', id)
  return { ok: true }
})
route('DELETE', '/ipam/subnets/:id', 'operator', async (c) => {
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
  const items = await query(`select id, host(ip) as ip, status, hostname, mac::text as mac, description, owner from addresses
    where subnet_id = $1 and ($2::text is null or hostname ilike $2 or host(ip) like $2 or mac::text ilike $2 or description ilike $2)
      and ($3::text is null or status = $3) order by ip`, [id, q ? `%${q}%` : null, st ?? null])
  return { items }
})

const addrBody = z.object({ ip: ipS, status: status.default('used'), hostname: host.nullable().optional(), mac: mac.nullable().optional(), description: z.string().max(500).nullable().optional(), owner: z.string().max(100).nullable().optional(), dns_zone_id: z.number().int().optional() })

/** Crée les enregistrements A/AAAA et PTR correspondant à une adresse (si une zone inverse primaire existe). */
async function syncDns(cl: PoolClient, ip: string, hostname: string, zoneId: number): Promise<void> {
  const z = (await cl.query("select id, name from dns_zones where id = $1 and type = 'primary'", [zoneId])).rows[0]
  if (!z) fail(400, 'zone_not_primary')
  const addr = parseIp(ip)!
  await cl.query("insert into dns_records (zone_id, name, type, rdata) values ($1,$2,$3,$4) on conflict do nothing", [z.id, hostname, addr.v === 4 ? 'A' : 'AAAA', ip])
  await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [z.id])
  const ptr = ptrName(addr)
  const rz = (await cl.query("select id, name from dns_zones where type = 'primary' and $1 like '%.' || lower(name) order by length(name) desc limit 1", [ptr])).rows[0]
  if (rz) {
    await cl.query('insert into dns_records (zone_id, name, type, rdata) values ($1,$2,$3,$4) on conflict do nothing', [rz.id, ptr.slice(0, -(rz.name.length + 1)), 'PTR', `${hostname}.${z.name}.`])
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [rz.id])
  }
}

route('POST', '/ipam/subnets/:id/addresses', 'operator', async (c) => {
  const sid = intParam(c, 'id')
  const b = await c.body(addrBody)
  const ip = normIp(b.ip)!
  const id = await tx(async (cl) => {
    const r = (await cl.query('insert into addresses (subnet_id, ip, status, hostname, mac, description, owner) values ($1,$2,$3,$4,$5,$6,$7) returning id',
      [sid, ip, b.status, b.hostname ?? null, b.mac ? normMac(b.mac) : null, b.description ?? null, b.owner ?? null])).rows[0].id
    if (b.dns_zone_id && b.hostname) await syncDns(cl, ip, b.hostname, b.dns_zone_id)
    return r as number
  })
  await audit(c, 'address_create', 'address', id, { ip })
  return { id }
})

// Prochaine adresse libre : hors adresses prises, passerelle, réseau/diffusion et plages DHCP
route('POST', '/ipam/subnets/:id/next', 'operator', async (c) => {
  const sid = intParam(c, 'id')
  const b = await c.body(z.object({ status: status.default('used'), hostname: host.nullable().optional(), description: z.string().max(500).nullable().optional(), dns_zone_id: z.number().int().optional() }))
  const out = await tx(async (cl) => {
    await cl.query('select 1 from subnets where id = $1 for update', [sid])
    const s = (await cl.query('select text(cidr) as cidr from subnets where id = $1', [sid])).rows[0]
    if (!s) fail(404, 'not_found')
    const cidr = parseCidr(s.cidr)!
    if (cidr.v !== 4) fail(400, 'ipv4_only')
    const taken = new Set<bigint>((await cl.query('select host(ip) as ip from addresses where subnet_id = $1', [sid])).rows.map((r) => parseIp(r.ip)!.n))
    const pools = (await cl.query('select host(p.start_ip) s, host(p.end_ip) e from dhcp_pools p join dhcp_scopes d on d.id = p.scope_id where d.subnet_id = $1', [sid])).rows
    const ip = nextFree(cidr, taken, pools.map((p) => [parseIp(p.s)!.n, parseIp(p.e)!.n] as [bigint, bigint]))
    if (!ip) fail(409, 'subnet_full')
    const id = (await cl.query('insert into addresses (subnet_id, ip, status, hostname, description) values ($1,$2,$3,$4,$5) returning id', [sid, ip, b.status, b.hostname ?? null, b.description ?? null])).rows[0].id
    if (b.dns_zone_id && b.hostname) await syncDns(cl, ip, b.hostname, b.dns_zone_id)
    return { id: id as number, ip }
  })
  await audit(c, 'address_allocate', 'address', out.id, { ip: out.ip })
  return out
})

route('PUT', '/ipam/addresses/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const b = await c.body(addrBody.omit({ ip: true, dns_zone_id: true }).partial())
  await query(`update addresses set status = coalesce($2, status), hostname = case when $3::boolean then $4 else hostname end, mac = case when $5::boolean then $6::macaddr else mac end,
    description = coalesce($7, description), owner = coalesce($8, owner), updated_at = now() where id = $1`,
    [id, b.status ?? null, b.hostname !== undefined, b.hostname ?? null, b.mac !== undefined, b.mac ? normMac(b.mac) : null, b.description ?? null, b.owner ?? null])
  await audit(c, 'address_update', 'address', id)
  return { ok: true }
})
route('DELETE', '/ipam/addresses/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  await query('delete from addresses where id = $1', [id])
  await audit(c, 'address_delete', 'address', id)
  return { ok: true }
})

// ---- VLAN ----
const vlanBody = z.object({ vlan_id: z.number().int().min(1).max(4094), name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional() })
route('GET', '/ipam/vlans', 'viewer', async () => ({ items: await query('select v.id, v.vlan_id, v.name, v.description, (select count(*)::int from subnets s where s.vlan_id = v.id) as subnets from vlans v order by v.vlan_id') }))
route('POST', '/ipam/vlans', 'operator', async (c) => {
  const b = await c.body(vlanBody)
  const r = await one<any>('insert into vlans (vlan_id, name, description) values ($1,$2,$3) returning id', [b.vlan_id, b.name, b.description ?? null])
  await audit(c, 'vlan_create', 'vlan', r.id)
  return { id: r.id }
})
route('PUT', '/ipam/vlans/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const b = await c.body(vlanBody.partial())
  await query('update vlans set vlan_id = coalesce($2, vlan_id), name = coalesce($3, name), description = coalesce($4, description) where id = $1', [id, b.vlan_id ?? null, b.name ?? null, b.description ?? null])
  await audit(c, 'vlan_update', 'vlan', id)
  return { ok: true }
})
route('DELETE', '/ipam/vlans/:id', 'operator', async (c) => {
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
