import { z } from 'zod'
import { setResponseHeader } from 'h3'
import { audit, fail, intParam, patchOf, qint, qstr, route } from '../utils/router'
import { getPool, one, query, tx } from '../utils/db'
import { classlessRange } from '../utils/reverse'
import { capacity, nextFree, nextFreeInRange, isHostname, normIp, normMac, parseCidr, cidrToString, cidrContainsIp, parseIp, ptrName } from '../utils/net'
import type { PoolClient } from 'pg'
import { cleanOptions, optionsS } from '../utils/dhcpopts'
import { aliasNames } from '../utils/alias-db'
import { formatError, formatName } from '../utils/naming'
import { namingOfSubnet, hostnameMatches } from '../utils/smartddi'
import { checkHostnameRule, patternError, resolveDnsZone, syncReservation } from '../utils/smartddi'
import { ensureLabels, labelsS, normLabel } from '../utils/labels'

const cidrS = z.string().trim().refine((v) => !!parseCidr(v), 'cidr')
const ipS = z.string().trim().refine((v) => !!normIp(v), 'ip')
const status = z.enum(['used', 'reserved', 'dhcp', 'gateway', 'infra', 'ghost'])
const host = z.string().trim().toLowerCase().refine(isHostname, 'hostname')
const mac = z.string().trim().refine((v) => !!normMac(v), 'mac')

const SUBNET_SQL = `select s.id, s.space_id, sp.name as space, s.kind, text(s.cidr) as cidr, family(s.cidr) as family, s.name, s.description, s.vlan_id, v.vlan_id as vlan, s.site,
  host(s.gateway) as gateway, coalesce(s.tags, '{}') as tags,
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
import { assertNoDhcpOverlap } from '../utils/dhcp-space'
import { allowAddress, allowPool, allowSpace, allowSubnet, denyScoped } from '../utils/scope'
const spaceBody = z.object({ name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional(), tags: labelsS.optional() })
route('GET', '/ipam/spaces', 'viewer', async () => ({ items: await query(`select sp.id, sp.name, sp.description, coalesce(sp.tags, '{}') as tags,
  (select count(*)::int from subnets s where s.space_id = sp.id) as subnets,
  (select count(*)::int from addresses a join subnets s on s.id = a.subnet_id where s.space_id = sp.id) as addresses from ipam_spaces sp order by sp.id`) }))
route('POST', '/ipam/spaces', 'operator', async (c) => {
  denyScoped(c)
  const b = await c.body(spaceBody)
  const r = await one<any>('insert into ipam_spaces (name, description, tags) values ($1,$2,$3) returning id', [b.name, b.description ?? null, b.tags ?? []])
  await ensureLabels(b.tags)
  await audit(c, 'space_create', 'space', r.id, { name: b.name })
  return { id: r.id }
})
route('PUT', '/ipam/spaces/:id', 'operator', async (c) => {
  allowSpace(c, Number(c.params.id))
  const id = intParam(c, 'id')
  const b = await c.body(patchOf(spaceBody))
  const r = await query('update ipam_spaces set name = coalesce($2, name), description = coalesce($3, description), tags = coalesce($4, tags), updated_at = now() where id = $1 returning id', [id, b.name ?? null, b.description ?? null, b.tags ?? null])
  await ensureLabels(b.tags)
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
  gateway: ipS.nullable().optional(), tags: labelsS.optional(),
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
    await ensureLabels(b.tags, cl)
    if (b.gateway) await cl.query("insert into addresses (subnet_id, ip, status, hostname, description, is_gateway) values ($1,$2,'gateway','gateway','Passerelle',true) on conflict do nothing", [r, normIp(b.gateway)])
    // gabarit : l'étendue DHCP naît avec le réseau, dans la même transaction (IPv4, réseau, espace par défaut : Kea ne distingue pas les espaces)
    let dhcp: 'scope_created' | 'scope_skipped' | null = null
    if (tpl?.create_scope) {
      if (parseCidr(cidr)!.v === 4 && kind === 'network') {
        const opts = { ...cleanOptions(tpl.dhcp_options) }
        if (!opts.routers && b.gateway) opts.routers = [normIp(b.gateway)]
        await assertNoDhcpOverlap(r, null, async (q, a) => (await cl.query(q, a)).rows)
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
  const b = await c.body(patchOf(subnetBody))
  const cur = await one<any>('select text(cidr) as cidr, (select count(*)::int from addresses where subnet_id = $1) as n from subnets where id = $1', [id])
  if (!cur) fail(404, 'not_found')
  if (b.space_id !== undefined) { allowSpace(c, b.space_id); await checkSpace(b.space_id); await assertNoDhcpOverlap(id, b.space_id) }
  if (b.kind === 'container' && cur.n > 0) fail(409, 'container_no_addresses')
  if (b.template_id && !(await one('select 1 from network_templates where id = $1', [b.template_id]))) fail(400, 'template_not_found')
  if (b.cidr && cidrToString(parseCidr(b.cidr)!) !== cur.cidr) fail(400, 'cidr_immutable')
  checkGateway(cur.cidr, b.gateway)
  await query(`update subnets set name = coalesce($2, name), description = coalesce($3, description), vlan_id = $4, site = coalesce($5, site),
    gateway = coalesce($6, gateway), tags = coalesce($7, tags), space_id = coalesce($8, space_id), kind = coalesce($9, kind), template_id = case when $10::boolean then $11::int else template_id end, updated_at = now() where id = $1`,
    [id, b.name ?? null, b.description ?? null, b.vlan_id === undefined ? (await one<any>('select vlan_id from subnets where id = $1', [id]))?.vlan_id ?? null : b.vlan_id, b.site ?? null, b.gateway ? normIp(b.gateway) : null, b.tags ?? null, b.space_id ?? null, b.kind ?? null, b.template_id !== undefined, b.template_id ?? null])
  await ensureLabels(b.tags)
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
/** Filtre « label » : un ou plusieurs labels séparés par des virgules ; l'objet doit les porter tous. */
function labelFilter(c: any): string[] {
  const v = qstr(c, 'label', 400)
  return v ? [...new Set(v.split(',').map(normLabel).filter(Boolean))].slice(0, 20) : []
}
// ---- Passerelles des réseaux (0.22.0) ----
/** Passerelles connues, sans rien saisir : routeurs de l'étendue DHCP du réseau (« dhcp ») et passerelle déclarée sur le réseau (« subnet »). Les valeurs libres
 *  (JSON des options, champ du réseau) sont contrôlées ici, en TypeScript : jamais de conversion SQL sur une donnée non vérifiée, et seule une IP du réseau est retenue. */
export async function gatewayList(subnetId = 0, run?: (sql: string, params: unknown[]) => Promise<any[]>): Promise<Array<{ subnet_id: number; ip: string; src: 'dhcp' | 'subnet' }>> {
  // « run » : à fournir dans une transaction, pour réutiliser sa connexion (une seconde connexion prise pendant qu'une première est tenue épuiserait le pool sous charge)
  const rows = await (run ?? ((sql, params) => query<any>(sql, params)))(`select s.id as subnet_id, text(s.cidr) as cidr, host(s.gateway) as gateway, ds.options->'routers' as routers from subnets s left join dhcp_scopes ds on ds.subnet_id = s.id
    where s.kind = 'network' and ($1::int = 0 or s.id = $1) and (s.gateway is not null or jsonb_typeof(ds.options->'routers') = 'array')`, [subnetId])
  const out: Array<{ subnet_id: number; ip: string; src: 'dhcp' | 'subnet' }> = []
  for (const r of rows) {
    const cidr = parseCidr(r.cidr); if (!cidr) continue
    const seen = new Set<string>()
    const add = (raw: unknown, src: 'dhcp' | 'subnet') => {
      if (typeof raw !== 'string') return
      const ip = parseIp(raw); if (!ip || !cidrContainsIp(cidr, ip)) return
      const n = normIp(raw); if (!n || seen.has(n)) return
      seen.add(n); out.push({ subnet_id: r.subnet_id, ip: n, src })
    }
    if (Array.isArray(r.routers)) for (const x of r.routers.slice(0, 8)) add(x, 'dhcp')   // le DHCP d'abord : si les deux désignent la même IP, la source automatique la plus parlante l'emporte
    add(r.gateway, 'subnet')
  }
  return out
}
/** Table « gw » (réseau, IP, source) à partir de la liste ci-dessus, passée en paramètre JSON numéro p. */
const GW_CTE = (p: number) => `gw as (select g.subnet_id, g.ip, g.src from jsonb_to_recordset($${p}::jsonb) as g(subnet_id int, ip inet, src text))`
/** Origine de la passerelle d'une adresse de l'IPAM : « dhcp » ou « subnet » (automatique), « flag » (drapeau ou statut passerelle), sinon rien. */
const GW_OF = (a: string) => `coalesce((select g.src from gw g where g.subnet_id = ${a}.subnet_id and g.ip = ${a}.ip limit 1), case when ${a}.is_gateway or ${a}.status = 'gateway' then 'flag' end)`

route('GET', '/ipam/subnets/:id/addresses', 'viewer', async (c) => {
  const id = intParam(c, 'id'), q = qstr(c, 'q'), st = qstr(c, 'status')
  const gws = JSON.stringify(await gatewayList(id))
  // adresses du réseau + passerelles automatiques (DHCP, réseau) qui n'y figurent pas : lignes en lecture seule, id nul
  const items = await query(`with lse as (${await leaseRows()}), ${GW_CTE(5)}, r as (
      select a.id, a.ip as ipv, host(a.ip) as ip, a.status::text as status, coalesce(a.hostname, (select l.hostname from lse l where l.ip = a.ip and l.subnet_id = a.subnet_id limit 1)) as hostname, a.mac::text as mac, a.description, a.owner, coalesce(a.tags, '{}') as tags, a.reachable, a.checked_at, (a.is_gateway or a.status = 'gateway') as is_gateway, ${GW_OF('a')} as gw
        from addresses a where a.subnet_id = $1
      union all
      select null::int, g.ip, host(g.ip), 'gateway', null::text, null::text, null::text, null::text, '{}'::text[], null::boolean, null::timestamptz, false, g.src
        from gw g where g.subnet_id = $1 and not exists (select 1 from addresses a where a.subnet_id = g.subnet_id and a.ip = g.ip))
    select id, ip, status, hostname, mac, description, owner, tags, reachable, checked_at, is_gateway, gw from r
    where ($2::text is null or hostname ilike $2 or ip like $2 or mac ilike $2 or description ilike $2 or exists (select 1 from unnest(tags) x where x ilike $2))
      and ($3::text is null or (case when $3 = 'gw' then gw is not null else status = $3 end)) and (cardinality($4::text[]) = 0 or tags @> $4::text[]) order by ipv`, [id, q ? `%${q}%` : null, st ?? null, labelFilter(c), gws])
  const al = await aliasNames((items as any[]).map((i) => i.ip))
  return { items: (items as any[]).map((i) => ({ ...i, aliases: al.get(normIp(i.ip) ?? '') ?? [] })) }
})

const addrBody = z.object({ ip: ipS, status: status.default('used'), hostname: host.nullable().optional(), mac: mac.nullable().optional(), description: z.string().max(500).nullable().optional(), owner: z.string().max(100).nullable().optional(), dns_zone_id: z.number().int().nullable().optional(), tags: labelsS.optional(), is_gateway: z.boolean().optional() })

async function classlessZone(cl: PoolClient, ip: string, viewId: number | null): Promise<{ id: number; name: string; parent: string } | null> {
  const [a, b, c, d] = ip.split('.').map(Number) as [number, number, number, number]
  const rows = (await cl.query("select id, lower(name) as name from dns_zones where type = 'primary' and view_id is not distinct from $1 and lower(name) like $2", [viewId, `%-%.${c}.${b}.${a}.in-addr.arpa`])).rows
  for (const r of rows) {
    const rg = classlessRange(r.name); if (!rg) continue
    const first = Number(rg.first.split('.')[3]), last = Number(rg.last.split('.')[3])
    if (d >= first && d <= last) return { id: r.id, name: r.name, parent: rg.parent }
  }
  return null
}

/** Crée les enregistrements A/AAAA et PTR correspondant à une adresse (si une zone inverse primaire existe). */
export async function syncDns(cl: PoolClient, ip: string, hostname: string, zoneId: number): Promise<void> {
  const z = (await cl.query("select id, name, view_id from dns_zones where id = $1 and type = 'primary'", [zoneId])).rows[0]
  if (!z) fail(400, 'zone_not_primary')
  const addr = parseIp(ip)!
  await cl.query("insert into dns_records (zone_id, name, type, rdata) values ($1,$2,$3,$4) on conflict do nothing", [z.id, hostname, addr.v === 4 ? 'A' : 'AAAA', ip])
  await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [z.id])
  const ptr = ptrName(addr)
  // zone inverse « classless » (RFC 2317) qui couvre l'adresse : le PTR y est écrit, et la zone parente le délègue par un CNAME
  const cz = addr.v === 4 ? await classlessZone(cl, ip, z.view_id) : null
  if (cz) {
    const last = ip.split('.')[3]!
    await cl.query('insert into dns_records (zone_id, name, type, rdata) values ($1,$2,$3,$4) on conflict do nothing', [cz.id, last, 'PTR', `${hostname}.${z.name}.`])
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [cz.id])
    const par = (await cl.query("select id from dns_zones where lower(name) = $1 and view_id is not distinct from $2 and type = 'primary'", [cz.parent, z.view_id])).rows[0]
    if (par) {
      await cl.query("delete from dns_records where zone_id = $1 and name = $2 and type = 'PTR'", [par.id, last])
      await cl.query("insert into dns_records (zone_id, name, type, rdata, comment) select $1,$2,'CNAME',$3,'RFC 2317' where not exists (select 1 from dns_records where zone_id = $1 and lower(name) = lower($2))", [par.id, last, `${last}.${cz.name}.`])
      await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [par.id])
    }
    return
  }
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
    const r = (await cl.query('insert into addresses (subnet_id, ip, status, hostname, mac, description, owner, tags, is_gateway) values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning id',
      [sid, ip, b.status, b.hostname ?? null, b.mac ? normMac(b.mac) : null, b.description ?? null, b.owner ?? null, b.tags ?? [], b.status === 'gateway' || !!b.is_gateway])).rows[0].id as number
    await ensureLabels(b.tags, cl)
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
  const b = await c.body(z.object({ status: status.default('used'), hostname: host.nullable().optional(), description: z.string().max(500).nullable().optional(), dns_zone_id: z.number().int().nullable().optional(), pool_id: z.number().int().optional(), auto_name: z.boolean().default(false), tags: labelsS.optional() }))
  const out = await tx(async (cl) => {
    await cl.query('select 1 from subnets where id = $1 for update', [sid])
    const s = (await cl.query('select text(cidr) as cidr, kind from subnets where id = $1', [sid])).rows[0]
    if (!s) fail(404, 'not_found')
    if (s.kind === 'container') fail(400, 'container_no_addresses')
    const cidr = parseCidr(s.cidr)!
    if (cidr.v !== 4) fail(400, 'ipv4_only')
    await checkHostnameRule(cl, sid, b.hostname)
    const taken = new Set<bigint>((await cl.query('select host(ip) as ip from addresses where subnet_id = $1', [sid])).rows.map((r) => parseIp(r.ip)!.n))
    for (const g of await gatewayList(sid, async (sql, params) => (await cl.query(sql, params)).rows)) taken.add(parseIp(g.ip)!.n)   // une passerelle connue (routeur DHCP, passerelle du réseau) n'est jamais proposée comme libre
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
    let hostname = b.hostname ?? null   // nom attribué d'après le format du VLAN / du gabarit si demandé et non saisi
    if (!hostname && b.auto_name) {
      const n = await namingOfSubnet(cl, sid), g = n?.format ? formatName(n.format, { ip: ip!, vlan: n.vlan, site: n.site }) : null
      if (!g) fail(400, 'name_not_generated')
      if (n!.pattern && !hostnameMatches(n!.pattern, g)) fail(400, 'hostname_rule', 'hostname_rule', { pattern: n!.pattern })
      hostname = g
    }
    const id = (await cl.query('insert into addresses (subnet_id, ip, status, hostname, description, tags, is_gateway) values ($1,$2,$3,$4,$5,$6,$7) returning id', [sid, ip, b.status, hostname, b.description ?? null, b.tags ?? [], b.status === 'gateway'])).rows[0].id
    await ensureLabels(b.tags, cl)
    const zone = hostname ? await resolveDnsZone(cl, sid, b.dns_zone_id) : null
    if (zone && hostname) await syncDns(cl, ip!, hostname, zone)
    return { id: id as number, ip, hostname, dhcp: await syncReservation(cl, id as number), dns: !!zone }
  })
  await audit(c, 'address_allocate', 'address', out.id, { ip: out.ip })
  return out
})

route('PUT', '/ipam/addresses/:id', 'operator', async (c) => {
  await allowAddress(c, Number(c.params.id))
  const id = intParam(c, 'id')
  const b = await c.body(patchOf(addrBody.omit({ ip: true, dns_zone_id: true })))
  const dhcp = await tx(async (cl) => {
    const cur = (await cl.query('select subnet_id from addresses where id = $1 for update', [id])).rows[0]
    if (!cur) fail(404, 'not_found')
    if (b.hostname) await checkHostnameRule(cl, cur.subnet_id, b.hostname)
    // drapeau passerelle : le statut « passerelle » le pose, un autre statut l'enlève, sinon il garde la valeur demandée (ou l'ancienne)
    await cl.query(`update addresses set status = coalesce($2, status), is_gateway = case when coalesce($2::text, status) = 'gateway' then true when $10::boolean is not null then $10 when $2::text is not null and status = 'gateway' then false else is_gateway end, hostname = case when $3::boolean then $4 else hostname end, mac = case when $5::boolean then $6::macaddr else mac end,
      description = coalesce($7, description), owner = coalesce($8, owner), tags = coalesce($9, tags), updated_at = now() where id = $1`,
      [id, b.status ?? null, b.hostname !== undefined, b.hostname ?? null, b.mac !== undefined, b.mac ? normMac(b.mac) : null, b.description ?? null, b.owner ?? null, b.tags ?? null, b.is_gateway ?? null])
    await ensureLabels(b.tags, cl)
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

// Baux actifs de Kea rattachés à un réseau IPAM (lease4.subnet_id = identifiant de l'étendue DHCP). Vide tant que Kea n'a pas de base de baux PostgreSQL.
/** Nom de bail nettoyé : espaces, point final et casse retirés ; vide → null. */
const LEASE_NAME = (col: string) => `nullif(lower(regexp_replace(trim(${col}), '\\.$', '')), '')`
const leaseRows = async (): Promise<string> => {
  const t = await one<any>("select to_regclass('public.lease4') is not null as ok")
  if (!t?.ok) return "select null::inet as ip, null::bytea as hwaddr, null::text as hostname, null::int as subnet_id where false"
  // nom du bail sans point final ni majuscules (l'option 81 du client le renvoie en FQDN absolu « poste.domaine. ») ; à défaut de nom fourni
  // par le client, un enregistrement A des zones gérées portant cette adresse (sinon la ligne reste sans nom)
  return `select l2.ip, l2.hwaddr, coalesce(l2.name, (select case when r.name = '@' then lower(z.name) else lower(r.name || '.' || z.name) end
        from dns_records r join dns_zones z on z.id = r.zone_id where r.type = 'A' and not r.disabled and r.rdata = host(l2.ip) order by r.id limit 1)) as hostname, l2.subnet_id
      from (select ('0.0.0.0'::inet + l.address) as ip, l.hwaddr, ${LEASE_NAME('l.hostname')} as name, ds.subnet_id
        from lease4 l join dhcp_scopes ds on ds.id = l.subnet_id where l.expire > now() and l.hwaddr is not null) l2`
}

// ---- Pools d'adresses (plages nommées dans un réseau) ----
const poolBody = z.object({ name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional(), start_ip: ipS, end_ip: ipS })
const POOL_SQL = `select q.id, q.subnet_id, q.name, q.description, host(q.start_ip) as start_ip, host(q.end_ip) as end_ip, text(s.cidr) as cidr, s.name as network, s.space_id, sp.name as space, family(q.start_ip) as family,
  case when family(q.start_ip) = 4 then (q.end_ip - q.start_ip + 1)::float8 else null end as size,
  (select count(*)::int from addresses a where a.subnet_id = q.subnet_id and a.ip between q.start_ip and q.end_ip) as used
  from ipam_pools q join subnets s on s.id = q.subnet_id join ipam_spaces sp on sp.id = s.space_id`
const withPct = (r: any) => ({ ...r, percent: r.size ? Math.min(100, Math.round((r.used / r.size) * 1000) / 10) : null })
route('GET', '/ipam/pools', 'viewer', async (c) => {
  const sp = qint(c, 'space_id', 0), sid = qint(c, 'subnet_id', 0), q = qstr(c, 'q', 100)
  const like = q ? `%${q.replace(/[%_\\]/g, '\\$&')}%` : null
  const mine = await query<any>(`${POOL_SQL} where ($1::int = 0 or s.space_id = $1) and ($2::int = 0 or q.subnet_id = $2)
    and ($3::text is null or q.name ilike $3 or host(q.start_ip) like $3 or text(s.cidr) like $3) order by s.space_id, s.cidr, q.start_ip limit 2000`, [sp, sid, like])
  // plages des étendues DHCP (lecture seule ici : elles se gèrent dans DHCP) ; « utilisées » = adresses IPAM + baux actifs de la plage
  const dhcp = await query<any>(`with lse as (${await leaseRows()})
    select -p.id as id, ds.subnet_id, coalesce(nullif(ds.name, ''), 'DHCP') as name, null::text as description, host(p.start_ip) as start_ip, host(p.end_ip) as end_ip, text(s.cidr) as cidr, s.name as network,
      s.space_id, sp.name as space, family(p.start_ip) as family,
      case when family(p.start_ip) = 4 then (p.end_ip - p.start_ip + 1)::float8 else null end as size,
      (select count(*)::int from (select a.ip from addresses a where a.subnet_id = ds.subnet_id and a.ip between p.start_ip and p.end_ip
        union select l.ip from lse l where l.subnet_id = ds.subnet_id and l.ip between p.start_ip and p.end_ip) u) as used
    from dhcp_pools p join dhcp_scopes ds on ds.id = p.scope_id join subnets s on s.id = ds.subnet_id join ipam_spaces sp on sp.id = s.space_id
    where ($1::int = 0 or s.space_id = $1) and ($2::int = 0 or ds.subnet_id = $2)
      and ($3::text is null or coalesce(ds.name, '') ilike $3 or host(p.start_ip) like $3 or text(s.cidr) like $3) order by s.space_id, s.cidr, p.start_ip limit 2000`, [sp, sid, like])
  const items = [...mine.map((r) => ({ ...r, source: 'ipam' })), ...dhcp.map((r) => ({ ...r, source: 'dhcp' }))]
  items.sort((a, b) => a.space_id - b.space_id || String(a.cidr).localeCompare(String(b.cidr), 'en', { numeric: true }) || String(a.start_ip).localeCompare(String(b.start_ip), 'en', { numeric: true }))
  return { items: items.map(withPct) }
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
  const b = await c.body(patchOf(poolBody))
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
  const args = [sp, sid, fam, q ? `%${q.replace(/[%_\\]/g, '\\$&')}%` : null, st ?? null, labelFilter(c), JSON.stringify(await gatewayList(sid))]
  // adresses de l'IPAM + baux DHCP actifs qui n'y figurent pas (lignes « bail », en lecture seule : id nul)
  const withAll = `with lse as (${await leaseRows()}), ${GW_CTE(7)}, r as (
    select a.id, a.subnet_id, a.ip, a.status::text as status, coalesce(a.hostname, (select l.hostname from lse l where l.ip = a.ip and l.subnet_id = a.subnet_id limit 1)) as hostname, a.mac::text as mac, a.description, a.owner, coalesce(a.tags, '{}') as tags, a.reachable, a.checked_at, (a.is_gateway or a.status = 'gateway') as is_gateway, ${GW_OF('a')} as gw from addresses a
    union all
    select null::int, l.subnet_id, l.ip, 'lease', l.hostname, regexp_replace(encode(l.hwaddr, 'hex'), '(..)(?=.)', '\\1:', 'g'), null::text, null::text, '{}'::text[], null::boolean, null::timestamptz, false, null::text
      from lse l where l.subnet_id is not null and not exists (select 1 from addresses a where a.ip = l.ip and a.subnet_id = l.subnet_id)
    union all
    select null::int, g.subnet_id, g.ip, 'gateway', null::text, null::text, null::text, null::text, '{}'::text[], null::boolean, null::timestamptz, false, g.src
      from gw g where not exists (select 1 from addresses a where a.ip = g.ip and a.subnet_id = g.subnet_id))`
  const where = `where ($1::int = 0 or s.space_id = $1) and ($2::int = 0 or r.subnet_id = $2) and ($3::int = 0 or family(r.ip) = $3)
    and ($4::text is null or r.hostname ilike $4 or host(r.ip) like $4 or r.mac ilike $4 or r.description ilike $4 or r.owner ilike $4 or exists (select 1 from unnest(r.tags) x where x ilike $4)) and ($5::text is null or (case when $5 = 'gw' then r.gw is not null else r.status = $5 end))
    and (cardinality($6::text[]) = 0 or r.tags @> $6::text[])`
  const total = (await one<any>(`${withAll} select count(*)::int as n from r join subnets s on s.id = r.subnet_id ${where}`, args)).n
  const items = await query(`${withAll} select r.id, r.subnet_id, host(r.ip) as ip, r.status, r.hostname, r.mac, r.description, r.owner, r.tags, r.reachable, r.checked_at, r.is_gateway, r.gw, text(s.cidr) as cidr, s.name as network, sp.name as space
    from r join subnets s on s.id = r.subnet_id join ipam_spaces sp on sp.id = s.space_id ${where} order by s.space_id, r.ip limit ${limit} offset ${offset}`, args)
  const al = await aliasNames((items as any[]).map((i) => i.ip))
  return { items: (items as any[]).map((i) => ({ ...i, aliases: al.get(normIp(i.ip) ?? '') ?? [] })), total }
})

// ---- Gabarits de réseau : règles héritées à la création d'un réseau ----
const templateBody = z.object({
  name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional(),
  create_scope: z.boolean().default(true), lease_time: z.number().int().min(60).max(31536000).default(86400),
  dhcp_options: optionsS.default({}), dns_zone_id: z.number().int().nullable().optional(),
  hostname_pattern: z.string().trim().nullable().optional(), name_format: z.string().trim().nullable().optional(),
})
async function checkTemplate(b: z.infer<typeof templateBody> | Partial<z.infer<typeof templateBody>>) {
  if (b.hostname_pattern) { const e = patternError(b.hostname_pattern); if (e) fail(400, e) }
  if (b.name_format) { const e = formatError(b.name_format); if (e) fail(400, e) }
  if (b.dns_zone_id && !(await one("select 1 from dns_zones where id = $1 and type = 'primary'", [b.dns_zone_id]))) fail(400, 'zone_not_primary')
}
route('GET', '/ipam/templates', 'viewer', async () => ({ items: await query(`select t.id, t.name, t.description, t.create_scope, t.lease_time, t.dhcp_options, t.dns_zone_id, z.name as dns_zone, t.hostname_pattern, t.name_format,
  (select count(*)::int from subnets s where s.template_id = t.id) as subnets from network_templates t left join dns_zones z on z.id = t.dns_zone_id order by lower(t.name)`) }))
route('POST', '/ipam/templates', 'operator', async (c) => {
  denyScoped(c)
  const b = await c.body(templateBody)
  await checkTemplate(b)
  const r = await one<any>('insert into network_templates (name, description, create_scope, lease_time, dhcp_options, dns_zone_id, hostname_pattern, name_format) values ($1,$2,$3,$4,$5::jsonb,$6,$7,$8) returning id',
    [b.name, b.description ?? null, b.create_scope, b.lease_time, JSON.stringify(cleanOptions(b.dhcp_options)), b.dns_zone_id ?? null, b.hostname_pattern || null, b.name_format || null])
  await audit(c, 'template_create', 'template', r.id, { name: b.name })
  return { id: r.id }
})
route('PUT', '/ipam/templates/:id', 'operator', async (c) => {
  denyScoped(c)
  const id = intParam(c, 'id')
  const b = await c.body(templateBody)
  await checkTemplate(b)
  const r = await query('update network_templates set name = $2, description = $3, create_scope = $4, lease_time = $5, dhcp_options = $6::jsonb, dns_zone_id = $7, hostname_pattern = $8, name_format = $9, updated_at = now() where id = $1 returning id',
    [id, b.name, b.description ?? null, b.create_scope, b.lease_time, JSON.stringify(cleanOptions(b.dhcp_options)), b.dns_zone_id ?? null, b.hostname_pattern || null, b.name_format || null])
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
const vlanBody = z.object({ vlan_id: z.number().int().min(1).max(4094), name: z.string().trim().min(1).max(100), description: z.string().max(500).nullable().optional(), hostname_pattern: z.string().trim().nullable().optional(), name_format: z.string().trim().nullable().optional(), tags: labelsS.optional() })
function checkNaming(b: { hostname_pattern?: string | null; name_format?: string | null }) {
  if (b.hostname_pattern) { const e = patternError(b.hostname_pattern); if (e) fail(400, e) }
  if (b.name_format) { const e = formatError(b.name_format); if (e) fail(400, e) }
}
route('GET', '/ipam/vlans', 'viewer', async () => ({ items: await query('select v.id, v.vlan_id, v.name, v.description, coalesce(v.tags, array[]::text[]) as tags, v.hostname_pattern, v.name_format, (select count(*)::int from subnets s where s.vlan_id = v.id) as subnets from vlans v order by v.vlan_id') }))
route('POST', '/ipam/vlans', 'operator', async (c) => {
  denyScoped(c)
  const b = await c.body(vlanBody)
  checkNaming(b)
  const r = await one<any>('insert into vlans (vlan_id, name, description, hostname_pattern, name_format, tags) values ($1,$2,$3,$4,$5,$6) returning id', [b.vlan_id, b.name, b.description ?? null, b.hostname_pattern || null, b.name_format || null, b.tags ?? []])
  await ensureLabels(b.tags)
  await audit(c, 'vlan_create', 'vlan', r.id)
  return { id: r.id }
})
route('PUT', '/ipam/vlans/:id', 'operator', async (c) => {
  denyScoped(c)
  const id = intParam(c, 'id')
  const b = await c.body(patchOf(vlanBody))
  checkNaming(b)
  await query('update vlans set vlan_id = coalesce($2, vlan_id), name = coalesce($3, name), description = coalesce($4, description) where id = $1', [id, b.vlan_id ?? null, b.name ?? null, b.description ?? null])
  if (b.tags !== undefined) { await query('update vlans set tags = $2 where id = $1', [id, b.tags]); await ensureLabels(b.tags) }
  if (b.hostname_pattern !== undefined) await query('update vlans set hostname_pattern = $2 where id = $1', [id, b.hostname_pattern || null])
  if (b.name_format !== undefined) await query('update vlans set name_format = $2 where id = $1', [id, b.name_format || null])
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
  const rows = await query<any>(`select text(s.cidr) as cidr, host(a.ip) as ip, a.status, a.hostname, a.mac::text as mac, a.description, array_to_string(a.tags, ';') as tags from addresses a join subnets s on s.id = a.subnet_id order by s.cidr, a.ip`)
  setResponseHeader(c.event, 'Content-Type', 'text/csv; charset=utf-8')
  setResponseHeader(c.event, 'Content-Disposition', 'attachment; filename="ipam-addresses.csv"')
  return ['cidr,ip,status,hostname,mac,description,labels', ...rows.map((r) => [r.cidr, r.ip, r.status, r.hostname, r.mac, r.description, r.tags].map(csvq).join(','))].join('\n') + '\n'
})

// Valeur exportée et lue par le point d'entrée : empêche l'élimination du module par l'optimiseur
export const registered = true

// ---- Nommage : suggestion et contrôle de convention (0.10.5) ----
route('GET', '/ipam/naming/suggest', 'viewer', async (c) => {
  const sid = qint(c, 'subnet_id', 0), ip = normIp(qstr(c, 'ip', 64) ?? '')
  if (!sid || !ip || parseIp(ip)?.v !== 4) fail(400, 'invalid_query')
  await allowSubnet(c, sid)
  const n = await namingOfSubnet({ query: (q: string, p?: unknown[]) => getPool().query(q, p) } as any, sid)
  if (!n) fail(404, 'not_found')
  const name = n.format ? formatName(n.format, { ip, vlan: n.vlan, site: n.site }) : null
  return { name, format: n.format, pattern: n.pattern, source: n.source, valid: name !== null && (!n.pattern || hostnameMatches(n.pattern, name)) }
})

// Adresses nommées qui ne respectent pas la règle de leur réseau (un réseau, ou tous pour un compte non restreint)
route('GET', '/ipam/naming/audit', 'viewer', async (c) => {
  const sid = qint(c, 'subnet_id', 0)
  if (sid) await allowSubnet(c, sid); else denyScoped(c)
  const rows = await query<any>(`select a.id, a.subnet_id, text(s.cidr) as cidr, host(a.ip) as ip, a.hostname, coalesce(v.hostname_pattern, t.hostname_pattern) as pattern
    from addresses a join subnets s on s.id = a.subnet_id left join vlans v on v.id = s.vlan_id left join network_templates t on t.id = s.template_id
    where a.hostname is not null and a.hostname <> '' and coalesce(v.hostname_pattern, t.hostname_pattern) is not null and ($1::int = 0 or a.subnet_id = $1) order by s.cidr, a.ip limit 20000`, [sid])
  const bad = rows.filter((r) => !hostnameMatches(r.pattern, r.hostname))
  const unnamed = await one<any>(`select count(*)::int n from addresses a join subnets s on s.id = a.subnet_id left join vlans v on v.id = s.vlan_id left join network_templates t on t.id = s.template_id
    where (a.hostname is null or a.hostname = '') and a.status in ('used','dhcp') and coalesce(v.hostname_pattern, t.hostname_pattern) is not null and ($1::int = 0 or a.subnet_id = $1)`, [sid])
  return { checked: rows.length, violations: bad.length, unnamed: unnamed?.n ?? 0, items: bad.slice(0, 500) }
})
