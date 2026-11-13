// Vue unifiée d'une adresse IP (0.9.53) : ses noms (A/AAAA), son PTR et ses alias (CNAME), gérés depuis l'adresse.
// L'adresse n'est liée à rien en base : ses noms sont les A/AAAA qui portent son IP, ses alias les CNAME qui y mènent (voir utils/aliases.ts).
import { z } from 'zod'
import { audit, fail, intParam, qstr, route } from '../utils/router'
import { one, query, tx } from '../utils/db'
import { normIp, parseIp, ptrName } from '../utils/net'
import { conflictError, isAdCritical, normalizeRdata, toRelativeName } from '../utils/dns'
import { aliasProblem, fqdnOf, stripDot, zoneForName } from '../utils/aliases'
import type { Alias } from '../utils/aliases'
import { aliasesOf, loadCnames, loadHosts } from '../utils/alias-db'
import type { HostRow } from '../utils/alias-db'
import { allowAddress } from '../utils/scope'
import { syncDns } from './ipam'

export const registered = true

const ttl = z.number().int().min(0).max(2147483647)
const aliasName = z.string().trim().min(1).max(253)

async function context(id: number) {
  const a = await one<any>('select a.id, host(a.ip) as ip, a.hostname, a.subnet_id from addresses a where a.id = $1', [id])
  if (!a) fail(404, 'not_found')
  const ip = normIp(a.ip)!
  const hosts = await loadHosts([ip]), cnames = await loadCnames()
  return { a, ip, hosts, cnames, aliases: aliasesOf(hosts, cnames) }
}
const aliasView = (x: Alias) => ({ id: x.rec.id, name: x.rec.name, fqdn: x.fqdn, zoneId: x.rec.zoneId, zone: x.rec.zone, view: x.rec.view, ttl: x.rec.ttl, comment: x.rec.comment, disabled: x.rec.disabled, protected: x.rec.protected, target: x.target, depth: x.depth })
const hostView = (h: HostRow) => ({ id: h.id, fqdn: h.fqdn, type: h.type, zoneId: h.zoneId, zone: h.zone, view: h.view, viewName: h.viewName, ttl: h.ttl })

route('GET', '/ipam/addresses/:id/dns', 'viewer', async (c) => {
  const id = intParam(c, 'id')
  const { a, ip, hosts, aliases } = await context(id)
  const ptrFq = ptrName(parseIp(ip)!)
  const ptrs = (await query<any>("select r.id, r.name, r.rdata, z.id as zone_id, z.name as zone from dns_records r join dns_zones z on z.id = r.zone_id where r.type = 'PTR' and z.type = 'primary' and not r.disabled and (r.name || '.' || z.name = $1 or (r.name = '@' and z.name = $1))", [ptrFq]))
    .map((r) => ({ id: r.id, fqdn: ptrFq, target: String(r.rdata).replace(/\.$/, ''), zoneId: r.zone_id, zone: r.zone }))
  const views = [...new Set(hosts.map((h) => h.view))]
  const zones = (await query<any>("select z.id, z.name, z.view_id, v.name as view from dns_zones z left join dns_views v on v.id = z.view_id where z.type = 'primary' order by z.name")).filter((z) => views.includes(z.view_id ?? null))
    .map((z) => ({ id: z.id, name: z.name, view: z.view_id ?? null, viewName: z.view ?? null }))
  // zones où créer le nom A/AAAA quand l'adresse n'en a pas encore (hostname connu de l'IPAM)
  const allZones = hosts.length ? [] : (await query<any>("select id, name from dns_zones where type = 'primary' and name not like '%.arpa' order by name")).map((z) => ({ id: z.id, name: z.name }))
  return { ip, hostname: a.hostname ?? null, hosts: hosts.map(hostView), ptr: ptrs, aliases: aliases.map(aliasView), zones, hostZones: allZones }
})

/** Crée les enregistrements A/AAAA (+ PTR) de l'adresse depuis son nom d'hôte IPAM, dans la zone choisie : préalable aux alias. */
route('POST', '/ipam/addresses/:id/dns', 'operator', async (c) => {
  await allowAddress(c, intParam(c, 'id'))
  const id = intParam(c, 'id')
  const b = await c.body(z.object({ zone_id: z.number().int() }))
  const { a, ip, hosts } = await context(id)
  if (!a.hostname) fail(400, 'no_hostname')
  if (hosts.length) fail(409, 'host_exists')
  await tx(async (cl) => { await syncDns(cl, ip, a.hostname, b.zone_id) })
  await audit(c, 'address_dns_create', 'address', id, { ip, zone_id: b.zone_id })
  return { ok: true }
})

const createBody = z.object({ name: aliasName, zone_id: z.number().int().optional(), target: z.string().trim().max(253).optional(), ttl: ttl.nullable().optional(), comment: z.string().max(500).nullable().optional() })

route('POST', '/ipam/addresses/:id/aliases', 'operator', async (c) => {
  await allowAddress(c, intParam(c, 'id'))
  const id = intParam(c, 'id')
  const b = await c.body(createBody)
  const { hosts, cnames, aliases } = await context(id)
  if (!hosts.length) fail(409, 'no_host_record')
  // cible : un nom de l'hôte (ou l'un de ses alias) ; sans précision, le nom unique de l'hôte
  const known = new Map<string, { view: number | null; zone: string }>()
  for (const h of hosts) known.set(h.fqdn, { view: h.view, zone: h.zone })
  for (const x of aliases) known.set(x.fqdn, { view: x.rec.view, zone: x.rec.zone })
  let target: string
  if (b.target) { target = stripDot(b.target); if (!known.has(target)) fail(400, 'alias_target_unknown') }
  else if (hosts.length === 1) target = hosts[0]!.fqdn
  else fail(400, 'alias_target_required')
  const tv = known.get(target)!
  const zones = (await query<any>("select id, name, view_id from dns_zones where type = 'primary'")).map((z) => ({ id: z.id, name: z.name as string, view: (z.view_id ?? null) as number | null }))
  let zone: { id: number; name: string; view: number | null } | null
  if (b.zone_id) { zone = zones.find((z) => z.id === b.zone_id) ?? null; if (!zone) fail(400, 'zone_not_primary'); if (zone.view !== tv.view) fail(400, 'alias_view_mismatch') }
  else {
    zone = zoneForName(b.name, tv.view, zones)
    if (!zone && !stripDot(b.name).includes('.')) zone = zones.find((z) => z.view === tv.view && z.name.toLowerCase() === tv.zone.toLowerCase()) ?? null   // nom court : zone de la cible
    if (!zone) fail(400, 'alias_zone_unknown')
  }
  const rel = toRelativeName(b.name, zone.name)
  if (!rel) fail(400, 'name_invalid')
  const existing = await query<any>('select id, name, type from dns_records where zone_id = $1 and lower(name) = lower($2)', [zone.id, rel])
  const ce = conflictError(existing, { name: rel, type: 'CNAME' }); if (ce) fail(409, ce)
  const fq = fqdnOf(rel, zone.name)
  const pb = aliasProblem(fq, target, tv.view, cnames); if (pb) fail(409, pb)
  const rd = normalizeRdata('CNAME', target + '.'); if (!rd.ok) fail(400, 'name_invalid')
  const rid = await tx(async (cl) => {
    const r = (await cl.query('insert into dns_records (zone_id, name, type, ttl, rdata, comment, protected) values ($1,$2,$3,$4,$5,$6,$7) returning id',
      [zone!.id, rel, 'CNAME', b.ttl ?? null, rd.value, b.comment ?? null, isAdCritical(rel, 'CNAME')])).rows[0].id as number
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [zone!.id])
    return r
  })
  await audit(c, 'alias_create', 'record', rid, { address: id, fqdn: fq, target })
  return { id: rid, fqdn: fq, target }
})

/** L'enregistrement doit être un alias de CETTE adresse : on ne modifie jamais un CNAME quelconque par ce chemin. */
async function mine(c: any) {
  await allowAddress(c, intParam(c, 'id'))
  const id = intParam(c, 'id'), rid = intParam(c, 'rid')
  const ctx = await context(id)
  const al = ctx.aliases.find((x) => x.rec.id === rid)
  if (!al) fail(404, 'alias_not_found')
  return { ...ctx, id, rid, al }
}
const dependents = (al: Alias, all: Alias[]): Alias[] => {
  const out: Alias[] = [], seen = new Set<number>([al.rec.id]); let front = [al.fqdn]
  while (front.length) { const nx: string[] = []; for (const x of all) if (!seen.has(x.rec.id) && front.includes(x.target) && x.rec.view === al.rec.view) { seen.add(x.rec.id); out.push(x); nx.push(x.fqdn) } front = nx }
  return out
}

route('PUT', '/ipam/addresses/:id/aliases/:rid', 'operator', async (c) => {
  const m = await mine(c)
  const b = await c.body(z.object({ name: aliasName.optional(), target: z.string().trim().max(253).optional(), ttl: ttl.nullable().optional(), comment: z.string().max(500).nullable().optional(), disabled: z.boolean().optional() }))
  if (m.al.rec.protected && c.user!.role !== 'admin') fail(403, 'protected_record')
  const deps = dependents(m.al, m.aliases)
  let name = m.al.rec.name, rdata = m.al.rec.rdata, fq = m.al.fqdn, target = m.al.target
  if (b.name !== undefined) {
    const rel = toRelativeName(b.name, m.al.rec.zone); if (!rel) fail(400, 'name_invalid')
    if (rel !== m.al.rec.name) {
      if (deps.length) fail(409, 'alias_has_dependents', 'alias_has_dependents', { count: deps.length })     // renommer un alias qui en porte d'autres les orphelinerait
      const existing = await query<any>('select id, name, type from dns_records where zone_id = $1 and lower(name) = lower($2)', [m.al.rec.zoneId, rel])
      const ce = conflictError(existing, { name: rel, type: 'CNAME' }, m.rid); if (ce) fail(409, ce)
      name = rel; fq = fqdnOf(rel, m.al.rec.zone)
    }
  }
  if (b.target !== undefined) {
    const t = stripDot(b.target)
    const ok = m.hosts.some((h) => h.fqdn === t && h.view === m.al.rec.view) || m.aliases.some((x) => x.fqdn === t && x.rec.view === m.al.rec.view)
    if (!ok) fail(400, 'alias_target_unknown')
    target = t
  }
  const pb = aliasProblem(fq, target, m.al.rec.view, m.cnames, m.rid); if (pb) fail(409, pb)
  if (b.target !== undefined || name !== m.al.rec.name) { const rd = normalizeRdata('CNAME', target + '.'); if (!rd.ok) fail(400, 'name_invalid'); rdata = rd.value }
  await tx(async (cl) => {
    await cl.query('update dns_records set name=$2, rdata=$3, ttl = case when $4::boolean then $5::int else ttl end, comment = case when $6::boolean then $7 else comment end, disabled = coalesce($8, disabled), updated_at = now() where id = $1',
      [m.rid, name, rdata, b.ttl !== undefined, b.ttl ?? null, b.comment !== undefined, b.comment ?? null, b.disabled ?? null])
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [m.al.rec.zoneId])
  })
  await audit(c, 'alias_update', 'record', m.rid, { address: m.id, fqdn: fq, target })
  return { ok: true }
})

route('DELETE', '/ipam/addresses/:id/aliases/:rid', 'operator', async (c) => {
  const m = await mine(c)
  if (m.al.rec.protected && c.user!.role !== 'admin') fail(403, 'protected_record')
  const deps = dependents(m.al, m.aliases)
  if (deps.length && qstr(c, 'cascade') !== '1') fail(409, 'alias_has_dependents', 'alias_has_dependents', { count: deps.length })
  if (deps.some((d) => d.rec.protected) && c.user!.role !== 'admin') fail(403, 'protected_record')
  const all = [m.al, ...deps]
  await tx(async (cl) => {
    await cl.query('delete from dns_records where id = any($1::int[])', [all.map((x) => x.rec.id)])
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = any($1::int[])', [[...new Set(all.map((x) => x.rec.zoneId))]])
  })
  await audit(c, 'alias_delete', 'record', m.rid, { address: m.id, fqdn: m.al.fqdn, removed: all.length })
  return { ok: true, removed: all.length }
})
