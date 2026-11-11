import { z } from 'zod'
import { audit, fail, intParam, qint, qstr, route } from '../utils/router'
import { getSetting, one, query, setSetting, tx } from '../utils/db'
import { cidrToString, isValidDnsName, normIp, parseCidr } from '../utils/net'
import { RECORD_TYPES, conflictError, isAdCritical, isRecordType, normalizeRdata, renderZone, toRelativeName } from '../utils/dns'
import { readAdState } from '../utils/adkrb'
import { DNS_DEFAULTS } from '../utils/render'
import { MAX_VIEWS, VIEW_NAME_RE, normalizeAcl, shadowedViews, uncoveredLocal } from '../utils/views'
import type { ViewInfo } from '../utils/views'
import type { DnsSettings } from '../utils/render'

const zoneName = z.string().trim().toLowerCase().transform((v) => v.replace(/\.$/, '')).refine((v) => /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(v) && v.length <= 253, 'zone_name')
const ipS = z.string().trim().refine((v) => !!normIp(v), 'ip')
const aclS = z.string().trim().refine((v) => !!normIp(v) || !!parseCidr(v), 'acl')
const ttl = z.number().int().min(0).max(2147483647)

const zoneBody = z.object({
  name: zoneName, type: z.enum(['primary', 'secondary', 'forward']),
  masters: z.array(ipS).max(10).default([]), forwarders: z.array(ipS).max(10).default([]), allow_transfer: z.array(aclS).max(20).default([]),
  ddns_enabled: z.boolean().default(false), ddns_secure: z.enum(['none', 'ms-self', 'krb5-self', 'both']).nullable().default('none'), ad_integrated: z.boolean().default(false), disabled: z.boolean().default(false),
  soa_mname: z.string().max(253).nullable().optional(), soa_rname: z.string().max(253).nullable().optional(),
  soa_refresh: ttl.default(3600), soa_retry: ttl.default(600), soa_expire: ttl.default(1209600), soa_minimum: ttl.default(3600), default_ttl: ttl.default(3600),
  comment: z.string().max(500).nullable().optional(),
  view_id: z.number().int().positive().nullable().optional(),
})
const norm = (z_: z.infer<typeof zoneBody>) => ({
  ...z_, ddns_secure: z_.ddns_secure === 'none' ? null : z_.ddns_secure, masters: z_.masters.map((x) => normIp(x)!), forwarders: z_.forwarders.map((x) => normIp(x)!),
  allow_transfer: z_.allow_transfer.map((x) => (parseCidr(x) ? cidrToString(parseCidr(x)!) : normIp(x)!)),
})
async function viewRule(viewId: number | null | undefined) {
  const n = (await one<any>('select count(*)::int n from dns_views'))!.n
  if (n > 0 && !viewId) fail(400, 'view_required')
  if (n === 0 && viewId) fail(400, 'view_not_found')
  if (viewId && !(await one('select 1 from dns_views where id = $1', [viewId]))) fail(400, 'view_not_found')
}
async function typeRules(b: z.infer<typeof zoneBody>) {
  await viewRule(b.view_id)
  if (b.type === 'secondary' && !b.masters.length) fail(400, 'masters_required')
  if (b.type === 'forward' && !b.forwarders.length) fail(400, 'forwarders_required')
  if (b.ddns_secure) {
    if (b.type !== 'primary') fail(400, 'secure_update_primary_only')
    const realm = (await readAdState())?.realm
    if (!realm) fail(409, 'kerberos_not_configured')   // sans domaine configuré par root, la politique ne serait jamais appliquée
    // BIND associe le compte machine « PC1$@CORP.LOCAL » au nom « pc1.corp.local » : ms-self n'a d'effet que dans la zone portant le nom du domaine
    if ((b.ddns_secure === 'ms-self' || b.ddns_secure === 'both') && b.name !== realm.toLowerCase()) fail(400, 'ms_self_zone_mismatch')
  }
}

const ZONE_SQL = `select z.id, z.name, z.type, z.masters, z.forwarders, z.allow_transfer, z.ddns_enabled, coalesce(z.ddns_secure, 'none') as ddns_secure, z.ad_integrated, z.disabled, z.soa_mname, z.soa_rname,
  z.soa_refresh, z.soa_retry, z.soa_expire, z.soa_minimum, z.default_ttl, z.serial::text as serial, z.dirty, z.comment, z.updated_at, z.view_id, v.name as view,
  (select count(*)::int from dns_records r where r.zone_id = z.id) as records from dns_zones z left join dns_views v on v.id = z.view_id`

route('GET', '/dns/types', 'viewer', async () => ({ items: RECORD_TYPES }))
route('GET', '/dns/zones', 'viewer', async () => ({ items: await query(`${ZONE_SQL} order by z.name, v.position`) }))
route('GET', '/dns/zones/:id', 'viewer', async (c) => {
  const z = await one(`${ZONE_SQL} where z.id = $1`, [intParam(c, 'id')])
  if (!z) fail(404, 'not_found')
  return z
})
route('POST', '/dns/zones', 'operator', async (c) => {
  const b = norm(await c.body(zoneBody)); await typeRules(zoneBody.parse(b))
  const r = await one<any>(`insert into dns_zones (name, type, masters, forwarders, allow_transfer, ddns_enabled, ddns_secure, ad_integrated, disabled, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_minimum, default_ttl, comment, view_id)
    values ($1,$2,$3,$4,$5,$6,$17,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$18) returning id`,
    [b.name, b.type, b.masters, b.forwarders, b.allow_transfer, b.ddns_enabled, b.ad_integrated, b.disabled, b.soa_mname ?? null, b.soa_rname ?? null, b.soa_refresh, b.soa_retry, b.soa_expire, b.soa_minimum, b.default_ttl, b.comment ?? null, b.ddns_secure, b.view_id ?? null])
  await audit(c, 'zone_create', 'zone', r.id, { name: b.name, type: b.type })
  return { id: r.id }
})
route('PUT', '/dns/zones/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const b = norm(await c.body(zoneBody))
  // sans « view_id » (client plus ancien, ou simple modification), la zone reste dans sa vue
  if (b.view_id === undefined) b.view_id = (await one<any>('select view_id from dns_zones where id = $1', [id]))?.view_id ?? undefined
  await typeRules(zoneBody.parse(b))
  const r = await one(`update dns_zones set name=$2, type=$3, masters=$4, forwarders=$5, allow_transfer=$6, ddns_enabled=$7, ad_integrated=$8, ddns_secure=$18, disabled=$9, soa_mname=$10, soa_rname=$11,
    soa_refresh=$12, soa_retry=$13, soa_expire=$14, soa_minimum=$15, default_ttl=$16, comment=$17, view_id=case when $20::boolean then $19 else view_id end, dirty=true, updated_at=now() where id=$1 returning id`,
    [id, b.name, b.type, b.masters, b.forwarders, b.allow_transfer, b.ddns_enabled, b.ad_integrated, b.disabled, b.soa_mname ?? null, b.soa_rname ?? null, b.soa_refresh, b.soa_retry, b.soa_expire, b.soa_minimum, b.default_ttl, b.comment ?? null, b.ddns_secure, b.view_id ?? null, true])
  if (!r) fail(404, 'not_found')
  await audit(c, 'zone_update', 'zone', id)
  return { ok: true }
})
route('DELETE', '/dns/zones/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const n = await one<any>('select count(*)::int n from dns_records where zone_id = $1', [id])
  if (n.n > 0 && qstr(c, 'force') !== '1') fail(409, 'zone_not_empty', 'zone_not_empty', { records: n.n })
  const prot = await one<any>('select count(*)::int n from dns_records where zone_id = $1 and protected', [id])
  if (prot.n > 0 && c.user!.role !== 'admin') fail(403, 'protected_record')
  await query('delete from dns_zones where id = $1', [id])
  await audit(c, 'zone_delete', 'zone', id)
  return { ok: true }
})
route('GET', '/dns/zones/:id/export', 'viewer', async (c) => {
  const z = await one<any>(`${ZONE_SQL} where z.id = $1`, [intParam(c, 'id')])
  if (!z) fail(404, 'not_found')
  const recs = await query('select name, type, ttl, rdata, disabled from dns_records where zone_id = $1', [z.id])
  return { name: z.name, content: renderZone({ ...z, serial: z.serial }, recs) }
})

// ---- Enregistrements ----
const recBody = z.object({
  zone_id: z.number().int(), name: z.string().trim().min(1).max(253), type: z.string().trim().toUpperCase(),
  ttl: ttl.nullable().optional(), rdata: z.string().min(1).max(65000), comment: z.string().max(500).nullable().optional(), disabled: z.boolean().optional(),
})

route('GET', '/dns/records', 'viewer', async (c) => {
  const zone = qint(c, 'zone_id', 0), type = qstr(c, 'type', 10), q = qstr(c, 'q', 100)
  const limit = qint(c, 'limit', 200, 1, 1000), offset = qint(c, 'offset', 0)
  const where = ['($1::int = 0 or r.zone_id = $1)', '($2::text is null or r.type = $2)', "($3::text is null or r.name ilike $3 or r.rdata ilike $3 or coalesce(r.comment,'') ilike $3)"]
  const args = [zone, type ? type.toUpperCase() : null, q ? `%${q}%` : null]
  const total = await one<any>(`select count(*)::int n from dns_records r where ${where.join(' and ')}`, args)
  const items = await query(`select r.id, r.zone_id, z.name as zone, v.name as view, r.name, r.type, r.ttl, r.rdata, r.comment, r.protected, r.disabled from dns_records r join dns_zones z on z.id = r.zone_id left join dns_views v on v.id = z.view_id
    where ${where.join(' and ')} order by z.name, v.position, r.name, r.type limit $4 offset $5`, [...args, limit, offset])
  return { items, total: total.n }
})

async function validateRecord(zoneId: number, b: z.infer<typeof recBody>, selfId?: number) {
  const zone = await one<any>('select id, name, type from dns_zones where id = $1', [zoneId])
  if (!zone) fail(400, 'zone_not_found')
  if (zone.type !== 'primary') fail(400, 'zone_not_primary')
  if (!isRecordType(b.type)) fail(400, 'type_unsupported')
  const name = toRelativeName(b.name, zone.name)
  if (!name) fail(400, 'name_invalid')
  const rd = normalizeRdata(b.type, b.rdata)
  if (!rd.ok) fail(400, rd.error.split(':')[0]!, rd.error, { type: b.type })
  const existing = await query<any>('select id, name, type from dns_records where zone_id = $1 and lower(name) = lower($2)', [zoneId, name])
  const ce = conflictError(existing, { name, type: b.type }, selfId)
  if (ce) fail(409, ce)
  return { name, type: b.type, rdata: rd.value, protectedFlag: isAdCritical(name, b.type) }
}

route('POST', '/dns/records', 'operator', async (c) => {
  const b = await c.body(recBody)
  const v = await validateRecord(b.zone_id, b)
  const id = await tx(async (cl) => {
    const r = (await cl.query('insert into dns_records (zone_id, name, type, ttl, rdata, comment, protected, disabled) values ($1,$2,$3,$4,$5,$6,$7,$8) returning id',
      [b.zone_id, v.name, v.type, b.ttl ?? null, v.rdata, b.comment ?? null, v.protectedFlag, b.disabled ?? false])).rows[0].id
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [b.zone_id])
    return r as number
  })
  await audit(c, 'record_create', 'record', id, { zone_id: b.zone_id, name: v.name, type: v.type })
  return { id, name: v.name, rdata: v.rdata }
})
route('PUT', '/dns/records/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const b = await c.body(recBody)
  const cur = await one<any>('select zone_id, protected from dns_records where id = $1', [id])
  if (!cur) fail(404, 'not_found')
  if (cur.protected && c.user!.role !== 'admin') fail(403, 'protected_record')
  if (cur.zone_id !== b.zone_id) fail(400, 'zone_immutable')
  const v = await validateRecord(b.zone_id, b, id)
  await tx(async (cl) => {
    await cl.query('update dns_records set name=$2, type=$3, ttl=$4, rdata=$5, comment=$6, protected=$7, disabled=$8, updated_at=now() where id=$1',
      [id, v.name, v.type, b.ttl ?? null, v.rdata, b.comment ?? null, cur.protected || v.protectedFlag, b.disabled ?? false])
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [b.zone_id])
  })
  await audit(c, 'record_update', 'record', id, { name: v.name, type: v.type })
  return { ok: true }
})
route('DELETE', '/dns/records/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const cur = await one<any>('select zone_id, protected from dns_records where id = $1', [id])
  if (!cur) fail(404, 'not_found')
  if (cur.protected && c.user!.role !== 'admin') fail(403, 'protected_record')
  await tx(async (cl) => {
    await cl.query('delete from dns_records where id = $1', [id])
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [cur.zone_id])
  })
  await audit(c, 'record_delete', 'record', id)
  return { ok: true }
})

// ---- Vues DNS : chaque vue répond selon le client (ou l'adresse du serveur interrogé) ; dès qu'une vue existe, toute zone appartient à une vue ----
const viewBody = z.object({
  name: z.string().trim().toLowerCase().refine((v) => VIEW_NAME_RE.test(v), 'view_name'),
  match_clients: z.array(z.string().max(64)).min(1).max(50), match_destinations: z.array(z.string().max(64)).max(50).default([]),
  recursion: z.boolean().default(true), comment: z.string().max(500).nullable().optional(),
})
const VIEW_SQL = `select v.id, v.name, v.position, v.match_clients, v.match_destinations, v.recursion, v.comment, v.updated_at, (select count(*)::int from dns_zones z where z.view_id = v.id) as zones from dns_views v`
function viewAcls(b: z.infer<typeof viewBody>) {
  const mc = normalizeAcl(b.match_clients), md = normalizeAcl(b.match_destinations)
  if (!mc) fail(400, 'view_acl'); if (!md) fail(400, 'view_acl')
  return { mc: mc!, md: md! }
}
async function viewDiagnostics() {
  const rows = await query<ViewInfo>('select id, name, position, match_clients, match_destinations, recursion from dns_views order by position, id')
  return { uncovered: rows.length ? uncoveredLocal(rows) : [], shadowed: shadowedViews(rows) }
}
route('GET', '/dns/views', 'viewer', async () => ({ items: await query(`${VIEW_SQL} order by v.position, v.id`), ...(await viewDiagnostics()), max: MAX_VIEWS }))
route('POST', '/dns/views', 'admin', async (c) => {
  const b = await c.body(viewBody.extend({ adopt_zones: z.boolean().default(false) }))
  const { mc, md } = viewAcls(b)
  const id = await tx(async (cl) => {
    const n = (await cl.query('select count(*)::int n from dns_views')).rows[0].n as number
    if (n >= MAX_VIEWS) fail(409, 'too_many_views')
    const loose = (await cl.query('select count(*)::int n from dns_zones where view_id is null')).rows[0].n as number
    // la première vue reprend les zones existantes (BIND n'admet pas de zone hors vue) : c'est explicite, jamais implicite
    if (n === 0 && loose > 0 && !b.adopt_zones) fail(409, 'zones_need_view', 'zones_need_view', { zones: loose })
    const r = (await cl.query('insert into dns_views (name, position, match_clients, match_destinations, recursion, comment) values ($1, (select coalesce(max(position), 0) + 1 from dns_views), $2, $3, $4, $5) returning id',
      [b.name, mc, md, b.recursion, b.comment ?? null])).rows[0].id as number
    if (n === 0 && loose > 0) await cl.query('update dns_zones set view_id = $1, dirty = true, updated_at = now() where view_id is null', [r])
    return r
  })
  await audit(c, 'view_create', 'view', id, { name: b.name })
  return { id }
})
route('PUT', '/dns/views/:id', 'admin', async (c) => {
  const id = intParam(c, 'id'), b = await c.body(viewBody)
  const { mc, md } = viewAcls(b)
  const r = await one('update dns_views set name=$2, match_clients=$3, match_destinations=$4, recursion=$5, comment=$6, updated_at=now() where id=$1 returning id', [id, b.name, mc, md, b.recursion, b.comment ?? null])
  if (!r) fail(404, 'not_found')
  // le nom fait partie du nom des fichiers de zone et de la clé de transfert : les zones de la vue sont à régénérer
  await query('update dns_zones set dirty = true where view_id = $1', [id])
  await audit(c, 'view_update', 'view', id, { name: b.name })
  return { ok: true }
})
route('POST', '/dns/views/order', 'admin', async (c) => {
  const b = await c.body(z.object({ ids: z.array(z.number().int().positive()).min(1).max(MAX_VIEWS) }))
  await tx(async (cl) => {
    const have = (await cl.query('select id from dns_views order by id')).rows.map((x: any) => x.id as number).sort((a: number, b2: number) => a - b2)
    if (JSON.stringify([...b.ids].sort((a, b2) => a - b2)) !== JSON.stringify(have)) fail(400, 'view_order')
    for (let i = 0; i < b.ids.length; i++) await cl.query('update dns_views set position = $2 where id = $1', [b.ids[i], i + 1])
  })
  await audit(c, 'view_order', 'view', 'order')
  return { ok: true }
})
route('DELETE', '/dns/views/:id', 'admin', async (c) => {
  const id = intParam(c, 'id')
  await tx(async (cl) => {
    const v = (await cl.query('select id from dns_views where id = $1 for update', [id])).rows[0]
    if (!v) fail(404, 'not_found')
    const zones = (await cl.query('select count(*)::int n from dns_zones where view_id = $1', [id])).rows[0].n as number
    const others = (await cl.query('select count(*)::int n from dns_views where id <> $1', [id])).rows[0].n as number
    // dernière vue : ses zones redeviennent des zones ordinaires (confirmation explicite) ; sinon la vue doit d'abord être vidée
    if (zones > 0 && others > 0) fail(409, 'view_not_empty', 'view_not_empty', { zones })
    if (zones > 0 && qstr(c, 'force') !== '1') fail(409, 'view_last_with_zones', 'view_last_with_zones', { zones })
    if (zones > 0) await cl.query('update dns_zones set view_id = null, dirty = true, updated_at = now() where view_id = $1', [id])
    await cl.query('delete from dns_views where id = $1', [id])
  })
  await audit(c, 'view_delete', 'view', id)
  return { ok: true }
})
// Copie d'une zone (avec ses enregistrements) dans une autre vue : point de départ habituel d'une vue « externe » à partir de la vue interne.
route('POST', '/dns/zones/:id/copy', 'operator', async (c) => {
  const id = intParam(c, 'id'), b = await c.body(z.object({ view_id: z.number().int().positive() }))
  const out = await tx(async (cl) => {
    const zr = (await cl.query('select * from dns_zones where id = $1', [id])).rows[0]
    if (!zr) fail(404, 'not_found')
    if (!(await cl.query('select 1 from dns_views where id = $1', [b.view_id])).rows[0]) fail(400, 'view_not_found')
    if (zr.view_id === b.view_id) fail(409, 'zone_exists')
    if ((await cl.query('select 1 from dns_zones where lower(name) = lower($1) and view_id = $2', [zr.name, b.view_id])).rows[0]) fail(409, 'zone_exists')
    const n = (await cl.query(`insert into dns_zones (name, type, masters, forwarders, allow_transfer, ddns_enabled, ddns_secure, ad_integrated, disabled, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_minimum, default_ttl, comment, view_id, serial, dirty)
      select name, type, masters, forwarders, allow_transfer, ddns_enabled, ddns_secure, ad_integrated, disabled, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_minimum, default_ttl, comment, $2, 1, true from dns_zones where id = $1 returning id`, [id, b.view_id])).rows[0].id as number
    const recs = await cl.query('insert into dns_records (zone_id, name, type, ttl, rdata, comment, protected, disabled) select $2, name, type, ttl, rdata, comment, protected, disabled from dns_records where zone_id = $1', [id, n])
    return { id: n, records: recs.rowCount ?? 0 }
  })
  await audit(c, 'zone_copy', 'zone', out.id, { from: id, view_id: b.view_id })
  return out
})

// ---- Paramètres globaux du serveur DNS ----
const settingsBody = z.object({
  listenOn: z.array(ipS).max(20), allowRecursion: z.array(aclS).max(50), allowQuery: z.array(aclS).max(50), forwarders: z.array(ipS).max(10),
  dnssecValidation: z.enum(['auto', 'no']), queryLog: z.boolean(),
  rpzEnabled: z.boolean(), rpzZone: zoneName, rpzAction: z.enum(['nxdomain', 'nodata', 'sinkhole']), sinkhole4: ipS, sinkhole6: ipS,
  // RRL : facultatif (un client plus ancien n'envoie pas ces champs) ; bornes prudentes
  rrlEnabled: z.boolean().optional(), rrlResponsesPerSecond: z.number().int().min(1).max(1000).optional(), rrlWindow: z.number().int().min(5).max(3600).optional(),
  rrlSlip: z.number().int().min(0).max(10).optional(), rrlLogOnly: z.boolean().optional(), rrlExempt: z.array(aclS).max(50).optional(),
})
export async function loadDnsSettings(): Promise<DnsSettings> { return { ...DNS_DEFAULTS, ...(await getSetting<Partial<DnsSettings>>('dns', {})) } }
route('GET', '/dns/settings', 'viewer', async () => await loadDnsSettings())
route('PUT', '/dns/settings', 'admin', async (c) => {
  const b = await c.body(settingsBody)
  const cur = await loadDnsSettings()
  const next = { ...cur, ...b, listenOn: b.listenOn.map((x) => normIp(x)!), forwarders: b.forwarders.map((x) => normIp(x)!), sinkhole4: normIp(b.sinkhole4)!, sinkhole6: normIp(b.sinkhole6)! }
  if (!isValidDnsName(next.rpzZone, false)) fail(400, 'zone_name')
  await setSetting('dns', next)
  await audit(c, 'dns_settings', 'settings', 'dns')
  return next
})

// Valeur exportée et lue par le point d'entrée : empêche l'élimination du module par l'optimiseur
export const registered = true
