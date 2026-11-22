import { z } from 'zod'
import { audit, fail, intParam, qint, route } from '../utils/router'
import { getSetting, one, query, setSetting, tx } from '../utils/db'
import { encryptSecret } from '../utils/auth'
import { isValidDnsName, normIp, normMac, parseCidr, parseIp, cidrContainsIp } from '../utils/net'
import { KEA_DEFAULTS } from '../utils/render'
import { cleanOptions, ip4, optionsS } from '../utils/dhcpopts'

async function scopeSubnet(id: number) {
  const r = await one<any>('select d.id, d.subnet_id, text(s.cidr) as cidr, family(s.cidr) as fam from dhcp_scopes d join subnets s on s.id = d.subnet_id where d.id = $1', [id])
  if (!r) fail(404, 'not_found')
  return { ...r, net: parseCidr(r.cidr)! }
}

import { assertNoDhcpOverlap } from '../utils/dhcp-space'
route('GET', '/dhcp/scopes', 'viewer', async () => ({ items: await query(`select d.id, d.subnet_id, text(s.cidr) as cidr, s.name as subnet_name, d.name, d.lease_time, d.enabled, d.options,
  (select count(*)::int from dhcp_pools p where p.scope_id = d.id) as pools, (select count(*)::int from dhcp_reservations r where r.scope_id = d.id) as reservations
  from dhcp_scopes d join subnets s on s.id = d.subnet_id order by s.cidr`) }))
route('GET', '/dhcp/scopes/:id', 'viewer', async (c) => {
  const id = intParam(c, 'id')
  const s = await one<any>('select d.id, d.subnet_id, text(s.cidr) as cidr, d.name, d.lease_time, d.enabled, d.options from dhcp_scopes d join subnets s on s.id = d.subnet_id where d.id = $1', [id])
  if (!s) fail(404, 'not_found')
  return { ...s, pools: await query('select id, host(start_ip) as start_ip, host(end_ip) as end_ip from dhcp_pools where scope_id = $1 order by start_ip', [id]),
    reservations: await query('select id, mac::text as mac, host(ip) as ip, hostname, description from dhcp_reservations where scope_id = $1 order by ip', [id]) }
})
const scopeBody = z.object({ subnet_id: z.number().int(), name: z.string().trim().max(100).nullable().optional(), lease_time: z.number().int().min(60).max(31536000).default(86400), enabled: z.boolean().default(true), options: optionsS.default({}) })
route('POST', '/dhcp/scopes', 'operator', async (c) => {
  const b = await c.body(scopeBody)
  const s = await one<any>('select family(cidr) as fam, space_id, kind from subnets where id = $1', [b.subnet_id])
  if (!s) fail(400, 'subnet_not_found')
  if (s.fam !== 4) fail(400, 'ipv4_only')
  if (s.kind === 'container') fail(400, 'container_no_addresses')
  if (b.enabled) await assertNoDhcpOverlap(b.subnet_id)   // Kea n'a qu'un espace d'adressage : pas de chevauchement entre espaces
  const r = await one<any>('insert into dhcp_scopes (subnet_id, name, lease_time, enabled, options) values ($1,$2,$3,$4,$5::jsonb) returning id', [b.subnet_id, b.name ?? null, b.lease_time, b.enabled, JSON.stringify(cleanOptions(b.options))])
  await audit(c, 'scope_create', 'dhcp_scope', r.id)
  return { id: r.id }
})
route('PUT', '/dhcp/scopes/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const b = await c.body(scopeBody.omit({ subnet_id: true }))
  const cur = await one<any>('select subnet_id from dhcp_scopes where id = $1', [id])
  if (cur && b.enabled) await assertNoDhcpOverlap(cur.subnet_id)
  const r = await one('update dhcp_scopes set name=$2, lease_time=$3, enabled=$4, options=$5::jsonb, updated_at=now() where id=$1 returning id', [id, b.name ?? null, b.lease_time, b.enabled, JSON.stringify(cleanOptions(b.options))])
  if (!r) fail(404, 'not_found')
  await audit(c, 'scope_update', 'dhcp_scope', id)
  return { ok: true }
})
route('DELETE', '/dhcp/scopes/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  await query('delete from dhcp_scopes where id = $1', [id])
  await audit(c, 'scope_delete', 'dhcp_scope', id)
  return { ok: true }
})

route('POST', '/dhcp/scopes/:id/pools', 'operator', async (c) => {
  const sid = intParam(c, 'id')
  const b = await c.body(z.object({ start: ip4, end: ip4 }))
  const sc = await scopeSubnet(sid)
  const a = parseIp(b.start)!, e = parseIp(b.end)!
  if (a.n > e.n) fail(400, 'pool_order')
  if (!cidrContainsIp(sc.net, a) || !cidrContainsIp(sc.net, e)) fail(400, 'pool_outside_subnet')
  const start = normIp(b.start)!, end = normIp(b.end)!
  const r = await tx(async (cl) => {
    await cl.query('select 1 from dhcp_scopes where id = $1 for update', [sid])
    const over = await cl.query('select 1 from dhcp_pools where scope_id = $1 and start_ip <= $3 and end_ip >= $2 limit 1', [sid, start, end])
    if (over.rowCount) fail(409, 'pool_overlap')
    return (await cl.query('insert into dhcp_pools (scope_id, start_ip, end_ip) values ($1,$2,$3) returning id', [sid, start, end])).rows[0].id as number
  })
  await audit(c, 'pool_create', 'dhcp_pool', r, { start, end })
  return { id: r }
})
route('DELETE', '/dhcp/pools/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  await query('delete from dhcp_pools where id = $1', [id])
  await audit(c, 'pool_delete', 'dhcp_pool', id)
  return { ok: true }
})

const hostLabel = z.string().trim().toLowerCase().regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/)
/** Crée la réservation et son reflet IPAM (adresse « réservée DHCP ») ; partagé par la saisie manuelle et le bouton « réserver » des baux. */
async function createReservation(sid: number, macIn: string, ipIn: string, hostname: string | null | undefined, description: string | null | undefined): Promise<{ id: number; mac: string; ip: string }> {
  const sc = await scopeSubnet(sid)
  if (!cidrContainsIp(sc.net, parseIp(ipIn)!)) fail(400, 'ip_outside_subnet')
  const mac = normMac(macIn)!, ip = normIp(ipIn)!
  const id = await tx(async (cl) => {
    const r = (await cl.query('insert into dhcp_reservations (scope_id, mac, ip, hostname, description) values ($1,$2,$3,$4,$5) returning id', [sid, mac, ip, hostname ?? null, description ?? null])).rows[0].id
    // reflet dans l'IPAM : l'adresse apparaît comme réservée DHCP
    const addr = (await cl.query(`insert into addresses (subnet_id, ip, status, hostname, mac) values ($1,$2,'dhcp',$3,$4)
      on conflict (subnet_id, ip) do update set status = 'dhcp', mac = excluded.mac, hostname = coalesce(excluded.hostname, addresses.hostname), updated_at = now() returning id`, [sc.subnet_id, ip, hostname ?? null, mac])).rows[0].id
    await cl.query('update dhcp_reservations set address_id = $2 where id = $1', [r, addr])
    return r as number
  })
  return { id, mac, ip }
}
route('POST', '/dhcp/scopes/:id/reservations', 'operator', async (c) => {
  const sid = intParam(c, 'id')
  const b = await c.body(z.object({ mac: z.string().trim().refine((v) => !!normMac(v), 'mac'), ip: ip4, hostname: hostLabel.nullable().optional(), description: z.string().max(200).nullable().optional() }))
  const r = await createReservation(sid, b.mac, b.ip, b.hostname, b.description)
  await audit(c, 'reservation_create', 'dhcp_reservation', r.id, { mac: r.mac, ip: r.ip })
  return { id: r.id }
})
route('DELETE', '/dhcp/reservations/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  await tx(async (cl) => {
    const r = (await cl.query('delete from dhcp_reservations where id = $1 returning address_id', [id])).rows[0]
    // l'adresse IPAM ne doit pas rester « réservation DHCP » sans réservation : elle redevient simplement utilisée
    if (r?.address_id) await cl.query("update addresses set status = 'used', updated_at = now() where id = $1 and status = 'dhcp'", [r.address_id])
  })
  await audit(c, 'reservation_delete', 'dhcp_reservation', id)
  return { ok: true }
})

// Baux actifs : lus dans la table lease4 de Kea (absente tant que le service DHCP n'est pas installé)
route('GET', '/dhcp/leases', 'viewer', async (c) => {
  const limit = qint(c, 'limit', 1000, 1, 5000)
  const t = await one<any>("select to_regclass('public.lease4') is not null as ok")
  if (!t?.ok) return { available: false, items: [] }
  try {
    const rows = await query<any>(`with l as (
        select ((address >> 24) & 255) || '.' || ((address >> 16) & 255) || '.' || ((address >> 8) & 255) || '.' || (address & 255) as ip,
          regexp_replace(encode(hwaddr, 'hex'), '(..)(?=.)', '\\1:', 'g') as mac, nullif(regexp_replace(trim(hostname), '\\.$', ''), '') as hostname, expire, subnet_id from lease4 where expire > now())
      select l.ip, l.mac, l.hostname, l.expire, l.subnet_id::int as scope_id, text(sn.cidr) as network,
        (select r.id from dhcp_reservations r where r.scope_id = l.subnet_id and (host(r.ip) = l.ip or (l.mac <> '' and r.mac::text = l.mac)) limit 1) as reservation_id
      from l left join dhcp_scopes d on d.id = l.subnet_id left join subnets sn on sn.id = d.subnet_id order by l.expire desc limit $1`, [limit])
    return { available: true, items: rows }
  } catch { return { available: false, items: [] } }
})

// « Réserver » depuis un bail : l'adresse et la MAC sont relues dans le bail (jamais fournies par le client)
route('POST', '/dhcp/leases/reserve', 'operator', async (c) => {
  const b = await c.body(z.object({ ip: ip4 }))
  const ipn = parseIp(b.ip)!
  const addr = Number(ipn.n)
  const t = await one<any>("select to_regclass('public.lease4') is not null as ok")
  if (!t?.ok) fail(404, 'not_found')
  const l = await one<any>("select regexp_replace(encode(hwaddr, 'hex'), '(..)(?=.)', '\\1:', 'g') as mac, hostname, subnet_id from lease4 where address = $1 and expire > now()", [addr])
  if (!l) fail(404, 'not_found')
  if (!l.mac) fail(400, 'lease_without_mac')
  if (!(await one('select 1 from dhcp_scopes where id = $1', [l.subnet_id]))) fail(409, 'no_scope')
  if (await one('select 1 from dhcp_reservations where scope_id = $1 and (ip = $2 or mac = $3::macaddr)', [l.subnet_id, normIp(b.ip), l.mac])) fail(409, 'reservation_exists')
  const label = hostLabel.safeParse(String(l.hostname ?? '').split('.')[0])
  const r = await createReservation(l.subnet_id, l.mac, b.ip, label.success ? label.data : null, null)
  await audit(c, 'reservation_create', 'dhcp_reservation', r.id, { mac: r.mac, ip: r.ip, from: 'lease' })
  return { id: r.id, ip: r.ip, mac: r.mac, hostname: label.success ? label.data : null }
})

const dhcpSettings = z.object({
  interfaces: z.array(z.string().regex(/^(\*|[A-Za-z0-9_.:-]{1,15})$/)).min(1).max(8), ddns: z.boolean(),
  lease: z.object({ type: z.enum(['memfile', 'postgresql']), name: z.string().min(1).max(200), user: z.string().max(60).optional(), host: z.string().max(253).optional(), password: z.string().max(200).optional() }),
  globalOptions: optionsS,
})
route('GET', '/dhcp/settings', 'viewer', async () => {
  const s = { ...KEA_DEFAULTS, ...(await getSetting<any>('dhcp', {})) }
  const { passwordEnc, password: _p, ...lease } = s.lease
  return { ...s, lease: { ...lease, passwordSet: !!passwordEnc } }
})
route('PUT', '/dhcp/settings', 'admin', async (c) => {
  const b = await c.body(dhcpSettings)
  const cur = { ...KEA_DEFAULTS, ...(await getSetting<any>('dhcp', {})) }
  const { password, ...lease } = b.lease
  const next = { ...cur, interfaces: b.interfaces, ddns: b.ddns, globalOptions: cleanOptions(b.globalOptions), lease: { ...lease, passwordEnc: password ? encryptSecret(password) : (cur.lease as any).passwordEnc } }
  await setSetting('dhcp', next)
  await audit(c, 'dhcp_settings', 'settings', 'dhcp', { passwordChanged: !!password })
  return { ok: true }
})

// Valeur exportée et lue par le point d'entrée : empêche l'élimination du module par l'optimiseur
export const registered = true
