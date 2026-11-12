import { z } from 'zod'
import { audit, fail, intParam, route } from '../utils/router'
import { getSetting, one, query, setSetting, tx } from '../utils/db'
import { decryptSecret, encryptSecret } from '../utils/auth'
import { AD_DEFAULTS, csvObjects, defaultLdapFactory, escapeFilter, parseAdSubnets, parseDhcpExport } from '../utils/ad'
import type { AdSettings } from '../utils/ad'
import { conflictError, isAdCritical, parseZoneFile } from '../utils/dns'
import { cidrContainsIp, cidrToString, isHostname, normIp, normMac, parseCidr, parseIp } from '../utils/net'
import type { PoolClient } from 'pg'
import { captureSnapshot } from '../utils/snapshots'

const content = z.object({ content: z.string().min(1).max(25_000_000), filename: z.string().max(200).optional() })
export const record = async (c: any, kind: string, filename: string | undefined, summary: unknown, snapshotId?: number | null) =>
  query('insert into import_runs (kind, filename, summary, username, snapshot_id) values ($1,$2,$3::jsonb,$4,$5)', [kind, filename ?? null, JSON.stringify(summary), c.user?.username ?? null, snapshotId ?? null])
/** Point de restauration pris AVANT toute écriture d'un import : « Annuler cet import » repose dessus. */
export const preImportSnapshot = (c: any, label: string) => captureSnapshot('pre-import', label, c.user?.username ?? null)

// ---------------------------------------------------------------------------------------------
// Zone DNS (fichier de zone BIND ou export Windows « dnscmd /ZoneExport »)
const dnsBody = content.extend({ zone_id: z.number().int(), mode: z.enum(['skip', 'replace']).default('skip'), apply_soa: z.boolean().default(false) })
async function dnsPlan(zoneId: number, text: string) {
  const zone = await one<any>("select id, name, type from dns_zones where id = $1", [zoneId])
  if (!zone) fail(404, 'not_found')
  if (zone.type !== 'primary') fail(400, 'zone_not_primary')
  const parsed = parseZoneFile(text, zone.name)
  const existing = await query<any>('select id, name, type, rdata from dns_records where zone_id = $1', [zoneId])
  const have = new Set(existing.map((r) => `${r.name}|${r.type}|${r.rdata}`))
  const byType: Record<string, number> = {}
  let fresh = 0, identical = 0, conflicts = 0, critical = 0
  const planned: typeof existing = [...existing]
  const toInsert: typeof parsed.records = []
  for (const r of parsed.records) {
    byType[r.type] = (byType[r.type] ?? 0) + 1
    if (isAdCritical(r.name, r.type)) critical++
    if (have.has(`${r.name}|${r.type}|${r.rdata}`)) { identical++; continue }
    if (conflictError(planned, r)) { conflicts++; continue }
    fresh++; toInsert.push(r); planned.push({ id: -1, name: r.name, type: r.type, rdata: r.rdata })
  }
  return { zone, parsed, toInsert, summary: { zone: zone.name, total: parsed.records.length, new: fresh, identical, conflicts, adCritical: critical, skipped: parsed.skipped, byType, soa: parsed.soa, warnings: parsed.warnings.slice(0, 100) } }
}
route('POST', '/import/dns/preview', 'operator', async (c) => {
  const b = await c.body(dnsBody)
  return (await dnsPlan(b.zone_id, b.content)).summary
})
route('POST', '/import/dns/commit', 'operator', async (c) => {
  const b = await c.body(dnsBody)
  if (b.mode === 'replace' && c.user!.role !== 'admin') fail(403, 'forbidden')
  return dnsCommitCore(c, b)
})
export async function dnsCommitCore(c: any, b: z.infer<typeof dnsBody>, existingSnapshot?: number) {
  const snapshotId = existingSnapshot ?? await preImportSnapshot(c, `avant import DNS (${b.filename ?? 'zone'})`)
  const { parsed, summary } = await dnsPlan(b.zone_id, b.content)
  let inserted = 0
  await tx(async (cl: PoolClient) => {
    if (b.mode === 'replace') await cl.query('delete from dns_records where zone_id = $1', [b.zone_id])
    const names = (await cl.query('select id, name, type from dns_records where zone_id = $1', [b.zone_id])).rows
    for (const r of parsed.records) {
      if (conflictError(names, r)) continue
      const res = await cl.query('insert into dns_records (zone_id, name, type, ttl, rdata, protected) values ($1,$2,$3,$4,$5,$6) on conflict do nothing returning id', [b.zone_id, r.name, r.type, r.ttl, r.rdata, isAdCritical(r.name, r.type)])
      if (res.rowCount) { inserted++; names.push({ id: res.rows[0].id, name: r.name, type: r.type }) }
    }
    const crit = parsed.records.some((r) => isAdCritical(r.name, r.type))
    await cl.query('update dns_zones set dirty = true, updated_at = now(), ad_integrated = ad_integrated or $2 where id = $1', [b.zone_id, crit])
    if (b.apply_soa && parsed.soa) await cl.query('update dns_zones set soa_mname=$2, soa_rname=$3, soa_refresh=$4, soa_retry=$5, soa_expire=$6, soa_minimum=$7 where id=$1', [b.zone_id, parsed.soa.mname, parsed.soa.rname, parsed.soa.refresh, parsed.soa.retry, parsed.soa.expire, parsed.soa.minimum])
  })
  const out = { ...summary, inserted, snapshotId }
  await record(c, 'dns', b.filename, out, snapshotId)
  await audit(c, 'import_dns', 'zone', b.zone_id, { inserted, mode: b.mode, snapshotId })
  return out
}

// ---------------------------------------------------------------------------------------------
// DHCP Windows (Export-DhcpServer -File dhcp.xml)
async function dhcpCommit(cl: PoolClient, text: string) {
  const plan = parseDhcpExport(text)
  const out = { scopes: 0, scopesSkipped: 0, subnetsCreated: 0, pools: 0, reservations: 0, reservationsSkipped: 0 }
  for (const sc of plan.scopes) {
    const net = parseCidr(sc.cidr)!
    let sub = (await cl.query('select id from subnets where space_id = 1 and cidr = $1', [sc.cidr])).rows[0]
    if (!sub) { sub = (await cl.query('insert into subnets (cidr, name) values ($1,$2) returning id', [sc.cidr, sc.name])).rows[0]; out.subnetsCreated++ }
    const have = (await cl.query('select 1 from dhcp_scopes where subnet_id = $1', [sub.id])).rowCount
    if (have) { out.scopesSkipped++; continue }
    const scope = (await cl.query('insert into dhcp_scopes (subnet_id, name, lease_time, enabled, options) values ($1,$2,$3,$4,$5::jsonb) returning id', [sub.id, sc.name, Math.min(Math.max(sc.leaseTime, 60), 31536000), sc.enabled, JSON.stringify(sc.options)])).rows[0]
    out.scopes++
    for (const p of sc.pools) {
      if (!cidrContainsIp(net, parseIp(p.start)!) || !cidrContainsIp(net, parseIp(p.end)!)) continue
      await cl.query('insert into dhcp_pools (scope_id, start_ip, end_ip) values ($1,$2,$3) on conflict do nothing', [scope.id, p.start, p.end]); out.pools++
    }
    for (const r of sc.reservations) {
      if (!cidrContainsIp(net, parseIp(r.ip)!)) { out.reservationsSkipped++; continue }
      const ins = await cl.query('insert into dhcp_reservations (scope_id, mac, ip, hostname, description) values ($1,$2,$3,$4,$5) on conflict do nothing returning id', [scope.id, r.mac, r.ip, r.hostname && isHostname(r.hostname) ? r.hostname : null, r.description])
      if (!ins.rowCount) { out.reservationsSkipped++; continue }
      out.reservations++
      await cl.query("insert into addresses (subnet_id, ip, status, hostname, mac) values ($1,$2,'dhcp',$3,$4) on conflict (subnet_id, ip) do update set status = 'dhcp', mac = excluded.mac", [sub.id, r.ip, r.hostname && isHostname(r.hostname) ? r.hostname : null, r.mac])
    }
  }
  return { ...out, warnings: plan.warnings.slice(0, 100) }
}
route('POST', '/import/dhcp/preview', 'operator', async (c) => {
  const b = await c.body(content)
  const plan = parseDhcpExport(b.content)
  const exist = new Set((await query<any>('select text(cidr) as c from subnets where space_id = 1')).map((r) => r.c))
  return {
    scopes: plan.scopes.map((s) => ({ cidr: s.cidr, name: s.name, leaseTime: s.leaseTime, enabled: s.enabled, pools: s.pools.length, reservations: s.reservations.length, exclusions: s.exclusions.length, subnetExists: exist.has(s.cidr) })),
    totals: { scopes: plan.scopes.length, pools: plan.scopes.reduce((n, s) => n + s.pools.length, 0), reservations: plan.scopes.reduce((n, s) => n + s.reservations.length, 0) },
    warnings: plan.warnings.slice(0, 100),
  }
})
route('POST', '/import/dhcp/commit', 'operator', async (c) => {
  const b = await c.body(content)
  const snapshotId = await preImportSnapshot(c, `avant import DHCP (${b.filename ?? 'export'})`)
  const out = { ...(await tx((cl) => dhcpCommit(cl, b.content))), snapshotId }
  await record(c, 'dhcp', b.filename, out, snapshotId)
  await audit(c, 'import_dhcp', 'dhcp_scope', undefined, out)
  return out
})

// ---------------------------------------------------------------------------------------------
// Sites et sous-réseaux AD, et CSV IPAM
route('POST', '/import/ad-subnets/preview', 'operator', async (c) => {
  const b = await c.body(content)
  const { rows, errors } = parseAdSubnets(b.content)
  const exist = new Set((await query<any>('select text(cidr) as c from subnets where space_id = 1')).map((r) => r.c))
  return { total: rows.length, new: rows.filter((r) => !exist.has(r.cidr)).length, existing: rows.filter((r) => exist.has(r.cidr)).length, errors: errors.slice(0, 100), sample: rows.slice(0, 20) }
})
route('POST', '/import/ad-subnets/commit', 'operator', async (c) => {
  const b = await c.body(content)
  const { rows, errors } = parseAdSubnets(b.content)
  const snapshotId = await preImportSnapshot(c, `avant import des sous-réseaux AD (${b.filename ?? 'export'})`)
  let created = 0, updated = 0
  await tx(async (cl) => {
    for (const r of rows) {
      const res = await cl.query('insert into subnets (cidr, name, site, description) values ($1,$2,$3,$4) on conflict (space_id, cidr) do nothing returning id', [r.cidr, r.site ? `${r.site} — ${r.cidr}` : r.cidr, r.site || null, r.description || null])
      if (res.rowCount) created++
      else if (r.site) { const u = await cl.query("update subnets set site = $2 where cidr = $1 and (site is null or site = '')", [r.cidr, r.site]); updated += u.rowCount ?? 0 }
    }
  })
  const out = { created, updated, errors: errors.slice(0, 100), snapshotId }
  await record(c, 'ad-subnets', b.filename, out, snapshotId)
  await audit(c, 'import_ad_subnets', 'subnet', undefined, { created, updated })
  return out
})

const csvBody = content.extend({ kind: z.enum(['subnets', 'addresses']) })
route('POST', '/import/ipam-csv/commit', 'operator', async (c) => {
  const b = await c.body(csvBody)
  const rows = csvObjects(b.content)
  const snapshotId = await preImportSnapshot(c, `avant import CSV IPAM (${b.kind})`)
  const out = { created: 0, skipped: 0, errors: [] as Array<{ line: number; code: string }>, snapshotId }
  await tx(async (cl) => {
    for (const [i, r] of rows.entries()) {
      const line = i + 2
      try {
        if (b.kind === 'subnets') {
          const cidr = parseCidr(r.cidr ?? '')
          if (!cidr) { out.errors.push({ line, code: 'cidr' }); continue }
          const gw = r.gateway ? normIp(r.gateway) : null
          const res = await cl.query('insert into subnets (cidr, name, description, site, gateway) values ($1,$2,$3,$4,$5) on conflict (space_id, cidr) do nothing returning id', [cidrToString(cidr), r.name || cidrToString(cidr), r.description || null, r.site || null, gw])
          if (res.rowCount) out.created++; else out.skipped++
        } else {
          const ip = normIp(r.ip ?? '')
          if (!ip) { out.errors.push({ line, code: 'ip' }); continue }
          const sub = (await cl.query('select id from subnets where space_id = 1 and cidr >>= $1::inet order by masklen(cidr) desc limit 1', [ip])).rows[0]
          if (!sub) { out.errors.push({ line, code: 'no_subnet' }); continue }
          const mac = r.mac ? normMac(r.mac) : null
          if (r.mac && !mac) { out.errors.push({ line, code: 'mac' }); continue }
          const st = ['used', 'reserved', 'dhcp', 'gateway', 'infra', 'ghost'].includes(r.status ?? '') ? r.status : 'used'
          const host = r.hostname && isHostname(r.hostname.toLowerCase()) ? r.hostname.toLowerCase() : null
          const res = await cl.query('insert into addresses (subnet_id, ip, status, hostname, mac, description) values ($1,$2,$3,$4,$5,$6) on conflict (subnet_id, ip) do nothing returning id', [sub.id, ip, st, host, mac, r.description || null])
          if (res.rowCount) out.created++; else out.skipped++
        }
      } catch { out.errors.push({ line, code: 'row' }) }
    }
  })
  out.errors = out.errors.slice(0, 100)
  await record(c, `csv-${b.kind}`, b.filename, out, snapshotId)
  await audit(c, 'import_csv', b.kind, undefined, { created: out.created })
  return out
})

route('GET', '/import/runs', 'operator', async () => ({ items: await query('select id, kind, filename, summary, username, created_at, snapshot_id from import_runs order by id desc limit 50') }))

// ---------------------------------------------------------------------------------------------
// Connexion Active Directory (LDAPS) : paramètres, test, jamais de mot de passe renvoyé
const adBody = z.object({
  enabled: z.boolean(), urls: z.array(z.string().regex(/^ldaps:\/\/[A-Za-z0-9._-]+(:\d{1,5})?$/, 'ldaps')).max(5), baseDn: z.string().max(500), bindDn: z.string().max(500),
  bindPassword: z.string().max(200).optional(), userAttr: z.enum(['sAMAccountName', 'userPrincipalName']),
  groupMap: z.array(z.object({ groupDn: z.string().min(3).max(500), role: z.enum(['admin', 'operator', 'viewer']) })).max(20),
  nestedGroups: z.boolean(), tlsRejectUnauthorized: z.boolean(), caPem: z.string().max(20000).regex(/^(|-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----\s*)$/).optional(),
})
route('GET', '/ad/settings', 'admin', async () => {
  const { bindPasswordEnc, ...s } = await getSetting<AdSettings>('ad', AD_DEFAULTS)
  return { ...s, bindPasswordSet: !!bindPasswordEnc }
})
route('PUT', '/ad/settings', 'admin', async (c) => {
  const b = await c.body(adBody)
  if (b.enabled && (!b.urls.length || !b.baseDn || !b.bindDn)) fail(400, 'ad_incomplete')
  const cur = await getSetting<AdSettings>('ad', AD_DEFAULTS)
  const { bindPassword, ...rest } = b
  await setSetting('ad', { ...cur, ...rest, bindPasswordEnc: bindPassword ? encryptSecret(bindPassword) : cur.bindPasswordEnc })
  await audit(c, 'ad_settings', 'settings', 'ad', { enabled: b.enabled, passwordChanged: !!bindPassword })
  return { ok: true }
})
route('POST', '/ad/test', 'admin', async (c) => {
  const b = await c.body(z.object({ username: z.string().max(100).optional() }))
  const s = await getSetting<AdSettings>('ad', AD_DEFAULTS)
  if (!s.urls.length || !s.bindDn) fail(400, 'ad_incomplete')
  const factory = defaultLdapFactory(s)
  for (const url of s.urls) {
    const cl = factory(url)
    try {
      try { await cl.bind(s.bindDn, s.bindPasswordEnc ? decryptSecret(s.bindPasswordEnc) : '') } catch { return { ok: false, step: 'bind', server: url } }
      if (b.username) {
        const r = await cl.search(s.baseDn, { scope: 'sub', filter: `(&(objectClass=user)(${s.userAttr}=${escapeFilter(b.username)}))`, attributes: ['dn'], sizeLimit: 2 })
        return { ok: r.searchEntries.length === 1, step: 'search', server: url, found: r.searchEntries.length }
      }
      return { ok: true, step: 'bind', server: url }
    } catch { /* serveur suivant */ } finally { await cl.unbind().catch(() => undefined) }
  }
  return { ok: false, step: 'connect' }
})
void intParam

// Valeur exportée et lue par le point d'entrée : empêche l'élimination du module par l'optimiseur
export const registered = true
