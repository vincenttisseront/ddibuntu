// Assistant d'import Active Directory (lecture en direct). Réservé aux administrateurs : il utilise le compte de service enregistré.
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { getSetting, one, query, tx } from '../utils/db'
import { decryptSecret } from '../utils/auth'
import { AD_DEFAULTS, defaultLdapFactory } from '../utils/ad'
import type { AdSettings } from '../utils/ad'
import { AdImportError, adDiscover, allowedDcHosts, axfrZone } from '../utils/adimport'
import { isAdCritical, parseZoneFile } from '../utils/dns'
import { isValidDnsName } from '../utils/net'
import { dnsCommitCore, preImportSnapshot, record } from './importer'

const adErr = (e: unknown): never => {
  if (e instanceof AdImportError) fail(e.code === 'ad_incomplete' ? 400 : 502, e.code)
  throw e
}
async function loadAd(): Promise<{ s: AdSettings; pw: string }> {
  const s = await getSetting<AdSettings>('ad', AD_DEFAULTS)
  return { s, pw: s.bindPasswordEnc ? decryptSecret(s.bindPasswordEnc) : '' }
}
async function discover() {
  const { s, pw } = await loadAd()
  try { return { s, d: await adDiscover(s, pw, defaultLdapFactory(s)) } } catch (e) { return adErr(e) }
}

route('POST', '/import/ad/discover', 'admin', async () => {
  const { d } = await discover()
  const have = new Set((await query<any>('select text(cidr) as c from subnets where space_id = 1')).map((r) => r.c))
  return { server: d.server, sites: d.sites, subnets: d.subnets.map((x) => ({ ...x, exists: have.has(x.cidr) })), dcs: allowedDcHosts((await loadAd()).s) }
})

route('POST', '/import/ad/subnets', 'admin', async (c) => {
  const b = await c.body(z.object({ cidrs: z.array(z.string().max(60)).min(1).max(20000) }))
  const { d } = await discover()   // relue côté serveur : on ne fait pas confiance à la liste renvoyée par le navigateur
  const wanted = new Set(b.cidrs), rows = d.subnets.filter((x) => wanted.has(x.cidr))
  const snapshotId = await preImportSnapshot(c, `avant import AD : ${rows.length} sous-réseau(x)`)
  let created = 0, updated = 0
  await tx(async (cl) => {
    for (const r of rows) {
      const ins = await cl.query("insert into subnets (cidr, name, site, description, source) values ($1,$2,$3,$4,'ad') on conflict (space_id, cidr) do nothing returning id", [r.cidr, r.name, r.site || null, r.description || null])
      if (ins.rowCount) created++
      else if (r.site) updated += (await cl.query("update subnets set site = $2 where cidr = $1 and (site is null or site = '')", [r.cidr, r.site])).rowCount ?? 0
    }
  })
  const out = { requested: b.cidrs.length, found: rows.length, created, updated, snapshotId }
  await record(c, 'ad-live-subnets', d.server, out, snapshotId)
  await audit(c, 'import_ad_live_subnets', 'subnet', undefined, out)
  return out
})

const dnsReq = z.object({ server: z.string().max(253), zone: z.string().max(253) })
async function axfrFor(b: z.infer<typeof dnsReq>) {
  const { s } = await loadAd()
  if (!allowedDcHosts(s).includes(b.server)) fail(400, 'axfr_server_not_allowed')
  const zone = b.zone.toLowerCase().replace(/\.$/, '')
  if (!isValidDnsName(zone, false)) fail(400, 'invalid_input')
  try { return { zone, text: await axfrZone(b.server, zone) } } catch (e) { return adErr(e) }
}
route('POST', '/import/ad/dns/preview', 'admin', async (c) => {
  const b = await c.body(dnsReq)
  const { zone, text } = await axfrFor(b)
  const parsed = parseZoneFile(text, zone)
  const exist = await one<any>('select id from dns_zones where lower(name) = $1', [zone])
  const byType: Record<string, number> = {}
  for (const r of parsed.records) byType[r.type] = (byType[r.type] ?? 0) + 1
  return { zone, zoneExists: !!exist, total: parsed.records.length, byType, adCritical: parsed.records.filter((r) => isAdCritical(r.name, r.type)).length, skipped: parsed.skipped, warnings: parsed.warnings.slice(0, 50) }
})
route('POST', '/import/ad/dns/commit', 'admin', async (c) => {
  const b = await c.body(dnsReq.extend({ create: z.boolean().default(false), applySoa: z.boolean().default(true) }))
  const { zone, text } = await axfrFor(b)
  const snapshotId = await preImportSnapshot(c, `avant import AD DNS : ${zone}`)
  let zrow = await one<any>('select id from dns_zones where lower(name) = $1', [zone])
  if (!zrow) {
    if (!b.create) fail(404, 'zone_missing')
    zrow = await one<any>("insert into dns_zones (name, type, ad_integrated, dirty) values ($1,'primary',true,true) returning id", [zone])
  }
  const out = await dnsCommitCore(c, { content: text, filename: `AXFR ${zone} @ ${b.server}`, zone_id: zrow.id, mode: 'skip', apply_soa: b.applySoa }, snapshotId)
  await audit(c, 'import_ad_live_dns', 'zone', zrow.id, { zone, server: b.server })
  return out
})

export const registered = true
