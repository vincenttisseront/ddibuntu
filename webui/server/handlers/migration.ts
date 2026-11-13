// Migration depuis DNS / DHCP Windows Server (0.12.0) : avancement du parcours guidé. Les étapes « importer » se détectent seules
// (historique des imports) ; les autres se cochent à la main. État COMMUN au cluster (table « settings », clé « migration »).
import { z } from 'zod'
import { audit, route } from '../utils/router'
import { getSetting, one, query, setSetting } from '../utils/db'
import { assess } from '../utils/migration-assess'

export const registered = true

export const MIGRATION_STEPS = ['scripts', 'assess', 'subnets', 'dhcp', 'dns', 'review', 'cutover', 'retire'] as const
type Step = (typeof MIGRATION_STEPS)[number]
/** Étapes dont l'accomplissement se déduit de l'historique des imports. */
const AUTO: Partial<Record<Step, string[]>> = { subnets: ['ad-subnets', 'ad-live-subnets'], dhcp: ['dhcp'], dns: ['dns'] }

export const parseMigration = (raw: unknown): Record<Step, boolean> => {
  const o = (raw && typeof raw === 'object' ? (raw as Record<string, unknown>).done : null) as Record<string, unknown> | null
  return Object.fromEntries(MIGRATION_STEPS.map((s) => [s, o?.[s] === true])) as Record<Step, boolean>
}

async function state() {
  const manual = parseMigration(await getSetting<unknown>('migration', null).catch(() => null))
  const runs = await query<any>("select kind, count(*)::int as n, max(created_at) as last from import_runs group by kind")
  const byKind = new Map(runs.map((r) => [r.kind as string, r]))
  const steps = MIGRATION_STEPS.map((id) => {
    const kinds = AUTO[id], hit = kinds?.map((k) => byKind.get(k)).filter(Boolean) ?? []
    return { id, manual: manual[id], auto: hit.length > 0, runs: hit.reduce((n, r: any) => n + r.n, 0), last: hit.map((r: any) => r.last).sort().pop() ?? null, detectable: !!kinds }
  })
  const c = await one<any>("select (select count(*)::int from dhcp_scopes) as scopes, (select count(*)::int from dns_zones where type = 'primary') as zones, (select count(*)::int from subnets) as subnets")
  const push = await getSetting<any>('migration_leases', null).catch(() => null)
  return { steps, totals: { scopes: c?.scopes ?? 0, zones: c?.zones ?? 0, subnets: c?.subnets ?? 0 }, leasePush: push && typeof push === 'object' ? { at: push.at ?? null, imported: push.imported ?? 0, total: push.total ?? 0 } : null }
}

route('GET', '/migration', 'viewer', async () => state())

route('PUT', '/migration', 'operator', async (c) => {
  const b = await c.body(z.object({ step: z.enum(MIGRATION_STEPS), done: z.boolean() }))
  const cur = parseMigration(await getSetting<unknown>('migration', null).catch(() => null))
  cur[b.step] = b.done
  await setSetting('migration', { done: cur })
  await audit(c, 'migration_step', 'settings', undefined, b)
  return state()
})

// ---- Évaluation de compatibilité (0.12.1) : lecture seule, rien n'est importé ni enregistré ----
route('POST', '/migration/assess', 'operator', async (c) => {
  const b = await c.body(z.object({ dhcp: z.string().max(25_000_000).optional(), zones: z.string().max(5_000_000).optional() }))
  const r = assess(b)
  if (r.findings.length) { const cur = parseMigration(await getSetting<unknown>('migration', null).catch(() => null)); cur.assess = true; await setSetting('migration', { done: cur }) }
  await audit(c, 'migration_assess', 'settings', undefined, { verdict: r.verdict, ...r.summary })
  return r
})

// ---- Reprise des baux actifs (0.12.2) : CSV de Get-DhcpServerv4Lease → table lease4 de Kea. Jamais d'écrasement d'un bail existant. ----
import { captureSnapshot } from '../utils/snapshots'
import { planLeases } from '../utils/lease-import'
import { fail } from '../utils/router'
import { record } from './importer'
import { tx } from '../utils/db'

const leasesBody = z.object({ content: z.string().min(1).max(25_000_000), filename: z.string().max(200).optional(), refresh: z.boolean().default(false) })
async function leasePlan(csv: string) {
  const scopes = (await query<any>('select d.id, text(s.cidr) as cidr, d.lease_time from dhcp_scopes d join subnets s on s.id = d.subnet_id')).map((r) => ({ id: r.id as number, cidr: r.cidr as string, leaseTime: r.lease_time as number }))
  const t = await one<any>("select to_regclass('public.lease4') is not null as ok")
  return { plan: planLeases(csv, scopes), available: !!t?.ok, scopes: scopes.length }
}
const view = (p: Awaited<ReturnType<typeof leasePlan>>) => ({ available: p.available, scopes: p.scopes, total: p.plan.total, toImport: p.plan.import.length, skipped: p.plan.skipped, errors: p.plan.errors })

route('POST', '/migration/leases/preview', 'operator', async (c) => view(await leasePlan((await c.body(leasesBody)).content)))

route('POST', '/migration/leases/commit', 'operator', async (c) => {
  const b = await c.body(leasesBody)
  const p = await leasePlan(b.content)
  if (p.plan.errors.length) fail(400, 'leases_csv_invalid')
  if (!p.available) fail(409, 'lease_db_missing')
  // Mode « rafraîchir » (envoi planifié depuis le serveur Windows tant qu'il sert encore les clients) : les baux déjà reçus sont mis à jour, sans instantané ni historique à chaque envoi.
  // Refusé une fois la bascule faite : Kea sert alors les clients et ses baux ne doivent plus être écrasés.
  if (b.refresh && parseMigration(await getSetting<unknown>('migration', null).catch(() => null)).cutover) fail(409, 'cutover_done')
  if (!p.plan.import.length) return { ...view(p), imported: 0, existing: 0, snapshotId: null }
  const snapshotId = b.refresh ? null : await captureSnapshot('pre-import', `avant reprise des baux (${b.filename ?? 'baux'})`, c.user?.username ?? null)
  const imported = await tx(async (cl) => {
    const cols = new Set((await cl.query("select column_name from information_schema.columns where table_schema = 'public' and table_name = 'lease4'")).rows.map((r) => r.column_name as string))
    for (const need of ['address', 'hwaddr', 'expire', 'subnet_id']) if (!cols.has(need)) fail(409, 'lease_db_missing')
    let n = 0
    for (const l of p.plan.import) {
      const v: Record<string, unknown> = { address: l.n, hwaddr: Buffer.from(l.mac.replace(/:/g, ''), 'hex'), valid_lifetime: l.lifetime, expire: l.expire.toISOString().slice(0, 19).replace('T', ' '), subnet_id: l.scopeId, fqdn_fwd: false, fqdn_rev: false, hostname: l.hostname ?? '', state: 0 }
      const use = Object.keys(v).filter((k) => cols.has(k))
      n += (await cl.query(`insert into lease4 (${use.join(', ')}) values (${use.map((_, i) => `$${i + 1}`).join(', ')}) on conflict (address) do ${b.refresh ? `update set ${use.filter((k) => k !== 'address').map((k) => `${k} = excluded.${k}`).join(', ')}` : 'nothing'}`, use.map((k) => v[k]))).rowCount ?? 0
    }
    return n
  })
  if (b.refresh) await setSetting('migration_leases', { at: new Date().toISOString(), imported, total: p.plan.total, by: c.user?.username ?? null })
  else {
    await record(c, 'dhcp-leases', b.filename, { ...view(p), imported }, snapshotId)
    await audit(c, 'migration_leases', 'lease4', undefined, { total: p.plan.total, imported })
  }
  return { ...view(p), imported, existing: b.refresh ? 0 : p.plan.import.length - imported, snapshotId }
})

// ---- Zones DNS (0.12.3) : création depuis l'inventaire, transfert de zone (AXFR) depuis le serveur Windows ----
import { planZones } from '../utils/zone-inventory'
import { parseZoneFile } from '../utils/dns'
import { normIp } from '../utils/net'
import { axfr, validServer } from '../utils/axfr'
import { dnsCommitCore, dnsPlan } from './importer'

const zonesBody = z.object({ content: z.string().min(1).max(5_000_000), filename: z.string().max(200).optional(), view_id: z.number().int().nullable().optional(), coexist: z.string().trim().max(253).optional() })
const coexistIp = (b: z.infer<typeof zonesBody>): string | null => { if (!b.coexist) return null; const ip = normIp(b.coexist); if (!ip) fail(400, 'axfr_server_invalid'); return ip }
async function zonesPlan(csv: string, viewId: number | null, coexist: string | null) {
  const views = (await one<any>('select count(*)::int n from dns_views'))!.n as number
  if (views > 0 && !viewId) fail(400, 'view_required')
  if (views === 0 && viewId) fail(400, 'view_not_found')
  if (viewId && !(await one('select 1 from dns_views where id = $1', [viewId]))) fail(400, 'view_not_found')
  const ex = await query<any>('select lower(name) as name from dns_zones where view_id is not distinct from $1', [viewId])
  return planZones(csv, new Set(ex.map((r) => r.name as string)), coexist)
}
const zonesView = (p: ReturnType<typeof planZones>) => ({ items: p.items, errors: p.errors, toCreate: p.items.filter((i) => i.action === 'create').length })

route('POST', '/migration/zones/preview', 'operator', async (c) => { const b = await c.body(zonesBody); return zonesView(await zonesPlan(b.content, b.view_id ?? null, coexistIp(b))) })
route('POST', '/migration/zones/commit', 'operator', async (c) => {
  const b = await c.body(zonesBody)
  const p = await zonesPlan(b.content, b.view_id ?? null, coexistIp(b))
  if (p.errors.length) fail(400, 'dns_csv_invalid')
  const todo = p.items.filter((i) => i.action === 'create')
  if (!todo.length) return { ...zonesView(p), created: 0, snapshotId: null }
  const snapshotId = await captureSnapshot('pre-import', `avant création des zones (${b.filename ?? 'inventaire'})`, c.user?.username ?? null)
  await tx(async (cl) => {
    for (const i of todo) await cl.query('insert into dns_zones (name, type, masters, forwarders, ad_integrated, view_id) values ($1,$2,$3,$4,$5,$6)', [i.name, i.type, i.masters, i.forwarders, i.adIntegrated, b.view_id ?? null])
  })
  const out = { ...zonesView(p), created: todo.length }
  await record(c, 'dns-zones', b.filename, out, snapshotId)
  await audit(c, 'migration_zones', 'zone', undefined, { created: todo.length })
  return { ...out, snapshotId }
})

const axfrBody = z.object({ server: z.string().trim().min(1).max(253), zone_id: z.number().int(), mode: z.enum(['skip', 'replace']).default('skip'), apply_soa: z.boolean().default(false) })
async function fetchZone(b: z.infer<typeof axfrBody>) {
  if (!validServer(b.server)) fail(400, 'axfr_server_invalid')
  const zone = await one<any>('select name, type from dns_zones where id = $1', [b.zone_id])
  if (!zone) fail(404, 'not_found')
  if (zone.type !== 'primary') fail(400, 'zone_not_primary')
  const r = await axfr(zone.name, b.server)
  if (!r.ok) fail(r.error === 'axfr_refused' ? 502 : r.error === 'dig_missing' ? 501 : 502, r.error!)
  return r.text
}
route('POST', '/migration/axfr/preview', 'admin', async (c) => { const b = await c.body(axfrBody); return (await dnsPlan(b.zone_id, await fetchZone(b))).summary })
route('POST', '/migration/axfr/commit', 'admin', async (c) => {
  const b = await c.body(axfrBody)
  const text = await fetchZone(b)
  return dnsCommitCore(c, { content: text, filename: `AXFR ${b.server}`, zone_id: b.zone_id, mode: b.mode, apply_soa: b.apply_soa })
})

// ---- Coexistence (0.12.4) : zones secondaires de notre BIND derrière le serveur Windows (qui reste maître), puis promotion en primaire à la bascule ----
route('GET', '/migration/coexist', 'viewer', async () => ({ items: await query<any>("select z.id, z.name, z.masters, v.name as view from dns_zones z left join dns_views v on v.id = z.view_id where z.type = 'secondary' and cardinality(z.masters) > 0 order by z.name") }))

async function coexistZone(id: number) {
  const z = await one<any>('select id, name, type, masters from dns_zones where id = $1', [id])
  if (!z) fail(404, 'not_found')
  if (z.type !== 'secondary' || !z.masters?.length) fail(400, 'zone_not_secondary')
  return z as { id: number; name: string; masters: string[] }
}
const zoneIdBody = z.object({ zone_id: z.number().int() })
route('POST', '/migration/coexist/check', 'admin', async (c) => {
  const z = await coexistZone((await c.body(zoneIdBody)).zone_id)
  const r = await axfr(z.name, z.masters[0]!)
  return { zone: z.name, master: z.masters[0], ok: r.ok, error: r.ok ? null : r.error, records: r.ok ? parseZoneFile(r.text, z.name).records.length : 0 }
})
route('POST', '/migration/coexist/promote', 'admin', async (c) => {
  const z = await coexistZone((await c.body(zoneIdBody)).zone_id)
  const r = await axfr(z.name, z.masters[0]!)
  if (!r.ok) fail(502, r.error!)   // rien n'a changé : la zone reste secondaire
  const snapshotId = await captureSnapshot('pre-import', `avant bascule de la zone ${z.name}`, c.user?.username ?? null)
  await query("update dns_zones set type = 'primary', masters = '{}', dirty = true, updated_at = now() where id = $1", [z.id])
  try {
    const out = await dnsCommitCore(c, { content: r.text, filename: `AXFR ${z.masters[0]}`, zone_id: z.id, mode: 'skip', apply_soa: true }, snapshotId)
    await audit(c, 'migration_promote', 'zone', z.id, { zone: z.name, master: z.masters[0], inserted: out.inserted })
    return { ok: true, zone: z.name, inserted: out.inserted, snapshotId }
  } catch (e) {
    await query("update dns_zones set type = 'secondary', masters = $2, updated_at = now() where id = $1", [z.id, z.masters])   // retour à l'état d'avant
    throw e
  }
})
