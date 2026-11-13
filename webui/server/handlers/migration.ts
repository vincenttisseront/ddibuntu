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
  return { steps, totals: { scopes: c?.scopes ?? 0, zones: c?.zones ?? 0, subnets: c?.subnets ?? 0 } }
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

const leasesBody = z.object({ content: z.string().min(1).max(25_000_000), filename: z.string().max(200).optional() })
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
  if (!p.plan.import.length) return { ...view(p), imported: 0, existing: 0, snapshotId: null }
  const snapshotId = await captureSnapshot('pre-import', `avant reprise des baux (${b.filename ?? 'baux'})`, c.user?.username ?? null)
  const imported = await tx(async (cl) => {
    const cols = new Set((await cl.query("select column_name from information_schema.columns where table_schema = 'public' and table_name = 'lease4'")).rows.map((r) => r.column_name as string))
    for (const need of ['address', 'hwaddr', 'expire', 'subnet_id']) if (!cols.has(need)) fail(409, 'lease_db_missing')
    let n = 0
    for (const l of p.plan.import) {
      const v: Record<string, unknown> = { address: l.n, hwaddr: Buffer.from(l.mac.replace(/:/g, ''), 'hex'), valid_lifetime: l.lifetime, expire: l.expire.toISOString().slice(0, 19).replace('T', ' '), subnet_id: l.scopeId, fqdn_fwd: false, fqdn_rev: false, hostname: l.hostname ?? '', state: 0 }
      const use = Object.keys(v).filter((k) => cols.has(k))
      n += (await cl.query(`insert into lease4 (${use.join(', ')}) values (${use.map((_, i) => `$${i + 1}`).join(', ')}) on conflict (address) do nothing`, use.map((k) => v[k]))).rowCount ?? 0
    }
    return n
  })
  await record(c, 'dhcp-leases', b.filename, { ...view(p), imported }, snapshotId)
  await audit(c, 'migration_leases', 'lease4', undefined, { total: p.plan.total, imported })
  return { ...view(p), imported, existing: p.plan.import.length - imported, snapshotId }
})
