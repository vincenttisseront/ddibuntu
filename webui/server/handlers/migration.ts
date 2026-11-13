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
