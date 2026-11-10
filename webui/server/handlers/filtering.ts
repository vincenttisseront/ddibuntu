import { z } from 'zod'
import { audit, fail, intParam, qstr, route } from '../utils/router'
import { one, query, tx } from '../utils/db'
import { cfg } from '../utils/config'
import { CATEGORIES, fetchList, parseBlocklist } from '../utils/blocklist'
import { normDomain, normIp } from '../utils/net'
import { loadDns } from '../utils/apply'
import { setSetting } from '../utils/db'
import { applyRule, touchFilter } from '../utils/filterstate'
import { ingestLogText } from '../utils/ingest'

const category = z.enum(CATEGORIES)
const format = z.enum(['hosts', 'domains', 'adblock'])
const domainS = z.string().trim().refine((v) => !!normDomain(v), 'domain')

route('GET', '/filter/lists', 'viewer', async () => ({ items: await query('select id, name, category, source_url, format, enabled, entries, sha256, updated_at, last_error from block_lists order by category, name') }))
route('POST', '/filter/lists', 'operator', async (c) => {
  const b = await c.body(z.object({ name: z.string().trim().min(1).max(100), category, source_url: z.string().url().max(500).nullable().optional(), format: format.default('domains'), enabled: z.boolean().default(true) }))
  if (b.source_url && !/^https?:\/\//i.test(b.source_url)) fail(400, 'url_scheme')
  const r = await one<any>('insert into block_lists (name, category, source_url, format, enabled) values ($1,$2,$3,$4,$5) returning id', [b.name, b.category, b.source_url ?? null, b.format, b.enabled])
  await audit(c, 'filter_list_create', 'block_list', r.id, { name: b.name })
  return { id: r.id }
})
route('PUT', '/filter/lists/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const b = await c.body(z.object({ name: z.string().trim().min(1).max(100), category, source_url: z.string().url().max(500).nullable().optional(), format, enabled: z.boolean() }))
  if (b.source_url && !/^https?:\/\//i.test(b.source_url)) fail(400, 'url_scheme')
  const r = await one('update block_lists set name=$2, category=$3, source_url=$4, format=$5, enabled=$6 where id=$1 returning id', [id, b.name, b.category, b.source_url ?? null, b.format, b.enabled])
  if (!r) fail(404, 'not_found')
  await touchFilter()
  await audit(c, 'filter_list_update', 'block_list', id)
  return { ok: true }
})
route('DELETE', '/filter/lists/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  await query('delete from block_lists where id = $1', [id])
  await touchFilter()
  await audit(c, 'filter_list_delete', 'block_list', id)
  return { ok: true }
})

async function replaceEntries(id: number, text: string, fmt: 'hosts' | 'domains' | 'adblock', sha: string | null) {
  const { domains, skipped } = parseBlocklist(text, fmt)
  await tx(async (cl) => {
    await cl.query('delete from block_entries where list_id = $1', [id])
    for (let i = 0; i < domains.length; i += 50000) {
      await cl.query('insert into block_entries (list_id, domain) select $1, unnest($2::text[]) on conflict do nothing', [id, domains.slice(i, i + 50000)])
    }
    await cl.query('update block_lists set entries = $2, sha256 = $3, updated_at = now(), last_error = null where id = $1', [id, domains.length, sha])
  })
  return { entries: domains.length, skipped }
}
route('POST', '/filter/lists/:id/import', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const b = await c.body(z.object({ content: z.string().min(1).max(30_000_000) }))
  const l = await one<any>('select format from block_lists where id = $1', [id])
  if (!l) fail(404, 'not_found')
  const r = await replaceEntries(id, b.content, l.format, null)
  await touchFilter()
  await audit(c, 'filter_list_import', 'block_list', id, r)
  return r
})
// Téléchargement : action explicite de l'administrateur, jamais au démarrage
route('POST', '/filter/lists/:id/update', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const l = await one<any>('select format, source_url from block_lists where id = $1', [id])
  if (!l) fail(404, 'not_found')
  if (!l.source_url) fail(400, 'no_source_url')
  try {
    const f = await fetchList(l.source_url, { allowPrivate: cfg().allowPrivateFetch, maxBytes: 100 * 1024 * 1024, timeoutMs: 60_000 })
    const r = await replaceEntries(id, f.text, l.format, f.sha256)
    await touchFilter()
  await audit(c, 'filter_list_update_remote', 'block_list', id, r)
    return r
  } catch (e: any) {
    const code = typeof e?.code === 'string' && /^[a-z_]+$/.test(e.code) ? e.code : 'fetch_failed'
    await query('update block_lists set last_error = $2 where id = $1', [id, code])
    fail(502, code)
  }
})

route('GET', '/filter/rules', 'viewer', async () => ({ items: await query('select id, domain, action, comment, created_at from filter_rules order by domain') }))
route('POST', '/filter/rules', 'operator', async (c) => {
  const b = await c.body(z.object({ domain: domainS, action: z.enum(['block', 'allow']), comment: z.string().max(200).nullable().optional() }))
  const r = await one<any>('insert into filter_rules (domain, action, comment) values ($1,$2,$3) returning id', [normDomain(b.domain), b.action, b.comment ?? null])
  await touchFilter()
  await audit(c, 'filter_rule_create', 'filter_rule', r.id, { domain: normDomain(b.domain), action: b.action })
  return { id: r.id }
})
route('DELETE', '/filter/rules/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  await query('delete from filter_rules where id = $1', [id])
  await touchFilter()
  await audit(c, 'filter_rule_delete', 'filter_rule', id)
  return { ok: true }
})

// « Ce domaine est-il bloqué, et pourquoi ? » : même logique de précédence que RPZ (le plus spécifique l'emporte)
route('GET', '/filter/check', 'viewer', async (c) => {
  const d = normDomain(qstr(c, 'domain') ?? '')
  if (!d) fail(400, 'domain')
  const labels = d.split('.')
  const cands = labels.slice(0, -1).map((_, i) => labels.slice(i).join('.'))
  const rules = await query<any>('select domain, action from filter_rules where domain = any($1)', [cands])
  const lists = await query<any>('select e.domain, l.name, l.category from block_entries e join block_lists l on l.id = e.list_id where l.enabled and e.domain = any($1)', [cands])
  const matches = [
    ...rules.map((r) => ({ domain: r.domain, kind: r.action === 'allow' ? 'allow_rule' : 'block_rule', source: null as string | null, category: null as string | null })),
    ...lists.map((l) => ({ domain: l.domain, kind: 'list', source: l.name as string, category: l.category as string })),
  ].sort((a, b) => b.domain.split('.').length - a.domain.split('.').length)
  if (!matches.length) return { domain: d, blocked: false, reason: 'no_match', matches }
  const top = matches[0]!.domain.split('.').length
  const best = matches.filter((m) => m.domain.split('.').length === top)
  const allowed = best.some((m) => m.kind === 'allow_rule')
  return { domain: d, blocked: !allowed, reason: allowed ? 'allow_rule' : best[0]!.kind, matches }
})

// ---- Paramètres RPZ (sous-ensemble des paramètres DNS) ----
route('GET', '/filter/settings', 'viewer', async () => { const s = await loadDns(); return { rpzEnabled: s.rpzEnabled, rpzZone: s.rpzZone, rpzAction: s.rpzAction, sinkhole4: s.sinkhole4, sinkhole6: s.sinkhole6 } })
route('PUT', '/filter/settings', 'admin', async (c) => {
  const b = await c.body(z.object({ rpzEnabled: z.boolean(), rpzAction: z.enum(['nxdomain', 'nodata', 'sinkhole']), sinkhole4: z.string().refine((v) => !!normIp(v), 'ip'), sinkhole6: z.string().refine((v) => !!normIp(v), 'ip') }))
  const s = await loadDns()
  await setSetting('dns', { ...s, ...b, sinkhole4: normIp(b.sinkhole4), sinkhole6: normIp(b.sinkhole6) })
  await touchFilter()
  await audit(c, 'filter_settings', 'settings', 'dns')
  return { ok: true }
})

// ---- Statistiques ----
const RANGES: Record<string, { mins: number; bin: string }> = { '15m': { mins: 15, bin: '1 minute' }, '1h': { mins: 60, bin: '1 minute' }, '6h': { mins: 360, bin: '5 minutes' }, '24h': { mins: 1440, bin: '15 minutes' } }
route('GET', '/filter/stats', 'viewer', async (c) => {
  const r = RANGES[qstr(c, 'range', 5) ?? '1h']
  if (!r) fail(400, 'invalid_query')
  const series = await query<any>(`select date_bin($1::interval, bucket, '2000-01-01'::timestamptz) as t, kind, sum(count)::bigint::text as n from dns_stats
    where bucket >= now() - make_interval(mins => $2) group by 1, 2 order by 1`, [r.bin, r.mins])
  const byCategory = await query<any>(`select key as category, sum(count)::bigint::text as n from dns_stats where kind = 'blocked' and bucket >= now() - make_interval(mins => $1) group by key order by sum(count) desc`, [r.mins])
  return { range: qstr(c, 'range', 5) ?? '1h', bin: r.bin, series, byCategory }
})
route('POST', '/filter/ingest-log', 'operator', async (c) => {
  const b = await c.body(z.object({ content: z.string().min(1).max(30_000_000) }))
  const r = await ingestLogText(b.content)
  await audit(c, 'filter_ingest_log', 'dns_stats', undefined, { events: r.events, stored: r.stored })
  return r
})

// Ajout en masse (liste blanche ou noire) : un domaine par ligne ; une règle opposée existante est remplacée
route('POST', '/filter/rules/bulk', 'operator', async (c) => {
  const b = await c.body(z.object({ domains: z.array(z.string().max(300)).min(1).max(5000), action: z.enum(['block', 'allow']), comment: z.string().max(200).nullable().optional() }))
  const valid = [...new Set(b.domains.map((d) => normDomain(d.trim())).filter((d): d is string => !!d))]
  const out = { added: 0, replaced: 0, existing: 0, invalid: b.domains.length - b.domains.filter((d) => !!normDomain(d.trim())).length }
  await tx(async (cl) => { for (const d of valid) { const r = await applyRule(cl, d, b.action, b.comment ?? null); if (r === 'created') out.added++; else if (r === 'replaced') out.replaced++; else out.existing++ } })
  await touchFilter()
  await audit(c, 'filter_rule_bulk', 'filter_rule', undefined, { action: b.action, ...out })
  return out
})

// Valeur exportée et lue par le point d'entrée : empêche l'élimination du module par l'optimiseur
export const registered = true
