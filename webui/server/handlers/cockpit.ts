// Cockpit de filtrage DNS (à la Pi-hole) : tableau de bord, journal des requêtes en direct, liste blanche/noire en un clic,
// pause du blocage, réglages de conservation. Les chiffres viennent du journal stocké (dns_queries).
import { z } from 'zod'
import { audit, fail, qint, qstr, route } from '../utils/router'
import { one, query, setSetting, tx } from '../utils/db'
import { normDomain } from '../utils/net'
import { loadDns } from '../utils/apply'
import { COCKPIT_DEFAULTS, applyRule, getPause, loadCockpit, pendingChanges, resumeBlocking, setBlocking, touchFilter } from '../utils/filterstate'

const RANGES: Record<string, { mins: number; bin: string }> = { '15m': { mins: 15, bin: '1 minute' }, '1h': { mins: 60, bin: '1 minute' }, '6h': { mins: 360, bin: '5 minutes' }, '24h': { mins: 1440, bin: '15 minutes' }, '7d': { mins: 10080, bin: '1 hour' } }
const range = (c: any) => { const k = qstr(c, 'range', 4) ?? '24h'; const r = RANGES[k]; if (!r) fail(400, 'invalid_query'); return { key: k, ...r } }

route('GET', '/cockpit/summary', 'viewer', async (c) => {
  const r = range(c), w = [r.mins]
  const tot = (await one<any>(`select count(*)::int as total, count(*) filter (where status = 'blocked')::int as blocked, count(distinct domain)::int as domains, count(distinct client)::int as clients, max(at) as last_at
    from dns_queries where at >= now() - make_interval(mins => $1)`, w))!
  const series = await query<any>(`select date_bin($2::interval, at, '2000-01-01'::timestamptz) as t, status, count(*)::int as n from dns_queries where at >= now() - make_interval(mins => $1) group by 1, 2 order by 1`, [r.mins, r.bin])
  const top = (status: string) => query<any>(`select domain, count(*)::int as n from dns_queries where status = $2 and at >= now() - make_interval(mins => $1) group by domain order by n desc, domain limit 10`, [r.mins, status])
  const clients = await query<any>(`select client, count(*)::int as total, count(*) filter (where status = 'blocked')::int as blocked from dns_queries where at >= now() - make_interval(mins => $1) group by client order by total desc, client limit 10`, w)
  const types = await query<any>(`select case when qtype = '' then '?' else qtype end as qtype, count(*)::int as n from dns_queries where at >= now() - make_interval(mins => $1) group by 1 order by n desc limit 8`, w)
  const reasons = await query<any>(`select reason, count(*)::int as n from dns_queries where status = 'blocked' and at >= now() - make_interval(mins => $1) group by reason order by n desc limit 10`, w)
  const dns = await loadDns(), pause = await getPause(), cock = await loadCockpit()
  const lists = (await one<any>('select coalesce(sum(entries) filter (where enabled), 0)::bigint::text as domains, count(*) filter (where enabled)::int as active from block_lists'))!
  const rules = (await one<any>("select count(*) filter (where action = 'allow')::int as allow, count(*) filter (where action = 'block')::int as block from filter_rules"))!
  return {
    range: r.key, bin: r.bin, total: tot.total, blocked: tot.blocked, percent: tot.total ? Math.round((tot.blocked / tot.total) * 1000) / 10 : 0, uniqueDomains: tot.domains, uniqueClients: tot.clients, lastQueryAt: tot.last_at,
    series, topBlocked: await top('blocked'), topAllowed: await top('allowed'), topClients: clients, byType: types, byReason: reasons,
    blocklist: { domains: lists.domains, lists: lists.active, allowRules: rules.allow, blockRules: rules.block },
    blocking: { enabled: dns.rpzEnabled, pausedUntil: pause?.until ?? null }, pending: await pendingChanges(), autoDeploy: cock.autoDeploy, retentionDays: cock.retentionDays,
  }
})

// Journal des requêtes : page par curseur (before_id) ou nouveautés (after_id) pour l'affichage en direct
route('GET', '/cockpit/queries', 'viewer', async (c) => {
  const limit = qint(c, 'limit', 100, 1, 500), before = qint(c, 'before_id', 0, 0, 2_000_000_000_000), after = qint(c, 'after_id', 0, 0, 2_000_000_000_000)
  const status = qstr(c, 'status', 10), client = qstr(c, 'client', 64), domain = qstr(c, 'domain', 253)?.toLowerCase(), qtype = qstr(c, 'qtype', 12)?.toUpperCase(), reason = qstr(c, 'reason', 120)
  if (status && !['allowed', 'blocked'].includes(status)) fail(400, 'invalid_query')
  const w: string[] = [], p: unknown[] = []
  const add = (sql: string, v: unknown) => { p.push(v); w.push(sql.replace('?', `$${p.length}`)) }
  if (before) add('id < ?', before); if (after) add('id > ?', after)
  if (status) add('status = ?', status); if (client) add('client = ?', client); if (qtype) add('qtype = ?', qtype); if (reason) add('reason = ?', reason)
  if (domain) add('position(? in domain) > 0', domain)
  p.push(limit)
  const rows = await query<any>(`select id, at, client, domain, qtype, status, reason, category from dns_queries ${w.length ? 'where ' + w.join(' and ') : ''} order by id desc limit $${p.length}`, p)
  return { items: rows, nextBefore: rows.length === limit ? rows[rows.length - 1].id : null }
})

route('POST', '/cockpit/action', 'operator', async (c) => {
  const b = await c.body(z.object({ domain: z.string().trim().max(253), action: z.enum(['allow', 'block', 'remove']), comment: z.string().max(200).nullable().optional() }))
  const domain = normDomain(b.domain)
  if (!domain) fail(400, 'domain')
  let result: string
  if (b.action === 'remove') result = (await query('delete from filter_rules where domain = $1 returning id', [domain])).length ? 'removed' : 'absent'
  else result = await tx((cl) => applyRule(cl, domain, b.action as 'allow' | 'block', b.comment ?? 'ajouté depuis le cockpit'))
  await touchFilter()
  await audit(c, 'cockpit_action', 'filter_rule', domain, { action: b.action, result })
  return { ok: true, domain, result, pending: await pendingChanges() }
})

// Pause du blocage : le RPZ est retiré puis redéployé ; la fin de pause est rétablie automatiquement (même après un redémarrage)
route('POST', '/cockpit/pause', 'admin', async (c) => {
  const b = await c.body(z.object({ minutes: z.number().int().min(0).max(1440) }))
  const dns = await loadDns()
  if (b.minutes === 0) {
    if (!(await resumeBlocking(c.user!.username))) fail(502, 'deploy_failed')   // la pause n'est effacée qu'après un déploiement réussi
    await audit(c, 'cockpit_resume', 'dns', undefined, {}); return { ok: true, blocking: true }
  }
  if (!dns.rpzEnabled && !(await getPause())) fail(409, 'blocking_disabled')
  const until = new Date(Date.now() + b.minutes * 60_000).toISOString()
  const r = await setBlocking(false, c.user!.username)
  if (!r.deployed) fail(502, 'deploy_failed')
  await setSetting('cockpit_pause', { until, by: c.user!.username })
  await audit(c, 'cockpit_pause', 'dns', undefined, { minutes: b.minutes })
  return { ok: true, blocking: false, until }
})

route('GET', '/cockpit/settings', 'viewer', async () => ({ ...(await loadCockpit()), queryLog: (await loadDns()).queryLog }))
route('PUT', '/cockpit/settings', 'admin', async (c) => {
  const b = await c.body(z.object({ retentionDays: z.number().int().min(0).max(90), anonymize: z.enum(['none', 'mask']), autoDeploy: z.boolean() }))
  await setSetting('cockpit', { ...COCKPIT_DEFAULTS, ...b })
  if (b.retentionDays > 0) await query('delete from dns_queries where at < now() - make_interval(days => $1)', [b.retentionDays]); else await query('delete from dns_queries')
  await audit(c, 'cockpit_settings', 'settings', 'cockpit', b)
  return { ok: true }
})
// Confidentialité : effacer tout l'historique des requêtes (les statistiques agrégées restent)
route('POST', '/cockpit/purge', 'admin', async (c) => {
  const r = await query('delete from dns_queries returning id')
  await audit(c, 'cockpit_purge', 'dns_queries', undefined, { deleted: r.length })
  return { deleted: r.length }
})

export const registered = true
