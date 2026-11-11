import { getRequestHeader, setResponseHeader } from 'h3'
import { z } from 'zod'
import { audit, fail, intParam, route } from '../utils/router'
import { inRecovery, one, query } from '../utils/db'
import { newToken } from '../utils/auth'
import { RULES } from '../utils/alert-rules'
import { ConfigInput, configError, hasMetricsToken, loadConfig, metricsTokenValid, publicConfig, saveConfig, setMetricsToken } from '../utils/alert-config'
import { alertSummary, gatherSnapshot, lastRunInfo, runEvaluation, SILENCED_SQL, testChannel } from '../utils/alert-engine'
import { renderMetrics } from '../utils/metrics'
import { installedVersion } from '../utils/selfupdate'

// Liste des alertes (ouvertes, historique), silences et dernières notifications. Un secondaire affiche ce que le leader a enregistré (réplication) mais n'évalue rien.
route('GET', '/alerts', 'operator', async () => {
  const active = await query<any>(`select e.id, e.rule, e.severity, e.node, e.subject, e.params, e.started_at, e.last_seen, ${SILENCED_SQL} as silenced from alert_events e where e.state = 'firing'
    order by case e.severity when 'critical' then 0 when 'warning' then 1 else 2 end, e.started_at`)
  const history = await query<any>("select id, rule, severity, node, subject, params, started_at, resolved_at from alert_events where state = 'resolved' order by resolved_at desc limit 50")
  const silences = await query<any>('select id, rule, node, subject, until, comment, created_by, created_at from alert_silences where until > now() order by until')
  const deliveries = await query<any>('select id, at, channel, kind, event_id, ok, detail from alert_deliveries order by id desc limit 20')
  return { active, history, silences, deliveries, summary: await alertSummary(), engine: { runsHere: !(await inRecovery()), last: lastRunInfo() }, rules: Object.keys(RULES) }
})

// Évaluation immédiate (bouton « Évaluer maintenant ») : le même passage que le minuteur.
route('POST', '/alerts/evaluate', 'operator', async () => {
  const r = await runEvaluation()
  if ('skipped' in r) fail(409, 'replica_no_engine')
  return r
})

const Silence = z.object({
  rule: z.string().refine((v) => v in RULES, { message: 'unknown_rule' }).nullable().optional(),
  node: z.string().regex(/^[a-z0-9-]{1,31}$/).nullable().optional(), subject: z.string().max(100).nullable().optional(),
  hours: z.number().int().min(1).max(24 * 30), comment: z.string().max(200).default(''),
}).strict()
route('POST', '/alerts/silences', 'operator', async (c) => {
  const b = await c.body(Silence)
  const r = await one<any>("insert into alert_silences (rule, node, subject, until, comment, created_by) values ($1,$2,$3, now() + make_interval(hours => $4), $5, $6) returning id, until",
    [b.rule ?? null, b.node ?? null, b.subject ?? null, b.hours, b.comment, c.user?.username ?? null])
  await audit(c, 'alerts.silence', 'alert_silence', r.id, { rule: b.rule ?? null, node: b.node ?? null, subject: b.subject ?? null, hours: b.hours })
  return r
})
route('DELETE', '/alerts/silences/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const r = await one<any>('delete from alert_silences where id = $1 returning id', [id])
  if (!r) fail(404, 'not_found')
  await audit(c, 'alerts.unsilence', 'alert_silence', id)
  return { deleted: true }
})

// Réglages : seuils, canaux de notification. Les secrets ne sont jamais renvoyés (seulement leur présence).
route('GET', '/alerts/config', 'admin', async () => publicConfig(await loadConfig(), await hasMetricsToken()))
route('PUT', '/alerts/config', 'admin', async (c) => {
  const b = await c.body(ConfigInput)
  const err = configError(b); if (err) fail(400, err)
  await saveConfig(b)
  await audit(c, 'alerts.configure', 'alerts', '', { webhook: b.webhook.enabled, email: b.email.enabled, minSeverity: b.minSeverity })   // jamais d'adresse ni de secret dans le journal
  return publicConfig(await loadConfig(), await hasMetricsToken())
})
route('POST', '/alerts/test/:channel', 'admin', async (c) => {
  const ch = c.params.channel
  if (ch !== 'webhook' && ch !== 'email') fail(404, 'not_found')
  const conf = await loadConfig()
  if (!(ch === 'webhook' ? conf.webhook.enabled : conf.email.enabled)) fail(409, 'channel_disabled')
  const d = await testChannel(ch)
  await audit(c, 'alerts.test', 'alerts', ch, { ok: d.ok })
  return d
})

// Jeton de l'export Prometheus : montré une seule fois ; seule son empreinte est conservée.
route('POST', '/alerts/metrics-token', 'admin', async (c) => {
  const token = 'ddm_' + newToken(32)
  await setMetricsToken(token)
  await audit(c, 'alerts.metrics_token.create', 'alerts', '')
  return { token }
})
route('DELETE', '/alerts/metrics-token', 'admin', async (c) => { await setMetricsToken(null); await audit(c, 'alerts.metrics_token.revoke', 'alerts', ''); return { revoked: true } })

// Export Prometheus : authentification par jeton « Bearer » uniquement (jamais dans l'adresse, où il finirait dans les journaux).
route('GET', '/metrics', 'public', async (c) => {
  const m = /^Bearer (ddm_[A-Za-z0-9_-]{20,100})$/.exec(getRequestHeader(c.event, 'authorization') ?? '')
  if (!m || !(await metricsTokenValid(m[1]!))) fail(401, 'unauthenticated')
  setResponseHeader(c.event, 'Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  return renderMetrics(await gatherSnapshot(), await alertSummary(), installedVersion())
})

export const registered = true
