// Moteur d'alertes : photographie → règles → événements (ouverture, résolution) → notifications. Ne tourne que sur la console AUTORISÉE À ÉCRIRE
// (le leader du cluster, ou un serveur seul) : sur un secondaire, la base est en lecture seule et la liste vient de la réplication.
import { readClusterState } from './cluster'
import { cfg } from './config'
import { getSetting, inRecovery, one, query, setSetting, tx } from './db'
import { readLocalHealth } from './health'
import { readBackupResult, readBackupStatus } from './backup'
import { subnetUsage } from './ipam-usage'
import { getLastRun, getSchedule } from './discovery-schedule'
import { evaluate, SEVERITY_RANK } from './alert-rules'
import type { Finding, Memory, Severity, Snapshot } from './alert-rules'
import { loadConfig } from './alert-config'
import { notifyAll } from './alert-notify'
import type { Delivery, Kind, NotifyEvent } from './alert-notify'

export async function gatherSnapshot(nowSec = Math.floor(Date.now() / 1000)): Promise<Snapshot> {
  const [cluster, localHealth, backup, backupResult, subnets] = await Promise.all([readClusterState(), readLocalHealth(), readBackupStatus(), readBackupResult(), subnetUsage().catch(() => [])])
  const hygiene = await gatherHygiene().catch(() => undefined)
  return { now: nowSec, cluster, localHealth, backup, backupResult, subnets, hygiene }
}

async function gatherHygiene() {
  if (await inRecovery()) return undefined
  const GHOST_DAYS = (await getSchedule()).ghostDays
  const g = (await query<any>("select count(*)::int as n from addresses where status in ('used','dhcp','ghost') and last_seen is not null and last_seen < now() - make_interval(days => $1)", [GHOST_DAYS]))[0]!.n
  const last = await getLastRun()
  return { ghosts: g, ghostDays: GHOST_DAYS, scanAt: last?.ok ? last.at : null, unknown: last?.unknown ?? 0, macChanged: last?.macChanged ?? 0 }
}

export interface RunInfo { at: number; ok: boolean; findings: number; opened: number; resolved: number; notified: number; error?: string }
let lastRun: RunInfo | null = null
export const lastRunInfo = () => lastRun
let running: Promise<RunInfo | { skipped: string }> | null = null

const MAX_ATTEMPTS = 5

// Règle d'or : une évaluation à la fois (le minuteur et le bouton « évaluer » se partagent le même passage).
export function runEvaluation(): Promise<RunInfo | { skipped: string }> {
  if (running !== null) return running
  running = doRun().finally(() => { running = null })
  return running
}

async function doRun(): Promise<RunInfo | { skipped: string }> {
  if (await inRecovery(0)) return { skipped: 'replica' }
  const conf = await loadConfig()
  try {
    const snap = await gatherSnapshot()
    const memory = await getSetting<Memory>('alert_memory', { leader: null, leaderChangedAt: null })
    const r = evaluate(snap, conf.thresholds, memory)
    // cluster non lisible ou périmé : la mémoire du leader n'est pas touchée (rien n'a été constaté)
    if (JSON.stringify(r.memory) !== JSON.stringify(memory)) await setSetting('alert_memory', r.memory)
    const { opened, resolved } = await reconcile(r.findings)
    const notified = await notifyPending(conf, snap.cluster?.cluster ?? '')
    lastRun = { at: snap.now, ok: true, findings: r.findings.length, opened, resolved, notified }
  } catch (e: any) {
    lastRun = { at: Math.floor(Date.now() / 1000), ok: false, findings: 0, opened: 0, resolved: 0, notified: 0, error: String(e?.message ?? e).slice(0, 200) }
    console.error('[alerts]', lastRun.error)
  }
  return lastRun!
}

export async function reconcile(findings: Finding[]): Promise<{ opened: number; resolved: number }> {
  const resolveMisses = cfg().alertResolveMisses
  return tx(async (c) => {
    await c.query('select pg_advisory_xact_lock(727728)')
    const firing: Array<{ id: number; key: string; severity: Severity; misses: number }> = (await c.query("select id, key, severity, misses from alert_events where state = 'firing'")).rows
    const byKey = new Map(firing.map((r) => [r.key, r]))
    const keys = new Set(findings.map((f) => f.key))
    let opened = 0, resolved = 0
    for (const f of findings) {
      const cur = byKey.get(f.key)
      if (cur) {
        // aggravation (avertissement → critique) : nouvelle notification
        const worse = SEVERITY_RANK[f.severity] > SEVERITY_RANK[cur.severity]
        await c.query(`update alert_events set last_seen = now(), misses = 0, severity = $2, params = $3::jsonb${worse ? ', notified_at = null, notify_attempts = 0' : ''} where id = $1`, [cur.id, f.severity, JSON.stringify(f.params)])
      } else {
        await c.query('insert into alert_events (key, rule, severity, node, subject, params) values ($1,$2,$3,$4,$5,$6::jsonb)', [f.key, f.rule, f.severity, f.node, f.subject, JSON.stringify(f.params)])
        opened++
      }
    }
    for (const r of firing) {
      if (keys.has(r.key)) continue
      if (r.misses + 1 >= resolveMisses) { await c.query("update alert_events set state = 'resolved', resolved_at = now(), misses = misses + 1 where id = $1", [r.id]); resolved++ }
      else await c.query('update alert_events set misses = misses + 1 where id = $1', [r.id])
    }
    return { opened, resolved }
  })
}

// Un silence couvre un événement quand chacun de ses critères renseignés (règle, nœud, objet) correspond.
export const SILENCED_SQL = `exists (select 1 from alert_silences s where s.until > now() and (s.rule is null or s.rule = e.rule) and (s.node is null or s.node = e.node) and (s.subject is null or s.subject = e.subject))`

async function notifyPending(conf: Awaited<ReturnType<typeof loadConfig>>, cluster: string): Promise<number> {
  if (!conf.webhook.enabled && !conf.email.enabled) return 0
  const minRank = SEVERITY_RANK[conf.minSeverity]
  const rows = await query<any>(`select e.*, ${SILENCED_SQL} as silenced from alert_events e
    where (e.state = 'firing' and e.notify_attempts < $2 and (e.notified_at is null or ($1::int > 0 and e.notified_at < now() - make_interval(hours => $1::int))))
       or (e.state = 'resolved' and e.notified_at is not null and not e.resolve_notified and e.resolved_at > now() - interval '1 day')
    order by e.id limit 50`, [conf.repeatHours, MAX_ATTEMPTS])
  let sent = 0
  for (const e of rows) {
    const resolved = e.state === 'resolved'
    if (SEVERITY_RANK[e.severity as Severity] < minRank) { if (resolved) await query('update alert_events set resolve_notified = true where id = $1', [e.id]); continue }
    if (e.silenced) { if (resolved) await query('update alert_events set resolve_notified = true where id = $1', [e.id]); continue }
    const kind: Kind = resolved ? 'resolved' : e.notified_at ? 'repeat' : 'firing'
    const ev: NotifyEvent = { id: Number(e.id), rule: e.rule, severity: e.severity, node: e.node, subject: e.subject, params: e.params ?? {}, startedAt: e.started_at, resolvedAt: e.resolved_at }
    const ds = await notifyAll(conf, ev, kind, cluster)
    await recordDeliveries(ds, kind, ev.id)
    if (ds.some((d) => d.ok)) { sent++; await query(resolved ? 'update alert_events set resolve_notified = true where id = $1' : 'update alert_events set notified_at = now(), notify_attempts = 0 where id = $1', [e.id]) }
    else if (ds.length) await query('update alert_events set notify_attempts = notify_attempts + 1' + (resolved ? ', resolve_notified = (notify_attempts + 1 >= $2)' : '') + ' where id = $1', resolved ? [e.id, MAX_ATTEMPTS] : [e.id])
  }
  return sent
}

export async function recordDeliveries(ds: Delivery[], kind: Kind, eventId: number | null): Promise<void> {
  for (const d of ds) await query('insert into alert_deliveries (channel, kind, event_id, ok, detail) values ($1,$2,$3,$4,$5)', [d.channel, kind, eventId, d.ok, d.detail.slice(0, 200)])
}

// Essai d'un canal avec la configuration ENREGISTRÉE (aucune alerte réelle n'est créée).
export async function testChannel(channel: 'webhook' | 'email'): Promise<Delivery> {
  const conf = await loadConfig()
  const probe = { ...conf, webhook: { ...conf.webhook, enabled: channel === 'webhook' }, email: { ...conf.email, enabled: channel === 'email' } }
  const ev: NotifyEvent = { id: null, rule: 'test', severity: 'info', node: '', subject: '', params: {}, startedAt: new Date(), resolvedAt: null }
  const snap = await readClusterState()
  const [d] = await notifyAll(probe, ev, 'test', snap?.cluster ?? '')
  const out = d ?? { channel, ok: false, detail: 'disabled' }
  await recordDeliveries([out], 'test', null)
  return out
}

export async function alertSummary() {
  const r = await one<any>(`select count(*) filter (where severity = 'critical' and not ${SILENCED_SQL})::int as critical, count(*) filter (where severity = 'warning' and not ${SILENCED_SQL})::int as warning,
    count(*) filter (where severity = 'info' and not ${SILENCED_SQL})::int as info, count(*) filter (where ${SILENCED_SQL})::int as silenced from alert_events e where e.state = 'firing'`)
  return r ?? { critical: 0, warning: 0, info: 0, silenced: 0 }
}

// Entretien (une fois par heure) : historique 90 jours, notifications 30 jours, silences échus depuis plus de 7 jours.
export async function prune(): Promise<void> {
  await query("delete from alert_events where state = 'resolved' and resolved_at < now() - interval '90 days'")
  await query("delete from alert_deliveries where at < now() - interval '30 days'")
  await query("delete from alert_silences where until < now() - interval '7 days'")
}
