// Export des journaux vers un SIEM : lit les nouveaux enregistrements de chaque flux choisi (curseur par destination), les met au format voulu
// et les envoie (syslog UDP / TCP / TLS, ou HTTPS). Un envoi échoué ne fait pas avancer le curseur : rien n'est perdu, rien n'est envoyé deux fois après un succès.
import dgram from 'node:dgram'
import net from 'node:net'
import tls from 'node:tls'
import { hostname } from 'node:os'
import { one, query } from './db'
import { plain } from './alert-config'
import { webhookUrlError } from './alert-config'
import { installedVersion } from './selfupdate'
import { SIEM_SOURCES, formatEvent, frame } from './siem-format'
import type { SiemEvent, SiemFormat, SiemSource } from './siem-format'

export interface SiemTarget {
  id: number; name: string; enabled: boolean; protocol: 'udp' | 'tcp' | 'tls' | 'https'; host: string; port: number | null; url: string
  format: SiemFormat; framing: 'newline' | 'octet'; facility: number; sources: string[]; tls_verify: boolean; auth_prefix: string; secret_enc: string | null; cursors: Record<string, number>
}
export const BATCH = 500

/** Adresse de destination : jamais le lien local ni le service de métadonnées (un SIEM interne en 10.x / 192.168.x reste permis). */
export function hostError(h: string): string | null {
  const x = h.toLowerCase()
  if (/^169\.254\./.test(x) || /^fe[89ab][0-9a-f]:/.test(x) || x === 'metadata.google.internal') return 'siem_host_forbidden'
  return null
}
export function targetError(t: { protocol: string; host: string; port: number | null; url: string }): string | null {
  if (t.protocol === 'https') { if (!t.url) return 'siem_url_required'; return webhookUrlError(t.url) }
  if (!t.host || !t.port) return 'siem_host_required'
  return hostError(t.host)
}

const reason = (e: any): string => String(e?.code ?? e?.message ?? e?.name ?? 'error').replace(/[^A-Za-z0-9 _:.-]/g, '').slice(0, 120)
const sev = (n: number) => n

// ---- lecture des flux (par id croissant, après le curseur)
const READERS: Record<SiemSource, (after: number, limit: number) => Promise<SiemEvent[]>> = {
  async audit(after, limit) {
    const rows = await query<any>('select id, at, username, action, entity, entity_id, detail, host(ip) as ip from audit_log where id > $1 order by id limit $2', [after, limit])
    return rows.map((r) => ({
      source: 'audit', id: Number(r.id), at: new Date(r.at), severity: /fail|denied|lock/i.test(r.action) ? 4 : 6, event: `audit.${r.action}`,
      message: `${r.username ?? '-'} : ${r.action}${r.entity ? ` ${r.entity}${r.entity_id ? ' ' + r.entity_id : ''}` : ''}`,
      fields: { user: r.username, action: r.action, entity: r.entity, entity_id: r.entity_id, ip: r.ip, detail: r.detail ? JSON.stringify(r.detail).slice(0, 1000) : null },
    }))
  },
  dns_queries: (after, limit) => dnsRows('', after, limit),
  dns_blocked: (after, limit) => dnsRows("and status = 'blocked'", after, limit),
  async alerts(after, limit) {
    const rows = await query<any>('select id, rule, severity, node, subject, params, state, started_at from alert_events where id > $1 order by id limit $2', [after, limit])
    return rows.map((r) => ({
      source: 'alerts', id: Number(r.id), at: new Date(r.started_at), severity: r.severity === 'critical' ? 2 : r.severity === 'warning' ? 4 : 6, event: `alert.${r.rule}`,
      message: `Alerte ${r.severity} : ${r.rule}${r.subject ? ' (' + r.subject + ')' : ''}${r.node ? ' sur ' + r.node : ''}`,
      fields: { rule: r.rule, node: r.node, subject: r.subject, status: r.state, detail: Object.keys(r.params ?? {}).length ? JSON.stringify(r.params).slice(0, 500) : null },
    }))
  },
  async deployments(after, limit) {
    const rows = await query<any>('select id, at, username, ok from deployments where id > $1 order by id limit $2', [after, limit])
    return rows.map((r) => ({
      source: 'deployments', id: Number(r.id), at: new Date(r.at), severity: r.ok ? 6 : 3, event: r.ok ? 'deploy.ok' : 'deploy.failed',
      message: `Déploiement #${r.id} ${r.ok ? 'réussi' : 'en échec'}`, fields: { user: r.username, outcome: r.ok ? 'success' : 'failure', deployment: r.id },
    }))
  },
}
async function dnsRows(filter: string, after: number, limit: number): Promise<SiemEvent[]> {
  const rows = await query<any>(`select id, at, client, domain, qtype, status, reason, category from dns_queries where id > $1 ${filter} order by id limit $2`, [after, limit])
  return rows.map((r) => ({
    source: r.status === 'blocked' ? 'dns_blocked' : 'dns_queries', id: Number(r.id), at: new Date(r.at), severity: r.status === 'blocked' ? 5 : 6, event: r.status === 'blocked' ? 'dns.blocked' : 'dns.query',
    message: `DNS ${r.status === 'blocked' ? 'bloquée' : 'autorisée'} : ${r.client} → ${r.domain} ${r.qtype}`,
    fields: { client: r.client, domain: r.domain, qtype: r.qtype, status: r.status, reason: r.reason, category: r.category },
  }))
}

/** Plus grand identifiant actuel de chaque flux : point de départ d'un flux nouvellement choisi (on n'envoie pas l'historique). */
export async function currentCursors(sources: string[]): Promise<Record<string, number>> {
  const q: Record<string, string> = { audit: 'audit_log', dns_queries: 'dns_queries', dns_blocked: 'dns_queries', alerts: 'alert_events', deployments: 'deployments' }
  const out: Record<string, number> = {}
  for (const s of sources) if (q[s]) out[s] = Number((await one<any>(`select coalesce(max(id), 0) as m from ${q[s]}`))?.m ?? 0)
  return out
}

// ---- envoi
function withTimeout<T>(p: Promise<T>, ms: number, close: () => void): Promise<T> {
  let t: ReturnType<typeof setTimeout>
  return Promise.race([p, new Promise<T>((_, rej) => { t = setTimeout(() => { close(); rej(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })) }, ms) })]).finally(() => clearTimeout(t!))
}
async function sendUdp(host: string, port: number, lines: string[]): Promise<void> {
  const type = net.isIPv6(host) ? 'udp6' : 'udp4'
  const sock = dgram.createSocket(type)
  try {
    for (const l of lines) {
      const buf = Buffer.from(l).subarray(0, 8000)
      await withTimeout(new Promise<void>((res, rej) => sock.send(buf, port, host, (e) => (e ? rej(e) : res()))), 5000, () => sock.close())
    }
  } finally { try { sock.close() } catch { /* déjà fermée */ } }
}
async function sendStream(t: SiemTarget, lines: string[]): Promise<void> {
  const data = frame(lines, t.framing)
  let sock: net.Socket
  await withTimeout(new Promise<void>((res, rej) => {
    const done = () => { sock.write(data, (e) => (e ? rej(e) : sock.end(() => res()))) }
    sock = t.protocol === 'tls'
      ? tls.connect({ host: t.host, port: t.port!, rejectUnauthorized: t.tls_verify, servername: net.isIP(t.host) ? undefined : t.host }, done)
      : net.connect({ host: t.host, port: t.port! }, done)
    sock.once('error', rej)
  }), 8000, () => sock?.destroy())
}
async function sendHttps(t: SiemTarget, lines: string[]): Promise<void> {
  const bad = webhookUrlError(t.url); if (bad) throw new Error(bad)
  const headers: Record<string, string> = { 'Content-Type': t.format === 'json' ? 'application/x-ndjson' : 'text/plain; charset=utf-8', 'User-Agent': 'DDI-Buntu-siem/1' }
  const secret = plain(t.secret_enc)
  if (secret) headers.Authorization = `${t.auth_prefix} ${secret}`.trim()
  const ac = new AbortController(), timer = setTimeout(() => ac.abort(), 10000)
  try {
    const res = await fetch(t.url, { method: 'POST', headers, body: lines.join('\n') + '\n', redirect: 'manual', signal: ac.signal })
    await res.arrayBuffer().catch(() => undefined)
    if (res.status < 200 || res.status >= 300) throw new Error(`http ${res.status}`)
  } finally { clearTimeout(timer) }
}
export async function deliver(t: SiemTarget, events: SiemEvent[]): Promise<void> {
  const ctx = { host: hostname().split('.')[0]!, version: installedVersion() || '0', facility: t.facility }
  const lines = events.map((e) => formatEvent(t.format, e, ctx))
  if (t.protocol === 'udp') return sendUdp(t.host, t.port!, lines)
  if (t.protocol === 'https') return sendHttps(t, lines)
  return sendStream(t, lines)
}

export function testEvent(): SiemEvent {
  return { source: 'test', id: null, at: new Date(), severity: 6, event: 'test', message: 'Événement de test Ipnoria : la destination fonctionne.', fields: { outcome: 'success' } }
}

/** Un passage : pour chaque destination active et chaque flux choisi, au plus BATCH événements. */
let running = false
export async function runSiem(opts: { only?: number } = {}): Promise<{ targets: number; sent: number; failed: number }> {
  if (running) return { targets: 0, sent: 0, failed: 0 }
  running = true
  let sent = 0, failed = 0, n = 0
  try {
    const targets = await query<SiemTarget>(`select * from siem_targets where enabled ${opts.only ? 'and id = $1' : ''} order by id`, opts.only ? [opts.only] : [])
    for (const t of targets) {
      n++
      const cursors: Record<string, number> = { ...(t.cursors ?? {}) }
      let ok = true, err = '', count = 0
      const sources = (t.sources ?? []).filter((s): s is SiemSource => (SIEM_SOURCES as readonly string[]).includes(s))
      for (const s of sources) {
        if (s === 'dns_blocked' && sources.includes('dns_queries')) continue    // déjà couvert par « toutes les requêtes »
        try {
          if (cursors[s] === undefined) cursors[s] = (await currentCursors([s]))[s] ?? 0
          const ev = await READERS[s](cursors[s]!, BATCH)
          if (!ev.length) continue
          await deliver(t, ev)
          cursors[s] = Math.max(...ev.map((e) => e.id ?? 0)); count += ev.length
        } catch (e) { ok = false; err = reason(e); break }   // on réessaie au prochain passage, à partir du même curseur
      }
      if (sources.includes('dns_queries') && cursors.dns_queries !== undefined) cursors.dns_blocked = cursors.dns_queries
      sent += count; if (!ok) failed++
      await query('update siem_targets set cursors = $2::jsonb, sent = sent + $3, last_at = case when $3 > 0 or not $4 then now() else last_at end, last_ok = case when $3 > 0 or not $4 then $4 else last_ok end, last_error = case when $4 then (case when $3 > 0 then \'\' else last_error end) else $5 end where id = $1',
        [t.id, JSON.stringify(cursors), count, ok, err])
    }
  } finally { running = false }
  void sev
  return { targets: n, sent, failed }
}
