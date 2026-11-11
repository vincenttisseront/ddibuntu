// Envoi des notifications : webhook JSON (signature HMAC optionnelle) et e-mail (SMTP). Ne lève jamais vers l'appelant : chaque canal rend son résultat.
import { createHmac } from 'node:crypto'
import { hostname } from 'node:os'
import { describe, SEVERITY_LABEL } from './alert-text'
import { plain, webhookUrlError } from './alert-config'
import type { AlertConfig } from './alert-config'
import { sendMail } from './smtp'

export type Kind = 'firing' | 'resolved' | 'repeat' | 'test'
export interface NotifyEvent { id: number | null; rule: string; severity: string; node: string; subject: string; params: Record<string, any>; startedAt: Date; resolvedAt: Date | null }
export interface Delivery { channel: 'webhook' | 'email'; ok: boolean; detail: string }
const LABEL: Record<'fr' | 'en', Record<Kind, string>> = { fr: { firing: '', resolved: 'RÉSOLU', repeat: 'RAPPEL', test: 'TEST' }, en: { firing: '', resolved: 'RESOLVED', repeat: 'REMINDER', test: 'TEST' } }

export function render(cfg: AlertConfig, ev: NotifyEvent, kind: Kind, cluster: string) {
  const lang = cfg.lang
  const text = ev.rule === 'test' ? (lang === 'en' ? 'Test notification from DDI-Buntu: the channel works.' : 'Notification de test de DDI-Buntu : le canal fonctionne.') : describe(ev.rule, ev.node, ev.subject, ev.params, lang)
  const head = kind === 'firing' ? SEVERITY_LABEL[lang][ev.severity] ?? ev.severity.toUpperCase() : `${LABEL[lang][kind]}${kind === 'test' ? '' : ' · ' + (SEVERITY_LABEL[lang][ev.severity] ?? ev.severity)}`
  const where = cluster || hostname().split('.')[0]!
  return { title: `[${head}] ${where}`, text, line: `[${head}] ${where} — ${text}` }
}

// Les messages d'erreur ne contiennent jamais l'adresse ni les identifiants : seulement un code lisible.
const reason = (e: any): string => String(e?.code ?? e?.message ?? e?.name ?? 'error').replace(/[^A-Za-z0-9 _:.-]/g, '').slice(0, 120)

export async function sendWebhook(cfg: AlertConfig, ev: NotifyEvent, kind: Kind, cluster: string): Promise<Delivery> {
  try {
    const bad = webhookUrlError(cfg.webhook.url); if (bad) throw new Error(bad)
    const r = render(cfg, ev, kind, cluster)
    const body = JSON.stringify({
      version: 1, source: 'ddibuntu', kind, cluster: cluster || null, text: r.line,
      alert: { id: ev.id, rule: ev.rule, severity: ev.severity, node: ev.node, subject: ev.subject, title: r.title, message: r.text, startedAt: ev.startedAt.toISOString(), resolvedAt: ev.resolvedAt ? ev.resolvedAt.toISOString() : null, params: ev.params },
    })
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'User-Agent': 'DDI-Buntu-alerts/1' }
    const secret = plain(cfg.webhook.secretEnc)
    if (secret) headers['X-DDIbuntu-Signature'] = 'sha256=' + createHmac('sha256', secret).update(body).digest('hex')
    const ac = new AbortController(), t = setTimeout(() => ac.abort(), 8000)
    try {
      const res = await fetch(cfg.webhook.url, { method: 'POST', headers, body, redirect: 'manual', signal: ac.signal })
      await res.arrayBuffer().catch(() => undefined)
      if (res.status < 200 || res.status >= 300) throw new Error(`http ${res.status}`)
      return { channel: 'webhook', ok: true, detail: `http ${res.status}` }
    } finally { clearTimeout(t) }
  } catch (e) { return { channel: 'webhook', ok: false, detail: reason(e) } }
}

export async function sendEmail(cfg: AlertConfig, ev: NotifyEvent, kind: Kind, cluster: string): Promise<Delivery> {
  try {
    const e = cfg.email, r = render(cfg, ev, kind, cluster)
    await sendMail({
      host: e.host, port: e.port, security: e.security, verifyCert: e.verifyCert, user: e.user || undefined, pass: plain(e.passEnc) || undefined, from: e.from, to: e.to,
      subject: `${r.title} ${r.text}`.slice(0, 150), text: `${r.text}\r\n\r\n${cfg.lang === 'en' ? 'Rule' : 'Règle'}: ${ev.rule}\r\n${cfg.lang === 'en' ? 'Node' : 'Nœud'}: ${ev.node || '-'}\r\n${cfg.lang === 'en' ? 'Since' : 'Depuis'}: ${ev.startedAt.toISOString()}\r\n`,
      heloName: hostname().split('.')[0],
    })
    return { channel: 'email', ok: true, detail: 'sent' }
  } catch (e) { return { channel: 'email', ok: false, detail: reason(e) } }
}

// Tous les canaux activés ; liste vide = aucun canal (rien n'est tenté, rien n'est compté comme échec).
export async function notifyAll(cfg: AlertConfig, ev: NotifyEvent, kind: Kind, cluster: string): Promise<Delivery[]> {
  const jobs: Array<Promise<Delivery>> = []
  if (cfg.webhook.enabled) jobs.push(sendWebhook(cfg, ev, kind, cluster))
  if (cfg.email.enabled) jobs.push(sendEmail(cfg, ev, kind, cluster))
  return Promise.all(jobs)
}
