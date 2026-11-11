// Réglages des alertes (table settings) : seuils, canaux de notification, jeton Prometheus. Les secrets sont chiffrés (AES-256-GCM) et jamais renvoyés.
import { z } from 'zod'
import { decryptSecret, encryptSecret, safeEqual, sha256hex } from './auth'
import { getSetting, setSetting } from './db'
import { ADDRESS_RE } from './smtp'
import { DEFAULT_THRESHOLDS } from './alert-rules'
import type { Thresholds } from './alert-rules'
import type { Lang } from './alert-text'

export interface AlertConfig {
  minSeverity: 'info' | 'warning' | 'critical'; repeatHours: number; lang: Lang; thresholds: Thresholds
  webhook: { enabled: boolean; url: string; secretEnc: string | null }
  email: { enabled: boolean; host: string; port: number; security: 'none' | 'starttls' | 'tls'; verifyCert: boolean; user: string; passEnc: string | null; from: string; to: string[] }
}
export const DEFAULT_CONFIG: AlertConfig = {
  minSeverity: 'warning', repeatHours: 0, lang: 'fr', thresholds: DEFAULT_THRESHOLDS,
  webhook: { enabled: false, url: '', secretEnc: null },
  email: { enabled: false, host: '', port: 587, security: 'starttls', verifyCert: true, user: '', passEnc: null, from: '', to: [] },
}

// Adresse de destination d'un webhook : http(s) uniquement, jamais l'adresse « métadonnées » des nuages ni le lien local (192.0.2.x et 10.x restent permis : c'est un outil interne).
export function webhookUrlError(u: string): string | null {
  let url: URL
  try { url = new URL(u) } catch { return 'webhook_url_invalid' }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'webhook_url_invalid'
  if (url.username || url.password) return 'webhook_url_credentials'
  const h = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (/^169\.254\./.test(h) || /^fe[89ab][0-9a-f]:/.test(h) || h === 'metadata.google.internal') return 'webhook_url_forbidden'
  return null
}

const Num = (min: number, max: number) => z.number().min(min).max(max)
export const ConfigInput = z.object({
  minSeverity: z.enum(['info', 'warning', 'critical']), repeatHours: z.number().int().min(0).max(168), lang: z.enum(['fr', 'en']),
  thresholds: z.object({
    diskWarn: Num(50, 99), diskCrit: Num(50, 100), certWarnDays: z.number().int().min(1).max(365), certCritDays: z.number().int().min(0).max(365),
    lagMiB: z.number().int().min(1).max(100000), backupMaxAgeHours: z.number().int().min(0).max(720), subnetWarn: Num(50, 100), subnetCrit: Num(50, 100),
  }).strict().refine((t) => t.diskCrit >= t.diskWarn && t.certCritDays <= t.certWarnDays && t.subnetCrit >= t.subnetWarn, { message: 'thresholds_order' }),
  webhook: z.object({ enabled: z.boolean(), url: z.string().max(500), secret: z.string().max(200).nullable().optional() }).strict(),
  email: z.object({
    enabled: z.boolean(), host: z.string().max(253), port: z.number().int().min(1).max(65535), security: z.enum(['none', 'starttls', 'tls']), verifyCert: z.boolean(),
    user: z.string().max(200), password: z.string().max(200).nullable().optional(), from: z.string().max(254), to: z.array(z.string().max(254)).max(10),
  }).strict(),
}).strict()
export type ConfigInputT = z.infer<typeof ConfigInput>

// Contrôles croisés (retourne le code d'erreur 400 ou null)
export function configError(c: ConfigInputT): string | null {
  if (c.webhook.enabled) { const e = webhookUrlError(c.webhook.url); if (e) return e }
  else if (c.webhook.url) { const e = webhookUrlError(c.webhook.url); if (e) return e }
  if (c.email.enabled) {
    if (!/^[A-Za-z0-9.:-]{1,253}$/.test(c.email.host)) return 'email_host_invalid'
    if (!ADDRESS_RE.test(c.email.from)) return 'email_from_invalid'
    if (c.email.to.length === 0 || !c.email.to.every((a) => ADDRESS_RE.test(a))) return 'email_to_invalid'
    if (c.email.user && c.email.security === 'none') return 'email_auth_requires_tls'
  }
  return null
}

export async function loadConfig(): Promise<AlertConfig> {
  const s = await getSetting<Partial<AlertConfig>>('alerts_config', {})
  return { ...DEFAULT_CONFIG, ...s, thresholds: { ...DEFAULT_THRESHOLDS, ...(s.thresholds ?? {}) }, webhook: { ...DEFAULT_CONFIG.webhook, ...(s.webhook ?? {}) }, email: { ...DEFAULT_CONFIG.email, ...(s.email ?? {}) } }
}
export async function saveConfig(input: ConfigInputT): Promise<void> {
  const cur = await loadConfig()
  const secret = (v: string | null | undefined, old: string | null) => (v === undefined ? old : v === null || v === '' ? null : encryptSecret(v))
  const next: AlertConfig = {
    minSeverity: input.minSeverity, repeatHours: input.repeatHours, lang: input.lang, thresholds: input.thresholds,
    webhook: { enabled: input.webhook.enabled, url: input.webhook.url, secretEnc: secret(input.webhook.secret, cur.webhook.secretEnc) },
    email: { enabled: input.email.enabled, host: input.email.host, port: input.email.port, security: input.email.security, verifyCert: input.email.verifyCert, user: input.email.user,
      passEnc: secret(input.email.password, cur.email.passEnc), from: input.email.from, to: input.email.to },
  }
  await setSetting('alerts_config', next)
}
// Vue publique : aucune valeur secrète, seulement leur présence.
export function publicConfig(c: AlertConfig, metricsToken: boolean) {
  return {
    minSeverity: c.minSeverity, repeatHours: c.repeatHours, lang: c.lang, thresholds: c.thresholds, metricsToken,
    webhook: { enabled: c.webhook.enabled, url: c.webhook.url, hasSecret: !!c.webhook.secretEnc },
    email: { enabled: c.email.enabled, host: c.email.host, port: c.email.port, security: c.email.security, verifyCert: c.email.verifyCert, user: c.email.user, hasPassword: !!c.email.passEnc, from: c.email.from, to: c.email.to },
  }
}
export const plain = (enc: string | null): string => { if (!enc) return ''; try { return decryptSecret(enc) } catch { return '' } }

// Jeton de l'export Prometheus : seul son empreinte est conservée ; le jeton lui-même n'est montré qu'une fois, à sa création.
export const hasMetricsToken = async (): Promise<boolean> => !!(await getSetting<string>('metrics_token_hash', ''))
export async function setMetricsToken(token: string | null): Promise<void> { await setSetting('metrics_token_hash', token ? sha256hex(token) : '') }
export async function metricsTokenValid(presented: string): Promise<boolean> {
  const h = await getSetting<string>('metrics_token_hash', '')
  return !!h && !!presented && safeEqual(sha256hex(presented), h)
}
