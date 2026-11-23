// Assistant IA (0.23.0) : réglages et test du serveur de modèles (administrateurs), état (tout utilisateur connecté),
// explications à la demande (opérateurs ; journal d'audit réservé aux administrateurs, comme sa lecture).
// Le navigateur n'envoie qu'une référence (numéro d'événement, ligne du journal) : le contexte est relu et nettoyé ici.
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import type { Ctx } from '../utils/router'
import { getSetting, one, query, setSetting } from '../utils/db'
import { decryptSecret, encryptSecret } from '../utils/auth'
import { readJournal } from '../utils/radius-journal'
import { AD_DEFAULTS } from '../utils/ad'
import type { AdSettings } from '../utils/ad'
import { OIDC_DEFAULTS } from '../utils/oidc'
import type { OidcSettings } from '../utils/oidc'
import type { JournalEvent } from '../utils/radius-journal'
import {
  AI_DEFAULTS, AI_USES, AiError, PROMPT_VERSION, Pseudonymizer, REASON_MEANING, auditMeaning, buildMessages, cacheGet, cacheKey, cachePut, chat, listModels, parseAiUrl, pseudoDeep, redact, resetAiState, takeQuota, withSlot,
} from '../utils/ai'
import type { AiLang, AiSettings, AiUse, HttpOpts } from '../utils/ai'

export const registered = true

const aiErr = (e: unknown): never => { if (e instanceof AiError) fail(e.status, e.code, undefined, e.upstream ? { upstream: e.upstream } : undefined); throw e }
const load = async (): Promise<AiSettings> => { const s = await getSetting<Partial<AiSettings>>('ai', {}); return { ...AI_DEFAULTS, ...s, uses: { ...AI_DEFAULTS.uses, ...(s.uses ?? {}) } } }
const keyOf = (s: AiSettings, given?: string) => (given ? given : s.keyEnc ? decryptSecret(s.keyEnc) : undefined)
const opts = (s: { tlsVerify: boolean; caPem?: string; timeoutSec?: number }, key?: string, timeoutMs?: number): HttpOpts =>
  ({ key, verify: s.tlsVerify, ca: s.caPem || undefined, timeoutMs: timeoutMs ?? (s.timeoutSec ?? 60) * 1000 })
const ready = (s: AiSettings) => s.enabled && !!s.url && !!s.model

const CA = z.string().max(20000).regex(/^(?:-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----\s*)?$/)
const conn = { api: z.enum(['ollama', 'openai']), url: z.string().trim().max(500), tlsVerify: z.boolean(), caPem: CA.optional(), allowHttp: z.boolean() }
const uses = z.object(Object.fromEntries(AI_USES.map((u) => [u, z.boolean()])) as Record<AiUse, z.ZodBoolean>)

// Ce que l'interface doit savoir pour afficher (ou non) les boutons « Expliquer » ; ni adresse ni clé.
route('GET', '/ai/status', 'viewer', async () => {
  const s = await load()
  const on = ready(s)
  return { enabled: on, model: on ? s.model : null, uses: Object.fromEntries(AI_USES.map((u) => [u, on && s.uses[u]])) }
})

route('GET', '/ai/settings', 'admin', async () => { const { keyEnc, ...s } = await load(); return { ...s, keySet: !!keyEnc, useList: AI_USES } })

route('PUT', '/ai/settings', 'admin', async (c) => {
  const b = await c.body(z.object({
    enabled: z.boolean(), ...conn, model: z.string().trim().max(200).regex(/^[\w.:/@+-]*$/), key: z.string().trim().max(500).optional(),
    timeoutSec: z.number().int().min(10).max(300), pseudonymize: z.boolean(), perHour: z.number().int().min(1).max(500), uses,
  }).strict())
  if (b.url) { try { parseAiUrl(b.url, b.allowHttp) } catch (e) { aiErr(e) } }
  if (b.enabled && (!b.url || !b.model)) fail(400, 'ai_incomplete')
  const cur = await load()
  const { key, ...rest } = b
  const keyEnc = key === undefined ? cur.keyEnc : key ? encryptSecret(key) : undefined   // absente = inchangée, vide = effacée
  await setSetting('ai', { ...rest, caPem: rest.caPem || undefined, ...(keyEnc ? { keyEnc } : {}) })
  resetAiState()
  await audit(c, 'ai.settings', 'settings', 'ai', { enabled: b.enabled, api: b.api, host: b.url ? new URL(b.url).host : null, model: b.model, pseudonymize: b.pseudonymize, uses: b.uses, keySet: !!keyEnc })
  return { ok: true }
})

// Connexion et liste des modèles du serveur (rien n'est envoyé d'autre qu'une lecture) : sert à remplir le choix du modèle.
route('POST', '/ai/test', 'admin', async (c) => {
  const b = await c.body(z.object({ ...conn, key: z.string().trim().max(500).optional(), model: z.string().trim().max(200).optional() }).strict())
  const s = await load()
  try {
    const base = parseAiUrl(b.url, b.allowHttp)
    const r = await listModels(b.api, base, opts(b, keyOf(s, b.key), 15_000))
    return { ok: true, version: r.version, models: r.models, modelFound: b.model ? r.models.includes(b.model) : null }
  } catch (e) { return aiErr(e) }
})

// ---------------------------------------------------------------------------------------------
// Contextes : relus côté serveur, sans secret

async function auditContext(id: string) {
  const r = await one<any>(`select id, at, coalesce(username, detail->>'username') as username, action, entity, entity_id, detail, host(ip) as ip from audit_log where id = $1`, [id])
  if (!r) fail(404, 'not_found')
  const d = r.detail && typeof r.detail === 'object' ? r.detail : {}
  const reason = typeof d.reason === 'string' ? d.reason : undefined
  const ev: Record<string, unknown> = {
    action: r.action, meaning: auditMeaning(r.action), at: new Date(r.at).toISOString(), user: r.username ?? null, entity: r.entity ?? null, entity_id: r.entity_id ?? null, ip: r.ip ?? null,
    detail: r.detail ?? null, reason_meaning: reason ? REASON_MEANING[reason] : undefined,
    tried: Array.isArray(d.tried) ? d.tried.map((t: any) => ({ ...t, meaning: REASON_MEANING[t?.result] })) : undefined,
  }
  // événements proches du même compte ou de la même adresse : c'est souvent l'enchaînement qui explique (formats d'identifiant, rafale, blocage).
  // Les demandes à l'assistant elles-mêmes sont exclues : sinon chaque explication changerait le contexte de la suivante (et la mémoire ne servirait jamais).
  const near = await query<any>(`select at, action, coalesce(username, detail->>'username') as username, host(ip) as ip, detail->>'reason' as reason from audit_log
    where id <> $1 and action not like 'ai.%' and at between $2::timestamptz - interval '30 minutes' and $2::timestamptz + interval '30 minutes'
      and ((ip is not null and host(ip) = $3) or ($4::text is not null and lower(coalesce(username, detail->>'username')) = lower($4)))
    order by abs(extract(epoch from at - $2::timestamptz)) limit 12`, [r.id, r.at, r.ip, r.username ?? null])
  if (near.length) ev.related_events = near.sort((a, b) => +new Date(a.at) - +new Date(b.at)).map((x) => ({ at: new Date(x.at).toISOString(), action: x.action, user: x.username ?? undefined, ip: x.ip ?? undefined, reason: x.reason ?? undefined }))
  if (/^login|^mfa_|^sso/.test(r.action)) {
    const ad = await getSetting<AdSettings>('ad', AD_DEFAULTS), ld = await getSetting<any>('ldap', {}), oidc = await getSetting<OidcSettings>('oidc', OIDC_DEFAULTS)
    ev.auth_config = {
      local_accounts: true,
      active_directory: ad.enabled ? { enabled: true, login_attribute: ad.userAttr, expected_username: ad.userAttr === 'userPrincipalName' ? 'user@domain (UPN)' : 'short name (sAMAccountName), without domain', domain_backslash_form_accepted: false, mapped_groups: ad.groupMap.length } : { enabled: false },
      ldap: { enabled: !!ld?.enabled }, sso_oidc: { enabled: !!oidc.enabled },
      lockout: '5 failures per account or 30 per address within 15 minutes block sign-in for 15 minutes',
    }
  }
  return ev
}

const evData = (e: JournalEvent) => ({
  at: new Date(e.at).toISOString(), result: e.kind, why: e.why, reason: e.reason || undefined, user: e.user || undefined, identity: e.identity || undefined,
  device: e.client || undefined, device_ip: e.nas || undefined, mac: e.mac || undefined, called_station: e.called || undefined, nas_id: e.nasId || undefined,
  cert_subject: e.subject || undefined, cert_issuer: e.issuer || undefined, cert_expires: e.expires || undefined, upn: e.upn || undefined, dns: e.dns || undefined,
  rule: e.decision || undefined, console_test: e.selftest || undefined,
})

async function radiusContext(b: { at: number; kind: string; mac: string; user: string }) {
  const r = await readJournal({ since: b.at, limit: 1000, selftest: true, q: b.mac || b.user || undefined })
  const e = r.events.find((x) => x.at === b.at && x.kind === b.kind && x.mac === b.mac && x.user === b.user)
  if (!e) fail(404, 'ai_event_gone')   // fichier tourné, ou ligne d'un autre nœud
  return evData(e)
}

const top = (m: Map<string, number>, n: number, key: string) => [...m].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ [key]: k, n: v }))
const bump = (m: Map<string, number>, k: string) => { if (k) m.set(k, (m.get(k) ?? 0) + 1) }

async function radiusSummaryContext(minutes: number) {
  const now = Date.now()
  const r = await readJournal({ since: now - minutes * 60_000, limit: 1000 }, now)
  const counts = { accept: 0, reject: 0, diag: 0 }
  const why = new Map<string, number>(), devices = new Map<string, number>(), who = new Map<string, number>(), unknown = new Map<string, number>(), okDevices = new Map<string, number>()
  for (const e of r.events) {
    counts[e.kind]++
    if (e.kind === 'accept') { bump(okDevices, e.client || e.nas); continue }
    bump(why, e.why)
    if (e.why === 'unknown_client') bump(unknown, e.nas)
    else { bump(devices, e.client || e.nas); bump(who, e.identity || e.upn || e.user || e.mac) }
  }
  return {
    period_minutes: minutes, events_read: r.events.length, window_full: r.events.length >= 1000, file_truncated: r.truncated,
    first: r.events.length ? new Date(r.events[r.events.length - 1]!.at).toISOString() : null, last: r.events.length ? new Date(r.events[0]!.at).toISOString() : null,
    counts, reject_reasons: top(why, 10, 'why'), rejects_by_device: top(devices, 8, 'device'), rejects_by_identity: top(who, 10, 'identity').filter((x) => x.n >= 2),
    unknown_devices: top(unknown, 8, 'device_ip'), accepts_by_device: top(okDevices, 5, 'device'),
  }
}

// ---------------------------------------------------------------------------------------------

const lang = z.enum(['fr', 'en']).default('fr')
const refresh = z.boolean().default(false)
const Explain = z.discriminatedUnion('use', [
  // numéro d'événement : bigint, rendu en texte par la base (et donc par l'interface)
  z.object({ use: z.literal('audit'), id: z.union([z.number().int().positive(), z.string().regex(/^[1-9]\d{0,17}$/)]).transform(String), lang, refresh }).strict(),
  z.object({ use: z.literal('radius'), at: z.number().int().positive(), kind: z.enum(['accept', 'reject', 'diag']), mac: z.string().max(64), user: z.string().max(300), lang, refresh }).strict(),
  z.object({ use: z.literal('radius_summary'), minutes: z.number().int().min(15).max(10080), lang, refresh }).strict(),
])

async function contextFor(c: Ctx, b: z.infer<typeof Explain>): Promise<{ data: unknown; ref: string }> {
  if (b.use === 'audit') {
    if (c.user?.role !== 'admin') fail(403, 'forbidden')   // le journal d'audit n'est lisible que par les administrateurs
    return { data: await auditContext(b.id), ref: String(b.id) }
  }
  if (b.use === 'radius') return { data: await radiusContext(b), ref: `${b.at}:${b.kind}` }
  return { data: await radiusSummaryContext(b.minutes), ref: `${b.minutes}min` }
}

route('POST', '/ai/explain', 'operator', async (c) => {
  const b = await c.body(Explain)
  const s = await load()
  if (!ready(s)) fail(409, 'ai_disabled')
  if (!s.uses[b.use]) fail(409, 'ai_use_disabled')
  const { data, ref } = await contextFor(c, b)
  const clean = redact(data)
  const key = cacheKey([PROMPT_VERSION, b.use, b.lang, s.api, s.url, s.model, s.pseudonymize, clean])
  if (!b.refresh) { const hit = cacheGet(key); if (hit) return { text: hit, model: s.model, cached: true, pseudonymized: s.pseudonymize, ms: 0 } }
  if (!takeQuota(c.user!.username, s.perHour)) fail(429, 'ai_quota')
  const p = new Pseudonymizer()
  const sent = s.pseudonymize ? pseudoDeep(clean, p) : clean
  const t0 = Date.now()
  let text: string
  try {
    const base = parseAiUrl(s.url, s.allowHttp)
    const answer = await withSlot(() => chat(s.api, base, s.model, buildMessages(b.use, b.lang as AiLang, sent, s.pseudonymize), opts(s, keyOf(s))))
    text = s.pseudonymize ? p.restore(answer) : answer
  } catch (e) {
    // seul le code est consigné : ni la question, ni la réponse, ni les données envoyées
    await audit(c, 'ai.explain', 'ai', b.use, { ref, model: s.model, ok: false, error: e instanceof AiError ? e.code : 'internal', ms: Date.now() - t0 })
    return aiErr(e)
  }
  const ms = Date.now() - t0
  cachePut(key, text)
  await audit(c, 'ai.explain', 'ai', b.use, { ref, model: s.model, ok: true, ms, pseudonymized: s.pseudonymize, masked: p.size })
  return { text, model: s.model, cached: false, pseudonymized: s.pseudonymize, ms }
})
