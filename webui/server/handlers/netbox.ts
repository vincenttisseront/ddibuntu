// Import depuis NetBox : paramètres, test, aperçu (aucune écriture), import confirmé. Réservé aux administrateurs.
import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { getPool, getSetting, setSetting, tx } from '../utils/db'
import { decryptSecret, encryptSecret } from '../utils/auth'
import { NB_DEFAULTS, NetboxError, applyNetbox, fetchAll, loadExisting, netboxVersion, normalizeNetbox, parseBaseUrl, planNetbox } from '../utils/netbox'
import type { NbData, NetboxSettings, PlanOpts } from '../utils/netbox'
import { preImportSnapshot, record } from './importer'

const nbErr = (e: unknown): never => { if (e instanceof NetboxError) fail(e.status, e.code, undefined, e.upstream ? { upstream: e.upstream } : undefined); throw e }
const CA = z.string().max(20000).regex(/^(|-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----\s*)$/)
const include = z.object({ vlans: z.boolean(), prefixes: z.boolean(), addresses: z.boolean() })
const common = { url: z.string().min(8).max(500), tlsVerify: z.boolean(), caPem: CA.optional(), include, mode: z.enum(['add', 'sync', 'sync_overwrite']), prune: z.boolean(), includeContainers: z.boolean() }

const load = () => getSetting<NetboxSettings>('netbox', NB_DEFAULTS)
const tokenFor = (s: NetboxSettings, given?: string) => { const t = given || (s.tokenEnc ? decryptSecret(s.tokenEnc) : ''); if (!t) fail(400, 'netbox_token_missing'); return t }

route('GET', '/netbox/settings', 'admin', async () => { const { tokenEnc, ...s } = { ...NB_DEFAULTS, ...(await load()) }; return { ...s, tokenSet: !!tokenEnc } })
route('PUT', '/netbox/settings', 'admin', async (c) => {
  const b = await c.body(z.object({ ...common, token: z.string().trim().max(300).optional(), rememberToken: z.boolean().default(false) }))
  try { parseBaseUrl(b.url) } catch (e) { nbErr(e) }
  const cur = await load()
  const { token, rememberToken, ...rest } = b
  // le jeton n'est conservé (chiffré) que sur demande explicite ; sinon il n'existe que le temps de l'import
  const tokenEnc = rememberToken ? (token ? encryptSecret(token) : cur.tokenEnc) : undefined
  await setSetting('netbox', { ...rest, ...(tokenEnc ? { tokenEnc } : {}) })
  await audit(c, 'netbox_settings', 'settings', 'netbox', { url: b.url, mode: b.mode, remember: rememberToken })
  return { ok: true }
})

route('POST', '/netbox/test', 'admin', async (c) => {
  const b = await c.body(z.object({ url: common.url, tlsVerify: common.tlsVerify, caPem: common.caPem, token: z.string().trim().max(300).optional() }))
  const s = await load()
  try { return { ok: true, version: await netboxVersion(parseBaseUrl(b.url), { token: tokenFor(s, b.token), verify: b.tlsVerify, ca: b.caPem || undefined, timeoutMs: 15000 }) } } catch (e) { return nbErr(e) }
})

// Les données récupérées pour l'aperçu sont gardées en mémoire (30 min) : l'import écrit EXACTEMENT ce qui a été prévisualisé.
interface Stored { at: number; data: NbData; opts: PlanOpts; url: string; user: string }
const plans = new Map<string, Stored>()
const sweep = () => { const lim = Date.now() - 30 * 60_000; for (const [k, v] of plans) if (v.at < lim) plans.delete(k); while (plans.size > 5) plans.delete(plans.keys().next().value as string) }

route('POST', '/netbox/preview', 'admin', async (c) => {
  const b = await c.body(z.object({ ...common, token: z.string().trim().max(300).optional() }))
  const s = await load()
  let data: NbData
  try {
    const base = parseBaseUrl(b.url), o = { token: tokenFor(s, b.token), verify: b.tlsVerify, ca: b.caPem || undefined }
    const raw = { vlans: b.include.vlans ? await fetchAll(base, 'ipam/vlans', o) : [], prefixes: b.include.prefixes ? await fetchAll(base, 'ipam/prefixes', o) : [], addresses: b.include.addresses ? await fetchAll(base, 'ipam/ip-addresses', o) : [] }
    data = normalizeNetbox(raw)
  } catch (e) { return nbErr(e) }
  const opts: PlanOpts = { include: b.include, mode: b.mode, prune: b.prune, includeContainers: b.includeContainers }
  const plan = planNetbox(data, await loadExisting(getPool()), opts)
  sweep()
  const planId = randomUUID()
  plans.set(planId, { at: Date.now(), data, opts, url: b.url, user: c.user!.username })
  await audit(c, 'netbox_preview', 'netbox', undefined, { url: b.url, fetched: { vlans: data.vlans.length, prefixes: data.prefixes.length, addresses: data.addresses.length } })
  return { planId, fetched: { vlans: data.vlans.length, prefixes: data.prefixes.length, addresses: data.addresses.length }, stats: plan.stats, samples: plan.samples }
})

route('POST', '/netbox/commit', 'admin', async (c) => {
  const b = await c.body(z.object({ planId: z.string().uuid() }))
  sweep()
  const st = plans.get(b.planId)
  if (!st || st.user !== c.user!.username) fail(404, 'plan_expired')
  plans.delete(b.planId)
  const snapshotId = await preImportSnapshot(c, `avant import NetBox (${new URL(st.url).host})`)
  const out = await tx(async (cl) => {
    // l'état est relu DANS la transaction : le plan est recalculé sur la base telle qu'elle est à cet instant
    const plan = planNetbox(st.data, await loadExisting(cl), st.opts)
    await applyNetbox(cl, plan)
    return plan.stats
  })
  const res = { ...out, snapshotId }
  await record(c, 'netbox', new URL(st.url).host, res, snapshotId)
  await audit(c, 'netbox_import', 'netbox', undefined, { host: new URL(st.url).host, snapshotId, mode: st.opts.mode })
  return res
})

export const registered = true
