// Publication des autorités de la PKI dans l'Active Directory (0.14.2) : réglages (compte de service dédié, administrateur seulement), test de liaison sans écriture,
// publication à la demande, rapprochement, retrait explicite, script de repli. La publication courante est faite par la tâche de fond (plugins/pki-ad.ts).
// Le mot de passe du compte est chiffré au repos et n'est jamais renvoyé ni journalisé ; aucune clé privée n'existe côté console.
import { setResponseHeader } from 'h3'
import { z } from 'zod'
import { encryptSecret } from '../utils/auth'
import { query } from '../utils/db'
import { audit, fail, route } from '../utils/router'
import { CA_NAME_RE } from '../utils/pki-ca'
import { delegation, fallbackScript } from '../utils/pki-ad'
import type { AdReason } from '../utils/pki-ad'
import {
  complete, connection, eligibleCas, loadAd, loadState, publicationViews, RECONCILE_S, runPublication, saveAd, testAd, withdrawPublication,
} from '../utils/pki-ad-store'
import type { PkiAdSettings } from '../utils/pki-ad-store'
import { loadDir } from '../utils/radius-dir-store'

export const registered = true
const noCtl = /^[^\x00-\x1f\x7f]*$/
const body = z.object({
  enabled: z.boolean(), source: z.enum(['radius', 'own']),
  urls: z.array(z.string().regex(/^ldaps:\/\/[A-Za-z0-9._-]+(:\d{1,5})?$/, 'ldaps')).max(5), tlsRejectUnauthorized: z.boolean(),
  caPem: z.string().max(20000).regex(/^(?:-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----\s*)?$/).optional(),
  bindDn: z.string().trim().max(500).regex(noCtl), bindPassword: z.string().max(200).optional(), clearPassword: z.boolean().optional(),
  repair: z.enum(['auto', 'manual']),
}).strict()

const REASON_CODE = (r: AdReason | 'not_found' | 'disabled' | 'busy') => `pkiad_${r}`
const STATUS: Record<string, number> = { not_found: 404, disabled: 409, busy: 409, conflict: 409 }

async function view() {
  const s = await loadAd(), conn = await connection(s), dir = await loadDir()
  const [publications, state, el] = await Promise.all([publicationViews(), loadState(), eligibleCas()])
  const account = s.account?.upn || s.account?.sam || s.bindDn
  return {
    settings: { enabled: s.enabled, source: s.source, urls: s.urls, tlsRejectUnauthorized: s.tlsRejectUnauthorized, caSet: !!s.caPem, bindDn: s.bindDn, bindPasswordSet: !!s.bindPasswordEnc, repair: s.repair,
      configNc: s.configNc ?? null, account: s.account ?? null },
    connection: { source: s.source, urls: conn.urls, tlsRejectUnauthorized: conn.tlsRejectUnauthorized, caSet: !!conn.caPem, radiusServers: dir.urls.length },
    complete: complete(s, conn),
    publications, eligible: el.items.length, unreadable: el.unreadable,
    state: { lastRun: state.lastRun ?? null, lastReconcile: state.lastReconcile ?? null, reconcileEvery: RECONCILE_S },
    delegation: s.configNc ? delegation({ configNc: s.configNc, account, ...(s.account?.sid ? { sid: s.account.sid } : {}) }) : null,
  }
}

route('GET', '/pki/ad', 'admin', view)

route('PUT', '/pki/ad', 'admin', async (c) => {
  const b = await c.body(body)
  const cur = await loadAd()
  const { bindPassword, clearPassword, ...rest } = b
  const next: PkiAdSettings = { ...cur, ...rest, bindPasswordEnc: bindPassword ? encryptSecret(bindPassword) : clearPassword ? undefined : cur.bindPasswordEnc }
  if (b.caPem === '') delete next.caPem   // absent : le certificat enregistré est conservé (il n'est jamais renvoyé) ; chaîne vide : il est effacé
  // ce que le dernier test a appris n'est plus valable si le compte ou le serveur changent
  if (b.bindDn !== cur.bindDn || b.source !== cur.source || JSON.stringify(b.urls) !== JSON.stringify(cur.urls)) { delete next.configNc; delete next.account }
  if (b.enabled && !complete(next, await connection(next))) fail(400, 'pkiad_incomplete')
  await saveAd(next)
  await query("update pki_ad_publication set next_try_at = now() where state = 'failed'")   // un réglage corrigé : les échecs sont repris au prochain passage
  await audit(c, 'pki.ad_settings', 'pki_ad', undefined, { enabled: b.enabled, source: b.source, servers: b.urls.length, repair: b.repair, passwordChanged: !!bindPassword, tlsRejectUnauthorized: b.tlsRejectUnauthorized })
  return { ok: true }
})

// Test : liaison, partition Configuration, existence des deux conteneurs et droit d'y créer un objet (lu dans l'attribut calculé allowedChildClassesEffective : rien n'est écrit).
route('POST', '/pki/ad/test', 'admin', async (c) => {
  const s = await loadAd()
  if (!complete(s, await connection(s))) fail(400, 'pkiad_incomplete')
  const r = await testAd(s)
  if (r.ok) await saveAd({ ...(await loadAd()), configNc: r.configNc, ...(r.account ? { account: r.account } : {}) })
  await audit(c, 'pki.ad_test', 'pki_ad', undefined, r.ok ? { ok: true, server: r.server, containers: r.containers.map((x) => ({ container: x.container, exists: x.exists, canCreate: x.canCreate })) } : { ok: false, reason: r.reason })
  if (!r.ok) return r
  const account = r.account?.upn || r.account?.sam || s.bindDn
  return { ...r, delegation: delegation({ configNc: r.configNc, account, ...(r.account?.sid ? { sid: r.account.sid } : {}) }) }
})

// Publication à la demande : une autorité (`name`) ou toutes ; `republish` pour une autorité retirée par l'administrateur.
route('POST', '/pki/ad/publish', 'admin', async (c) => {
  const b = await c.body(z.object({ name: z.string().regex(CA_NAME_RE).optional(), republish: z.boolean().optional() }).strict())
  if (b.republish && !b.name) fail(400, 'validation')
  if (b.name && !(await eligibleCas()).items.some((i) => i.ca.name === b.name)) fail(404, 'not_found')
  const r = await runPublication({ trigger: 'manual', ...(b.name ? { only: b.name } : {}), ...(b.republish ? { republish: true } : {}), audit: (a, id, d) => audit(c, a, 'pki_ad', id, d) })
  if (r.status === 'disabled') fail(409, 'pkiad_disabled')
  if (r.status === 'incomplete') fail(400, 'pkiad_incomplete')
  if (r.status === 'busy') fail(409, 'pkiad_busy')
  await audit(c, 'pki.ad_run', 'pki_ad', b.name, r.status === 'done' ? { ...r.summary } : { status: r.status })
  return r.status === 'done' ? { status: 'done', summary: r.summary } : { status: r.status }
})

// Rapprochement à la demande : l'AD porte-t-il encore ce que le DDI y a publié ? (écart : republié si le réglage « auto » est choisi, sinon signalé)
route('POST', '/pki/ad/reconcile', 'admin', async (c) => {
  const r = await runPublication({ trigger: 'reconcile', audit: (a, id, d) => audit(c, a, 'pki_ad', id, d) })
  if (r.status === 'disabled') fail(409, 'pkiad_disabled')
  if (r.status === 'incomplete') fail(400, 'pkiad_incomplete')
  if (r.status === 'busy') fail(409, 'pkiad_busy')
  await audit(c, 'pki.ad_reconcile', 'pki_ad', undefined, r.status === 'done' ? { ...r.summary } : { status: r.status })
  return r.status === 'done' ? { status: 'done', summary: r.summary } : { status: r.status }
})

// Retrait explicite : jamais automatique (retirer une racine retire la confiance de toutes les machines du domaine). Confirmation par le nom de l'autorité.
route('POST', '/pki/ad/:name/withdraw', 'admin', async (c) => {
  const name = c.params.name ?? ''
  if (!CA_NAME_RE.test(name)) fail(404, 'not_found')
  const b = await c.body(z.object({ confirm: z.string().trim().max(100) }).strict())
  if (b.confirm.toLowerCase() !== name.toLowerCase()) fail(400, 'pkiad_confirm_mismatch')
  const r = await withdrawPublication(name, (a, id, d) => audit(c, a, 'pki_ad', id, d))
  if (!r.ok) fail(STATUS[r.reason] ?? 502, REASON_CODE(r.reason))
  return { ok: true, action: r.action }
})

// Repli sans compte délégué : script PowerShell (certutil -dspublish) à faire exécuter par un administrateur du domaine ; certificats publics intégrés.
route('GET', '/pki/ad/script', 'admin', async (c) => {
  const { items } = await eligibleCas()
  if (!items.length) fail(409, 'pkiad_no_ca')
  const sorted = [...items].sort((a, b) => (a.container === b.container ? a.ca.name.localeCompare(b.ca.name) : a.container === 'roots' ? -1 : 1))
  setResponseHeader(c.event, 'Content-Type', 'text/plain; charset=utf-8')
  setResponseHeader(c.event, 'Content-Disposition', 'attachment; filename="ddi-pki-publication-ad.ps1"')
  return Buffer.from(fallbackScript(sorted.map((i) => ({ name: i.ca.name, container: i.container, der: i.der }))), 'utf8')
})
