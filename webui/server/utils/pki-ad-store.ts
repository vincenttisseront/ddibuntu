// Publication des autorités de la PKI dans l'Active Directory (0.14.2) : réglages, exécuteur (tâche de fond et actions manuelles) et état par autorité.
// Une ligne de la table pki_ad_publication par autorité. La console ne publie QUE ce que root a publié (liste et certificats publics de la PKI) ; la clé
// privée d'une autorité n'est jamais ici. Un seul exécuteur à la fois (verrou de processus + verrou consultatif PostgreSQL : deux nœuds ne publient pas ensemble).
import { decryptSecret } from './auth'
import { getPool, getSetting, inRecovery, query, setSetting } from './db'
import { loadDir } from './radius-dir-store'
import { readCaFile, readPkiCas } from './pki-ca'
import type { PkiCa } from './pki-ca'
import {
  accountInfo, backoffSeconds, checkCa, checkContainers, classifyWrite, containerFor, defaultPkiLdapFactory, objectDn, pemToDer, publishCa, rootDse, sha256Hex, withdrawCa,
} from './pki-ad'
import type { AccountInfo, AdReason, Container, ContainerCheck, PkiLdap, PkiLdapFactory } from './pki-ad'

export const AD_KEY = 'pki_ad'
export const STATE_KEY = 'pki_ad_state'
export const RECONCILE_S = Number(process.env.DDI_PKI_AD_RECONCILE_S) || 86_400

export interface PkiAdSettings {
  enabled: boolean
  /** « radius » : serveurs, CA TLS et validation du certificat repris de l'annuaire RADIUS ; « own » : ceux de cette page. Le compte d'écriture est toujours le sien. */
  source: 'radius' | 'own'
  urls: string[]; tlsRejectUnauthorized: boolean; caPem?: string
  bindDn: string; bindPasswordEnc?: string
  /** Écart constaté au rapprochement : republier tout seul (« auto ») ou seulement signaler (« manual »). Le retrait n'est jamais automatique. */
  repair: 'auto' | 'manual'
  /** Remplis par le test de liaison. */
  configNc?: string; account?: AccountInfo
}
export const AD_DEFAULTS: PkiAdSettings = { enabled: false, source: 'radius', urls: [], tlsRejectUnauthorized: true, bindDn: '', repair: 'auto' }
export const loadAd = async (): Promise<PkiAdSettings> => ({ ...AD_DEFAULTS, ...(await getSetting<PkiAdSettings>(AD_KEY, AD_DEFAULTS)) })
export const saveAd = (s: PkiAdSettings) => setSetting(AD_KEY, s)

export interface Connection { urls: string[]; tlsRejectUnauthorized: boolean; caPem?: string }
export async function connection(s: PkiAdSettings): Promise<Connection> {
  if (s.source === 'own') return { urls: s.urls, tlsRejectUnauthorized: s.tlsRejectUnauthorized, ...(s.caPem ? { caPem: s.caPem } : {}) }
  const d = await loadDir()
  return { urls: d.urls, tlsRejectUnauthorized: d.tlsRejectUnauthorized, ...(d.caPem ? { caPem: d.caPem } : {}) }
}
/** Serveur, compte et mot de passe renseignés : de quoi essayer une liaison. */
export const complete = (s: PkiAdSettings, c: Connection) => c.urls.length > 0 && !!s.bindDn && !!s.bindPasswordEnc

export type Trigger = 'auto' | 'manual' | 'reconcile'
export interface RunSummary { at: number; trigger: Trigger; ok: boolean; reason?: AdReason; server?: string; published: number; unchanged: number; failed: number; conflicts: number; drift: number; checked: number }
export interface PkiAdState { lastRun?: RunSummary; lastReconcile?: number }
export const loadState = () => getSetting<PkiAdState>(STATE_KEY, {})

export type PubState = 'pending' | 'published' | 'failed' | 'conflict' | 'drift' | 'withdrawn'
export interface PubRow {
  ca_name: string; container: Container; dn: string; sha256: string; published_sha256: string | null; state: PubState; reason: string | null; attempts: number
  published_at: Date | null; checked_at: Date | null; next_try_at: Date | null
}

// ---- Session LDAP ----
export type AdSession<T> = { ok: true; server: string; value: T } | { ok: false; reason: AdReason; attempts: Array<{ server: string; reason: AdReason }> }
/** Ouvre une session de service sur le premier serveur qui répond (un refus d'identifiants prime sur un serveur injoignable dans le diagnostic). */
export async function withAd<T>(s: PkiAdSettings, conn: Connection, factory: PkiLdapFactory, fn: (c: PkiLdap, server: string) => Promise<T>): Promise<AdSession<T>> {
  const attempts: Array<{ server: string; reason: AdReason }> = []
  if (!s.bindPasswordEnc || !s.bindDn) return { ok: false, reason: 'bind', attempts }
  let pw: string
  try { pw = decryptSecret(s.bindPasswordEnc) } catch { return { ok: false, reason: 'bind', attempts } }
  for (const url of conn.urls) {
    const c = factory(url)
    try {
      try { await c.bind(s.bindDn, pw) } catch (e) { const r = classifyWrite(e); attempts.push({ server: url, reason: r === 'other' ? 'unreachable' : r }); continue }
      return { ok: true, server: url, value: await fn(c, url) }
    } catch (e) { attempts.push({ server: url, reason: classifyWrite(e) }) } finally { await c.unbind().catch(() => undefined) }
  }
  const reasons = attempts.map((a) => a.reason)
  const reason: AdReason = (['bind', 'tls', 'unreachable'] as const).find((r) => reasons.includes(r)) ?? reasons[0] ?? 'unreachable'
  return { ok: false, reason, attempts }
}
export const factoryFor = (conn: Connection): PkiLdapFactory => defaultPkiLdapFactory(conn)

// ---- Ce qu'il y a à publier ----
export interface Eligible { ca: PkiCa; container: Container; der: Buffer; sha: string }
/** Autorités publiables : racines et racines hors ligne (→ Certification Authorities), émettrices (→ AIA), actives ou externes, avec un certificat lisible. Jamais
 *  ManagementCA (l'autorité interne d'EJBCA) ni une autorité au nom que le DDI ne gère pas. */
export async function eligibleCas(): Promise<{ items: Eligible[]; unreadable: string[]; at: number | null }> {
  const pk = await readPkiCas()
  const items: Eligible[] = [], unreadable: string[] = []
  for (const ca of pk?.cas ?? []) {
    const container = containerFor(ca.kind)
    if (!container || !ca.managed || ca.name === 'ManagementCA' || !ca.files.cert || (ca.state !== 'active' && ca.state !== 'external')) continue
    const pem = await readCaFile(ca.name, 'cert'), der = pem ? pemToDer(pem) : null
    if (!der) { unreadable.push(ca.name); continue }
    items.push({ ca, container, der, sha: sha256Hex(der) })
  }
  return { items, unreadable, at: pk?.at ?? null }
}

/** Crée la ligne d'une autorité nouvelle ; un certificat qui a changé (renouvellement) remet la publication en attente — sauf si l'administrateur l'a retirée. */
async function syncRows(items: Eligible[]): Promise<void> {
  for (const i of items) {
    await query(`insert into pki_ad_publication (ca_name, container, sha256, state) values ($1,$2,$3,'pending')
      on conflict (ca_name) do update set container = excluded.container, sha256 = excluded.sha256, updated_at = now(),
        state = case when pki_ad_publication.sha256 <> excluded.sha256 and pki_ad_publication.state <> 'withdrawn' then 'pending' else pki_ad_publication.state end,
        attempts = case when pki_ad_publication.sha256 <> excluded.sha256 then 0 else pki_ad_publication.attempts end,
        next_try_at = case when pki_ad_publication.sha256 <> excluded.sha256 then null else pki_ad_publication.next_try_at end,
        reason = case when pki_ad_publication.sha256 <> excluded.sha256 then null else pki_ad_publication.reason end`, [i.ca.name, i.container, i.sha])
  }
}

// ---- Traçabilité ----
export type AuditFn = (action: string, id: string, detail: Record<string, unknown>) => Promise<void>
/** Audit d'une exécution automatique : acteur « système ». (Les actions de l'administrateur passent leur propre fonction, avec son nom.) */
export const auditSystem: AuditFn = async (action, id, detail) => {
  if (await inRecovery().catch(() => false)) return
  await query("insert into audit_log (user_id, username, action, entity, entity_id, detail, ip) values (null, 'système', $1, 'pki_ad', $2, $3::jsonb, null)", [action, id, JSON.stringify(detail)])
}

// ---- Exécuteur ----
let busy = false
/** Un seul exécuteur à la fois : verrou de processus, puis verrou consultatif PostgreSQL (une autre console du cluster ne publie pas en même temps). */
async function exclusive<T>(fn: () => Promise<T>): Promise<T | 'busy'> {
  if (busy) return 'busy'
  busy = true
  const c = await getPool().connect()
  try {
    const got = (await c.query('select pg_try_advisory_lock(727729) as ok')).rows[0]?.ok === true
    if (!got) return 'busy'
    try { return await fn() } finally { await c.query('select pg_advisory_unlock(727729)').catch(() => undefined) }
  } finally { c.release(); busy = false }
}

export interface RunOptions {
  trigger: Trigger
  /** Une seule autorité (action de l'administrateur). */
  only?: string
  /** Republier une autorité retirée (seulement avec `only`, jamais automatique). */
  republish?: boolean
  audit?: AuditFn
  factory?: PkiLdapFactory
}
export type RunResult = { status: 'disabled' | 'incomplete' | 'busy' | 'idle' } | { status: 'done'; summary: RunSummary }

const iso = (d: Date | null) => (d ? d.toISOString() : null)
const setRow = (name: string, f: Partial<Record<string, unknown>>) => {
  const cols = Object.keys(f), vals = Object.values(f)
  return query(`update pki_ad_publication set ${cols.map((c, i) => `${c} = $${i + 2}`).join(', ')}, updated_at = now() where ca_name = $1`, [name, ...vals])
}

export async function runPublication(o: RunOptions): Promise<RunResult> {
  const s = await loadAd()
  if (!s.enabled) return { status: 'disabled' }
  const conn = await connection(s)
  if (!complete(s, conn)) return { status: 'incomplete' }
  const r = await exclusive(() => doRun(s, conn, o))
  return r === 'busy' ? { status: 'busy' } : r
}

async function doRun(s: PkiAdSettings, conn: Connection, o: RunOptions): Promise<RunResult> {
  const audit = o.audit ?? auditSystem
  const { items } = await eligibleCas()
  await syncRows(items)
  const byName = new Map(items.map((i) => [i.ca.name, i]))
  const st = await loadState()
  const nowMs = Date.now()
  const reconcileDue = o.trigger === 'reconcile' || (o.trigger === 'auto' && nowMs / 1000 - (st.lastReconcile ?? 0) >= RECONCILE_S)
  const rows = (await query<PubRow>('select * from pki_ad_publication order by ca_name')).filter((r) => byName.has(r.ca_name) && (!o.only || r.ca_name === o.only))
  const manual = o.trigger === 'manual'
  const due = (r: PubRow) => !!r.next_try_at && r.next_try_at.getTime() <= nowMs
  const write: PubRow[] = [], check: PubRow[] = []
  for (const r of rows) {
    if (r.state === 'withdrawn') { if (manual && o.only && o.republish) write.push(r); continue }
    if (r.state === 'pending' || (manual && (r.state === 'failed' || r.state === 'conflict' || r.state === 'drift' || o.only))) write.push(r)
    else if (r.state === 'failed') { if (due(r)) write.push(r) }
    else if (r.state === 'drift') { if (s.repair === 'auto') write.push(r) }
    else if (r.state === 'published' && (reconcileDue || manual)) check.push(r)
  }
  if (!write.length && !check.length) return { status: 'idle' }

  const sum: RunSummary = { at: Math.floor(nowMs / 1000), trigger: o.trigger, ok: true, published: 0, unchanged: 0, failed: 0, conflicts: 0, drift: 0, checked: 0 }
  const fail = async (r: PubRow, reason: AdReason) => {
    const attempts = r.attempts + 1
    if (reason === 'conflict') { sum.conflicts++; await setRow(r.ca_name, { state: 'conflict', reason, attempts, next_try_at: null }) }
    else { sum.failed++; await setRow(r.ca_name, { state: 'failed', reason, attempts, next_try_at: new Date(nowMs + backoffSeconds(attempts - 1) * 1000) }) }
    await audit('pki.ad_failed', r.ca_name, { reason, attempts })
  }
  const sess = await withAd(s, conn, o.factory ?? factoryFor(conn), async (c, server) => {
    const dse = await rootDse(c)
    if ('error' in dse) throw Object.assign(new Error('configurationNamingContext invalide'), { code: -1, name: 'ConfigNcError' })
    const dnOf = (r: PubRow) => objectDn(dse.configNc, r.container, r.ca_name)
    const doWrite = async (r: PubRow) => {
      const it = byName.get(r.ca_name)!, dn = dnOf(r)
      await setRow(r.ca_name, { dn })
      const res = await publishCa(c, { dn, name: r.ca_name, der: it.der, owned: !!r.published_sha256 })
      if (!res.ok) { await fail({ ...r, dn }, res.reason); return }
      if (res.action === 'unchanged') sum.unchanged++; else sum.published++
      await setRow(r.ca_name, { state: 'published', reason: null, attempts: 0, next_try_at: null, published_sha256: res.sha, checked_at: new Date(),
        ...(res.action === 'unchanged' && r.published_sha256 === res.sha && r.published_at ? {} : { published_at: new Date() }) })
      if (res.action !== 'unchanged') await audit('pki.ad_publish', r.ca_name, { action: res.action, container: r.container, dn, sha256: res.sha })
    }
    for (const r of write) await doWrite(r)
    for (const r of check) {
      const dn = dnOf(r); sum.checked++
      const res = await checkCa(c, dn, r.sha256)
      // lecture impossible (délégation retirée, panne…) : l'état connu ne change pas, mais le passage est signalé en échec
      if (!res.ok) { sum.failed++; sum.ok = false; sum.reason = res.reason; continue }
      if (res.state === 'ok') { await setRow(r.ca_name, { checked_at: new Date(), dn }); continue }
      sum.drift++
      await setRow(r.ca_name, { state: 'drift', reason: res.state, dn, checked_at: new Date() })
      await audit('pki.ad_drift', r.ca_name, { found: res.state, container: r.container, dn })
      if (s.repair === 'auto') await doWrite({ ...r, state: 'drift' })
    }
    return server
  })
  if (!sess.ok) {
    sum.ok = false; sum.reason = sess.reason
    for (const r of write) await fail(r, sess.reason)   // les autorités à vérifier gardent leur état : une panne passagère ne dit rien de leur publication
  } else sum.server = sess.value
  await setSetting(STATE_KEY, { ...st, lastRun: sum, ...(sess.ok && (check.length || reconcileDue) ? { lastReconcile: sum.at } : {}) })
  return { status: 'done', summary: sum }
}

// ---- Retrait explicite ----
export type WithdrawOutcome = { ok: true; action: 'deleted' | 'absent' } | { ok: false; reason: AdReason | 'not_found' | 'disabled' | 'busy' }
/** Retire un objet de l'AD (action explicite de l'administrateur : retirer une racine retire la confiance de TOUTES les machines du domaine). */
export async function withdrawPublication(name: string, audit: AuditFn, factory?: PkiLdapFactory): Promise<WithdrawOutcome> {
  const s = await loadAd()
  const row = (await query<PubRow>('select * from pki_ad_publication where ca_name = $1', [name]))[0]
  if (!row) return { ok: false, reason: 'not_found' }
  const conn = await connection(s)
  if (!complete(s, conn)) return { ok: false, reason: 'disabled' }
  const r = await exclusive(async (): Promise<WithdrawOutcome> => {
    const sess = await withAd(s, conn, factory ?? factoryFor(conn), async (c) => {
      const dse = await rootDse(c)
      if ('error' in dse) throw Object.assign(new Error('configurationNamingContext invalide'), { code: -1, name: 'ConfigNcError' })
      const dn = objectDn(dse.configNc, row.container, name)
      return { dn, res: await withdrawCa(c, { dn, sha: row.sha256, owned: !!row.published_sha256 }) }
    })
    if (!sess.ok) return { ok: false, reason: sess.reason }
    if (!sess.value.res.ok) return { ok: false, reason: sess.value.res.reason }
    await setRow(name, { state: 'withdrawn', reason: null, published_sha256: null, attempts: 0, next_try_at: null, dn: sess.value.dn, checked_at: new Date() })
    await audit('pki.ad_withdraw', name, { container: row.container, dn: sess.value.dn, action: sess.value.res.action })
    return { ok: true, action: sess.value.res.action }
  })
  return r === 'busy' ? { ok: false, reason: 'busy' } : r
}

// ---- Test de liaison (sans écrire) ----
export interface AdTest { ok: true; server: string; configNc: string; host: string; containers: ContainerCheck[]; account: AccountInfo | null }
export async function testAd(s: PkiAdSettings, factory?: PkiLdapFactory): Promise<AdTest | { ok: false; reason: AdReason; attempts: Array<{ server: string; reason: AdReason }> }> {
  const conn = await connection(s)
  const sess = await withAd(s, conn, factory ?? factoryFor(conn), async (c, server) => {
    const dse = await rootDse(c)
    if ('error' in dse) throw Object.assign(new Error('configurationNamingContext invalide'), { code: -1, name: 'ConfigNcError' })
    return { server, configNc: dse.configNc, host: dse.host, containers: await checkContainers(c, dse.configNc), account: await accountInfo(c, s.bindDn, dse.defaultNc) }
  })
  if (!sess.ok) return { ok: false, reason: sess.reason, attempts: sess.attempts }
  return { ok: true, ...sess.value }
}

// ---- Lecture pour la console ----
export interface PubView {
  name: string; kind: string; container: Container; state: PubState | 'not_published'; reason: string | null; attempts: number
  sha256: string; publishedSha256: string | null; publishedAt: string | null; checkedAt: string | null; nextTryAt: string | null; dn: string
  /** autorité qui n'est plus dans la PKI (ligne conservée : l'objet de l'AD, lui, y est toujours) */
  orphan: boolean
}
export async function publicationViews(): Promise<PubView[]> {
  const [rows, { items }] = await Promise.all([query<PubRow>('select * from pki_ad_publication order by ca_name'), eligibleCas()])
  const byName = new Map(rows.map((r) => [r.ca_name, r]))
  const out: PubView[] = []
  for (const i of items) {
    const r = byName.get(i.ca.name)
    out.push({ name: i.ca.name, kind: i.ca.kind, container: i.container, state: r?.state ?? 'not_published', reason: r?.reason ?? null, attempts: r?.attempts ?? 0, sha256: i.sha, publishedSha256: r?.published_sha256 ?? null,
      publishedAt: iso(r?.published_at ?? null), checkedAt: iso(r?.checked_at ?? null), nextTryAt: iso(r?.next_try_at ?? null), dn: r?.dn ?? '', orphan: false })
  }
  const live = new Set(items.map((i) => i.ca.name))
  for (const r of rows) if (!live.has(r.ca_name)) out.push({ name: r.ca_name, kind: '', container: r.container, state: r.state, reason: r.reason, attempts: r.attempts, sha256: r.sha256, publishedSha256: r.published_sha256,
    publishedAt: iso(r.published_at), checkedAt: iso(r.checked_at), nextTryAt: iso(r.next_try_at), dn: r.dn, orphan: true })
  return out
}

/** État de publication par autorité (lignes seulement, sans relire les certificats) : de quoi annoter la liste des autorités. */
export async function publicationMap(): Promise<Record<string, { state: PubState; reason: string | null; publishedAt: string | null; checkedAt: string | null; nextTryAt: string | null; current: boolean }>> {
  const out: Record<string, { state: PubState; reason: string | null; publishedAt: string | null; checkedAt: string | null; nextTryAt: string | null; current: boolean }> = {}
  for (const r of await query<PubRow>('select * from pki_ad_publication')) {
    out[r.ca_name] = { state: r.state, reason: r.reason, publishedAt: iso(r.published_at), checkedAt: iso(r.checked_at), nextTryAt: iso(r.next_try_at), current: r.published_sha256 === r.sha256 }
  }
  return out
}
