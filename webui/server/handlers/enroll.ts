// Enrôlement des postes (0.18.0) : voir utils/enroll.ts. Deux familles de routes :
//   - POST /enroll/v1/machine : PUBLIQUE (pas de session) ; seule l'authentification Kerberos « Negotiate » du compte machine l'ouvre ;
//   - /enroll* : réglages, keytab, script, journal : administrateur.
import { setResponseHeader } from 'h3'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import type { Ctx } from '../utils/router'
import { query, setSetting } from '../utils/db'
import { normDn } from '../utils/text'
import { groupExists, lookupAccount } from '../utils/radius-dir'
import { dirComplete, dirPassword, factoryFor, loadDir } from '../utils/radius-dir-store'
import { blob, blobBytes, readCaFile, readPkiCas } from '../utils/pki-ca'
import { DNS_RE } from '../utils/pki-certs'
import { issueCert } from './pkicert'
import {
  acceptNegotiate, dnsInDomain, dnsMatchesAccount, domainOfDn, enrollSerial, ENROLL_DEFAULTS, ENROLL_KEY, ENROLL_LIMITS, enrollBody, enrollComplete, KEYTAB_KEY, keytabProblem, loadEnroll, loadKeytab,
  machineFromPrincipal, negotiateToken, parseKeytab, preAuthAuditOk, principalAllowed, principalAuditOk, rateVerdict, sealKeytab,
} from '../utils/enroll'
import { enrollScript } from '../utils/enroll-script'
import { gpoFiles, gpoScript, trustAnchors } from '../utils/enroll-gpo'
import { ACCOUNT_RE, createGroup, createOu, GpoError, gpoLdapFactory, pushGpo, pushGpoSerial, smbclientRunner } from '../utils/enroll-gpo-push'

export const registered = true

const refuse = async (c: Ctx, status: number, code: string, who: string | undefined, extra: Record<string, unknown> = {}): Promise<never> => {
  // le journal des refus est borné : avant authentification (who absent) globalement, ensuite par principal
  if (who !== undefined ? principalAuditOk(who) : preAuthAuditOk()) await audit(c, 'enroll.refused', 'machine', who ?? '-', { ...extra, reason: code })
  fail(status, code)
}
const negotiate = (c: Ctx): never => {
  setResponseHeader(c.event, 'WWW-Authenticate', 'Negotiate')
  fail(401, 'enroll_negotiate')
}

route('POST', '/enroll/v1/machine', 'public', async (c) => {
  const s = await loadEnroll()
  if (!s.enabled || !enrollComplete(s)) fail(404, 'not_found')   // service éteint : rien ne le distingue d'une route absente
  const header = c.event.node.req.headers.authorization
  const token = negotiateToken(Array.isArray(header) ? header[0] : header)
  if (!token) return negotiate(c)
  const kt = await loadKeytab()
  if (!kt) return refuse(c, 503, 'enroll_no_keytab', undefined)
  const acc = await acceptNegotiate(token, kt)
  if (!acc.ok) {
    if (acc.error === 'busy') fail(429, 'enroll_rate_busy')
    if (acc.error === 'gssapi_missing' || acc.error === 'helper_failed' || acc.error === 'no_keytab') return refuse(c, 503, 'enroll_unavailable', undefined, { error: acc.error })
    return refuse(c, 401, 'enroll_kerberos', undefined, { error: acc.error })
  }
  if (!principalAllowed(acc.principal)) fail(429, 'enroll_rate_busy')   // avant tout accès à l'annuaire
  const sam = machineFromPrincipal(acc.principal, kt.realm)
  if (!sam) return refuse(c, 403, 'enroll_not_machine', acc.principal.slice(0, 80))   // le ticket est valide : refus authentifié, journalisé (dans la limite par principal)

  // l'identité vient de l'annuaire, pas de la demande : compte actif, membre du groupe d'enrôlement, nom DNS connu
  const dir = await loadDir()
  if (!dirComplete(dir)) return refuse(c, 503, 'enroll_no_directory', sam)
  const lk = await lookupAccount(dir, dirPassword(dir), factoryFor(dir), 'computer', sam)
  if (!lk.ok) return refuse(c, 503, 'enroll_directory', sam, { directory: lk.reason })
  const acct = lk.value
  if (!acct.found || acct.kind !== 'computer') return refuse(c, 403, 'enroll_unknown_machine', sam)
  if (!acct.state.usable) return refuse(c, 403, 'enroll_account_unusable', sam, { reasons: acct.state.reasons })
  if (acct.sam.toLowerCase() !== sam.toLowerCase()) return refuse(c, 403, 'enroll_unknown_machine', sam)
  const want = normDn(s.groupDn)
  if (!acct.groups.some((g) => normDn(g.dn) === want)) return refuse(c, 403, 'enroll_not_in_group', sam)
  const fqdn = (acct.dnsHostName ?? '').toLowerCase()
  if (!fqdn || !DNS_RE.test(fqdn)) return refuse(c, 403, 'enroll_no_dns_name', sam)
  // le nom DNS doit être celui du compte : l'AD n'autorise un poste à écrire son dNSHostName que sur son propre nom, mais on ne s'y fie pas seul
  if (!dnsMatchesAccount(fqdn, sam) || !dnsInDomain(fqdn, domainOfDn(acct.dn))) return refuse(c, 403, 'enroll_name_mismatch', sam, { dns: fqdn })   // et le suffixe est celui du domaine du compte

  const b = await c.body(z.object({ csr: blob }).strict())
  const csr = blobBytes(b.csr, 'csr')
  if (!csr) return refuse(c, 400, 'pki_bad_file', sam)
  // limitation + émission + décompte dans le même créneau : des requêtes simultanées d'un même poste ne passent pas toutes la vérification
  const x = await enrollSerial(async () => {
    const verdict = await rateVerdict(sam, s)
    if (verdict !== 'ok') return refuse(c, 429, `enroll_rate_${verdict}`, sam)
    // le nom du certificat : jamais celui de la demande. CN = nom court du compte, SAN dNSName = dNSHostName de l'annuaire (ce que lisent les règles RADIUS)
    let issued
    try { issued = await issueCert(c, { ca: s.ca, profile: 'machine', cn: sam.replace(/\$$/, ''), dns: [fqdn], ip: [], mail: [], upn: [] }, csr) }
    catch (e: any) {
      await audit(c, 'enroll.refused', 'machine', sam, { reason: e?.data?.code ?? e?.statusMessage ?? 'issue_failed' })
      throw e
    }
    await audit(c, 'enroll.issued', 'machine', sam, { serial: issued.serial, dns: fqdn, ca: s.ca, notAfter: issued.notAfter })
    return issued
  })
  if (acc.token) setResponseHeader(c.event, 'WWW-Authenticate', `Negotiate ${acc.token}`)
  return { certificate: x.certPem, chain: x.chainPem, serial: x.serial, notAfter: x.notAfter }
})

// ---- Administration ----
const issuers = async () => ((await readPkiCas())?.cas ?? []).filter((x) => x.kind === 'issuing' && x.state === 'active' && x.managed)
const cnOf = (dn: string) => /(?:^|,)\s*CN=((?:[^,\\]|\\.)+)/i.exec(dn)?.[1]?.replace(/\\(.)/g, '$1').trim() ?? ''

route('GET', '/enroll', 'admin', async () => {
  const s = await loadEnroll(), kt = await loadKeytab(), cas = await issuers()
  const recent = await query<any>(
    "select at, action, entity_id as machine, detail from audit_log where action in ('enroll.issued','enroll.refused') order by at desc limit 50")
  const stats = await query<any>(
    "select action, count(*)::int as n from audit_log where action in ('enroll.issued','enroll.refused') and at > now() - interval '1 day' group by action")
  const keytab = kt ? { principals: kt.principals, realm: kt.realm, kvno: kt.kvno, size: kt.size, at: kt.at, problem: s.host ? keytabProblem({ entries: kt.entries, principals: kt.principals, realm: kt.realm }, s.host) : null } : null
  return {
    settings: s, limits: ENROLL_LIMITS, defaults: ENROLL_DEFAULTS, keytab, issuers: cas.map((x) => x.name),
    last24h: { issued: stats.find((r) => r.action === 'enroll.issued')?.n ?? 0, refused: stats.find((r) => r.action === 'enroll.refused')?.n ?? 0 },
    recent, ready: enrollComplete(s) && !!kt,
  }
})

route('PUT', '/enroll/config', 'admin', async (c) => {
  const b = await c.body(enrollBody)
  if (b.enabled) {
    if (!b.ca || !b.groupDn || !b.host) fail(400, 'enroll_incomplete')
    if (!(await issuers()).some((x) => x.name === b.ca)) fail(409, 'pki_ca_not_issuing')
    const stored = await loadKeytab()
    if (!stored) fail(409, 'enroll_no_keytab')
    const kp = keytabProblem({ entries: stored.entries ?? [], principals: stored.principals, realm: stored.realm }, b.host)
    if (kp) fail(409, `enroll_${kp}`)
    const dir = await loadDir()
    if (!dirComplete(dir)) fail(409, 'enroll_no_directory')
    // le groupe doit exister et être un groupe (et non un conteneur comme CN=Computers) : sinon aucun poste ne serait jamais accepté
    const g = await groupExists(dir, dirPassword(dir), factoryFor(dir), b.groupDn)
    if (!g.ok) fail(503, 'enroll_directory')
    if (!g.value) fail(400, 'enroll_group_invalid')
  }
  await setSetting(ENROLL_KEY, b)
  await audit(c, 'enroll.config', 'settings', ENROLL_KEY, { enabled: b.enabled, ca: b.ca, host: b.host, groupDn: b.groupDn, minIntervalSec: b.minIntervalSec, maxPerDay: b.maxPerDay })
  return { ok: true }
})

// Le keytab est un secret : chiffré en base (il suit donc le cluster), jamais renvoyé ni journalisé.
const Keytab = z.object({ keytab: z.string().max(90000).regex(/^[A-Za-z0-9+/=\s]+$/) }).strict()
route('PUT', '/enroll/keytab', 'admin', async (c) => {
  const b = await c.body(Keytab)
  const raw = Buffer.from(b.keytab.replace(/\s+/g, ''), 'base64')
  let info
  try { info = parseKeytab(raw) } catch (e: any) { return fail(400, e?.message === 'keytab_realms' ? 'enroll_keytab_realms' : 'invalid_keytab') }
  const s = await loadEnroll()
  if (s.host) { const p = keytabProblem(info, s.host); if (p) fail(400, `enroll_${p}`) }
  else if (!info.principals.some((p) => /^http\//i.test(p))) fail(400, 'enroll_keytab_spn')
  else if (info.principals.some((p) => !/^http\//i.test(p))) fail(400, 'enroll_keytab_extra')
  await setSetting(KEYTAB_KEY, sealKeytab(raw, info))
  await audit(c, 'enroll.keytab', 'settings', KEYTAB_KEY, { principals: info.principals, bytes: raw.length })
  return { ok: true, principals: info.principals, realm: info.realm }
})
route('DELETE', '/enroll/keytab', 'admin', async (c) => {
  await setSetting(KEYTAB_KEY, null)
  await setSetting(ENROLL_KEY, { ...(await loadEnroll()), enabled: false })
  await audit(c, 'enroll.keytab_removed', 'settings', KEYTAB_KEY)
  return { ok: true }
})

route('GET', '/enroll/script', 'admin', async (c) => {
  const s = await loadEnroll()
  if (!s.host || !s.ca) fail(409, 'enroll_incomplete')
  const ca = (await issuers()).find((x) => x.name === s.ca)
  if (!ca) fail(409, 'pki_ca_not_issuing')
  let text: string
  try { text = enrollScript(s.host, cnOf(ca.dn) || ca.name) } catch { return fail(409, 'enroll_incomplete') }
  await audit(c, 'enroll.script', 'settings', ENROLL_KEY)
  setResponseHeader(c.event, 'Content-Type', 'text/plain; charset=utf-8')
  setResponseHeader(c.event, 'Content-Disposition', 'attachment; filename="enroll.ps1"')
  return text
})

// Script de mise en place de la GPO : embarque enroll.ps1 et les racines à confiance (certificat HTTPS de la console s'il est auto-signé, racine de la PKI)
async function gpoMaterial() {
  const s = await loadEnroll()
  if (!s.host || !s.ca) fail(409, 'enroll_incomplete')
  const ca = (await issuers()).find((x) => x.name === s.ca)
  if (!ca) fail(409, 'pki_ca_not_issuing')
  const pems = [process.env.NITRO_SSL_CERT || process.env.DDI_TLS_CERT_PEM || '']
  for (const k of ['chain', 'cert'] as const) pems.push((await readCaFile(ca.name, k))?.toString('utf8') ?? '')
  try { return { enrollPs1: enrollScript(s.host, cnOf(ca.dn) || ca.name), anchors: trustAnchors(...pems) } } catch { return fail(409, 'enroll_incomplete') }
}
route('GET', '/enroll/gpo-script', 'admin', async (c) => {
  const m = await gpoMaterial()
  const text = gpoScript(m.enrollPs1, m.anchors)
  await audit(c, 'enroll.gpo_script', 'settings', ENROLL_KEY, { anchors: Object.keys(m.anchors).length })
  setResponseHeader(c.event, 'Content-Type', 'text/plain; charset=utf-8')
  setResponseHeader(c.event, 'Content-Disposition', 'attachment; filename="deploy-gpo.ps1"')
  return text
})

// La console met elle-même la GPO en place : l'administrateur fournit l'unité d'organisation et un compte pour CETTE opération (jamais stocké ni journalisé).
const DnField = z.string().min(8).max(400).regex(/^[^\x00-\x1f\x7f]+$/)
const GpoCreds = { account: z.string().regex(ACCOUNT_RE), password: z.string().min(1).max(256) }
// une cible : une unité d'organisation OU un groupe d'ordinateurs (GPO liée à la racine du domaine, filtrée sur le groupe)
const GpoPush = z.object({ ou: DnField.optional(), group: DnField.optional(), ...GpoCreds, dry: z.boolean() }).strict().refine((b) => !!b.ou !== !!b.group)
const GPO_STATUS: Record<string, number> = { tls: 409, bind: 409, denied: 409, ou: 400, ou_missing: 400, ou_container: 400, group: 400, group_missing: 400, group_broad: 400, group_dc: 400, smbclient: 409, unreachable: 502, ldap: 502, smb: 502, no_dc: 502 }
const OuCreate = z.object({ ou: DnField, ...GpoCreds }).strict()
const GroupCreate = z.object({ group: DnField, ...GpoCreds }).strict()
function gpoFail(e: unknown): never {
  if (e instanceof GpoError) fail(GPO_STATUS[e.reason] ?? 502, `enroll_gpo_${e.reason}`, undefined, e.detail ? { detail: e.detail } : undefined)
  throw e
}
// Crée l'unité d'organisation demandée (avec le même compte à usage unique) quand elle n'existe pas encore : une GPO ne se lie pas à un conteneur « CN= »
route('POST', '/enroll/gpo/ou', 'admin', async (c) => {
  const b = await c.body(OuCreate)
  const dir = await loadDir()
  if (!dir.urls.length) fail(409, 'enroll_gpo_no_directory')
  let r
  try { r = await pushGpoSerial(() => createOu({ urls: dir.urls, ldap: gpoLdapFactory(dir) }, b)) } catch (e) {
    if (e instanceof GpoError) await audit(c, 'enroll.gpo_refused', 'settings', ENROLL_KEY, { ou: b.ou, account: b.account, reason: e.reason, detail: e.detail })
    gpoFail(e)
  }
  await audit(c, 'enroll.gpo_ou', 'settings', ENROLL_KEY, { ou: r.ou, account: b.account, created: r.created })
  return r
})
// Crée le groupe d'ordinateurs (global, vide) quand il n'existe pas : on y ajoute ensuite les postes, qui doivent redémarrer pour recevoir la GPO
route('POST', '/enroll/gpo/group', 'admin', async (c) => {
  const b = await c.body(GroupCreate)
  const dir = await loadDir()
  if (!dir.urls.length) fail(409, 'enroll_gpo_no_directory')
  let r
  try { r = await pushGpoSerial(() => createGroup({ urls: dir.urls, ldap: gpoLdapFactory(dir) }, b)) } catch (e) {
    if (e instanceof GpoError) await audit(c, 'enroll.gpo_refused', 'settings', ENROLL_KEY, { group: b.group, account: b.account, reason: e.reason, detail: e.detail })
    gpoFail(e)
  }
  await audit(c, 'enroll.gpo_group', 'settings', ENROLL_KEY, { group: r.group, account: b.account, created: r.created })
  return r
})
route('POST', '/enroll/gpo', 'admin', async (c) => {
  const b = await c.body(GpoPush)
  const dir = await loadDir()
  if (!dir.urls.length) fail(409, 'enroll_gpo_no_directory')
  const m = await gpoMaterial()
  let r
  try {
    r = await pushGpoSerial(() => pushGpo({ urls: dir.urls, ldap: gpoLdapFactory(dir), smb: smbclientRunner, files: gpoFiles(m.enrollPs1, m.anchors) }, b))
  } catch (e) {
    if (e instanceof GpoError) await audit(c, 'enroll.gpo_refused', 'settings', ENROLL_KEY, { ou: b.ou, group: b.group, account: b.account, dry: b.dry, reason: e.reason, detail: e.detail })
    gpoFail(e)
  }
  await audit(c, b.dry ? 'enroll.gpo_checked' : 'enroll.gpo_applied', 'settings', ENROLL_KEY, { ou: r.ou, group: r.group, account: b.account, gpoId: r.gpoId, created: r.created, domain: r.domain })
  return r
})
