// Certificats de la PKI du DDI (0.14.3) : émission depuis une demande de certificat (CSR) ou avec une clé fabriquée ici et remise dans un PKCS#12, liste,
// recherche, export CSV, téléchargement, révocation. La console ne signe rien : elle dépose une demande minuscule et la demande de certificat (publique),
// root revalide tout et parle à EJBCA (utils/pki-certs.ts). La clé d'un PKCS#12 n'existe que dans ce processus le temps de la requête.
import { setResponseHeader } from 'h3'
import { cfg } from '../utils/config'
import { audit, fail, qint, qstr, route } from '../utils/router'
import type { Ctx } from '../utils/router'
import { depositPkiRequest, pkiRequestPending, readPkiStatus } from '../utils/pki'
import type { PkiRequest } from '../utils/pki'
import { blobBytes, dropDeposit, putDeposit, readPkiCas } from '../utils/pki-ca'
import type { PkiCa } from '../utils/pki-ca'
import {
  awaitIssue, awaitRef, buildP12, caChainPem, CertDbError, CERT_LIMIT, certFileName, certsCsv, FINGERPRINT_RE, findCert, issueCsrBody, issueP12Body, issueRequest, KEY_ALGS, MAX_REQUEST_JSON,
  newIssueId, newKeyAndCsr, PROFILE_KEYS, PROFILES, REVOKE_REASONS, revokeBody, SAN_MAX, searchCerts, serialized,
} from '../utils/pki-certs'
import type { CertQuery, IssuedCert, ProfileKey } from '../utils/pki-certs'

export const registered = true

async function needHealthy() {
  const st = await readPkiStatus()
  if (!st?.installed) fail(409, 'pki_not_installed')
  if (st.state !== 'healthy') fail(409, 'pki_not_ready')
  return st
}
async function idle() { if (await pkiRequestPending()) fail(409, 'request_pending') }
/** L'autorité demandée doit exister, être active et être une émettrice du DDI : une racine ne délivre pas de certificats finaux. */
async function issuer(name: string): Promise<PkiCa> {
  const ca = (await readPkiCas())?.cas.find((x) => x.name === name)
  if (!ca) fail(404, 'not_found')
  if (ca.kind !== 'issuing' || ca.state !== 'active' || !ca.managed) fail(409, 'pki_ca_not_issuing')
  return ca
}
const dbGuard = async <T>(fn: () => Promise<T>): Promise<T> => { try { return await fn() } catch (e) { if (e instanceof CertDbError) fail(503, 'pki_certs_unavailable'); throw e } }

route('GET', '/pki/certs/meta', 'admin', async () => ({
  profiles: PROFILE_KEYS.map((k) => ({ key: k, name: PROFILES[k].name, allowed: PROFILES[k].allowed, needAny: PROFILES[k].needAny, eku: PROFILES[k].eku, days: PROFILES[k].days })),
  keyAlgs: KEY_ALGS, reasons: REVOKE_REASONS, sanMax: SAN_MAX, limit: CERT_LIMIT,
}))

// ---- Liste, recherche, export ----
const STATES = ['active', 'revoked', 'expired'] as const
function parseQuery(c: Ctx, max: number, def: number): CertQuery {
  const profile = qstr(c, 'profile', 12), state = qstr(c, 'state', 12), ca = qstr(c, 'ca', 48)
  if (profile && ![...PROFILE_KEYS, 'other'].includes(profile)) fail(400, 'invalid_query')
  if (state && !(STATES as readonly string[]).includes(state)) fail(400, 'invalid_query')
  const expiring = qint(c, 'expiring', 0, 0, 3650)
  return { q: qstr(c, 'q', 100), ca, profile: profile as CertQuery['profile'], state: state as CertQuery['state'], expiring: expiring || undefined,
    limit: qint(c, 'limit', def, 1, max), offset: qint(c, 'offset', 0, 0, 1_000_000) }
}
route('GET', '/pki/certs', 'admin', async (c) => {
  const q = parseQuery(c, CERT_LIMIT.max, CERT_LIMIT.default)
  const cas = (await readPkiCas())?.cas ?? []
  const issuers = cas.filter((x) => x.kind === 'issuing' && x.state === 'active' && x.managed).map((x) => x.name)
  const st = await readPkiStatus()
  if (!issuers.length) return { rows: [], total: 0, issuers, ready: st?.state === 'healthy' }
  const r = await dbGuard(() => searchCerts(q, cas.filter((x) => x.kind === 'issuing')))
  return { ...r, issuers, ready: st?.state === 'healthy', limit: q.limit, offset: q.offset }
})
route('GET', '/pki/certs.csv', 'admin', async (c) => {
  const q = parseQuery(c, CERT_LIMIT.csv, CERT_LIMIT.csv)
  q.offset = 0
  const cas = (await readPkiCas())?.cas.filter((x) => x.kind === 'issuing') ?? []
  const { rows } = await dbGuard(() => searchCerts(q, cas))
  await audit(c, 'pki.cert_export', 'pki_cert', undefined, { rows: rows.length })
  setResponseHeader(c.event, 'Content-Type', 'text/csv; charset=utf-8')
  setResponseHeader(c.event, 'Content-Disposition', 'attachment; filename="certificats-pki.csv"')
  return certsCsv(rows)
})
const FILES = { 'cert.pem': false, 'chain.pem': true } as const
route('GET', '/pki/certs/:fp/:file', 'admin', async (c) => {
  const fp = c.params.fp ?? '', file = c.params.file ?? ''
  if (!FINGERPRINT_RE.test(fp) || !(file in FILES)) fail(404, 'not_found')
  const cas = (await readPkiCas())?.cas.filter((x) => x.kind === 'issuing') ?? []
  const f = await dbGuard(() => findCert(fp, cas))
  if (!f) fail(404, 'not_found')
  const body = FILES[file as keyof typeof FILES] ? f.pem + await caChainPem(f.row.ca) : f.pem
  setResponseHeader(c.event, 'Content-Type', 'application/x-pem-file')
  setResponseHeader(c.event, 'Content-Disposition', `attachment; filename="${certFileName(f.row.subject.replace(/^CN=([^,]*).*$/, '$1'))}-${f.row.serial.slice(-8)}.${file === 'cert.pem' ? 'pem' : 'chain.pem'}"`)
  return body
})

// ---- Émission ----
/** Dépose la demande, attend la réponse de root et rend le certificat publié. Une seule émission à la fois dans ce processus. */
export async function issueCert(c: Ctx, b: { ca: string; profile: ProfileKey; cn: string; ou?: string; o?: string; c?: string; dns: string[]; ip: string[]; mail: string[]; upn: string[] }, csr: Buffer): Promise<IssuedCert> {
  await needHealthy()
  await issuer(b.ca)
  return serialized(async () => {
    await idle()
    const id = newIssueId()
    const req = issueRequest(id, b)
    if (JSON.stringify(req).length > MAX_REQUEST_JSON) fail(400, 'pki_request_too_large')
    const startedAt = Math.floor(Date.now() / 1000)
    await putDeposit(id, 'csr.pem', csr)
    try { await depositPkiRequest(req as PkiRequest) } catch (e) { await dropDeposit(id, 'csr.pem'); throw e }
    const out = await awaitIssue(id, startedAt, { timeoutMs: cfg().pkiIssueTimeoutMs })
    const detail = { id, ca: b.ca, profile: b.profile, cn: b.cn }
    if (!out.ok) {
      await audit(c, 'pki.cert_issue_failed', 'pki_cert', id, { ...detail, reason: out.code, message: out.message.slice(0, 200) })
      if (out.code === 'refused') fail(422, 'pki_issue_refused', undefined, { detail: out.message })
      if (out.code === 'timeout') fail(504, 'pki_timeout')
      fail(502, 'pki_issue_unknown')
    }
    await audit(c, 'pki.cert_issue', 'pki_cert', id, { ...detail, serial: out.cert.serial })
    return out.cert
  })
}
const publicInfo = (x: IssuedCert) => ({ id: x.id, ca: x.ca, profile: x.profile, serial: x.serial, sha256: x.sha256, notBefore: x.notBefore, notAfter: x.notAfter, subject: x.subject })

// Émission à partir d'une demande de certificat (CSR) : la clé reste chez le demandeur, la console ne la voit jamais
route('POST', '/pki/certs/csr', 'admin', async (c) => {
  const b = await c.body(issueCsrBody)
  const csr = blobBytes(b.csr, 'csr')
  if (!csr) fail(400, 'pki_bad_file')
  const x = await issueCert(c, b, csr)
  return { ...publicInfo(x), certificate: x.certPem, chain: x.chainPem }
})

// Émission avec une clé fabriquée ici : la clé n'est ni stockée ni journalisée, elle ne sort que dans le fichier PKCS#12 protégé par le mot de passe donné
route('POST', '/pki/certs/p12', 'admin', async (c) => {
  const b = await c.body(issueP12Body)
  await needHealthy()
  await issuer(b.ca)
  const { keyPem, csrPem } = await newKeyAndCsr(b.alg, b.cn)
  const x = await issueCert(c, b, Buffer.from(csrPem, 'utf8'))
  let p12: Buffer
  try { p12 = await buildP12(keyPem, x.certPem, x.chainPem, b.password, b.cn, b.compat) } catch { fail(500, 'pki_p12_failed') }
  await audit(c, 'pki.cert_p12', 'pki_cert', x.id, { ca: x.ca, profile: x.profile, serial: x.serial, alg: b.alg, compat: b.compat })
  setResponseHeader(c.event, 'Content-Type', 'application/x-pkcs12')
  setResponseHeader(c.event, 'Content-Disposition', `attachment; filename="${certFileName(b.cn)}.p12"`)
  setResponseHeader(c.event, 'X-Pki-Serial', x.serial)
  setResponseHeader(c.event, 'X-Pki-Id', x.id)
  setResponseHeader(c.event, 'Access-Control-Expose-Headers', 'X-Pki-Serial, X-Pki-Id, Content-Disposition')
  return p12
})

// ---- Révocation : la CRL de l'autorité est renouvelée tout de suite par root ----
route('POST', '/pki/certs/:fp/revoke', 'admin', async (c) => {
  const fp = c.params.fp ?? ''
  if (!FINGERPRINT_RE.test(fp)) fail(400, 'invalid_id')
  const b = await c.body(revokeBody)
  await needHealthy()
  const cas = (await readPkiCas())?.cas.filter((x) => x.kind === 'issuing') ?? []
  const f = await dbGuard(() => findCert(fp, cas))
  if (!f || !f.row.ca) fail(404, 'not_found')
  if (f.row.state === 'revoked') fail(409, 'pki_cert_revoked')
  return serialized(async () => {
    await idle()
    const id = newIssueId()
    const startedAt = Math.floor(Date.now() / 1000)
    await depositPkiRequest({ action: 'cert_revoke', ca: f.row.ca, serial: f.row.serial, reason: b.reason, id } as PkiRequest & { id: string })
    const out = await awaitRef(id, startedAt, { timeoutMs: cfg().pkiIssueTimeoutMs })
    const detail = { ca: f.row.ca, serial: f.row.serial, reason: b.reason, subject: f.row.subject }
    if (!out.ok) {
      await audit(c, 'pki.cert_revoke_failed', 'pki_cert', fp, { ...detail, reason_code: out.code, message: out.message.slice(0, 200) })
      if (out.code === 'refused') fail(422, 'pki_revoke_refused', undefined, { detail: out.message })
      if (out.code === 'timeout') fail(504, 'pki_timeout')
      fail(502, 'pki_issue_unknown')
    }
    await audit(c, 'pki.cert_revoke', 'pki_cert', fp, detail)
    return { ok: true, serial: f.row.serial, ca: f.row.ca, message: out.message }
  })
})
