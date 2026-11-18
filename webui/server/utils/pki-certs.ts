// Certificats de la PKI du DDI (0.14.3) : émission depuis une demande de certificat (CSR) ou avec une clé fabriquée ICI et remise dans un fichier PKCS#12,
// recherche, export CSV, révocation. Frontière de privilèges : la console ne signe rien et ne touche à aucune clé d'autorité ; elle dépose une demande JSON
// minuscule (.pki-request) et la demande de certificat (publique, pki-in/<id>.csr.pem), root revalide tout (pki-helper.py) puis demande le certificat à EJBCA.
// La LISTE des certificats est lue directement dans la base d'EJBCA avec le rôle de la console, qui n'a le droit de lire que deux tables publiques
// (certificatedata, base64certdata) : jamais les clés des autorités (cadata), jamais les entités finales.
// La clé privée d'un certificat PKCS#12 n'existe que dans la mémoire de ce processus et, quelques millisecondes, dans un fichier de /dev/shm (0600, effacé
// aussitôt) pour que openssl l'emballe : elle n'est ni écrite sur le disque, ni journalisée, ni envoyée à root ni à EJBCA.
// Les contrôles de forme ci-dessous sont les MÊMES que ceux de root (pki-helper.py) : ils répondent vite, ils ne protègent pas.
import { generateKeyPair } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { randomBytes } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'
import pg from 'pg'
import { z } from 'zod'
import { cfg } from './config'
import { openssl, withTmp } from './openssl'
import { blob, caName, CA_NAME_RE, DN_VALUE_RE } from './pki-ca'
import type { PkiCa } from './pki-ca'
import { readPkiResult } from './pki'
import { ipToString, parseIp } from './net'

// ---- Profils fournis (importés dans EJBCA par root, voir tools/pki-profiles/Gen.java) ----
export const PROFILE_KEYS = ['server', 'machine', 'user', 'network'] as const
export type ProfileKey = typeof PROFILE_KEYS[number]
export type SanKind = 'dns' | 'ip' | 'mail' | 'upn'
export interface ProfileDef { id: number; name: string; allowed: readonly SanKind[]; needAny: readonly SanKind[]; eku: readonly ('server' | 'client')[]; days: number }
/** id : identifiant du profil de certificat dans EJBCA (fixe, gravé dans les modèles fournis). */
export const PROFILES: Record<ProfileKey, ProfileDef> = {
  server: { id: 5010001, name: 'DDI-RADIUS-Server', allowed: ['dns', 'ip'], needAny: ['dns'], eku: ['server'], days: 730 },
  machine: { id: 5010002, name: 'DDI-Client-Machine', allowed: ['dns'], needAny: ['dns'], eku: ['client'], days: 365 },
  user: { id: 5010003, name: 'DDI-Client-User', allowed: ['upn', 'mail'], needAny: ['upn', 'mail'], eku: ['client'], days: 365 },
  network: { id: 5010004, name: 'DDI-Network-Device', allowed: ['dns', 'ip'], needAny: ['dns', 'ip'], eku: ['server', 'client'], days: 365 },
}
export const SAN_MAX: Record<SanKind, number> = { dns: 8, ip: 4, mail: 2, upn: 2 }
export const KEY_ALGS = ['rsa2048', 'rsa3072', 'ecp256', 'ecp384'] as const
export type KeyAlg = typeof KEY_ALGS[number]
export const REVOKE_REASONS = [0, 1, 3, 4, 5] as const   // non précisé, clé compromise, changement d'affiliation, remplacé, cessation d'activité
/** Une demande JSON plus longue est refusée par root (4096 octets). */
export const MAX_REQUEST_JSON = 4000

export const DNS_RE = /^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/
export const MAIL_RE = /^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9]([A-Za-z0-9.-]{0,188}[A-Za-z0-9])?$/
export const ISSUE_ID_RE = /^[0-9a-f]{16}$/
export const FINGERPRINT_RE = /^[0-9a-f]{40}$/
export const SERIAL_RE = /^[0-9A-Fa-f]{1,40}$/

export const dnsList = z.array(z.string().trim().regex(DNS_RE).transform((v) => v.toLowerCase())).max(SAN_MAX.dns).default([])
export const ipList = z.array(z.string().trim().max(45).transform((v, ctx) => {
  const ip = parseIp(v)
  if (!ip) { ctx.addIssue({ code: 'custom', message: 'ip' }); return z.NEVER }
  return ipToString(ip)
})).max(SAN_MAX.ip).default([])
const mailList = z.array(z.string().trim().regex(MAIL_RE)).max(SAN_MAX.mail).default([])
const upnList = z.array(z.string().trim().regex(MAIL_RE)).max(SAN_MAX.upn).default([])
const optDn = z.union([z.literal(''), z.string().trim().regex(DN_VALUE_RE)]).optional()
const optCountry = z.union([z.literal(''), z.string().trim().regex(/^[A-Z]{2}$/)]).optional()

/** Champs communs à une émission : autorité, profil, nom et SAN (0.14.8 : repris tels quels par le préenregistrement SCEP). */
export const certCommon = {
  ca: caName, profile: z.enum(PROFILE_KEYS), cn: z.string().trim().regex(DN_VALUE_RE), ou: optDn, o: optDn, c: optCountry,
  dns: dnsList, ip: ipList, mail: mailList, upn: upnList,
}
type Sans = { dns: string[]; ip: string[]; mail: string[]; upn: string[]; profile: ProfileKey }
/** Types de SAN permis par le profil, et au moins un des types requis : mêmes règles que root. */
export function sanRules(b: Sans, ctx: z.RefinementCtx) {
  const def = PROFILES[b.profile]
  for (const k of ['dns', 'ip', 'mail', 'upn'] as const) {
    if (b[k].length && !def.allowed.includes(k)) ctx.addIssue({ code: 'custom', path: [k], message: 'san_not_allowed' })
    if (new Set(b[k]).size !== b[k].length) ctx.addIssue({ code: 'custom', path: [k], message: 'san_duplicate' })
  }
  if (!def.needAny.some((k) => b[k].length)) ctx.addIssue({ code: 'custom', path: [def.needAny[0]!], message: 'san_required' })
}
export const issueCsrBody = z.object({ ...certCommon, csr: blob }).strict().superRefine(sanRules)
const PASSWORD_RE = /^[^\x00-\x1f\x7f]{8,128}$/
export const issueP12Body = z.object({ ...certCommon, alg: z.enum(KEY_ALGS), password: z.string().regex(PASSWORD_RE), compat: z.boolean().default(false) }).strict().superRefine(sanRules)
export const revokeBody = z.object({ reason: z.union([z.literal(0), z.literal(1), z.literal(3), z.literal(4), z.literal(5)]) }).strict()
export type IssueCsrBody = z.infer<typeof issueCsrBody>
export type IssueP12Body = z.infer<typeof issueP12Body>

/** Charge utile de la demande JSON que root revalide : seules les valeurs non vides, jamais de mot de passe ni de clé. */
export function issueRequest(id: string, b: { ca: string; profile: ProfileKey; cn: string; ou?: string; o?: string; c?: string } & Pick<Sans, 'dns' | 'ip' | 'mail' | 'upn'>) {
  const r: any = { action: 'cert_issue', id, ca: b.ca, profile: b.profile, cn: b.cn }
  for (const k of ['ou', 'o', 'c'] as const) if (b[k]) r[k] = b[k]
  for (const k of ['dns', 'ip', 'mail', 'upn'] as const) if (b[k].length) r[k] = b[k]
  return r as Extract<import('./pki').PkiRequest, { action: 'cert_issue' }>
}
export const newIssueId = () => randomBytes(8).toString('hex')

// ---- Clé et demande fabriquées ici (PKCS#12) ----
const genKeyPair = promisify(generateKeyPair) as (t: any, o: any) => Promise<{ privateKey: KeyObject; publicKey: KeyObject }>
/** Clé privée (PKCS#8 PEM) et demande de certificat (PEM). Le sujet de la demande est ignoré par EJBCA : le nom vient du formulaire validé par root. */
export async function newKeyAndCsr(alg: KeyAlg, cn: string): Promise<{ keyPem: string; csrPem: string }> {
  const { privateKey } = alg === 'ecp256' ? await genKeyPair('ec', { namedCurve: 'prime256v1' })
    : alg === 'ecp384' ? await genKeyPair('ec', { namedCurve: 'secp384r1' })
    : await genKeyPair('rsa', { modulusLength: alg === 'rsa3072' ? 3072 : 2048 })
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  // « req -key » exige un fichier (un tube Node est un socket) : dossier privé 0700 en mémoire (/dev/shm), fichier 0600, effacé dans tous les cas
  const r = await withTmp(async (_d, put) => openssl(['req', '-new', '-key', await put('k.pem', keyPem), '-sha256', '-subj', `/CN=${cn}`]), { ram: true })
  if (r.code !== 0 || !r.stdout.includes('BEGIN CERTIFICATE REQUEST')) throw new Error('csr_failed')
  return { keyPem, csrPem: r.stdout.trim() + '\n' }
}
/** Fichier PKCS#12 (clé, certificat, chaîne) protégé par le mot de passe de l'administrateur. `compat` : 3DES + SHA-1 pour les très anciens clients. */
export async function buildP12(keyPem: string, certPem: string, chainPem: string, password: string, name: string, compat: boolean): Promise<Buffer> {
  return withTmp(async (dir, put) => {
    const out = join(dir, 'o.p12')
    const args = ['pkcs12', '-export', '-inkey', await put('k.pem', keyPem), '-in', await put('c.pem', certPem), '-name', name, '-passout', 'env:DDI_P12OUT', '-out', out]
    if (chainPem.trim()) args.push('-certfile', await put('ch.pem', chainPem))
    if (compat) args.push('-certpbe', 'PBE-SHA1-3DES', '-keypbe', 'PBE-SHA1-3DES', '-macalg', 'sha1')
    const r = await openssl(args, { env: { DDI_P12OUT: password }, timeoutMs: 30_000 })
    if (r.code !== 0) throw new Error('p12_failed')
    const buf = await fs.readFile(out)
    if (buf.length < 100 || buf.length > 262144) throw new Error('p12_failed')
    return buf
  }, { ram: true })
}

// ---- Lecture de ce que root publie après une émission ----
export interface IssuedCert { id: string; ca: string; profile: ProfileKey | 'other'; serial: string; sha256: string; notBefore: string; notAfter: string; subject: string; certPem: string; chainPem: string }
const PEM_RE = /^-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/
async function readSmall(p: string, max = 65536): Promise<string | null> {
  try { const st = await fs.lstat(p); if (!st.isFile() || st.size > max) return null; return await fs.readFile(p, 'utf8') } catch { return null }
}
export async function readIssued(id: string): Promise<IssuedCert | null> {
  if (!ISSUE_ID_RE.test(id)) return null
  const d = join(cfg().pkiCertDir, id)
  const [m, cert, chain] = await Promise.all([readSmall(join(d, 'meta.json'), 8192), readSmall(join(d, 'cert.pem')), readSmall(join(d, 'chain.pem'))])
  if (!m || !cert || !PEM_RE.test(cert)) return null
  let j: any
  try { j = JSON.parse(m) } catch { return null }
  const str = (v: unknown, n: number) => String(v ?? '').slice(0, n)
  return { id, ca: str(j.ca, 80), profile: (PROFILE_KEYS as readonly string[]).includes(j.profile) ? j.profile : 'other', serial: /^[0-9A-F]{1,40}$/.test(j.serial ?? '') ? j.serial : '',
    sha256: /^[0-9a-f]{64}$/.test(j.sha256 ?? '') ? j.sha256 : '', notBefore: str(j.notBefore, 24), notAfter: str(j.notAfter, 24), subject: str(j.subject, 512), certPem: cert, chainPem: chain ?? '' }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
export type RefOutcome = { ok: true; message: string } | { ok: false; code: 'refused' | 'timeout' | 'unknown'; message: string }
/** Attend que root ait traité la demande `id` : son résultat porte la même référence. `done` : autre signe de réussite (le dossier du certificat est publié AVANT le résultat). */
export async function awaitRef(id: string, startedAt: number, opts: { timeoutMs?: number; pollMs?: number; done?: () => Promise<boolean> } = {}): Promise<RefOutcome> {
  const timeout = opts.timeoutMs ?? 120_000, poll = opts.pollMs ?? 400
  const t0 = Date.now()
  let other = 0
  while (Date.now() - t0 < timeout) {
    if (opts.done && await opts.done()) return { ok: true, message: '' }
    const res = await readPkiResult()
    if (res?.ref === id) return res.ok ? { ok: true, message: res.message } : { ok: false, code: 'refused', message: res.message }
    // le résultat d'une autre demande a remplacé le nôtre avant qu'on le lise : court délai, puis on abandonne (le certificat, s'il existe, est dans la liste)
    if (res && res.at >= startedAt && res.ref !== id && ++other * poll > 5000) return { ok: false, code: 'unknown', message: 'result_replaced' }
    await sleep(poll)
  }
  return { ok: false, code: 'timeout', message: 'timeout' }
}
export type IssueOutcome = { ok: true; cert: IssuedCert } | { ok: false; code: 'refused' | 'timeout' | 'unknown'; message: string }
export async function awaitIssue(id: string, startedAt: number, opts: { timeoutMs?: number; pollMs?: number } = {}): Promise<IssueOutcome> {
  const r = await awaitRef(id, startedAt, { ...opts, done: async () => (await readIssued(id)) !== null })
  if (!r.ok) return r
  const cert = await readIssued(id)
  return cert ? { ok: true, cert } : { ok: false, code: 'unknown', message: 'cert_missing' }
}

/** Une émission à la fois dans ce processus : root traite les demandes une à une et n'a qu'un fichier de résultat. */
let chain: Promise<unknown> = Promise.resolve()
export function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const next = chain.then(fn, fn)
  chain = next.catch(() => undefined)
  return next
}

// ---- Base d'EJBCA (lecture seule) ----
let pool: pg.Pool | null = null
function ejbca(): pg.Pool {
  if (!pool) {
    pool = new pg.Pool({ connectionString: cfg().ejbcaDatabaseUrl, max: 3, idleTimeoutMillis: 30000, connectionTimeoutMillis: 4000, statement_timeout: 15000, query_timeout: 20000 })
    pool.on('error', () => { /* connexion inactive coupée : la suivante est rouverte */ })
  }
  return pool
}
export async function closeEjbcaPool() { const p = pool; pool = null; await p?.end().catch(() => {}) }

export type CertState = 'active' | 'revoked' | 'expired' | 'other'
export interface CertRow {
  fingerprint: string; serial: string; ca: string; subject: string; san: string; profile: ProfileKey | 'other'; state: CertState
  notBefore: string; notAfter: string; revokedAt: string | null; reason: number | null
}
export const iso = (ms: unknown): string | null => { const n = Number(ms); return Number.isFinite(n) && n > 0 ? new Date(n).toISOString().replace(/\.\d{3}Z$/, 'Z') : null }
const PROFILE_BY_ID = new Map<number, ProfileKey>(PROFILE_KEYS.map((k) => [PROFILES[k].id, k]))

export interface CertQuery { q?: string; ca?: string; profile?: ProfileKey | 'other'; state?: 'active' | 'revoked' | 'expired'; expiring?: number; limit: number; offset: number }
export const CERT_LIMIT = { default: 50, max: 200, csv: 20000 } as const
const likeOf = (q: string) => `%${q.replace(/[%_\\]/g, '\\$&')}%`

/** Autorités du DDI qui délivrent des certificats finaux : nom → nom distinctif d'EJBCA (celui de cadata.subjectdn, publié par root). */
export function caDnMap(cas: PkiCa[]): Map<string, string> {
  const m = new Map<string, string>()
  for (const c of cas) if (c.managed && c.dn && c.state === 'active') m.set(c.name, c.dn)
  return m
}
export class CertDbError extends Error { constructor(public code: 'ejbca_unavailable') { super(code) } }

function buildWhere(q: CertQuery, dns: Map<string, string>, now: number): { where: string; params: unknown[] } {
  const params: unknown[] = []
  const add = (v: unknown) => { params.push(v); return `$${params.length}` }
  const all = [...dns.values()]
  const issuers = q.ca ? (dns.has(q.ca) ? [dns.get(q.ca)!] : []) : all
  const where = ['d.type = 1', `d.issuerdn = any(${add(issuers)}::text[])`]
  if (q.q) {
    const like = add(likeOf(q.q))
    const hex = /^[0-9a-f]{4,40}$/i.test(q.q) ? add(BigInt('0x' + q.q).toString(10)) : null
    where.push(`(d.subjectdn ilike ${like} or d.subjectaltname ilike ${like}${hex ? ` or d.serialnumber = ${hex}` : ''})`)
  }
  if (q.profile === 'other') where.push(`d.certificateprofileid <> all(${add([...PROFILE_BY_ID.keys()])}::int[])`)
  else if (q.profile) where.push(`d.certificateprofileid = ${add(PROFILES[q.profile].id)}`)
  if (q.state === 'active') where.push(`d.status in (20, 21) and d.expiredate >= ${add(now)}`)
  else if (q.state === 'revoked') where.push('d.status = 40')
  else if (q.state === 'expired') where.push(`d.status in (20, 21, 60) and d.expiredate < ${add(now)}`)
  if (q.expiring) where.push(`d.status in (20, 21) and d.expiredate >= ${add(now)} and d.expiredate < ${add(now + q.expiring * 86_400_000)}`)
  return { where: where.join(' and '), params }
}
function toRow(r: any, byDn: Map<string, string>, now: number): CertRow {
  const status = Number(r.status), exp = Number(r.expiredate)
  const state: CertState = status === 40 ? 'revoked' : status === 20 || status === 21 || status === 60 ? (exp < now ? 'expired' : status === 60 ? 'expired' : 'active') : 'other'
  let hex = ''
  try { hex = BigInt(String(r.serialnumber)).toString(16).toUpperCase() } catch { hex = '' }
  return {
    fingerprint: String(r.fingerprint), serial: hex, ca: byDn.get(String(r.issuerdn)) ?? '', subject: String(r.subjectdn ?? '').slice(0, 512), san: String(r.subjectaltname ?? '').slice(0, 1024),
    profile: PROFILE_BY_ID.get(Number(r.certificateprofileid)) ?? 'other', state, notBefore: iso(r.notbefore) ?? '', notAfter: iso(r.expiredate) ?? '',
    revokedAt: state === 'revoked' ? iso(r.revocationdate) : null, reason: state === 'revoked' && Number.isInteger(Number(r.revocationreason)) ? Number(r.revocationreason) : null,
  }
}
const COLS = 'd.fingerprint, d.serialnumber, d.issuerdn, d.subjectdn, d.subjectaltname, d.status, d.certificateprofileid, d.notbefore, d.expiredate, d.revocationdate, d.revocationreason'

export async function searchCerts(q: CertQuery, cas: PkiCa[], now = Date.now()): Promise<{ rows: CertRow[]; total: number }> {
  const dns = caDnMap(cas)
  if (!dns.size || (q.ca && !dns.has(q.ca))) return { rows: [], total: 0 }
  const byDn = new Map([...dns].map(([n, dn]) => [dn, n]))
  const { where, params } = buildWhere(q, dns, now)
  try {
    const p = ejbca()
    const [rows, count] = await Promise.all([
      p.query(`select ${COLS} from certificatedata d where ${where} order by d.notbefore desc, d.serialnumber desc limit $${params.length + 1} offset $${params.length + 2}`, [...params, q.limit, q.offset]),
      p.query(`select count(*)::int as n from certificatedata d where ${where}`, params),
    ])
    return { rows: rows.rows.map((r) => toRow(r, byDn, now)), total: Number(count.rows[0]?.n ?? 0) }
  } catch { throw new CertDbError('ejbca_unavailable') }
}
/** Un certificat par empreinte (SHA-1 d'EJBCA), seulement s'il est délivré par une autorité du DDI : ligne et PEM. */
export async function findCert(fp: string, cas: PkiCa[], now = Date.now()): Promise<{ row: CertRow; pem: string } | null> {
  if (!FINGERPRINT_RE.test(fp)) return null
  const dns = caDnMap(cas)
  if (!dns.size) return null
  const byDn = new Map([...dns].map(([n, dn]) => [dn, n]))
  try {
    const r = await ejbca().query(`select ${COLS}, coalesce(b.base64cert, d.base64cert) as b64 from certificatedata d left join base64certdata b on b.fingerprint = d.fingerprint
      where d.fingerprint = $1 and d.type = 1 and d.issuerdn = any($2::text[])`, [fp, [...dns.values()]])
    const x = r.rows[0]
    if (!x) return null
    const b64 = String(x.b64 ?? '').replace(/\s+/g, '')
    if (!/^[A-Za-z0-9+/=]{100,8192}$/.test(b64)) return null
    return { row: toRow(x, byDn, now), pem: `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n` }
  } catch { throw new CertDbError('ejbca_unavailable') }
}
/** Chaîne PEM de l'autorité émettrice (certificat de l'autorité puis ses supérieurs, racine en dernier), lue dans les fichiers publics de root. */
export async function caChainPem(name: string): Promise<string> {
  if (!CA_NAME_RE.test(name)) return ''
  const [c, ch] = await Promise.all([readSmall(join(cfg().pkiCaDir, name, 'cert.pem')), readSmall(join(cfg().pkiCaDir, name, 'chain.pem'))])
  return (c ?? '') + (ch ?? '')
}

// ---- Export CSV ----
const csvq = (v: unknown) => { const s = v === null || v === undefined ? '' : String(v); return /^[=+\-@\t\r]/.test(s) ? `"'${s.replace(/"/g, '""')}"` : /[",\n;\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s }
export const CSV_HEADER = ['autorite', 'profil', 'serie', 'sujet', 'noms_alternatifs', 'debut', 'fin', 'etat', 'revoque_le', 'motif', 'empreinte_sha1']
export function certsCsv(rows: CertRow[]): string {
  return [CSV_HEADER.join(','), ...rows.map((r) => [r.ca, r.profile, r.serial, r.subject, r.san, r.notBefore, r.notAfter, r.state, r.revokedAt ?? '', r.reason ?? '', r.fingerprint].map(csvq).join(','))].join('\n') + '\n'
}
export const certFileName = (cn: string) => (cn.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60) || 'certificat')
