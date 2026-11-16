// PKI de l'accès réseau EAP-TLS (0.13.2) : autorités de confiance (racine + intermédiaires), certificat et clé du serveur RADIUS, CRL.
// La console tient l'état et le valide pour guider l'administrateur ; root (ddibuntu-radius) REVALIDE tout avec openssl avant d'installer quoi que ce soit.
// Ce fichier ne touche ni à la base ni au disque (sauf openssl en lecture) : l'état est un objet que le gestionnaire charge et enregistre.
import { createHash, createPrivateKey, generateKeyPair, randomBytes, X509Certificate } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { promisify } from 'node:util'
import { openssl, withTmp } from './openssl'

export const PKI_KEY = 'radius_pki'
export const MAX_CAS = 20
export const MAX_CRL_BYTES = 8 * 1024 * 1024
export const OID_SERVER_AUTH = '1.3.6.1.5.5.7.3.1'
export const OID_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2'

export interface CrlInfo { pem: string; fetchedAt: number; thisUpdate: number; nextUpdate: number; revoked: number; source: 'url' | 'upload'; sha256: string }
export interface CaEntry { id: string; name: string; pem: string; hash: string; crlUrl?: string; crl?: CrlInfo; crlError?: { at: number; code: string } }
export interface ServerCert { pem: string; keyEnc: string }
export interface Pending { keyEnc: string; csrPem: string; cn: string; sans: string[]; keyType: KeyType; createdAt: number }
export interface PkiState { checkCrl: boolean; cas: CaEntry[]; server?: ServerCert; pending?: Pending; crlPushed?: string }
export const PKI_DEFAULTS: PkiState = { checkCrl: true, cas: [] }
export type KeyType = 'rsa2048' | 'rsa3072' | 'ec256'

export interface CertInfo {
  subject: string; issuer: string; serial: string; notBefore: number; notAfter: number; fingerprint: string
  ca: boolean; ekus: string[] | null; sans: string[]; keyType: string; keyBits: number | null; selfSigned: boolean
}
const dn = (s: string) => s.split('\n').filter(Boolean).reverse().join(', ')
const ms = (s: string) => Date.parse(s)

/** Certificats PEM d'un texte. Toute autre chose (clé privée, texte, certificat tronqué) est refusée : on ne laisse rien passer en silence. */
export function splitCerts(text: string): string[] {
  const rx = /-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+?-----END CERTIFICATE-----/g
  const blocks = text.match(rx) ?? []
  if (!blocks.length) throw new PkiError('pem_no_certificate')
  if (/PRIVATE KEY/.test(text)) throw new PkiError('pem_has_private_key')
  if (text.replace(rx, '').trim()) throw new PkiError('pem_unexpected_content')
  return blocks.map((b) => b.replace(/\r\n/g, '\n').trim() + '\n')
}
/** Certificat(s) reçus en texte PEM ou en fichier (base64) : PEM, DER (« .cer » d'AD CS) ou PKCS#7 (« .p7b », avec chaîne). Renvoie du PEM. */
export async function asPem(pem?: string, b64?: string): Promise<string> {
  if (!b64) { if (!pem?.trim()) throw new PkiError('pem_no_certificate'); return pem }
  const buf = Buffer.from(b64, 'base64')
  if (!buf.length || buf.length > 500_000) throw new PkiError('pem_invalid')
  const isPem = buf.includes('-----BEGIN')
  if (isPem && !buf.includes('BEGIN PKCS7') && !buf.includes('BEGIN CMS')) return buf.toString('utf8')
  if (!isPem) { try { return new X509Certificate(buf).toString() } catch { /* peut être un PKCS#7 DER */ } }
  const r = await openssl(['pkcs7', '-inform', isPem ? 'PEM' : 'DER', '-print_certs'], { input: buf })
  const blocks = r.code === 0 ? (r.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []) : []
  if (!blocks.length) throw new PkiError('pem_invalid')
  return blocks.join('\n') + '\n'
}
export class PkiError extends Error { constructor(public code: string, public data?: Record<string, unknown>) { super(code) } }

export function parseCert(pem: string): { info: CertInfo; x: X509Certificate } {
  let x: X509Certificate
  try { x = new X509Certificate(pem) } catch { throw new PkiError('pem_invalid') }
  const kd: any = x.publicKey.asymmetricKeyDetails ?? {}
  const keyType = x.publicKey.asymmetricKeyType ?? 'unknown'
  const selfSigned = x.subject === x.issuer && (() => { try { return x.verify(x.publicKey) } catch { return false } })()
  return { x, info: {
    subject: dn(x.subject), issuer: dn(x.issuer), serial: x.serialNumber, notBefore: ms(x.validFrom), notAfter: ms(x.validTo), fingerprint: x.fingerprint256,
    ca: x.ca === true, ekus: Array.isArray(x.keyUsage) ? x.keyUsage : null,
    sans: (x.subjectAltName ?? '').split(/,\s*/).filter(Boolean).slice(0, 50), keyType, keyBits: typeof kd.modulusLength === 'number' ? kd.modulusLength : null, selfSigned } }
}
const issuedBy = (child: X509Certificate, parent: X509Certificate) => { try { return child.checkIssued(parent) && child.verify(parent.publicKey) } catch { return false } }

// ---- Chaîne de confiance ----
export interface CaView { id: string; name: string; info: CertInfo; root: boolean; issuing: boolean; chainOk: boolean; expired: boolean; hash: string; crlUrl: string | null; crl: Omit<CrlInfo, 'pem'> | null; crlError: { at: number; code: string } | null }
const crlSummary = ({ pem: _pem, ...rest }: CrlInfo): Omit<CrlInfo, 'pem'> => rest
export function analyzeCas(s: PkiState, now = Date.now()): CaView[] {
  const parsed = s.cas.map((c) => ({ c, ...parseCert(c.pem) }))
  const isRoot = (i: number) => parsed[i]!.info.selfSigned
  const parents = (i: number) => parsed.map((_o, j) => j).filter((j) => j !== i && !isRoot(i) && issuedBy(parsed[i]!.x, parsed[j]!.x))
  const reaches = (i: number, seen = new Set<number>()): boolean => {
    if (isRoot(i)) return true
    if (seen.has(i)) return false
    seen.add(i)
    return parents(i).some((j) => reaches(j, seen))
  }
  return parsed.map((p, i) => {
    const hasChild = parsed.some((o, j) => j !== i && !isRoot(j) && issuedBy(o.x, p.x))
    return { id: p.c.id, name: p.c.name, info: p.info, root: isRoot(i), issuing: !hasChild, chainOk: reaches(i), expired: p.info.notAfter <= now, hash: p.c.hash,
      crlUrl: p.c.crlUrl ?? null, crl: p.c.crl ? crlSummary(p.c.crl) : null, crlError: p.c.crlError ?? null }
  })
}

/** Chaîne que le serveur présente aux clients : certificat, puis les intermédiaires de la liste de confiance (jamais la racine). null = chaîne incomplète. */
export function serverChain(s: PkiState): { leaf: X509Certificate; pem: string; chainOk: boolean } | null {
  if (!s.server) return null
  const leaf = parseCert(s.server.pem).x
  const cas = s.cas.map((c) => parseCert(c.pem))
  const out = [s.server.pem.trim() + '\n']
  let cur = leaf, ok = false
  for (let depth = 0; depth < 10; depth++) {
    const parent = cas.find((c) => issuedBy(cur, c.x))
    if (!parent) break
    if (parent.info.selfSigned) { ok = true; break }
    out.push(parent.x.toString().trim() + '\n'); cur = parent.x
  }
  return { leaf, pem: out.join(''), chainOk: ok }
}

// ---- Disponibilité du déploiement ----
export interface Problem { code: string; ref?: string }
export interface Readiness { ready: boolean; empty: boolean; problems: Problem[]; warnings: Problem[] }
export function readiness(s: PkiState, now = Date.now()): Readiness {
  const problems: Problem[] = [], warnings: Problem[] = []
  const empty = !s.cas.length && !s.server
  if (empty) return { ready: false, empty: true, problems, warnings }
  const cas = analyzeCas(s, now)
  if (!cas.length) problems.push({ code: 'no_ca' })
  else if (!cas.some((c) => c.root)) problems.push({ code: 'no_root' })
  for (const c of cas) {
    if (c.expired) problems.push({ code: 'ca_expired', ref: c.id })
    else if (!c.chainOk) problems.push({ code: 'ca_chain', ref: c.id })
    else if (c.info.notAfter - now < 90 * 86400_000) warnings.push({ code: 'ca_expiring', ref: c.id })
    if (s.checkCrl && c.issuing && c.chainOk && !c.expired) {
      if (!c.crl) problems.push({ code: 'crl_missing', ref: c.id })
      else if (c.crl.nextUpdate <= now) problems.push({ code: 'crl_expired', ref: c.id })
      else if (c.crl.nextUpdate - now < 86400_000) warnings.push({ code: 'crl_expiring', ref: c.id })
    }
  }
  if (!s.server) problems.push({ code: 'no_server' })
  else {
    const { info } = parseCert(s.server.pem), ch = serverChain(s)
    if (info.notAfter <= now) problems.push({ code: 'server_expired' })
    else if (info.notAfter - now < 30 * 86400_000) warnings.push({ code: 'server_expiring' })
    if (info.ekus && !info.ekus.includes(OID_SERVER_AUTH)) problems.push({ code: 'server_usage' })
    if (!ch?.chainOk) problems.push({ code: 'server_chain' })
  }
  return { ready: problems.length === 0, empty: false, problems, warnings }
}

// ---- Modification de la liste de confiance ----
export function addCas(s: PkiState, text: string, name?: string): { state: PkiState; added: string[]; skipped: number } {
  const blocks = splitCerts(text)
  const next: PkiState = { ...s, cas: [...s.cas] }
  const have = new Set(next.cas.map((c) => parseCert(c.pem).info.fingerprint))
  const added: string[] = []; let skipped = 0
  for (const b of blocks) {
    const { info } = parseCert(b)
    if (!info.ca) throw new PkiError('ca_not_a_ca', { subject: info.subject })
    if (info.notAfter <= Date.now()) throw new PkiError('ca_expired', { subject: info.subject })
    if (have.has(info.fingerprint)) { skipped++; continue }
    if (next.cas.length >= MAX_CAS) throw new PkiError('ca_too_many')
    have.add(info.fingerprint)
    const id = randomBytes(4).toString('hex')
    next.cas.push({ id, name: (blocks.length === 1 && name ? name : info.subject.split(',')[0]!.replace(/^CN=/, '')).slice(0, 80), pem: b, hash: '' })
    added.push(id)
  }
  return { state: next, added, skipped }
}
/** Empreinte de nom (identique à celle d'openssl) des autorités ajoutées : sert à rattacher une CRL à son émettrice. */
export async function fillHashes(s: PkiState): Promise<PkiState> {
  const cas = await Promise.all(s.cas.map(async (c) => {
    if (c.hash) return c
    const r = await openssl(['x509', '-noout', '-subject_hash'], { input: c.pem })
    const h = r.stdout.trim()
    return { ...c, hash: /^[0-9a-f]{8}$/.test(h) ? h : '' }
  }))
  return { ...s, cas }
}

// ---- CRL ----
export interface ParsedCrl { pem: string; caId: string; thisUpdate: number; nextUpdate: number; revoked: number; sha256: string }
const whenOf = (t: string, key: string) => { const m = new RegExp(key + '=(.+)').exec(t); return m ? Date.parse(m[1]!.trim()) : NaN }
/** Lit une CRL (PEM ou DER), vérifie sa signature par une autorité de la liste et la rattache à celle-ci. */
export async function parseCrl(raw: Buffer, s: PkiState, now = Date.now()): Promise<ParsedCrl> {
  if (!raw.length || raw.length > MAX_CRL_BYTES) throw new PkiError('crl_size')
  const asText = raw.toString('latin1')
  const isPem = asText.includes('-----BEGIN X509 CRL-----')
  const conv = await openssl(['crl', '-inform', isPem ? 'PEM' : 'DER', '-outform', 'PEM'], { input: raw, timeoutMs: 60_000, maxBytes: 3 * MAX_CRL_BYTES })
  if (conv.code !== 0 || !conv.stdout.includes('BEGIN X509 CRL')) throw new PkiError('crl_invalid')
  const pem = (conv.stdout.match(/-----BEGIN X509 CRL-----[\s\S]+?-----END X509 CRL-----/) ?? [''])[0]! + '\n'
  return withTmp(async (_dir, put) => {
    const f = await put('crl.pem', pem)
    const head = await openssl(['crl', '-in', f, '-noout', '-hash', '-lastupdate', '-nextupdate'], { timeoutMs: 60_000 })
    const hash = /(?:^|=)([0-9a-f]{8})\s*$/m.exec(head.stdout.split('\n')[0] ?? '')?.[1] ?? ''
    const thisUpdate = whenOf(head.stdout, 'lastUpdate'), nextUpdate = whenOf(head.stdout, 'nextUpdate')
    if (head.code !== 0 || !Number.isFinite(thisUpdate) || !Number.isFinite(nextUpdate)) throw new PkiError('crl_invalid')
    const candidates = s.cas.filter((c) => c.hash === hash)
    if (!candidates.length) throw new PkiError('crl_unknown_issuer')
    let caId = ''
    for (const c of candidates) {
      const ca = await put(`ca-${c.id}.pem`, c.pem)
      const v = await openssl(['crl', '-in', f, '-noout', '-CAfile', ca], { timeoutMs: 60_000 })
      if (v.code === 0 && /verify OK/.test(v.stdout + v.stderr)) { caId = c.id; break }
    }
    if (!caId) throw new PkiError('crl_bad_signature')
    if (thisUpdate > now + 60_000) throw new PkiError('crl_not_yet_valid')   // horloge de l'autorité en avance : OpenSSL refuserait tous les certificats jusque-là
    if (nextUpdate <= now) throw new PkiError('crl_expired')
    const text = await openssl(['crl', '-in', f, '-noout', '-text'], { timeoutMs: 120_000, maxBytes: 64 * MAX_CRL_BYTES })
    const revoked = (text.stdout.match(/^\s+Serial Number:/gm) ?? []).length
    return { pem, caId, thisUpdate, nextUpdate, revoked, sha256: createHash('sha256').update(pem).digest('hex') }
  })
}
/** Enregistre une CRL vérifiée pour l'autorité `caId` ; refuse une CRL plus ancienne que celle déjà en place (retour en arrière). */
export function applyCrl(s: PkiState, p: ParsedCrl, source: 'url' | 'upload', now = Date.now()): { state: PkiState; changed: boolean } {
  const cur = s.cas.find((c) => c.id === p.caId)
  if (!cur) throw new PkiError('ca_not_found')
  if (cur.crl && p.thisUpdate < cur.crl.thisUpdate) throw new PkiError('crl_older')
  const same = cur.crl?.sha256 === p.sha256
  const crl: CrlInfo = { pem: p.pem, fetchedAt: now, thisUpdate: p.thisUpdate, nextUpdate: p.nextUpdate, revoked: p.revoked, source, sha256: p.sha256 }
  return { changed: !same, state: { ...s, cas: s.cas.map((c) => { if (c.id !== p.caId) return c; const { crlError: _e, ...rest } = c; return { ...rest, crl } }) } }
}
/** Télécharge et enregistre la CRL de l'autorité `caId` depuis son adresse. L'état est toujours renvoyé (l'erreur éventuelle y est mémorisée). */
export async function refreshCrl(s: PkiState, caId: string, fetchFn: typeof fetch = fetch, now = Date.now()): Promise<{ state: PkiState; changed: boolean; error?: PkiError }> {
  const ca = s.cas.find((c) => c.id === caId)
  if (!ca?.crlUrl) return { state: s, changed: false, error: new PkiError('crl_no_url') }
  try {
    const url = normCrlUrl(ca.crlUrl)
    if (!url) throw new PkiError('crl_url_invalid')
    const raw = await fetchCrl(url, fetchFn)
    const parsed = await parseCrl(raw, s, now)
    if (parsed.caId !== caId) throw new PkiError('crl_wrong_issuer')
    return applyCrl(s, parsed, 'url', now)
  } catch (e) {
    const err = e instanceof PkiError ? e : new PkiError('crl_fetch_failed')
    return { state: { ...s, cas: s.cas.map((c) => c.id === caId ? { ...c, crlError: { at: now, code: err.code } } : c) }, changed: false, error: err }
  }
}

/** Empreinte de l'ensemble des CRL : sert à savoir si root doit en recevoir une nouvelle version. */
export const crlSetDigest = (s: PkiState) => createHash('sha256').update(s.cas.filter((c) => c.crl).map((c) => `${c.id}:${c.crl!.sha256}`).sort().join('\n')).digest('hex')

/** Adresse de CRL autorisée : http(s) avec un nom ou une adresse (pas de bouclage ni de lien local), sans identifiants. */
export function normCrlUrl(raw: string): string | null {
  const v = raw.trim()
  if (v.length > 300 || !/^https?:\/\/[A-Za-z0-9._-]+(:\d{1,5})?(\/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*)?(\?[A-Za-z0-9._~%!$&'()*+,;=:@/?-]*)?$/.test(v)) return null
  const host = new URL(v).hostname.toLowerCase()
  if (process.env.DDI_TEST_MODE !== '1' && (host === 'localhost' || host.endsWith('.localhost'))) return null
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(host)
  if (m) { const [a, b] = [Number(m[1]), Number(m[2])]; if ((a === 127 && process.env.DDI_TEST_MODE !== '1') || a === 0 || (a === 169 && b === 254) || a >= 224) return null }
  return v
}
export async function fetchCrl(url: string, fetchFn: typeof fetch = fetch): Promise<Buffer> {
  let res: Response
  try { res = await fetchFn(url, { redirect: 'manual', signal: AbortSignal.timeout(20_000), headers: { accept: 'application/pkix-crl, application/x-pkcs7-crl, */*' } }) }
  catch { throw new PkiError('crl_fetch_failed') }
  if (res.status !== 200) throw new PkiError('crl_fetch_status', { status: res.status })
  const len = Number(res.headers.get('content-length') ?? 0)
  if (len > MAX_CRL_BYTES) throw new PkiError('crl_size')
  const chunks: Uint8Array[] = []; let size = 0
  const reader = res.body?.getReader()
  if (!reader) throw new PkiError('crl_fetch_failed')
  for (;;) {
    let r: ReadableStreamReadResult<Uint8Array>
    try { r = await reader.read() } catch { throw new PkiError('crl_fetch_failed') }
    if (r.done) break
    size += r.value.length
    if (size > MAX_CRL_BYTES) { await reader.cancel().catch(() => {}); throw new PkiError('crl_size') }
    chunks.push(r.value)
  }
  return Buffer.concat(chunks)
}

// ---- Certificat du serveur ----
const genKeyPair = promisify(generateKeyPair) as (t: any, o: any) => Promise<{ privateKey: KeyObject; publicKey: KeyObject }>
export async function newKey(t: KeyType): Promise<string> {
  const { privateKey } = t === 'ec256' ? await genKeyPair('ec', { namedCurve: 'prime256v1' }) : await genKeyPair('rsa', { modulusLength: t === 'rsa3072' ? 3072 : 2048 })
  return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
}
export const DNS_RE = /^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$/
export const CN_RE = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,62}[A-Za-z0-9]$|^[A-Za-z0-9]$/
/** Demande de signature (CSR) pour la clé donnée : CN, noms alternatifs DNS, usage « authentification de serveur ». */
export async function makeCsr(keyPem: string, cn: string, sans: string[]): Promise<string> {
  if (!CN_RE.test(cn) || sans.length > 20 || sans.some((d) => !DNS_RE.test(d))) throw new PkiError('csr_invalid_name')
  // « req -key » exige un fichier (ni « - » ni /dev/stdin avec un tube) : dossier temporaire privé 0700, fichier 0600, effacé dans tous les cas
  const r = await withTmp(async (_d, put) => openssl(['req', '-new', '-key', await put('k.pem', keyPem), '-sha256', '-subj', `/CN=${cn}`,
    '-addext', `subjectAltName=${[cn, ...sans].filter((v, i, a) => a.indexOf(v) === i).map((d) => `DNS:${d}`).join(',')}`,
    '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'keyUsage=digitalSignature,keyEncipherment']))
  if (r.code !== 0 || !r.stdout.includes('BEGIN CERTIFICATE REQUEST')) throw new PkiError('csr_failed')
  return r.stdout.trim() + '\n'
}
/** Clé privée PEM non chiffrée, ou une erreur claire : clé chiffrée sans mot de passe, mot de passe faux, type non pris en charge, RSA trop courte. */
export async function normalizeKey(keyPem: string, password?: string): Promise<{ pem: string; key: KeyObject }> {
  if (!/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/.test(keyPem) || (keyPem.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----/g) ?? []).length !== 1) throw new PkiError('key_invalid')
  const encrypted = /BEGIN ENCRYPTED PRIVATE KEY|Proc-Type: 4,ENCRYPTED/.test(keyPem)
  if (encrypted && !password) throw new PkiError('key_needs_password')
  const r = await openssl(['pkey', ...(encrypted ? ['-passin', 'env:DDI_KEYPASS'] : [])], { input: keyPem, env: password ? { DDI_KEYPASS: password } : {} })
  if (r.code !== 0 || !r.stdout.includes('PRIVATE KEY')) throw new PkiError(encrypted ? 'key_bad_password' : 'key_invalid')
  const key = createPrivateKey(r.stdout)
  const t = key.asymmetricKeyType, d: any = key.asymmetricKeyDetails ?? {}
  if (t === 'rsa') { if ((d.modulusLength ?? 0) < 2048) throw new PkiError('key_weak') }
  else if (t === 'ec') { if (!['prime256v1', 'secp384r1', 'secp521r1'].includes(d.namedCurve)) throw new PkiError('key_curve') }
  else throw new PkiError('key_type')
  return { pem: r.stdout.trim() + '\n', key }
}
/** Extrait certificat, chaîne et clé d'un fichier PKCS#12 (.pfx). Essaie d'abord openssl 3 standard, puis le module « legacy » (anciens chiffrements RC2). */
export async function readPkcs12(p12: Buffer, password: string): Promise<{ certs: string; key: string }> {
  if (!p12.length || p12.length > 1024 * 1024) throw new PkiError('p12_size')
  let r = await openssl(['pkcs12', '-passin', 'env:DDI_P12PASS', '-nodes'], { input: p12, env: { DDI_P12PASS: password } })
  if (r.code !== 0) r = await openssl(['pkcs12', '-passin', 'env:DDI_P12PASS', '-nodes', '-legacy'], { input: p12, env: { DDI_P12PASS: password } })
  if (r.code !== 0) throw new PkiError(/mac verify|invalid password|maybe wrong password/i.test(r.stderr) ? 'p12_bad_password' : 'p12_invalid')
  const certs = (r.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []).join('\n')
  const keys = r.stdout.match(/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC )?PRIVATE KEY-----/g) ?? []
  if (!certs || keys.length !== 1) throw new PkiError('p12_content')
  return { certs, key: keys[0]! }
}
/** Choisit dans `certsText` le certificat qui correspond à la clé (les autres sont ignorés : la chaîne vient de la liste de confiance). */
export function pickServerCert(certsText: string, key: KeyObject): string {
  for (const b of splitCerts(certsText)) { const { x } = parseCert(b); try { if (x.checkPrivateKey(key)) return b } catch { /* clé d'un autre type */ } }
  throw new PkiError('server_key_mismatch')
}

// ---- Vérification d'un certificat client (à blanc : rien n'est déployé) ----
export interface ClientCheck {
  ok: boolean
  chain: { ok: boolean; code: string | null; detail: string | null }
  revocation: 'good' | 'revoked' | 'crl_missing' | 'crl_expired' | 'skipped'
  identity: { subject: string; issuer: string; serial: string; notAfter: number; upn: string | null; dns: string[]; email: string[]; crlUrls: string[]; clientAuth: boolean }
}
const VERIFY_CODES: Record<string, string> = { '10': 'expired', '9': 'not_yet_valid', '23': 'revoked', '3': 'crl_missing', '12': 'crl_expired', '20': 'untrusted', '2': 'untrusted', '21': 'untrusted', '19': 'untrusted', '18': 'untrusted', '26': 'usage', '27': 'usage', '24': 'untrusted' }
export async function checkClientCert(s: PkiState, pem: string): Promise<ClientCheck> {
  const [leafPem, ...rest] = splitCerts(pem)
  const { info } = parseCert(leafPem!)
  const cas = s.cas.map((c) => c.pem).join('')
  const crls = s.cas.filter((c) => c.crl).map((c) => c.crl!.pem).join('')
  return withTmp(async (_d, put) => {
    const leaf = await put('leaf.pem', leafPem!)
    const args = ['verify', '-purpose', 'sslclient']
    if (cas) args.push('-CAfile', await put('cas.pem', cas)); else args.push('-no-CAfile', '-no-CApath')
    if (rest.length) args.push('-untrusted', await put('chain.pem', rest.join('')))
    if (s.checkCrl) { args.push('-crl_check'); if (crls) args.push('-CRLfile', await put('crls.pem', crls)) }
    args.push(leaf)
    const v = await openssl(args)
    const ok = v.code === 0 && /: OK/.test(v.stdout)
    const err = /error (\d+) at \d+ depth lookup: (.*)/.exec(v.stdout + v.stderr)
    const code = ok ? null : (err ? (VERIFY_CODES[err[1]!] ?? 'invalid') : 'invalid')
    const ext = await openssl(['x509', '-in', leaf, '-noout', '-ext', 'subjectAltName,crlDistributionPoints'])
    const text = ext.stdout
    const upn = /UPN::([^\s,]+)/.exec(text)?.[1] ?? null
    const dns = [...text.matchAll(/DNS:([^\s,]+)/g)].map((m) => m[1]!).slice(0, 20)
    const email = [...text.matchAll(/email:([^\s,]+)/g)].map((m) => m[1]!).slice(0, 20)
    const crlUrls = [...text.matchAll(/URI:(https?:\/\/[^\s,]+)/g)].map((m) => m[1]!).slice(0, 10)
    const revocation: ClientCheck['revocation'] = !s.checkCrl ? 'skipped' : code === 'revoked' ? 'revoked' : code === 'crl_missing' ? 'crl_missing' : code === 'crl_expired' ? 'crl_expired' : 'good'
    return { ok, chain: { ok, code, detail: err ? err[2]!.slice(0, 200) : null }, revocation,
      identity: { subject: info.subject, issuer: info.issuer, serial: info.serial, notAfter: info.notAfter, upn, dns, email, crlUrls, clientAuth: !info.ekus || info.ekus.includes(OID_CLIENT_AUTH) } }
  })
}

// ---- Dépôt pour root ----
export interface PkiDeposit { checkCrl: boolean; ca: string; server: string; key: string; crls: Record<string, string> }
/** Contenu du dossier radius-pki/ à déposer. Suppose readiness(s).ready ; la clé est déchiffrée ici (par l'appelant) juste avant l'écriture. */
export function buildDeposit(s: PkiState, keyPem: string): PkiDeposit {
  const ch = serverChain(s)
  if (!ch?.chainOk) throw new PkiError('server_chain')
  const crls: Record<string, string> = {}
  for (const c of s.cas) if (c.crl) crls[`${c.id}.pem`] = c.crl.pem
  return { checkCrl: s.checkCrl, ca: s.cas.map((c) => c.pem).join(''), server: ch.pem, key: keyPem, crls }
}
