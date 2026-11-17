// Autorités de la PKI du DDI (0.14.1) : racine auto-signée (laboratoire), émettrice signée par une racine du DDI ou par une racine HORS LIGNE (le DDI
// fabrique la demande de certificat, la racine la signe ailleurs, le certificat est importé), CRL. La console ne touche à aucune clé : elle dépose une
// demande JSON minuscule (.pki-request) et, pour les fichiers publics qu'on lui remet (chaîne, certificat signé, CRL), un dépôt dans pki-in/ ; root
// (ddibuntu-pki + pki-helper.py) revalide tout, y compris ces fichiers, puis publie la liste des autorités et leurs fichiers publics dans /run/ddibuntu.
// Les contrôles de forme ci-dessous sont les MÊMES que ceux de root (pki-helper.py) : ils ne servent qu'à répondre vite, jamais à protéger.
import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'
import { cfg } from './config'

export const CA_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/
export const EXTROOT_RE = /^ExtRoot-[0-9a-f]{8}$/
export const ALGS = ['rsa3072', 'rsa4096', 'ecp256', 'ecp384'] as const
export const ROOT_DAYS = { min: 365, max: 7305 } as const
export const ISSUING_DAYS = { min: 365, max: 3650 } as const
/** Taille maximale d'un fichier déposé (une chaîne de 5 certificats tient largement) : même limite que root. */
export const MAX_DEPOSIT = 16384
/** PKCS#12 d'une autorité existante (clé + chaîne) : 64 Ko au plus, comme root ; mot de passe de 1 à 128 caractères. */
export const MAX_P12 = 65536
// élément de nom distinctif : aucun séparateur (virgule, plus, égal, barre oblique inverse, guillemets, <, >, ;, #, /), aucun caractère de contrôle
export const DN_VALUE_RE = /^[^\x00-\x1f\x7f,+=\\"<>;#/\s]([^\x00-\x1f\x7f,+=\\"<>;#/]{0,62}[^\x00-\x1f\x7f,+=\\"<>;#/\s])?$/

/** Nom d'une autorité créée par le DDI : jamais « ManagementCA » (celle d'EJBCA) ni « ExtRoot-… » (racines hors ligne importées par le DDI). */
export const caName = z.string().trim().regex(CA_NAME_RE).refine((n) => n !== 'ManagementCA' && !n.startsWith('ExtRoot-'))
const optDn = z.union([z.literal(''), z.string().trim().regex(DN_VALUE_RE)]).optional()
const optCountry = z.union([z.literal(''), z.string().trim().regex(/^[A-Z]{2}$/)]).optional()

const B64_RE = /^[A-Za-z0-9+/=\s]*$/
/** Fichier remis par l'administrateur : texte PEM, ou binaire DER en base64 (un certificat .cer ou une CRL peuvent être l'un ou l'autre). */
export const blob = z.object({ pem: z.string().max(MAX_DEPOSIT * 2).optional(), der: z.string().max(MAX_DEPOSIT * 2).regex(B64_RE).optional() }).strict()
  .refine((b) => (b.pem === undefined) !== (b.der === undefined))
export type Blob = z.infer<typeof blob>

const dnFields = { cn: z.string().trim().regex(DN_VALUE_RE), ou: optDn, o: optDn, c: optCountry }
export const rootBody = z.object({
  name: caName, alg: z.enum(ALGS), days: z.number().int().min(ROOT_DAYS.min).max(ROOT_DAYS.max), ...dnFields,
}).strict()
export const issuingBody = z.object({
  name: caName, alg: z.enum(ALGS), days: z.number().int().min(ISSUING_DAYS.min).max(ISSUING_DAYS.max), ...dnFields,
  signedBy: z.union([z.literal('external'), caName]).default('external'),
  chain: blob.optional(),
}).strict().refine((b) => (b.signedBy === 'external') === (b.chain !== undefined))
export type RootBody = z.infer<typeof rootBody>
export type IssuingBody = z.infer<typeof issuingBody>
export const importBody = z.object({ certificate: blob }).strict()
/** Autorité existante (0.14.4) : fichier PKCS#12 en base64 et son mot de passe. Rien de tout cela n'est gardé : root les consomme puis les efface. */
export const importP12Body = z.object({
  name: caName, p12: z.string().min(8).max(Math.ceil(MAX_P12 / 3) * 4 + 8).regex(B64_RE),
  password: z.string().min(1).max(128).refine((p) => !/[\x00-\x1f\x7f]/.test(p)), confirm: z.string().max(80),
}).strict()
export type ImportP12Body = z.infer<typeof importP12Body>
export const rootCrlBody = z.object({ crl: blob }).strict()
export const resetBody = z.object({ confirm: z.string().trim().toLowerCase().max(253) }).strict()

/** Éléments facultatifs vides ignorés : ce que root reçoit ne contient que des valeurs. */
export function dnOf(b: { cn: string; ou?: string; o?: string; c?: string }): { cn: string; ou?: string; o?: string; c?: string } {
  const out: { cn: string; ou?: string; o?: string; c?: string } = { cn: b.cn }
  if (b.ou) out.ou = b.ou
  if (b.o) out.o = b.o
  if (b.c) out.c = b.c
  return out
}

export type DepositKind = 'chain.pem' | 'cert.pem' | 'crl' | 'csr.pem' | 'p12' | 'p12pw'
export type BlobKind = 'certs' | 'crl' | 'csr'
/** Octets d'un fichier remis, ou null s'il n'a pas la forme attendue (certificat / CRL en PEM ou en DER, ≤ 16 Ko). Root refait tous les contrôles. */
export function blobBytes(b: Blob, kind: BlobKind): Buffer | null {
  let buf: Buffer
  if (b.pem !== undefined) {
    const re = kind === 'certs' ? /-----BEGIN CERTIFICATE-----/ : kind === 'csr' ? /-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----/ : /-----BEGIN X509 CRL-----/
    if (!re.test(b.pem)) return null
    buf = Buffer.from(b.pem.replace(/\r\n?/g, '\n'), 'utf8')
  } else {
    buf = Buffer.from(b.der!.replace(/\s+/g, ''), 'base64')
    if (buf.length < 2 || buf[0] !== 0x30) return null   // un DER commence toujours par une SEQUENCE
  }
  return buf.length > 0 && buf.length <= MAX_DEPOSIT ? buf : null
}

/** Octets d'un PKCS#12 remis en base64, ou null s'il n'a pas la forme attendue (DER commençant par une SEQUENCE, 64 Ko au plus). Root refait tous les contrôles. */
export function p12Bytes(b64: string): Buffer | null {
  const buf = Buffer.from(b64.replace(/\s+/g, ''), 'base64')
  return buf.length >= 16 && buf.length <= MAX_P12 && buf[0] === 0x30 ? buf : null
}

const inDir = () => join(cfg().generatedDir, 'pki-in')
/** Dépôt SECRET (PKCS#12 d'une autorité et son mot de passe) pour root : 0600, supprimé avant d'être réécrit ; root l'efface aussitôt lu, quoi qu'il arrive. */
export async function putSecretDeposit(name: string, kind: 'p12' | 'p12pw', data: Buffer): Promise<void> {
  if (!CA_NAME_RE.test(name)) throw new Error('nom de dépôt invalide')
  await fs.mkdir(inDir(), { recursive: true, mode: 0o750 })
  const p = join(inDir(), `${name}.${kind}`)
  await fs.rm(p, { force: true })
  await fs.writeFile(p, data, { mode: 0o600, flag: 'wx' })
}
/** Dépose un fichier public pour root (jamais de secret ici) : l'ancien dépôt est supprimé avant, pour ne jamais écrire à travers un lien. */
export async function putDeposit(name: string, kind: DepositKind, data: Buffer): Promise<void> {
  if (!CA_NAME_RE.test(name)) throw new Error('nom de dépôt invalide')
  await fs.mkdir(inDir(), { recursive: true, mode: 0o750 })
  const p = join(inDir(), `${name}.${kind}`)
  await fs.rm(p, { force: true })
  await fs.writeFile(p, data, { mode: 0o640, flag: 'wx' })
}
export const dropDeposit = (name: string, kind: DepositKind) => fs.rm(join(inDir(), `${name}.${kind}`), { force: true }).catch(() => {})

// ---- Lecture de ce que root publie ----
export type CaKind = 'root' | 'issuing' | 'extroot' | 'unknown'
export type CaState = 'active' | 'waiting' | 'external' | 'other'
const KINDS: readonly CaKind[] = ['root', 'issuing', 'extroot', 'unknown']
const CA_STATES: readonly CaState[] = ['active', 'waiting', 'external', 'other']
export interface PkiCa {
  name: string; kind: CaKind; state: CaState; dn: string; issuer: string; selfSigned: boolean; serial: string; notBefore: string; notAfter: string
  keyAlg: string; keyBits: number; curve: string; sigAlg: string; pathLen: number | null; sha256: string
  signedBy: string; alg: string; createdAt: number | null; crlUrl: string; certUrl: string
  /** Autorité reprise d'un fichier PKCS#12 (0.14.4) : sa clé est dans la base du DDI, comme celle d'une racine de laboratoire. */
  imported: boolean
  /** Émettrice sous une racine hors ligne : la racine (ExtRoot-…) dont les adresses CRL / certificat vont dans le certificat à faire signer. */
  extRoot: string
  crl: { number: number; thisUpdate: string; nextUpdate: string; bytes: number } | null
  files: { cert: boolean; chain: boolean; csr: boolean; crl: boolean }
  /** Nom utilisable pour une action (certificat, CRL, import) : une autorité créée à la main dans EJBCA peut porter un nom que le DDI ne gère pas. */
  managed: boolean
}
const str = (v: unknown, n: number) => String(v ?? '').slice(0, n)
export async function readPkiCas(): Promise<{ at: number; cas: PkiCa[] } | null> {
  let j: any
  try { j = JSON.parse(await fs.readFile(cfg().pkiCasFile, 'utf8')) } catch { return null }
  if (typeof j?.at !== 'number' || !Array.isArray(j.cas)) return null
  const cas: PkiCa[] = []
  for (const c of j.cas.slice(0, 200)) {
    if (typeof c?.name !== 'string' || !c.name) continue
    const crl = c.crl && typeof c.crl === 'object' ? { number: Number(c.crl.number) || 0, thisUpdate: str(c.crl.thisUpdate, 24), nextUpdate: str(c.crl.nextUpdate, 24), bytes: Number(c.crl.bytes) || 0 } : null
    const f = c.files ?? {}
    const name = str(c.name, 80)
    cas.push({
      name, kind: KINDS.includes(c.kind) ? c.kind : 'unknown', state: CA_STATES.includes(c.state) ? c.state : 'other',
      dn: str(c.dn, 512), issuer: str(c.issuer, 512), selfSigned: c.selfSigned === true, serial: str(c.serial, 80), notBefore: str(c.notBefore, 24), notAfter: str(c.notAfter, 24),
      keyAlg: str(c.keyAlg, 12), keyBits: Number(c.keyBits) || 0, curve: str(c.curve, 24), sigAlg: str(c.sigAlg, 40), pathLen: Number.isInteger(c.pathLen) ? c.pathLen : null,
      sha256: /^[0-9a-f]{64}$/.test(c.sha256 ?? '') ? c.sha256 : '', signedBy: str(c.signedBy, 80), alg: str(c.alg, 12), imported: c.imported === true,
      createdAt: Number.isInteger(c.createdAt) ? c.createdAt : null, extRoot: EXTROOT_RE.test(c.extRoot ?? '') ? c.extRoot : '', crlUrl: str(c.crlUrl, 1024), certUrl: str(c.certUrl, 1024), crl,
      files: { cert: f.cert === true, chain: f.chain === true, csr: f.csr === true, crl: f.crl === true },
      managed: CA_NAME_RE.test(name) && name !== 'ManagementCA',
    })
  }
  return { at: j.at, cas }
}

export const FILES = { cert: { file: 'cert.pem', type: 'application/x-pem-file', ext: 'pem' }, chain: { file: 'chain.pem', type: 'application/x-pem-file', ext: 'chain.pem' },
  csr: { file: 'csr.pem', type: 'application/pkcs10', ext: 'csr' }, crl: { file: 'crl.der', type: 'application/pkix-crl', ext: 'crl' } } as const
export type FileKey = keyof typeof FILES
/** Fichier public d'une autorité (jamais une clé : root n'en publie aucune). null s'il est absent ou si ce n'est pas un fichier ordinaire. */
export async function readCaFile(name: string, key: FileKey): Promise<Buffer | null> {
  if (!CA_NAME_RE.test(name) || !(key in FILES)) return null
  const p = join(cfg().pkiCaDir, name, FILES[key].file)
  try {
    const st = await fs.lstat(p)
    if (!st.isFile() || st.size > 65536) return null
    return await fs.readFile(p)
  } catch { return null }
}
