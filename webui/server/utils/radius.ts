// Service RADIUS (0.13.0, itération 1 ; EAP-TLS 0.13.2 ; règles d'accès 0.13.3) : clients (équipements réseau) et pilotage du service FreeRADIUS de CE nœud.
// La console ne démarre rien et ne touche à aucune configuration système : elle dépose radius-clients.conf + .radius-request, que root
// (ddibuntu-radius) revalide ligne à ligne, installe, contrôle (freeradius -Cx) et applique, puis publie l'état et le résultat.
import { createHmac, randomInt } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'
import { decryptSecret, encryptSecret } from './auth'
import { cfg, requireSecret } from './config'
import { cidrToString, parseCidr, parseIp } from './net'
import type { Cidr } from './net'
import type { PkiDeposit } from './radius-pki'

export const USAGES = ['wifi', 'vpn', 'switch', 'other'] as const
export type Usage = (typeof USAGES)[number]
export const SELFTEST_NAME = 'ddi-selftest'
export const MAX_CLIENTS = 2000

// Secret partagé : caractères sûrs dans clients.conf (ni guillemet, ni barre oblique inverse, ni « $ » « % » « # », ni espace)
export const SECRET_RE = /^[A-Za-z0-9._~+=:@,;()!*-]{16,128}$/
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
/** Secret aléatoire de 32 caractères (alphabet sans caractères ambigus), tirage uniforme. */
export function genSecret(len = 32): string { let s = ''; for (let i = 0; i < len; i++) s += ALPHABET[randomInt(ALPHABET.length)]; return s }

/** Secret du client d'essai local (127.0.0.1) : dérivé de la clé de la console, jamais affiché ni stocké. */
export function selftestSecret(): string { return createHmac('sha256', requireSecret()).update('ddibuntu-radius-selftest').digest('hex').slice(0, 32) }

/** Adresse ou réseau d'un client → réseau normalisé, ou null. Mêmes bornes que ddibuntu-radius (root les revérifie) : pas de bouclage, de multicast, de lien local ; /16 IPv4 et /48 IPv6 au plus larges. */
export function normClientAddress(raw: string): string | null {
  const v = raw.trim()
  if (!v || v.length > 64) return null
  let c: Cidr | null
  if (v.includes('/')) c = parseCidr(v)
  else { const ip = parseIp(v); c = ip ? { v: ip.v, n: ip.n, prefix: ip.v === 4 ? 32 : 128 } : null }
  if (!c) return null
  if (c.v === 4) {
    const o1 = Number(c.n >> 24n), o2 = Number((c.n >> 16n) & 255n)
    if (c.prefix < 16 || o1 === 0 || o1 === 127 || o1 >= 224 || (o1 === 169 && o2 === 254)) return null
  } else {
    const top = Number(c.n >> 112n)
    if (c.prefix < 48 || c.n === 0n || c.n === 1n || (top >> 8) === 0xff || (top & 0xffc0) === 0xfe80) return null
  }
  return cidrToString(c)
}

export const clientBody = z.object({
  name: z.string().trim().toLowerCase().regex(/^[a-z][a-z0-9-]{0,40}$/).refine((n) => n !== SELFTEST_NAME, 'reserved'),
  address: z.string().trim().min(1).max(64),
  usage: z.enum(USAGES).default('other'),
  secret: z.string().max(128).nullish(),
  mfa: z.boolean().default(false),   // 0.17.0 : second facteur (mot de passe + code vérifiés par le fournisseur MFA) ; le client n'utilise alors plus EAP
  enabled: z.boolean().default(true),
  comment: z.string().trim().max(500).nullish(),
}).strict().transform((b, ctx) => {
  const address = normClientAddress(b.address)
  if (!address) { ctx.addIssue({ code: 'custom', path: ['address'], message: 'address' }); return z.NEVER }
  const secret = b.secret ? b.secret : null
  if (secret !== null && !SECRET_RE.test(secret)) { ctx.addIssue({ code: 'custom', path: ['secret'], message: 'secret' }); return z.NEVER }
  return { ...b, address, secret, comment: b.comment || null }
})

export interface ClientRow { name: string; address: string; secret_enc: string; enabled: boolean; mfa?: boolean }
/** Un client MFA transporte un mot de passe (masqué par le secret partagé, pas chiffré) : secret long exigé, comme la 0.17.0 le promet à l'administrateur. */
export const MFA_SECRET_MIN = 32
export const MFA_SECRET_LEN = 40

/** clients.conf : le client d'essai local, puis les clients actifs (ordre du nom). Forme imposée, relue telle quelle par root. */
export function renderClientsConf(rows: ClientRow[], selfSecret = selftestSecret()): string {
  const block = (name: string, address: string, secret: string, mfa = false) => {
    const c = parseCidr(address)!
    const host = c.prefix === (c.v === 4 ? 32 : 128)
    const addr = host ? cidrToString(c).replace(/\/\d+$/, '') : cidrToString(c)
    return [`client "${name}" {`, `\t${c.v === 4 ? 'ipaddr' : 'ipv6addr'} = ${addr}`, `\tsecret = "${secret}"`, `\tshortname = ${name}`, '\trequire_message_authenticator = yes', '\tnas_type = other', ...(mfa ? ['\tvirtual_server = ddibuntu-mfa'] : []), '}', ''].join('\n')
  }
  const out = [block(SELFTEST_NAME, '127.0.0.1/32', selfSecret)]
  for (const r of [...rows].filter((x) => x.enabled).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    out.push(block(r.name, r.address, decryptSecret(r.secret_enc), r.mfa === true))
  }
  return out.join('\n')
}
export const sealSecret = (s: string) => encryptSecret(s)

// ---- Dépôt de la demande et lecture de l'état publié par root ----
export interface EapStatus { enabled: boolean; server: { subject: string; notAfter: number | null } | null; cas: number; checkCrl: boolean; crls: Array<{ issuer: string; nextUpdate: number | null }> }
export interface AuthzStatus { enabled: boolean; rules: number; servers: string[] }
/** Jonction de CE nœud au domaine (PEAP-MSCHAPv2) publiée par root : sans secret. `trust` : null = non mesuré (winbindd arrêté). */
export interface WinbindStatus { joined: boolean; realm: string; netbios: string; computer: string; at: number | null; active: boolean; trust: boolean | null }
export interface RadiusStatus { winbind: WinbindStatus; at: number; installed: boolean; version: string; configured: boolean; active: boolean; enabled: boolean; clients: number; eap: EapStatus; authz: AuthzStatus; ldapModule: boolean; restModule: boolean }
/** Règles d'accès déposées pour root : DONNÉES seulement (rules.json, ldap.json, ldap-ca.pem), jamais de texte de configuration. */
export interface AuthzDeposit { rules: string; ldap: string; caPem?: string; auth?: string; mfa?: string; mfaCa?: string }
/** Compte qui joint le domaine : transmis une fois à root (fichier 0600 écrasé après usage), jamais conservé par la console. */
export interface JoinDeposit { realm: string; netbios: string; servers: string[]; user?: string; password?: string }
export interface RadiusResult { at: number; action: string; ok: boolean; message: string }
export async function readRadiusStatus(): Promise<RadiusStatus | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().radiusStatusFile, 'utf8'))
    if (typeof j?.at !== 'number') return null
    const e = j.eap ?? {}
    const eap: EapStatus = { enabled: e.enabled === true, server: e.server ? { subject: String(e.server.subject ?? '').slice(0, 300), notAfter: typeof e.server.not_after === 'number' ? e.server.not_after * 1000 : null } : null,
      cas: Number(e.cas) || 0, checkCrl: e.check_crl === true,
      crls: (Array.isArray(e.crls) ? e.crls : []).slice(0, 64).map((c: any) => ({ issuer: String(c?.issuer ?? '').slice(0, 300), nextUpdate: typeof c?.next_update === 'number' ? c.next_update * 1000 : null })) }
    const z = j.authz ?? {}
    const authz: AuthzStatus = { enabled: z.enabled === true, rules: Number(z.rules) || 0, servers: (Array.isArray(z.servers) ? z.servers : []).slice(0, 5).map((x: unknown) => String(x).slice(0, 300)) }
    const w = j.winbind ?? {}
    const winbind: WinbindStatus = { joined: w.joined === true, realm: String(w.realm ?? '').slice(0, 253), netbios: String(w.netbios ?? '').slice(0, 15), computer: String(w.computer ?? '').slice(0, 15),
      at: typeof w.at === 'number' ? w.at * 1000 : null, active: w.active === true, trust: typeof w.trust === 'boolean' ? w.trust : null }
    return { at: j.at, installed: j.installed === true, version: String(j.version ?? '').slice(0, 24), configured: j.configured === true, active: j.active === true, enabled: j.enabled === true, clients: Number(j.clients) || 0, eap, authz, ldapModule: j.ldap_module === true, restModule: j.rest_module === true, winbind }
  } catch { return null }
}
export async function readRadiusResult(): Promise<RadiusResult | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().radiusResultFile, 'utf8'))
    if (typeof j?.at !== 'number') return null
    return { at: j.at, action: String(j.action ?? '').slice(0, 24), ok: j.ok === true, message: String(j.message ?? '').slice(0, 300) }
  } catch { return null }
}
export async function radiusRequestPending(): Promise<boolean> {
  try { await fs.lstat(join(cfg().generatedDir, '.radius-request')); return true } catch { return false }
}
export type RadiusRequest = { action: 'apply'; clients: string; pki?: PkiDeposit; authz?: AuthzDeposit } | { action: 'stop' } | { action: 'status' } | { action: 'crl'; crls: Record<string, string> }
  | { action: 'join'; join: JoinDeposit } | { action: 'leave'; join?: JoinDeposit }
/** Écrit le dossier radius-pki/ (fichiers 0600 : la clé privée n'est lisible que du propriétaire et de root ; root les efface après traitement). */
async function writePkiDir(dir: string, files: Record<string, string>, crls: Record<string, string>) {
  const root = join(dir, 'radius-pki')
  await fs.rm(root, { recursive: true, force: true })
  await fs.mkdir(join(root, 'crl'), { recursive: true, mode: 0o750 })
  for (const [n, data] of Object.entries(files)) await fs.writeFile(join(root, n), data, { mode: 0o600 })
  for (const [n, data] of Object.entries(crls)) {
    if (!/^[A-Za-z0-9._-]{1,64}\.pem$/.test(n)) throw new Error('crl_name')
    await fs.writeFile(join(root, 'crl', n), data, { mode: 0o600 })
  }
}
/** Écrit le dossier radius-authz/ (fichiers 0600 : ldap.json contient le mot de passe de liaison ; root les efface après traitement). */
async function writeAuthzDir(dir: string, a: AuthzDeposit) {
  const root = join(dir, 'radius-authz')
  await fs.rm(root, { recursive: true, force: true })
  await fs.mkdir(root, { recursive: true, mode: 0o750 })
  await fs.writeFile(join(root, 'rules.json'), a.rules, { mode: 0o600 })
  await fs.writeFile(join(root, 'ldap.json'), a.ldap, { mode: 0o600 })
  if (a.caPem) await fs.writeFile(join(root, 'ldap-ca.pem'), a.caPem, { mode: 0o600 })
  if (a.auth) await fs.writeFile(join(root, 'auth.json'), a.auth, { mode: 0o600 })
  if (a.mfa) await fs.writeFile(join(root, 'mfa.json'), a.mfa, { mode: 0o600 })   // porte le secret client du fournisseur MFA : root l'efface après traitement
  if (a.mfaCa) await fs.writeFile(join(root, 'mfa-ca.pem'), a.mfaCa, { mode: 0o600 })
}
/** Écrit le dossier radius-join/ (join.json 0600 : il porte le mot de passe du compte qui joint ; root l'écrase après usage). */
async function writeJoinDir(dir: string, j: JoinDeposit) {
  const root = join(dir, 'radius-join')
  await fs.rm(root, { recursive: true, force: true })
  await fs.mkdir(root, { recursive: true, mode: 0o750 })
  await fs.writeFile(join(root, 'join.json'), JSON.stringify(j) + '\n', { mode: 0o600 })
}
export async function depositRadiusRequest(req: RadiusRequest): Promise<{ requestedAt: number }> {
  const dir = cfg().generatedDir
  if (req.action === 'apply') {
    if (req.authz && !req.pki) throw new Error('authz_needs_pki')
    // un dépôt ancien (non traité) ne doit jamais être relu : on repart d'un dossier propre
    await fs.rm(join(dir, 'radius-authz'), { recursive: true, force: true })
    if (req.pki) await writePkiDir(dir, { 'pki.json': JSON.stringify({ checkCrl: req.pki.checkCrl }) + '\n', 'ca.pem': req.pki.ca, 'server.pem': req.pki.server, 'server.key': req.pki.key }, req.pki.crls)
    if (req.authz) await writeAuthzDir(dir, req.authz)
    await fs.writeFile(join(dir, 'radius-clients.conf'), req.clients, { mode: 0o640 })
  }
  if (req.action === 'crl') await writePkiDir(dir, {}, req.crls)
  if (req.action === 'join' || req.action === 'leave') {
    await fs.rm(join(dir, 'radius-join'), { recursive: true, force: true })
    if (req.join) await writeJoinDir(dir, req.join)
  }
  // si la demande ne peut pas être écrite, le mot de passe déposé ne doit pas rester sur le disque
  try { await writeRequestFile(dir, req) } catch (e) { await fs.rm(join(dir, 'radius-join'), { recursive: true, force: true }); throw e }
  return { requestedAt: Math.floor(Date.now() / 1000) }
}
async function writeRequestFile(dir: string, req: RadiusRequest) {
  // la demande est écrite EN DERNIER : root est déclenché par sa modification, les fichiers déposés sont donc déjà en place
  await fs.writeFile(join(dir, '.radius-request'), JSON.stringify(req.action === 'apply' && req.pki ? { action: 'apply', pki: true, ...(req.authz ? { authz: true } : {}) } : { action: req.action }) + '\n', { mode: 0o640 })
}
