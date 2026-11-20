// Enrôlement des postes (0.18.0) : un poste du domaine obtient son certificat EAP-TLS de la PKI du DDI en s'authentifiant par Kerberos (compte machine).
// La clé privée naît et reste sur le poste (la demande de certificat seule voyage). Le nom du certificat vient du compte Kerberos authentifié et de
// l'attribut dNSHostName de l'annuaire, JAMAIS de la demande. Ce fichier : réglages, keytab (chiffré en base), acceptation Kerberos, limitation.
import { spawn } from 'node:child_process'
import { promises as fs } from 'node:fs'
import { z } from 'zod'
import { cfg } from './config'
import { decryptSecret, encryptSecret } from './auth'
import { getSetting, one } from './db'
import { withTmp } from './openssl'
import { caName } from './pki-ca'
import { GROUP_DN_RE } from './radius-rules'
import { DNS_RE } from './pki-certs'

export const ENROLL_KEY = 'enroll_settings'
export const KEYTAB_KEY = 'enroll_keytab'

export interface EnrollSettings {
  enabled: boolean
  /** Autorité émettrice (créée par le DDI) qui signe les certificats de postes. */
  ca: string
  /** Groupe AD dont le compte machine doit être membre (DN complet) ; l'appartenance transitive compte. */
  groupDn: string
  /** Adresse (nom DNS) sous laquelle les postes joignent la console : doit être celle du SPN HTTP/… du keytab. */
  host: string
  /** Délai minimal entre deux émissions pour un même poste (secondes) et plafond par 24 h ; plafond global par minute. */
  minIntervalSec: number
  maxPerDay: number
  maxPerMinute: number
}
export const ENROLL_DEFAULTS: EnrollSettings = { enabled: false, ca: '', groupDn: '', host: '', minIntervalSec: 300, maxPerDay: 6, maxPerMinute: 30 }
export const ENROLL_LIMITS = { minInterval: { min: 30, max: 86_400 }, perDay: { min: 1, max: 50 }, perMinute: { min: 1, max: 600 } }

export const enrollBody = z.object({
  enabled: z.boolean(),
  ca: z.union([z.literal(''), caName]),
  groupDn: z.union([z.literal(''), z.string().trim().regex(GROUP_DN_RE)]),
  host: z.union([z.literal(''), z.string().trim().toLowerCase().regex(DNS_RE)]),
  minIntervalSec: z.number().int().min(ENROLL_LIMITS.minInterval.min).max(ENROLL_LIMITS.minInterval.max),
  maxPerDay: z.number().int().min(ENROLL_LIMITS.perDay.min).max(ENROLL_LIMITS.perDay.max),
  maxPerMinute: z.number().int().min(ENROLL_LIMITS.perMinute.min).max(ENROLL_LIMITS.perMinute.max),
}).strict()

export const loadEnroll = async (): Promise<EnrollSettings> => ({ ...ENROLL_DEFAULTS, ...(await getSetting<Partial<EnrollSettings>>(ENROLL_KEY, {})) })
/** Un service activé doit être complet : autorité, groupe, nom de la console. */
export const enrollComplete = (s: EnrollSettings) => !!s.ca && !!s.groupDn && !!s.host

// ---- Keytab du service (SPN HTTP/<nom de la console>) ----
export interface KeytabEntry { principal: string; kvno: number; enctype: number }
export interface KeytabInfo { entries: KeytabEntry[]; principals: string[]; realm: string }
export interface StoredKeytab { enc: string; entries: KeytabEntry[]; principals: string[]; realm: string; kvno: Record<string, number>; size: number; at: number }
const ENCTYPE_BAD = new Set([1, 2, 3, 23, 24])   // DES (1-3) et RC4 / exportable (23, 24) : refusés, un keytab de service doit porter de l'AES

/** Lit un keytab MIT (format 0x0502) : principaux, numéros de version et types de chiffrement. Refuse tout ce qui n'est pas bien formé. */
export function parseKeytab(buf: Buffer): KeytabInfo {
  if (buf.length < 8 || buf.length > 65536 || buf[0] !== 0x05 || buf[1] !== 0x02) throw new Error('keytab_format')
  const entries: KeytabEntry[] = []
  let o = 2
  while (o + 4 <= buf.length) {
    const size = buf.readInt32BE(o); o += 4
    if (size < 0) { o += -size; continue }   // trou laissé par une suppression
    if (size === 0 || o + size > buf.length) throw new Error('keytab_format')
    const end = o + size
    let p = o
    const u16 = () => { if (p + 2 > end) throw new Error('keytab_format'); const v = buf.readUInt16BE(p); p += 2; return v }
    const str = () => { const n = u16(); if (p + n > end) throw new Error('keytab_format'); const v = buf.toString('utf8', p, p + n); p += n; return v }
    const ncomp = u16()
    if (ncomp < 1 || ncomp > 4) throw new Error('keytab_format')
    const realm = str()
    const comps = Array.from({ length: ncomp }, str)
    if (p + 9 > end) throw new Error('keytab_format')
    p += 4 + 4                      // type de nom, date
    let kvno = buf[p]!; p += 1
    const enctype = u16(); const keylen = u16()
    if (p + keylen > end) throw new Error('keytab_format')
    p += keylen
    if (p + 4 <= end) kvno = buf.readUInt32BE(p)
    entries.push({ principal: `${comps.join('/')}@${realm}`, kvno, enctype })
    o = end
  }
  if (!entries.length) throw new Error('keytab_empty')
  const principals = [...new Set(entries.map((e) => e.principal))]
  const realms = new Set(principals.map((x) => x.slice(x.lastIndexOf('@') + 1)))
  if (realms.size !== 1) throw new Error('keytab_realms')
  return { entries, principals, realm: [...realms][0]! }
}
/** Le keytab doit porter le service HTTP/<hôte> en AES ; sinon le motif est rendu. */
export function keytabProblem(info: KeytabInfo, host: string): string | null {
  const mine = info.entries.filter((e) => e.principal.toLowerCase().startsWith(`http/${host.toLowerCase()}@`))
  if (!mine.length) return 'keytab_spn'
  if (info.principals.some((x) => !/^http\//i.test(x))) return 'keytab_extra'   // un keytab d'enrôlement ne porte que le service HTTP/… (un autre principal ouvrirait d'autres tickets)
  if (mine.every((e) => ENCTYPE_BAD.has(e.enctype))) return 'keytab_enctype'
  return null
}
export const loadKeytab = () => getSetting<StoredKeytab | null>(KEYTAB_KEY, null)
export function sealKeytab(raw: Buffer, info: KeytabInfo): StoredKeytab {
  const kvno: Record<string, number> = {}
  for (const e of info.entries) kvno[e.principal] = Math.max(kvno[e.principal] ?? 0, e.kvno)
  return { enc: encryptSecret(raw.toString('base64')), entries: info.entries.slice(0, 64), principals: info.principals, realm: info.realm, kvno, size: raw.length, at: Math.floor(Date.now() / 1000) }
}

// ---- Acceptation Kerberos : « Authorization: Negotiate <jeton> » ----
export type Accepted = { ok: true; principal: string; token: string } | { ok: false; error: 'busy' | 'no_token' | 'no_keytab' | 'bad_token' | 'replay' | 'clock' | 'keytab' | 'rejected' | 'gssapi_missing' | 'helper_failed' }
export function negotiateToken(header: string | undefined): string | null {
  const m = /^Negotiate ([A-Za-z0-9+/=]{16,32768})$/.exec((header ?? '').trim())
  if (!m) return null
  // un jeton SPNEGO commence par l'étiquette ASN.1 0x60 (jeton initial) ou 0xA1 (réponse) : tout autre début est refusé avant de déchiffrer le keytab ou de lancer l'assistant
  const first = Buffer.from(m[1]!.slice(0, 8), 'base64')[0]
  return first === 0x60 || first === 0xa1 ? m[1]! : null
}
/** Par principal authentifié : au plus 60 demandes et 20 refus écrits au journal par minute (un compte du domaine peut obtenir un ticket pour ce service ; il ne doit ni remplir le journal ni faire travailler l'annuaire sans limite). */
const gates = new Map<string, { w: number; req: number; aud: number }>()
function gate(key: string, now: number) {
  let g = gates.get(key)
  if (!g || now - g.w > 60_000) {
    if (gates.size > 10_000) for (const [k, v] of gates) if (now - v.w > 60_000) gates.delete(k)
    g = { w: now, req: 0, aud: 0 }; gates.set(key, g)
  }
  return g
}
export const principalAllowed = (principal: string, now = Date.now()): boolean => ++gate(principal.toLowerCase(), now).req <= 60
export const principalAuditOk = (principal: string, now = Date.now()): boolean => ++gate(principal.toLowerCase(), now).aud <= 20
/** Le domaine DNS d'un compte, lu dans les composants « DC= » de son DN (CN=PC003,CN=Computers,DC=lab,DC=test → lab.test). */
export function domainOfDn(dn: string): string {
  return [...dn.matchAll(/(?:^|,)\s*DC=([^,]+)/gi)].map((m) => m[1]!.trim().toLowerCase()).join('.')
}
export const dnsInDomain = (fqdn: string, domain: string): boolean => !!domain && fqdn.toLowerCase().endsWith(`.${domain}`)
const MAX_HELPERS = 4
let helpers = 0
/** Journal des refus AVANT authentification : borné (un flot de requêtes anonymes ne doit ni remplir la base ni noyer l'activité) ; au-delà, le refus est compté mais pas écrit. */
let preWindow = 0, preCount = 0
export function preAuthAuditOk(now = Date.now()): boolean {
  if (now - preWindow > 60_000) { preWindow = now; preCount = 0 }
  return ++preCount <= 20
}
/** Lance l'assistant (compte de la console, jamais root) avec une copie du keytab en mémoire partagée, effacée aussitôt ; au plus MAX_HELPERS à la fois. */
export async function acceptNegotiate(token: string, kt: StoredKeytab): Promise<Accepted> {
  if (helpers >= MAX_HELPERS) return { ok: false, error: 'busy' }
  helpers++
  try { return await runHelper(token, kt) } finally { helpers-- }
}
async function runHelper(token: string, kt: StoredKeytab): Promise<Accepted> {
  let keytab: Buffer
  try { keytab = Buffer.from(decryptSecret(kt.enc), 'base64') } catch { return { ok: false, error: 'no_keytab' } }
  await fs.mkdir(cfg().enrollRcacheDir, { recursive: true, mode: 0o700 }).catch(() => undefined)
  return withTmp(async (_d, put) => {
    const path = await put('http.keytab', keytab)
    return new Promise<Accepted>((resolve) => {
      const child = spawn(cfg().enrollGss, [], { env: { PATH: '/usr/bin:/bin', LANG: 'C', KRB5_KTNAME: `FILE:${path}`, KRB5RCACHEDIR: cfg().enrollRcacheDir, KRB5_CONFIG: '/dev/null' }, stdio: ['pipe', 'pipe', 'ignore'] })
      let out = ''
      const timer = setTimeout(() => { child.kill('SIGKILL') }, 10_000)
      child.stdout.on('data', (d) => { if (out.length < 40_000) out += d })
      child.on('error', () => { clearTimeout(timer); resolve({ ok: false, error: 'helper_failed' }) })
      child.on('close', () => {
        clearTimeout(timer)
        try {
          const j = JSON.parse(out.split('\n')[0] ?? '')
          if (j?.ok === true && typeof j.principal === 'string') return resolve({ ok: true, principal: j.principal, token: typeof j.token === 'string' ? j.token : '' })
          const codes = ['bad_token', 'replay', 'clock', 'keytab', 'rejected', 'gssapi_missing']
          return resolve({ ok: false, error: codes.includes(j?.error) ? j.error : 'rejected' })
        } catch { resolve({ ok: false, error: 'helper_failed' }) }
      })
      child.stdin.on('error', () => undefined)
      child.stdin.end(token)
    })
  }, { ram: true })
}

/** « POSTE$@REALM » → « POSTE$ » ; un compte d'utilisateur, un autre domaine ou une forme inattendue sont refusés (null). */
export function machineFromPrincipal(principal: string, realm: string): string | null {
  const m = /^([A-Za-z0-9_-]{1,19}\$)@([A-Za-z0-9.-]{1,64})$/.exec(principal)
  if (!m || m[2]!.toUpperCase() !== realm.toUpperCase()) return null
  return m[1]!
}

// ---- Limitation : lue dans le journal d'audit (aucune table de plus, elle suit le cluster) ----
export type RateVerdict = 'ok' | 'too_soon' | 'daily' | 'busy'
export async function rateVerdict(sam: string, s: Pick<EnrollSettings, 'minIntervalSec' | 'maxPerDay' | 'maxPerMinute'>): Promise<RateVerdict> {
  const own = await one<{ last: number | null; day: number }>(
    "select extract(epoch from (now() - max(at)))::float8 as last, count(*)::int as day from audit_log where action = 'enroll.issued' and lower(entity_id) = lower($1) and at > now() - interval '1 day'", [sam])
  if (own && own.day >= s.maxPerDay) return 'daily'
  if (own?.last !== null && own?.last !== undefined && own.last < s.minIntervalSec) return 'too_soon'
  const all = await one<{ n: number }>("select count(*)::int as n from audit_log where action = 'enroll.issued' and at > now() - interval '1 minute'")
  if ((all?.n ?? 0) >= s.maxPerMinute) return 'busy'
  return 'ok'
}

/** Une seule émission d'enrôlement à la fois dans ce processus : la limitation est lue puis l'émission comptée dans le même créneau (sinon des requêtes simultanées passent toutes la vérification). */
let chain: Promise<unknown> = Promise.resolve()
export function enrollSerial<T>(fn: () => Promise<T>): Promise<T> {
  const run = chain.then(() => fn())
  chain = run.catch(() => undefined)
  return run
}
/** Le premier label du nom DNS doit être celui du compte (au plus 15 caractères en NetBIOS : un nom plus long est tronqué dans sAMAccountName). */
export function dnsMatchesAccount(fqdn: string, sam: string): boolean {
  const label = fqdn.split('.')[0]!.toLowerCase(), base = sam.replace(/\$$/, '').toLowerCase()
  return label === base || (base.length === 15 && label.startsWith(base))
}
