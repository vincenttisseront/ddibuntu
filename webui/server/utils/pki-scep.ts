// SCEP de la PKI du DDI (0.14.8). EJBCA Community n'a que le mode « CA » : l'équipement est PRÉENREGISTRÉ (nom, profil, noms alternatifs) avec un défi à usage unique ; il
// s'inscrit ensuite tout seul auprès de l'alias SCEP, avec SA clé (jamais vue ici). Le nom distinctif et les SAN viennent de l'entité préenregistrée, jamais de sa demande.
// Frontière de privilèges : la console fabrique le défi et le dépose dans un fichier SECRET (pki-in/<id>.scepw, 0600) que root lit une fois puis efface ; la demande JSON
// (≤ 4 Ko) n'en porte jamais. Le défi n'est rendu QU'UNE fois à l'administrateur : ni stocké, ni journalisé, ni publié (EJBCA n'en garde qu'une empreinte).
// Root publie /run/ddibuntu/pki-scep.json (alias, adresse, équipements et leur état) ; rien n'en est repris sans être borné et revalidé ici.
import { randomInt } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { z } from 'zod'
import { cfg } from './config'
import { certCommon, sanRules } from './pki-certs'
import { readPkiResult } from './pki'
import type { PkiResult } from './pki'

/** Nom fixe de l'alias SCEP dans EJBCA : il figure dans l'adresse donnée aux équipements. */
export const SCEP_ALIAS = 'ddibuntu'
/** Nom de l'équipement = nom d'utilisateur de l'entité dans EJBCA : mêmes bornes que root (pki-helper.py). */
export const SCEP_CN_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/
/** Entités de service d'EJBCA ; tout nom commençant par « ddi- » est réservé aux entités d'émission du DDI. */
export const SCEP_RESERVED = ['ejbca', 'superadmin'] as const
export const SCEP_STATES = ['waiting', 'expired', 'failed', 'issued', 'revoked', 'other'] as const
export type ScepState = (typeof SCEP_STATES)[number]
export const SCEP_PROFILES = ['server', 'machine', 'user', 'network'] as const

export const scepCnOk = (n: string) => SCEP_CN_RE.test(n) && !(SCEP_RESERVED as readonly string[]).includes(n.toLowerCase()) && !n.toLowerCase().startsWith('ddi-')
export const scepCn = z.string().trim().refine(scepCnOk)
export const scepOfferBody = z.object({ ...certCommon, cn: scepCn }).strict().superRefine(sanRules)
export type ScepOfferBody = z.infer<typeof scepOfferBody>
export const scepCnParam = (v: string) => scepCnOk(v)

// ---- Défi à usage unique ----
/** Sans I, O, 0, 1 : le défi se recopie à la main sur un équipement. 24 symboles de 32 = 120 bits. Root accepte [A-Za-z0-9]{16,64}. */
const CHALLENGE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
export const CHALLENGE_LEN = 24
export function newChallenge(): string {
  let s = ''
  for (let i = 0; i < CHALLENGE_LEN; i++) s += CHALLENGE_ALPHABET[randomInt(CHALLENGE_ALPHABET.length)]
  return s
}

// ---- Lecture de ce que root publie ----
export interface ScepCert { serial: string; notAfter: string; revoked: boolean; sha1: string }
export interface ScepOffer {
  cn: string; state: ScepState; status: number; ca: string; profile: (typeof SCEP_PROFILES)[number] | ''; dn: string; san: string
  createdAt: number; modifiedAt: number; expiresAt: number | null; cert: ScepCert | null
}
export interface PkiScep { at: number; enabled: boolean; alias: string; path: string; port: number; url: string; offerDays: number; offers: ScepOffer[] }

const n = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : 0)
const s = (v: unknown, max: number) => String(v ?? '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, max)
/** L'adresse n'est reprise que si elle a la forme exacte donnée par root : http(s)://nom:port/ejbca/publicweb/apply/scep/<alias>/pkiclient.exe. */
const URL_RE = /^http:\/\/[a-z0-9.-]{1,253}:[0-9]{1,5}\/ejbca\/publicweb\/apply\/scep\/ddibuntu\/pkiclient\.exe$/

function parseOffer(o: any): ScepOffer | null {
  if (!o || typeof o !== 'object' || typeof o.cn !== 'string' || !SCEP_CN_RE.test(o.cn)) return null
  const c = o.cert && typeof o.cert === 'object' ? o.cert : null
  return {
    cn: o.cn, state: (SCEP_STATES as readonly string[]).includes(o.state) ? o.state : 'other', status: n(o.status), ca: s(o.ca, 48),
    profile: (SCEP_PROFILES as readonly string[]).includes(o.profile) ? o.profile : '', dn: s(o.dn, 512), san: s(o.san, 1024),
    createdAt: n(o.createdAt), modifiedAt: n(o.modifiedAt), expiresAt: Number.isInteger(o.expiresAt) && o.expiresAt > 0 ? o.expiresAt : null,
    cert: c && /^[0-9A-F]{1,40}$/.test(c.serial ?? '') ? { serial: c.serial, notAfter: s(c.notAfter, 24), revoked: c.revoked === true, sha1: /^[0-9a-f]{40}$/.test(c.sha1 ?? '') ? c.sha1 : '' } : null,
  }
}
export function parsePkiScep(j: any): PkiScep | null {
  if (!j || typeof j !== 'object' || typeof j.at !== 'number') return null
  const offers = (Array.isArray(j.offers) ? j.offers : []).slice(0, 2000).map(parseOffer).filter((x: ScepOffer | null): x is ScepOffer => !!x)
  const port = n(j.port)
  return { at: n(j.at), enabled: j.enabled === true, alias: SCEP_ALIAS, path: `/ejbca/publicweb/apply/scep/${SCEP_ALIAS}/pkiclient.exe`, port: port > 0 && port < 65536 ? port : 8080,
    url: typeof j.url === 'string' && URL_RE.test(j.url) ? j.url : '', offerDays: Math.min(365, Math.max(0, n(j.offerDays))), offers }
}
export async function readPkiScep(): Promise<PkiScep | null> {
  try {
    const st = await fs.lstat(cfg().pkiScepFile)
    if (!st.isFile() || st.size > 2_000_000) return null
    return parsePkiScep(JSON.parse(await fs.readFile(cfg().pkiScepFile, 'utf8')))
  } catch { return null }
}

// ---- Attente du résultat de root ----
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
export type ActionOutcome = { ok: true; message: string } | { ok: false; code: 'refused' | 'timeout'; message: string }
/**
 * Attend le résultat d'une demande SANS référence (activation, désactivation, annulation) : le résultat de la même action, publié après le dépôt, une fois la demande consommée.
 * `pending` dit si le fichier de demande est encore là (root l'efface en le prenant en charge). `before` : le résultat qui était publié AVANT le dépôt : un résultat de même action,
 * de la même seconde et identique à lui (deux annulations rapprochées) n'est pas celui de cette demande. Les résultats de root portent le nom de l'équipement : ils diffèrent.
 */
export async function awaitAction(action: string, startedAt: number, pending: () => Promise<boolean>, opts: { timeoutMs?: number; pollMs?: number; before?: PkiResult | null } = {}): Promise<ActionOutcome> {
  const timeout = opts.timeoutMs ?? 120_000, poll = opts.pollMs ?? 400, b = opts.before ?? null
  const t0 = Date.now()
  while (Date.now() - t0 < timeout) {
    const res: PkiResult | null = await readPkiResult()
    const fresh = !!res && (!b || res.at > b.at || res.ok !== b.ok || res.message !== b.message || res.action !== b.action)
    if (res && fresh && res.action === action && res.at >= startedAt && !(await pending())) return res.ok ? { ok: true, message: res.message } : { ok: false, code: 'refused', message: res.message }
    await sleep(poll)
  }
  return { ok: false, code: 'timeout', message: 'timeout' }
}
