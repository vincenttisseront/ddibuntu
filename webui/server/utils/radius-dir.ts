// Annuaire Active Directory du service RADIUS (0.13.1, itération 2) : liaison LDAPS en LECTURE SEULE, état d'un compte (utilisateur ou machine)
// et groupes, imbriqués compris. Aucune écriture dans l'annuaire : seules les opérations bind / search / unbind sont utilisées.
// Le mot de passe de liaison est chiffré au repos (réglage « radius_directory ») et n'est jamais renvoyé ni journalisé.
import { escapeFilter } from './ad'
import type { LdapLike } from './ad'
import { normDn } from './text'
import { GROUP_DN_RE } from './radius-rules'

export interface DirSettings { urls: string[]; baseDn: string; bindDn: string; bindPasswordEnc?: string; tlsRejectUnauthorized: boolean; caPem?: string }
export const DIR_DEFAULTS: DirSettings = { urls: [], baseDn: '', bindDn: '', tlsRejectUnauthorized: true }
export const DIR_KEY = 'radius_directory'

/** Règle de correspondance « appartenance transitive » d'Active Directory (LDAP_MATCHING_RULE_IN_CHAIN). */
export const IN_CHAIN = '1.2.840.113556.1.4.1941'
const UAC_ACCOUNTDISABLE = 0x2
const UAC_LOCKOUT = 0x10
export const MAX_GROUPS = 500
export const MAX_FOUND_GROUPS = 50

export type Kind = 'user' | 'computer'
export type DirFailure = 'service_bind' | 'tls' | 'unreachable'
export type Factory = (url: string) => LdapLike

const arr = (x: unknown): any[] => (x === undefined || x === null || x === '' ? [] : Array.isArray(x) ? x : [x])
const first = (x: unknown): string => String(arr(x)[0] ?? '')

/** FILETIME (intervalles de 100 ns depuis 1601) → millisecondes Unix ; null = « jamais » (0, valeur maximale) ou valeur illisible. */
export function filetimeToMs(v: unknown): number | null {
  const s = first(v)
  if (!/^\d{1,20}$/.test(s)) return null
  const n = BigInt(s)
  if (n === 0n || n >= 0x7fffffffffffffffn) return null
  const ms = Number(n / 10000n) - 11644473600000
  return Number.isFinite(ms) ? ms : null
}

export interface AccountState { enabled: boolean; locked: boolean; expired: boolean; expiresAt: number | null; usable: boolean; reasons: Array<'unreadable' | 'disabled' | 'locked' | 'expired'> }
/** État d'un compte d'après ses attributs : désactivé (userAccountControl), verrouillé (attribut calculé par l'AD), expiré (accountExpires).
 *  Un userAccountControl absent ou illisible (droits de lecture insuffisants du compte de liaison, par exemple) rend le compte INUTILISABLE (« unreadable ») :
 *  une décision d'accès ne doit jamais reposer sur une absence d'information. */
export function decodeAccount(e: Record<string, unknown>, now = Date.now()): AccountState {
  const rawUac = first(e.userAccountControl)
  const known = /^\d{1,10}$/.test(rawUac)
  const uac = known ? Number(rawUac) : 0
  const rawComputed = first(e['msDS-User-Account-Control-Computed'])
  const enabled = known && (uac & UAC_ACCOUNTDISABLE) === 0
  // l'attribut calculé donne l'état de verrouillage réel (durée de verrouillage écoulée comprise) ; à défaut, le drapeau de userAccountControl
  const locked = /^\d{1,10}$/.test(rawComputed) ? (Number(rawComputed) & UAC_LOCKOUT) !== 0 : (uac & UAC_LOCKOUT) !== 0
  const expiresAt = filetimeToMs(e.accountExpires)
  const expired = expiresAt !== null && expiresAt <= now
  const reasons: AccountState['reasons'] = []
  if (!known) reasons.push('unreadable')
  else if (!enabled) reasons.push('disabled')
  if (locked) reasons.push('locked')
  if (expired) reasons.push('expired')
  return { enabled, locked, expired, expiresAt, usable: reasons.length === 0, reasons }
}

/** Filtre de recherche d'un compte. Utilisateur : UPN si « @ », sinon sAMAccountName. Machine : nom DNS si « . », sinon sAMAccountName (avec « $ »). */
export function accountFilter(kind: Kind, name: string): string {
  const n = name.trim()
  if (kind === 'user') {
    const attr = n.includes('@') ? 'userPrincipalName' : 'sAMAccountName'
    return `(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))(${attr}=${escapeFilter(n)}))`
  }
  if (n.includes('.')) return `(&(objectClass=computer)(dNSHostName=${escapeFilter(n)}))`
  return `(&(objectClass=computer)(sAMAccountName=${escapeFilter(n.endsWith('$') ? n : n + '$')}))`
}
export const groupSearchFilter = (q: string) => `(&(objectCategory=group)(|(cn=*${escapeFilter(q)}*)(sAMAccountName=*${escapeFilter(q)}*)))`

/** Classe une erreur de liaison / de connexion : refus d'identifiants, certificat refusé (TLS) ou serveur injoignable. */
export function classify(err: any): DirFailure {
  const text = `${err?.name ?? ''} ${err?.code ?? ''} ${err?.message ?? ''}`
  if (/InvalidCredentials|invalid credentials|\b49\b/i.test(text)) return 'service_bind'
  if (/cert|tls|ssl|self[- ]signed|unable to verify|hostname|altname/i.test(text)) return 'tls'
  return 'unreachable'
}

export type Attempt = { server: string; ok: true } | { server: string; ok: false; reason: DirFailure }
export type Session<T> = { ok: true; server: string; value: T } | { ok: false; reason: DirFailure; attempts: Attempt[] }

/** Ouvre une session de service (liaison en lecture seule) sur le premier serveur qui répond et y exécute `fn`. Un mot de passe vide est refusé : une liaison sans mot de passe réussirait « anonymement ». */
export async function withService<T>(s: DirSettings, bindPassword: string, factory: Factory, fn: (c: LdapLike) => Promise<T>): Promise<Session<T>> {
  const attempts: Attempt[] = []
  if (!bindPassword) return { ok: false, reason: 'service_bind', attempts }
  for (const url of s.urls) {
    const c = factory(url)
    try {
      try { await c.bind(s.bindDn, bindPassword) } catch (e) { attempts.push({ server: url, ok: false, reason: classify(e) }); continue }
      attempts.push({ server: url, ok: true })
      return { ok: true, server: url, value: await fn(c) }
    } catch (e) { attempts.push({ server: url, ok: false, reason: classify(e) }) } finally { await c.unbind().catch(() => undefined) }
  }
  // la cause la plus parlante : un refus d'identifiants prime sur un serveur injoignable
  const reasons = attempts.map((a) => (a.ok ? null : a.reason))
  const reason: DirFailure = reasons.includes('service_bind') ? 'service_bind' : reasons.includes('tls') ? 'tls' : 'unreachable'
  return { ok: false, reason, attempts }
}

/** Test de liaison, serveur par serveur (aucune recherche). */
export async function testBind(s: DirSettings, bindPassword: string, factory: Factory): Promise<{ ok: boolean; attempts: Attempt[] }> {
  const attempts: Attempt[] = []
  for (const url of s.urls) {
    const c = factory(url)
    try { if (!bindPassword) throw Object.assign(new Error('invalid credentials'), { name: 'InvalidCredentialsError' }); await c.bind(s.bindDn, bindPassword); attempts.push({ server: url, ok: true }) }
    catch (e) { attempts.push({ server: url, ok: false, reason: classify(e) }) } finally { await c.unbind().catch(() => undefined) }
  }
  return { ok: attempts.some((a) => a.ok), attempts }
}

export interface Group { dn: string; name: string; direct: boolean }
export type Lookup =
  | { found: false; ambiguous: boolean }
  | { found: true; kind: Kind; dn: string; sam: string; upn: string | null; dnsHostName: string | null; displayName: string; state: AccountState; groups: Group[]; groupsTruncated: boolean }

/** Cherche un compte, décode son état et liste TOUS ses groupes (directs et imbriqués, règle de chaîne d'appartenance). */
export async function lookupAccount(s: DirSettings, bindPassword: string, factory: Factory, kind: Kind, name: string, now = Date.now()): Promise<Session<Lookup>> {
  return withService(s, bindPassword, factory, async (c): Promise<Lookup> => {
    const r = await c.search(s.baseDn, { scope: 'sub', filter: accountFilter(kind, name), sizeLimit: 2,
      attributes: ['dn', 'sAMAccountName', 'userPrincipalName', 'dNSHostName', 'displayName', 'userAccountControl', 'msDS-User-Account-Control-Computed', 'accountExpires', 'memberOf'] })
    if (r.searchEntries.length === 0) return { found: false, ambiguous: false }
    if (r.searchEntries.length > 1) return { found: false, ambiguous: true }
    const e = r.searchEntries[0]!
    const dn = String(e.dn)
    const direct = new Set(arr(e.memberOf).map((g) => normDn(String(g))))
    const g = await c.search(s.baseDn, { scope: 'sub', filter: `(&(objectCategory=group)(member:${IN_CHAIN}:=${escapeFilter(dn)}))`, attributes: ['dn', 'cn'], sizeLimit: MAX_GROUPS + 1 })
    const groups = g.searchEntries.slice(0, MAX_GROUPS).map((x): Group => ({ dn: String(x.dn), name: first(x.cn) || String(x.dn).split(',')[0]!.replace(/^cn=/i, ''), direct: direct.has(normDn(String(x.dn))) }))
      .sort((a, b) => Number(b.direct) - Number(a.direct) || a.name.localeCompare(b.name))
    return { found: true, kind, dn, sam: first(e.sAMAccountName), upn: first(e.userPrincipalName) || null, dnsHostName: first(e.dNSHostName) || null,
      displayName: first(e.displayName) || first(e.sAMAccountName), state: decodeAccount(e, now), groups, groupsTruncated: g.searchEntries.length > MAX_GROUPS }
  })
}

export interface FoundGroup { dn: string; name: string; description: string; /** false : le DN contient un échappement que le serveur RADIUS ne sait pas comparer (voir GROUP_DN_RE) */ usable: boolean }
/** Recherche de groupes par fragment de nom (utile pour écrire les règles d'accès). */
export async function findGroups(s: DirSettings, bindPassword: string, factory: Factory, q: string): Promise<Session<{ groups: FoundGroup[]; truncated: boolean }>> {
  return withService(s, bindPassword, factory, async (c) => {
    const r = await c.search(s.baseDn, { scope: 'sub', filter: groupSearchFilter(q), attributes: ['dn', 'cn', 'description'], sizeLimit: MAX_FOUND_GROUPS + 1 })
    const groups = r.searchEntries.slice(0, MAX_FOUND_GROUPS).map((x): FoundGroup => ({ dn: String(x.dn), name: first(x.cn), description: first(x.description), usable: GROUP_DN_RE.test(String(x.dn)) })).sort((a, b) => a.name.localeCompare(b.name))
    return { groups, truncated: r.searchEntries.length > MAX_FOUND_GROUPS }
  })
}

/** Le DN désigne-t-il un groupe de l'annuaire ? Un conteneur (CN=Computers), une unité d'organisation, un compte ou un objet absent répondent « non ». */
export async function groupExists(s: DirSettings, bindPassword: string, factory: Factory, dn: string): Promise<Session<boolean>> {
  return withService(s, bindPassword, factory, async (c) => {
    try {
      const r = await c.search(dn, { scope: 'base', filter: '(objectClass=group)', attributes: ['dn'], sizeLimit: 1 })
      return r.searchEntries.length > 0
    } catch (e: any) {
      if (/NoSuchObject|no such object|\b32\b/i.test(`${e?.name ?? ''} ${e?.code ?? ''} ${e?.message ?? ''}`)) return false
      throw e
    }
  })
}

// ---- Résolution de groupes par SID (0.13.10, import d'un NPS : les stratégies désignent leurs groupes par SID) ----
const SID_RE = /^S-1-\d{1,3}(?:-\d{1,10}){1,15}$/
/** Base de recherche « <SID=S-1-5-21-…> » (DN étendu d'Active Directory et de Samba) : le SID est écrit en clair, sans filtre binaire — essayé contre un vrai Samba AD,
 *  où un filtre `objectSid=\01\05…` passé par ldapts ne trouve rien (la valeur est lue comme du texte). Le SID est validé : rien d'autre ne peut entrer dans la base. */
export const sidBase = (sid: string): string | null => (SID_RE.test(sid) ? `<SID=${sid}>` : null)
export type SidLookup = { found: false } | { found: true; dn: string; name: string; usable: boolean }
/** Un SID qu'aucun objet ne porte (ou d'un autre domaine, ou mal formé) : réponse « introuvable » normale, pas une panne de l'annuaire. */
const notThere = (e: any) => /NoSuchObject|InvalidDNSyntax|Referral|0x20\b|0x22\b/i.test(`${e?.name ?? ''} ${e?.code ?? ''} ${e?.message ?? ''}`)
/** Cherche chaque SID parmi les groupes de l'annuaire (une seule liaison de service, lecture seule). Un SID introuvable (groupe supprimé, autre domaine) donne { found: false }. */
export async function resolveGroupSids(s: DirSettings, bindPassword: string, factory: Factory, sids: string[]): Promise<Session<Map<string, SidLookup>>> {
  return withService(s, bindPassword, factory, async (c) => {
    const out = new Map<string, SidLookup>()
    for (const sid of sids) {
      const base = sidBase(sid)
      if (!base) { out.set(sid, { found: false }); continue }
      try {
        const r = await c.search(base, { scope: 'base', filter: '(objectCategory=group)', attributes: ['dn', 'cn'], sizeLimit: 2 })
        const e = r.searchEntries.length === 1 ? r.searchEntries[0] : null
        out.set(sid, e ? { found: true, dn: String(e.dn), name: first(e.cn) || String(e.dn).split(',')[0]!.replace(/^cn=/i, ''), usable: GROUP_DN_RE.test(String(e.dn)) } : { found: false })
      } catch (e) { if (!notThere(e)) throw e; out.set(sid, { found: false }) }
    }
    return out
  })
}
