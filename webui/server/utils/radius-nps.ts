// Import d'un NPS Windows (0.13.10, itération 5) : lecture de l'export `netsh nps export … exportPSK=YES` (ou `Export-NpsConfiguration`), puis PLAN d'import
// (clients RADIUS → clients DDI-Buntu, stratégies réseau → règles d'accès) avec, pour chaque élément, un statut :
//   imported : repris tel quel · adapted : repris avec une adaptation ou à contrôler · skipped : non pris en charge (avec la raison).
// Ce fichier est PUR (aucune base, aucun annuaire, aucun réseau) : le plan se calcule sur ce qu'on lui donne (clients et règles existants, groupes déjà
// résolus). Il n'écrit rien : l'écriture est faite par la route de validation (handlers/radiusnps.ts), après aperçu.
//
// Principes de sûreté du plan :
//  - une règle n'est jamais plus LARGE que la stratégie d'origine sans être marquée « adapted » (condition non reprise, groupe « Tout le monde », etc.) ;
//    seules les règles reprises sans aucune réserve (« imported ») peuvent être créées actives, et seulement si l'administrateur le demande ;
//  - aucune expression régulière n'est construite à partir du fichier (motifs réduits à des littéraux et des jokers, comparés à la main) ;
//  - les secrets partagés ne figurent jamais dans le plan : seul leur sort (« repris » / « nouveau secret ») y est indiqué.
//
// Format : les structures ci-dessous sont celles de l'export NPS (éléments portant un attribut `name` et un enfant `Properties`), telles que lues par l'outil
// d'audit AD-NPS sur de vrais exports : clients sous `Clients/Children/<client>/Properties` (IP_Address, Shared_Secret), stratégies reconnues à leurs
// propriétés (msNPSequence, msNPConstraint, msNPAction), profils à leurs propriétés (msEAPConfiguration, msNPAllowDialin…), lien stratégie → profil par
// msNPAction, « Proxy » dans le nom d'un ancêtre = stratégie de demande de connexion.
import { XMLParser, XMLValidator } from 'fast-xml-parser'
import { normClientAddress, SECRET_RE, SELFTEST_NAME, MAX_CLIENTS } from './radius'
import type { Usage } from './radius'
import { RULES_MAX, SSID_RE } from './radius-rules'
import type { GroupRef, Kind } from './radius-rules'
import { parseCidr, parseIp } from './net'

export const NPS_MAX_BYTES = 8_000_000
const MAX_ELEMENTS = 300_000
const MAX_DEPTH = 40
const MAX_SIDS = 300

export class NpsParseError extends Error {
  constructor(public code: 'nps_empty' | 'nps_xml' | 'nps_doctype' | 'nps_too_big' | 'nps_not_nps') { super(code) }
}

// ---- Arbre XML (ordre et doublons conservés : une stratégie porte plusieurs `msNPConstraint`) ----
interface XEl { tag: string; name: string | null; children: XEl[]; text: string }

function build(nodes: any[], depth: number, count: { n: number }): XEl[] {
  if (depth > MAX_DEPTH) throw new NpsParseError('nps_too_big')
  const out: XEl[] = []
  for (const n of nodes) {
    const tag = Object.keys(n).find((k) => k !== ':@' && k !== '#text')
    if (tag === undefined) continue
    if (++count.n > MAX_ELEMENTS) throw new NpsParseError('nps_too_big')
    const kids: any[] = Array.isArray(n[tag]) ? n[tag] : []
    const attr = n[':@']?.['@_name']
    out.push({ tag, name: typeof attr === 'string' ? attr : null, children: build(kids, depth + 1, count), text: kids.filter((k) => typeof k?.['#text'] === 'string').map((k) => k['#text'] as string).join('').trim() })
  }
  return out
}

const lc = (s: string) => s.toLowerCase()
const prop = (e: XEl, name: string): string[] => {
  const p = e.children.find((c) => lc(c.tag) === 'properties')
  return p ? p.children.filter((c) => lc(c.tag) === lc(name)).map((c) => c.text) : []
}
const propNames = (e: XEl): string[] => e.children.find((c) => lc(c.tag) === 'properties')?.children.map((c) => c.tag) ?? []
const hasProps = (e: XEl) => e.children.some((c) => lc(c.tag) === 'properties')

// ---- Export lu ----
export interface NpsClientIn { name: string; address: string; secret: string | null }
export interface NpsPolicyIn {
  name: string; connection: boolean; order: number | null; enabled: boolean | null; conditions: string[]
  /** null = l'export ne dit pas si l'accès est accordé ou refusé */
  grant: boolean | null
  profileFound: boolean
  eapTypes: number[]; authTypes: number[]
  /** noms des propriétés de profil que ce plan ne sait pas reprendre (valeurs jamais conservées) */
  otherAttrs: string[]
}
export interface NpsExport { clients: NpsClientIn[]; policies: NpsPolicyIn[]; clientsContainer: boolean }

const POLICY_MARKERS = ['msnpsequence', 'msnpconstraint', 'msnpaction']
const PROFILE_MARKERS = ['mseapconfiguration', 'msnpallowdialin', 'msnpauthenticationtype2', 'msnpallowedeaptype', 'msauthprovidertype']
/** Propriétés de profil sans équivalent à reprendre (ou déjà exploitées ci-dessus) : leur présence ne rend pas une règle « à revoir ». */
const BENIGN_ATTRS = new Set(['msnpallowdialin', 'mseapconfiguration', 'msnpallowedeaptype', 'msnpauthenticationtype', 'msnpauthenticationtype2', 'msauthprovidertype', 'msradiusframedprotocol', 'msradiusservicetype'])

function hexBytes(v: string): number[] | null {
  const h = v.replace(/\s+/g, '')
  if (!h || h.length % 2 !== 0 || !/^[0-9A-Fa-f]+$/.test(h)) return null
  const out: number[] = []
  for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16))
  return out
}
const flag = (v: string | undefined): boolean | null => (v === undefined ? null : /^(1|true|-1)$/i.test(v.trim()) ? true : /^(0|false)$/i.test(v.trim()) ? false : null)

export function parseNpsExport(xml: string): NpsExport {
  const text = xml.replace(/^﻿/, '')
  if (!text.trim()) throw new NpsParseError('nps_empty')
  if (text.length > NPS_MAX_BYTES) throw new NpsParseError('nps_too_big')
  // un export NPS n'a ni DTD ni entité : on refuse d'emblée (aucune expansion d'entité à craindre)
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) throw new NpsParseError('nps_doctype')
  if (XMLValidator.validate(text) !== true) throw new NpsParseError('nps_xml')
  let nodes: any[]
  try {
    nodes = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', removeNSPrefix: true, parseTagValue: false, parseAttributeValue: false, trimValues: true, preserveOrder: true }).parse(text)
  } catch { throw new NpsParseError('nps_xml') }
  const roots = build(Array.isArray(nodes) ? nodes : [], 0, { n: 0 })

  const clients: NpsClientIn[] = []
  const profiles: Array<{ name: string; connection: boolean; el: XEl }> = []
  const policies: Array<{ name: string; connection: boolean; el: XEl }> = []
  let clientsContainer = false
  const walk = (e: XEl, anc: XEl[]) => {
    if ((lc(e.tag) === 'clients' || lc(e.name ?? '') === 'clients') && e.children.some((c) => lc(c.tag) === 'children')) {
      clientsContainer = true
      for (const k of e.children.filter((c) => lc(c.tag) === 'children').flatMap((c) => c.children).filter(hasProps)) {
        clients.push({ name: (k.name ?? k.tag).trim(), address: (prop(k, 'IP_Address')[0] ?? '').trim(), secret: prop(k, 'Shared_Secret')[0] || null })
      }
    }
    if (e.name !== null && hasProps(e)) {
      const names = new Set(propNames(e).map(lc))
      const connection = anc.some((a) => lc(a.tag).includes('proxy') || lc(a.name ?? '').includes('proxy'))
      if (POLICY_MARKERS.some((m) => names.has(m))) policies.push({ name: e.name.trim(), connection, el: e })
      else if (PROFILE_MARKERS.some((m) => names.has(m))) profiles.push({ name: e.name.trim(), connection, el: e })
    }
    for (const c of e.children) walk(c, [...anc, e])
  }
  for (const r of roots) walk(r, [])
  if (!clientsContainer && !policies.length && !profiles.length) throw new NpsParseError('nps_not_nps')

  const out: NpsPolicyIn[] = policies.map((p) => {
    const link = (prop(p.el, 'msNPAction')[0] ?? '').trim() || p.name
    const profile = profiles.find((x) => x.connection === p.connection && x.name === link)
    const eapTypes: number[] = [], authTypes: number[] = []
    let grant: boolean | null = null
    const others = new Set<string>()
    if (profile) {
      for (const v of prop(profile.el, 'msEAPConfiguration')) { const b = hexBytes(v); if (b && b.length >= 4) eapTypes.push((b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0) }
      for (const v of prop(profile.el, 'msNPAllowedEapType')) {
        const t = v.trim()
        if (/^\d{1,3}$/.test(t)) eapTypes.push(Number(t))
        else { const b = hexBytes(t); if (b && b.length >= 1) eapTypes.push(b.length >= 4 ? ((b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0) : b[0]!) }
      }
      for (const v of prop(profile.el, 'msNPAuthenticationType2')) { const n = Number(v.trim()); if (Number.isInteger(n) && n !== 5) authTypes.push(n) }
      grant = flag(prop(profile.el, 'msNPAllowDialin')[0])
      for (const n of propNames(profile.el)) if (!BENIGN_ATTRS.has(lc(n))) others.add(n)
    }
    const seq = Number((prop(p.el, 'msNPSequence')[0] ?? '').trim())
    return { name: p.name, connection: p.connection, order: Number.isInteger(seq) && prop(p.el, 'msNPSequence')[0] ? seq : null, enabled: flag(prop(p.el, 'Policy_Enabled')[0]),
      conditions: prop(p.el, 'msNPConstraint'), grant, profileFound: !!profile, eapTypes: [...new Set(eapTypes)], authTypes: [...new Set(authTypes)], otherAttrs: [...others].slice(0, 30) }
  })
  return { clients, policies: out, clientsContainer }
}

// ---- Conditions de stratégie ----
export interface Cond { fn: string; arg: string }
/** `NTGROUPS("S-1-…")`, `MATCH("NAS-Port-Type=^19$")`, `TIMEOFDAY("…")` → nom de fonction et argument sans les guillemets extérieurs. */
export function parseCondition(raw: string): Cond | null {
  const m = /^\s*([A-Za-z][\w-]*)\s*\(([\s\S]*)\)\s*$/.exec(raw)
  if (!m) return null
  let arg = m[2]!.trim()
  if (arg.length >= 2 && arg.startsWith('"') && arg.endsWith('"')) arg = arg.slice(1, -1)
  return { fn: m[1]!.toUpperCase(), arg }
}
const SID_RE_G = /S-1-\d{1,3}(?:-\d{1,10}){1,15}/g
export function extractSids(text: string): string[] { return [...new Set(text.match(SID_RE_G) ?? [])] }

export type SidClass = { t: 'everyone' } | { t: 'primary'; kind: Kind } | { t: 'group' }
/** « Tout le monde » (S-1-1-0) et « Utilisateurs authentifiés » (S-1-5-11) ; groupes principaux « Utilisateurs du domaine » (RID 513) et « Ordinateurs du domaine » (RID 515). */
export function classifySid(sid: string): SidClass {
  if (sid === 'S-1-1-0' || sid === 'S-1-5-11') return { t: 'everyone' }
  const m = /^S-1-5-21-\d+-\d+-\d+-(\d+)$/.exec(sid)
  if (m && m[1] === '513') return { t: 'primary', kind: 'user' }
  if (m && m[1] === '515') return { t: 'primary', kind: 'computer' }
  return { t: 'group' }
}
/** SID à résoudre dans l'annuaire (groupes ordinaires seulement), dans l'ordre d'apparition, bornés. */
export function sidsToResolve(exp: NpsExport): string[] {
  const out = new Set<string>()
  for (const p of exp.policies) {
    if (p.connection) continue
    for (const raw of p.conditions) { const c = parseCondition(raw); if (c && GROUP_FNS[c.fn] !== undefined) for (const s of extractSids(c.arg)) if (classifySid(s).t === 'group') out.add(s) }
  }
  return [...out].slice(0, MAX_SIDS)
}
const GROUP_FNS: Record<string, Kind | null> = { NTGROUPS: null, USERGROUPS: 'user', MACHINEGROUPS: 'computer' }

// ---- Motifs (expressions régulières NPS) réduits à des jokers : aucune RegExp n'est construite depuis le fichier ----
/** Motif → alternatives sous forme de globs (« * » = n'importe quoi), ou null si le motif est plus riche que des littéraux et « .* ». Non ancré = « contient ». */
export function globAlternatives(re: string): string[] | null {
  if (!re || re.length > 500) return null
  const parts = re.split('|')
  if (parts.length > 200) return null
  const out: string[] = []
  for (let p of parts) {
    let head = '*', tail = '*'
    if (p.startsWith('^')) { head = ''; p = p.slice(1) }
    if (p.endsWith('$') && !p.endsWith('\\$')) { tail = ''; p = p.slice(0, -1) }
    let g = ''
    for (let i = 0; i < p.length; i++) {
      const c = p[i]!
      if (c === '\\') { const n = p[i + 1]; if (n === undefined || /[A-Za-z0-9*]/.test(n)) return null; g += n; i++ }
      else if (c === '.' && p[i + 1] === '*') { g += '*'; i++ }
      else if (/[.[\](){}+?^$*]/.test(c)) return null
      else g += c
    }
    if (!g) return null   // aucune partie littérale (« | », « ^$ »…) : motif dégénéré
    out.push((head + g + tail).replace(/\*+/g, '*'))
  }
  return out
}
/** Correspondance glob (insensible à la casse), sans RegExp. */
export function globMatch(glob: string, value: string): boolean {
  const g = glob.toLowerCase(), v = value.toLowerCase()
  let gi = 0, vi = 0, star = -1, mark = 0
  while (vi < v.length) {
    if (gi < g.length && g[gi] === '*') { star = gi++; mark = vi }
    else if (gi < g.length && g[gi] === v[vi]) { gi++; vi++ }
    else if (star >= 0) { gi = star + 1; vi = ++mark }
    else return false
  }
  while (gi < g.length && g[gi] === '*') gi++
  return gi === g.length
}

// ---- Noms et adresses de clients ----
/** Nom d'affichage NPS → nom de client DDI-Buntu (minuscules, chiffres, tirets ; une lettre au début ; 41 caractères au plus ; jamais le nom réservé). */
export function normClientName(raw: string): string {
  let s = raw.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
  if (!s) s = 'nas'
  if (!/^[a-z]/.test(s)) s = `nas-${s}`
  s = s.slice(0, 41).replace(/-+$/, '')
  if (s === SELFTEST_NAME) s = 'nas-ddi-selftest'
  return s
}
function uniqueName(base: string, taken: Set<string>): string {
  if (!taken.has(base)) return base
  for (let i = 2; i < 10_000; i++) { const suf = `-${i}`, c = base.slice(0, 41 - suf.length).replace(/-+$/, '') + suf; if (!taken.has(c)) return c }
  return base
}
const dottedMask = (m: string): number | null => {
  const ip = parseIp(m)
  if (!ip || ip.v !== 4) return null
  const bits = ip.n.toString(2).padStart(32, '0')
  return /^1*0*$/.test(bits) ? bits.indexOf('0') === -1 ? 32 : bits.indexOf('0') : null
}
export type AddressProblem = 'address_dns' | 'address_invalid' | 'address_range'
/** Adresse NPS (IP, IP/préfixe, IP/masque, nom DNS) → réseau accepté par DDI-Buntu, ou la raison du refus. Aucune résolution DNS : un nom n'est pas repris. */
export function npsAddress(raw: string): { ok: true; address: string } | { ok: false; problem: AddressProblem } {
  let v = raw.trim()
  if (!v) return { ok: false, problem: 'address_invalid' }
  const m = /^([^/]+)\/(\d{1,3}(?:\.\d{1,3}){0,3})$/.exec(v)
  if (m && m[2]!.includes('.')) { const p = dottedMask(m[2]!); if (p === null) return { ok: false, problem: 'address_invalid' }; v = `${m[1]}/${p}` }
  const looksNet = parseCidr(v) !== null || parseIp(v) !== null
  if (!looksNet) return { ok: false, problem: /[A-Za-z]/.test(v) && !v.includes(':') ? 'address_dns' : 'address_invalid' }
  const a = normClientAddress(v)
  return a ? { ok: true, address: a } : { ok: false, problem: 'address_range' }
}

// ---- Plan ----
export type Status = 'imported' | 'adapted' | 'skipped'
export interface Note { code: string; params?: Record<string, string | number> }
export interface ClientPlan {
  key: string; original: string; name: string; address: string | null; rawAddress: string; status: Status; notes: Note[]; usage: Usage
  /** repris tel quel du fichier, ou nouveau secret généré (à saisir sur l'équipement ; montré une seule fois à la validation) */
  secret: 'reused' | 'generated' | null; selected: boolean
}
export interface RulePlan {
  key: string; name: string; order: number | null; status: Status; notes: Note[]; action: 'accept' | 'reject'; npsEnabled: boolean | null; enabled: boolean
  kind: Kind | null; groups: GroupRef[]; clients: string[]; usages: Usage[]; ssids: string[]; conditions: string[]; selected: boolean; comment: string
}
export type GroupState = { state: 'found'; dn: string; name: string } | { state: 'notfound' } | { state: 'unusable'; name: string }
export interface PlanCtx {
  existingClients: Array<{ name: string; address: string }>
  existingRules: Array<{ name: string; comment: string | null }>
  /** 'ok' : les groupes ont été cherchés ; sinon la raison pour laquelle on n'a pas pu */
  directory: 'ok' | 'missing' | 'unreachable'
  groups: Map<string, GroupState>
  opts: { usages: Record<string, Usage>; activate: boolean; exclude: Set<string> }
}
export interface Plan {
  clients: ClientPlan[]; rules: RulePlan[]; connectionPolicies: number
  totals: { clients: Record<Status, number>; rules: Record<Status, number> }
  directory: PlanCtx['directory']; clientsContainer: boolean
}

export const RULE_COMMENT_PREFIX = 'Import NPS'
const PORT_TYPES: Record<number, Usage> = { 19: 'wifi', 15: 'switch', 5: 'vpn' }
const EAP_TLS = 13

export function planClients(exp: NpsExport, ctx: PlanCtx): ClientPlan[] {
  const takenNames = new Set(ctx.existingClients.map((c) => c.name))
  const existingAddr = new Map(ctx.existingClients.map((c) => [c.address, c.name]))
  const fileAddr = new Map<string, string>()
  const out: ClientPlan[] = []
  let room = MAX_CLIENTS - ctx.existingClients.length
  for (const c of exp.clients) {
    const key = `c:${c.name}`, notes: Note[] = []
    const base: ClientPlan = { key, original: c.name, name: normClientName(c.name), address: null, rawAddress: c.address.slice(0, 80), status: 'skipped', notes, usage: ctx.opts.usages[c.name] ?? 'other', secret: null, selected: false }
    const a = npsAddress(c.address)
    if (!a.ok) { notes.push({ code: a.problem }); out.push(base); continue }
    base.address = a.address
    // l'adresse est unique dans DDI-Buntu : déjà utilisée par le même client (import déjà fait), par un autre client, ou par un autre client du même fichier
    const owner = existingAddr.get(a.address)
    if (owner !== undefined) { notes.push(owner === base.name ? { code: 'exists', params: { name: owner } } : { code: 'address_taken', params: { name: owner } }); out.push(base); continue }
    const twin = fileAddr.get(a.address)
    if (twin !== undefined) { notes.push({ code: 'address_dup', params: { name: twin } }); out.push(base); continue }
    if (room <= 0) { notes.push({ code: 'limit' }); out.push(base); continue }
    room--
    const name = uniqueName(base.name, takenNames)
    base.name = name; takenNames.add(name); fileAddr.set(a.address, name)
    if (name !== c.name) notes.push({ code: 'renamed', params: { name } })
    if (c.secret && SECRET_RE.test(c.secret)) base.secret = 'reused'
    else { base.secret = 'generated'; notes.push({ code: c.secret ? 'secret_weak' : 'secret_absent' }) }
    base.status = notes.length ? 'adapted' : 'imported'
    base.selected = !ctx.opts.exclude.has(key)
    out.push(base)
  }
  return out
}

const sidShort = (s: string) => (s.length > 40 ? `${s.slice(0, 18)}…${s.slice(-12)}` : s)
const ruleName = (n: string) => n.replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, 80) || 'NPS'

export function planRules(exp: NpsExport, clients: ClientPlan[], ctx: PlanCtx): { rules: RulePlan[]; connection: number } {
  const finalOf = new Map<string, string | null>(clients.map((c) => [c.original.toLowerCase(), c.selected && c.status !== 'skipped' ? c.name : null]))
  // un client déjà présent dans DDI-Buntu sous le même nom (« exists ») reste désignable par les règles
  for (const c of clients) if (c.status === 'skipped' && c.notes.some((n) => n.code === 'exists')) finalOf.set(c.original.toLowerCase(), c.name)
  const allNames = exp.clients.map((c) => c.name)
  const doneRules = new Set(ctx.existingRules.filter((r) => (r.comment ?? '').startsWith(RULE_COMMENT_PREFIX)).map((r) => r.name))
  const net = exp.policies.map((p, i) => ({ p, i })).filter((x) => !x.p.connection).sort((a, b) => (a.p.order ?? 1e9) - (b.p.order ?? 1e9) || a.i - b.i)
  const out: RulePlan[] = []
  let room = RULES_MAX - ctx.existingRules.length
  for (const { p } of net) {
    const key = `r:${p.name}`, notes: Note[] = [], review: Note[] = []
    const name = ruleName(p.name)
    const r: RulePlan = { key, name, order: p.order, status: 'skipped', notes, action: 'reject', npsEnabled: p.enabled, enabled: false, kind: null, groups: [], clients: [], usages: [], ssids: [], conditions: p.conditions.map((c) => c.slice(0, 200)).slice(0, 30), selected: false, comment: '' }
    let skip = false
    const stop = (n: Note) => { notes.push(n); skip = true }
    const adapt = (n: Note) => { notes.push(n); review.push(n) }

    // 1. accès accordé / refusé
    if (p.grant === null) adapt({ code: 'access_unknown' })
    r.action = p.grant === true ? 'accept' : 'reject'
    if (!p.profileFound) adapt({ code: 'profile_missing' })

    // 2. méthodes d'authentification : DDI-Buntu n'accepte que EAP-TLS
    const others = p.eapTypes.filter((t) => t !== EAP_TLS)
    if (p.eapTypes.includes(EAP_TLS)) { if (others.length || p.authTypes.length) adapt({ code: 'auth_extra_dropped', params: { methods: [...others.map((t) => `EAP ${t}`), ...p.authTypes.map((t) => `#${t}`)].join(', ') } }) }
    else if (others.length) adapt({ code: 'auth_converted', params: { methods: others.map((t) => (t === 25 ? 'PEAP' : t === 26 ? 'EAP-MSCHAPv2' : `EAP ${t}`)).join(', ') } })
    else if (p.authTypes.length) stop({ code: 'auth_none', params: { methods: p.authTypes.map((t) => `#${t}`).join(', ') } })
    else if (p.profileFound) adapt({ code: 'auth_unknown' })

    // 3. conditions
    const groupConds: Array<{ fn: string; sids: string[] }> = []
    const dropped = new Set<string>()
    const ports: number[][] = [], friendly: string[][] = [], calling: string[][] = []
    for (const raw of p.conditions) {
      const c = parseCondition(raw)
      if (!c) { dropped.add('?'); continue }
      if (GROUP_FNS[c.fn] !== undefined) { groupConds.push({ fn: c.fn, sids: extractSids(c.arg) }); continue }
      if (c.fn === 'MATCH') {
        const eq = c.arg.indexOf('='); const attr = eq < 0 ? '' : c.arg.slice(0, eq).trim().toLowerCase(), re = eq < 0 ? '' : c.arg.slice(eq + 1)
        if (attr === 'nas-port-type') { const alts = globAlternatives(re); const nums = alts?.map((a) => (/^\d{1,3}$/.test(a) ? Number(a) : NaN)); if (nums && nums.every((n) => !Number.isNaN(n))) ports.push(nums); else dropped.add('NAS-Port-Type'); continue }
        if (attr === 'client-friendly-name') { const alts = globAlternatives(re); if (alts) friendly.push(alts); else dropped.add('Client-Friendly-Name'); continue }
        if (attr === 'called-station-id' || attr === 'called-station-identifier') { const alts = globAlternatives(re); if (alts) calling.push(alts); else dropped.add('Called-Station-Id'); continue }
        dropped.add(c.arg.slice(0, eq < 0 ? 30 : eq).trim() || c.fn); continue
      }
      dropped.add(c.fn)
    }

    // 3a. groupes
    const g0 = groupConds[0]
    if (groupConds.length > 1) adapt({ code: 'groups_and' })
    if (g0) {
      const kindFn = GROUP_FNS[g0.fn] ?? null
      let any = false; const prim = new Set<Kind>(); const refs: GroupRef[] = []; const lost: string[] = []
      for (const sid of g0.sids) {
        const k = classifySid(sid)
        if (k.t === 'everyone') { any = true; continue }
        if (k.t === 'primary') { prim.add(k.kind); continue }
        const st = ctx.groups.get(sid)
        if (st?.state === 'found') { if (!refs.some((x) => x.dn.toLowerCase() === st.dn.toLowerCase())) refs.push({ dn: st.dn, name: st.name }) }
        else { lost.push(sid); notes.push(st?.state === 'unusable' ? { code: 'group_unusable', params: { name: st.name } } : ctx.directory !== 'ok' ? { code: 'group_directory', params: { sid: sidShort(sid), why: ctx.directory } } : { code: 'group_notfound', params: { sid: sidShort(sid) } }) }
      }
      if (!g0.sids.length) { notes.push({ code: 'groups_empty' }); skip = true }
      else if (any) { adapt({ code: 'group_everyone' }); r.kind = kindFn }
      else if (prim.size && !refs.length) {
        adapt({ code: 'group_primary' })
        r.kind = prim.size === 1 ? [...prim][0]! : kindFn
        if (kindFn && prim.size === 1 && r.kind !== kindFn) { notes.push({ code: 'group_kind_conflict' }); skip = true }
        if (lost.length) review.push({ code: 'groups_partial' })
      } else if (refs.length) {
        r.groups = refs; r.kind = kindFn
        if (prim.size) adapt({ code: 'groups_mixed' })
        if (lost.length) { review.push({ code: 'groups_partial' }); notes.push({ code: 'groups_partial' }) }
      } else skip = true   // aucun groupe exploitable : il n'y a rien à reprendre (les raisons sont déjà dans les notes)
    }

    // 3b. clients, types de port, SSID
    if (friendly.length) {
      const sets = friendly.map((alts) => allNames.filter((n) => alts.some((g) => globMatch(g, n))))
      const matched = sets[0]!.filter((n) => sets.every((s) => s.includes(n)))   // plusieurs conditions « nom » = toutes (intersection)
      if (friendly.length > 1) adapt({ code: 'cond_repeated', params: { type: 'Client-Friendly-Name' } })
      const kept = [...new Set(matched.map((n) => finalOf.get(n.toLowerCase()) ?? null).filter((x): x is string => x !== null))]
      if (!matched.length) stop({ code: 'clients_none' })
      else if (!kept.length) stop({ code: 'clients_not_imported' })
      else { r.clients = kept.sort(); if (kept.length < matched.length) adapt({ code: 'clients_partial', params: { kept: kept.length, total: matched.length } }) }
    }
    if (ports.length) {
      if (ports.length > 1) adapt({ code: 'cond_repeated', params: { type: 'NAS-Port-Type' } })
      const us = [...new Set(ports[0]!.map((n) => PORT_TYPES[n]).filter((x): x is Usage => !!x))]
      if (us.length) { adapt({ code: 'port_type', params: { usages: us.join(', ') } }); if (us.length < ports[0]!.length) adapt({ code: 'port_type_partial' }); if (r.clients.length) { adapt({ code: 'usage_dropped' }) } else r.usages = us.sort() as Usage[] }
      else dropped.add('NAS-Port-Type')
    }
    if (calling.length) {
      if (calling.length > 1) adapt({ code: 'cond_repeated', params: { type: 'Called-Station-Id' } })
      const ss: string[] = []; let bad = false
      for (const g of calling[0]!) { const m = /^\*:([^*]+)$/.exec(g); const v = m ? m[1]! : null; if (v && SSID_RE.test(v)) ss.push(v); else bad = true }
      if (ss.length) { r.ssids = [...new Set(ss)]; if (bad) adapt({ code: 'ssid_partial' }) } else dropped.add('Called-Station-Id')
    }
    for (const d of dropped) adapt({ code: 'cond_dropped', params: { type: d } })
    if (p.otherAttrs.length) adapt({ code: 'attrs_lost', params: { names: p.otherAttrs.slice(0, 8).join(', ') + (p.otherAttrs.length > 8 ? '…' : '') } })
    if (p.enabled === false) notes.push({ code: 'disabled_in_nps' })

    // 4. verdict
    if (doneRules.has(name)) { notes.length = 0; stop({ code: 'rule_exists' }) }
    else if (!skip && room <= 0) stop({ code: 'limit' })
    r.status = skip ? 'skipped' : review.length ? 'adapted' : 'imported'
    if (!skip) {
      room--
      r.selected = !ctx.opts.exclude.has(key)
      r.enabled = ctx.opts.activate && r.status === 'imported' && p.enabled !== false
      r.comment = `${RULE_COMMENT_PREFIX} · ordre ${p.order ?? '?'}${review.length ? ' · à revoir : ' + [...new Set(review.map((n) => n.code))].join(', ') : ''}`.slice(0, 500)
    }
    out.push(r)
  }
  return { rules: out, connection: exp.policies.filter((p) => p.connection).length }
}

export function planImport(exp: NpsExport, ctx: PlanCtx): Plan {
  const clients = planClients(exp, ctx)
  const { rules, connection } = planRules(exp, clients, ctx)
  const tally = <T extends { status: Status }>(xs: T[]) => ({ imported: xs.filter((x) => x.status === 'imported').length, adapted: xs.filter((x) => x.status === 'adapted').length, skipped: xs.filter((x) => x.status === 'skipped').length })
  return { clients, rules, connectionPolicies: connection, totals: { clients: tally(clients), rules: tally(rules) }, directory: ctx.directory, clientsContainer: exp.clientsContainer }
}

