// Règles d'accès RADIUS (0.13.3, itération 4) : liste ORDONNÉE, première correspondance, refus par défaut. Une règle = conditions (toutes doivent
// être vraies ; plusieurs valeurs d'une même condition = « l'une d'elles ») + décision (accepter, avec VLAN / pool / durée / attributs, ou refuser).
//
// Ce fichier est LA définition de la décision côté console : l'évaluateur `evaluate` sert à la simulation, et la même logique est écrite en unlang
// par root (ddibuntu-radius, validate_authz) à partir des données déposées. Les deux sont comparées sur de vrais échanges EAP-TLS par la batterie
// tests/b30 (même tableau de cas) : toute modification de l'un exige de modifier l'autre.
//
// Ordre de la décision (identique des deux côtés) :
//   1. identité du certificat : UPN → utilisateur ; sinon premier nom DNS → machine ; sinon refus
//   2. compte dans l'annuaire : introuvable, ambigu ou annuaire indisponible → refus
//   3. état du compte : illisible, désactivé, verrouillé, expiré → refus (ce n'est PAS une règle : aucune règle ne peut l'outrepasser)
//   4. règles dans l'ordre : la première qui correspond décide
//   5. aucune ne correspond → refus
import { z } from 'zod'
import { USAGES } from './radius'
import type { Usage } from './radius'
import type { AccountState } from './radius-dir'

export const RULES_MAX = 200
export const MAX_RULE_GROUPS = 30
export const MAX_RULE_SSIDS = 20
export const MAX_RULE_ATTRS = 8
export const MAX_RULE_CLIENTS = 2000

// ---- Listes blanches (root applique les MÊMES contrôles, voir validate_authz) ----
// DN de groupe : pas de caractère de contrôle, de guillemet, de « $ », « % », « { », « } », ni d'accent grave ; la barre oblique inverse n'est admise
// que comme échappement de DN suivi d'un caractère spécial (« \, » « \+ » « \< » « \> » « \; » « \= » « \# » « \  » « \\ »). L'échappement
// hexadécimal (« \3D ») est REFUSÉ : FreeRADIUS normalise les DN de groupe de l'annuaire et ne retrouve alors plus celui de la règle (essai réel contre
// Samba, qui écrit ainsi « = » et « ; ») — la simulation dirait « accepté » et le serveur refuserait. Il faut renommer un tel groupe.
export const GROUP_DN_RE = /^(?:[^\x00-\x1f\x7f"$%{}`\\]|\\[,+<>;=# \\]){3,512}$/
export const SSID_RE = /^[A-Za-z0-9 ._@#&+=,;:!()/-]{1,32}$/
export const POOL_RE = /^[A-Za-z0-9._-]{1,63}$/
export const FILTER_ID_RE = /^[A-Za-z0-9 ._:@=/,;()#*+-]{1,128}$/
export const CLIENT_NAME_RE = /^[a-z][a-z0-9-]{0,40}$/
/** Attributs constructeur autorisés (liste blanche) : nom → forme de la valeur. */
export const VENDOR_ATTRS = {
  'Aruba-User-Role': /^[A-Za-z0-9 ._:@=/,;()#*+-]{1,128}$/,
  'Fortinet-Group-Name': /^[A-Za-z0-9 ._:@=/,;()#*+-]{1,128}$/,
  'Reply-Message': /^[A-Za-z0-9 ._:@=/,;()#*+!?-]{1,128}$/,
  'Cisco-AVPair': /^[A-Za-z0-9 ._:@=/,;()#*+-]{1,200}$/,
} as const
export type VendorAttr = keyof typeof VENDOR_ATTRS
export const VENDOR_NAMES = Object.keys(VENDOR_ATTRS) as VendorAttr[]

export type Kind = 'user' | 'computer'
export interface GroupRef { dn: string; name: string }
export interface RuleConds { kind: Kind | null; groups: GroupRef[]; clients: string[]; usages: Usage[]; ssids: string[] }
export interface RuleReply { vlan?: number; pool?: string; sessionTimeout?: number; filterId?: string; attrs?: Array<{ name: VendorAttr; value: string }> }
export interface RuleRow { id: number; rank: number; name: string; enabled: boolean; action: 'accept' | 'reject'; conds: RuleConds; reply: RuleReply; comment: string | null }

const groupRef = z.object({ dn: z.string().regex(GROUP_DN_RE, 'group_dn').refine((d) => d.includes('='), 'group_dn'), name: z.string().trim().max(200).default('') }).strict()
const replySchema = z.object({
  vlan: z.number().int().min(1).max(4094).optional(),
  pool: z.string().trim().regex(POOL_RE, 'pool').optional(),
  sessionTimeout: z.number().int().min(60).max(2592000).optional(),
  filterId: z.string().trim().regex(FILTER_ID_RE, 'filter_id').optional(),
  attrs: z.array(z.object({ name: z.enum(VENDOR_NAMES as [VendorAttr, ...VendorAttr[]]), value: z.string().trim() }).strict()).max(MAX_RULE_ATTRS).optional(),
}).strict()

export const ruleBody = z.object({
  name: z.string().trim().min(1).max(80).regex(/^[^\x00-\x1f\x7f]+$/, 'name'),
  enabled: z.boolean().default(true),
  action: z.enum(['accept', 'reject']),
  kind: z.enum(['user', 'computer']).nullish(),
  groups: z.array(groupRef).max(MAX_RULE_GROUPS).default([]),
  clients: z.array(z.string().regex(CLIENT_NAME_RE, 'client')).max(MAX_RULE_CLIENTS).default([]),
  usages: z.array(z.enum(USAGES)).max(USAGES.length).default([]),
  ssids: z.array(z.string().regex(SSID_RE, 'ssid')).max(MAX_RULE_SSIDS).default([]),
  reply: replySchema.default({}),
  comment: z.string().trim().max(500).nullish(),
}).strict().transform((b, ctx) => {
  const reply: RuleReply = {}
  if (b.reply.vlan !== undefined) reply.vlan = b.reply.vlan
  if (b.reply.pool) reply.pool = b.reply.pool
  if (b.reply.sessionTimeout !== undefined) reply.sessionTimeout = b.reply.sessionTimeout
  if (b.reply.filterId) reply.filterId = b.reply.filterId
  const attrs: NonNullable<RuleReply['attrs']> = []
  for (const [i, a] of (b.reply.attrs ?? []).entries()) {
    if (!VENDOR_ATTRS[a.name].test(a.value)) { ctx.addIssue({ code: 'custom', path: ['reply', 'attrs', i, 'value'], message: 'attr_value' }); return z.NEVER }
    if (attrs.some((x) => x.name === a.name)) { ctx.addIssue({ code: 'custom', path: ['reply', 'attrs', i, 'name'], message: 'attr_dup' }); return z.NEVER }
    attrs.push({ name: a.name, value: a.value })
  }
  if (attrs.length) reply.attrs = attrs
  if (b.action === 'reject' && Object.keys(reply).length) { ctx.addIssue({ code: 'custom', path: ['reply'], message: 'reject_reply' }); return z.NEVER }
  const dns = new Set<string>()
  for (const g of b.groups) { if (dns.has(g.dn.toLowerCase())) { ctx.addIssue({ code: 'custom', path: ['groups'], message: 'group_dup' }); return z.NEVER } dns.add(g.dn.toLowerCase()) }
  return {
    name: b.name, enabled: b.enabled, action: b.action, comment: b.comment || null, reply,
    conds: { kind: b.kind ?? null, groups: b.groups.map((g) => ({ dn: g.dn, name: g.name || (g.dn.split(',')[0] ?? g.dn).replace(/^cn=/i, '') })),
      clients: [...new Set(b.clients)].sort(), usages: [...new Set(b.usages)].sort() as Usage[], ssids: [...new Set(b.ssids)] } satisfies RuleConds,
  }
})
export type RuleInput = z.output<typeof ruleBody>

/** Ligne de la base → règle (valeurs par défaut sur les champs absents : le JSON stocké a été validé à l'écriture, mais on ne s'y fie pas aveuglément). */
export function rowToRule(r: any): RuleRow {
  const c = r.conds ?? {}
  return {
    id: Number(r.id), rank: Number(r.rank), name: String(r.name), enabled: r.enabled === true, action: r.action === 'accept' ? 'accept' : 'reject', comment: r.comment ?? null,
    conds: { kind: c.kind === 'user' || c.kind === 'computer' ? c.kind : null, groups: Array.isArray(c.groups) ? c.groups : [], clients: Array.isArray(c.clients) ? c.clients : [],
      usages: Array.isArray(c.usages) ? c.usages : [], ssids: Array.isArray(c.ssids) ? c.ssids : [] },
    reply: r.reply && typeof r.reply === 'object' ? r.reply : {},
  }
}

// ---- Compilation (ce que root reçoit) ----
export interface ClientInfo { name: string; usage: Usage; enabled: boolean }
export interface CompiledRule { n: number; id: number; name: string; action: 'accept' | 'reject'; kind: Kind | null; groups: string[]; nas: string[] | null; ssids: string[]; reply: RuleReply }

/** Règles ACTIVES, dans l'ordre. Les conditions « clients » et « usages » (réunies : l'un OU l'autre) sont résolues en noms de clients ACTIFS au moment du
 *  déploiement : `nas: null` = n'importe quel client ; `nas: []` = aucun client ne correspond (la règle ne s'applique jamais). */
export function compileRules(rows: RuleRow[], clients: ClientInfo[]): CompiledRule[] {
  const active = clients.filter((c) => c.enabled)
  return rows.filter((r) => r.enabled).sort((a, b) => a.rank - b.rank || a.id - b.id).map((r, i): CompiledRule => {
    const restricted = r.conds.clients.length > 0 || r.conds.usages.length > 0
    const nas = restricted ? active.filter((c) => r.conds.clients.includes(c.name) || r.conds.usages.includes(c.usage)).map((c) => c.name).sort() : null
    return { n: i + 1, id: r.id, name: r.name, action: r.action, kind: r.conds.kind, groups: r.conds.groups.map((g) => g.dn), nas, ssids: r.conds.ssids, reply: r.reply }
  })
}
/** Contenu de rules.json (données seules ; root ne lit ni identifiants ni texte de configuration). */
export function rulesJson(rules: CompiledRule[]): string {
  return JSON.stringify({ rules: rules.map((r) => ({ name: r.name, action: r.action, kind: r.kind, groups: r.groups, nas: r.nas, ssids: r.ssids, reply: r.reply })) }) + '\n'
}

// ---- SSID ----
/** SSID d'un Called-Station-Id « AA-BB-CC-DD-EE-FF:SSID » (séparateurs « - », « : », « . » ou aucun). Même expression que root (POSIX ERE). */
export function ssidFromCalledStation(csid: string): string | null {
  const m = /^(?:[0-9A-Fa-f]{2}[-:.]?){5}[0-9A-Fa-f]{2}:(.+)$/.exec(csid)
  return m ? m[1]! : null
}

// ---- Évaluation ----
export type Directory =
  | { status: 'unavailable' }
  | { status: 'ok'; found: false; ambiguous: boolean }
  | { status: 'ok'; found: true; state: AccountState; groups: string[] }
export interface EvalInput { identity: { kind: Kind; name: string } | null; directory: Directory; client: { name: string; usage: Usage } | null; ssid: string | null }
export type Stage = 'identity' | 'directory' | 'account' | 'rule' | 'default'
export type Code =
  | 'no_identity' | 'directory_unavailable' | 'account_not_found' | 'account_ambiguous'
  | 'account_unreadable' | 'account_disabled' | 'account_locked' | 'account_expired'
  | 'rule_accept' | 'rule_reject' | 'default_reject'
export interface Cond { type: 'kind' | 'groups' | 'nas' | 'ssid'; ok: boolean; wanted: string[]; got: string | string[] | null }
export interface RuleTrace { n: number; id: number; name: string; matched: boolean; never?: boolean; conds: Cond[] }
export interface ReplyAttr { name: string; value: string }
export interface Decision { decision: 'accept' | 'reject'; stage: Stage; code: Code; rule: number | null; ruleId: number | null; reply: ReplyAttr[]; trace: RuleTrace[] }

/** Attributs de réponse tels que FreeRADIUS les envoie (même ordre que le unlang généré par root). */
export function replyAttrs(r: RuleReply): ReplyAttr[] {
  const a: ReplyAttr[] = []
  if (r.vlan !== undefined) a.push({ name: 'Tunnel-Type', value: 'VLAN' }, { name: 'Tunnel-Medium-Type', value: 'IEEE-802' }, { name: 'Tunnel-Private-Group-Id', value: String(r.vlan) })
  if (r.pool) a.push({ name: 'Framed-Pool', value: r.pool })
  if (r.sessionTimeout !== undefined) a.push({ name: 'Session-Timeout', value: String(r.sessionTimeout) })
  if (r.filterId) a.push({ name: 'Filter-Id', value: r.filterId })
  for (const x of r.attrs ?? []) a.push({ name: x.name, value: x.value })
  return a
}
const REASON_CODE: Record<AccountState['reasons'][number], Code> = { unreadable: 'account_unreadable', disabled: 'account_disabled', locked: 'account_locked', expired: 'account_expired' }

/** Évalue les règles COMPILÉES (voir compileRules). Les DN de groupe se comparent à l'identique (FreeRADIUS compare les chaînes telles que l'annuaire les renvoie). */
export function evaluate(rules: CompiledRule[], input: EvalInput): Decision {
  const stop = (stage: Stage, code: Code, trace: RuleTrace[] = []): Decision => ({ decision: 'reject', stage, code, rule: null, ruleId: null, reply: [], trace })
  if (!input.identity) return stop('identity', 'no_identity')
  const d = input.directory
  if (d.status === 'unavailable') return stop('directory', 'directory_unavailable')
  if (!d.found) return stop('directory', d.ambiguous ? 'account_ambiguous' : 'account_not_found')
  if (!d.state.usable) return stop('account', REASON_CODE[d.state.reasons[0] ?? 'unreadable'])
  const trace: RuleTrace[] = []
  for (const r of rules) {
    const conds: Cond[] = []
    const never = r.nas !== null && r.nas.length === 0
    if (r.kind) conds.push({ type: 'kind', ok: input.identity.kind === r.kind, wanted: [r.kind], got: input.identity.kind })
    if (r.groups.length) { const hit = r.groups.filter((g) => d.groups.includes(g)); conds.push({ type: 'groups', ok: hit.length > 0, wanted: r.groups, got: hit }) }
    if (r.nas !== null) conds.push({ type: 'nas', ok: !!input.client && r.nas.includes(input.client.name), wanted: r.nas, got: input.client?.name ?? null })
    if (r.ssids.length) conds.push({ type: 'ssid', ok: input.ssid !== null && r.ssids.includes(input.ssid), wanted: r.ssids, got: input.ssid })
    const matched = !never && conds.every((c) => c.ok)
    trace.push({ n: r.n, id: r.id, name: r.name, matched, ...(never ? { never: true } : {}), conds })
    if (matched) return { decision: r.action, stage: 'rule', code: r.action === 'accept' ? 'rule_accept' : 'rule_reject', rule: r.n, ruleId: r.id, reply: r.action === 'accept' ? replyAttrs(r.reply) : [], trace }
  }
  return stop('default', 'default_reject', trace)
}

// ---- Analyse de la liste (avertissements affichés dans la console) ----
export type Warning = { code: 'no_accept' | 'empty_nas' | 'catch_all_accept' | 'shadowed'; rule?: number; by?: number }
const subset = (a: string[], b: string[]) => a.every((x) => b.includes(x))
/** La règle `j` (plus haut dans la liste) est-elle au moins aussi large que `i` sur chaque condition ? Alors `i` n'est jamais atteinte. Analyse prudente : jamais de faux positif. */
function covers(j: CompiledRule, i: CompiledRule): boolean {
  if (j.nas !== null && j.nas.length === 0) return false
  if (j.kind && j.kind !== i.kind) return false
  if (j.groups.length && !(i.groups.length && subset(i.groups, j.groups))) return false
  if (j.nas !== null && !(i.nas !== null && subset(i.nas, j.nas))) return false
  if (j.ssids.length && !(i.ssids.length && subset(i.ssids, j.ssids))) return false
  return true
}
export function analyze(rules: CompiledRule[]): Warning[] {
  const w: Warning[] = []
  if (!rules.some((r) => r.action === 'accept')) w.push({ code: 'no_accept' })
  for (const [idx, r] of rules.entries()) {
    if (r.nas !== null && r.nas.length === 0) { w.push({ code: 'empty_nas', rule: r.n }); continue }
    const by = rules.slice(0, idx).find((j) => covers(j, r))
    if (by) w.push({ code: 'shadowed', rule: r.n, by: by.n })
    else if (r.action === 'accept' && !r.kind && !r.groups.length && r.nas === null && !r.ssids.length) w.push({ code: 'catch_all_accept', rule: r.n })
  }
  return w
}
