// Compatibilité Active Directory : analyse des exports Windows (DHCP, sous-réseaux) et authentification
// LDAPS avec correspondance groupes -> rôles. Le mot de passe de liaison n'est jamais renvoyé ni journalisé.
import { XMLParser, XMLValidator } from 'fast-xml-parser'
import { Client } from 'ldapts'
import { cidrToString, ipToString, normMac, parseCidr, parseIp } from './net'
import type { Role } from './auth'
import { normDn } from './text'

// ---------------------------------------------------------------------------------------------
// CSV (RFC 4180 simplifié)
export function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = [], cur = '', q = false
  const src = text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n')
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!
    if (q) {
      if (c === '"') { if (src[i + 1] === '"') { cur += '"'; i++ } else q = false } else cur += c
    } else if (c === '"') q = true
    else if (c === ',' || c === ';') { row.push(cur); cur = '' }
    else if (c === '\n') { row.push(cur); if (row.some((x) => x.trim() !== '')) rows.push(row); row = []; cur = '' }
    else cur += c
  }
  row.push(cur)
  if (row.some((x) => x.trim() !== '')) rows.push(row)
  return rows
}
export function csvObjects(text: string): Array<Record<string, string>> {
  const rows = parseCsv(text)
  if (!rows.length) return []
  const head = rows[0]!.map((h) => h.trim().toLowerCase())
  return rows.slice(1).map((r) => Object.fromEntries(head.map((h, i) => [h, (r[i] ?? '').trim()])))
}

// ---------------------------------------------------------------------------------------------
// Sites et sous-réseaux AD : Get-ADReplicationSubnet -Filter * | Select Name,Site,Location | Export-Csv
export interface AdSubnetRow { cidr: string; site: string; description: string }
export function parseAdSubnets(text: string): { rows: AdSubnetRow[]; errors: Array<{ line: number; value: string }> } {
  const rows: AdSubnetRow[] = [], errors: Array<{ line: number; value: string }> = []
  csvObjects(text).forEach((o, i) => {
    const raw = o.name ?? o.subnet ?? o.network ?? o.cidr ?? ''
    const c = parseCidr(raw)
    if (!c) { errors.push({ line: i + 2, value: raw }); return }
    // le nom du site peut être un DN : « CN=Paris,CN=Sites,CN=Configuration,... »
    const site = (o.site ?? '').replace(/^CN=([^,]+),.*$/i, '$1')
    rows.push({ cidr: cidrToString(c), site, description: o.location ?? o.description ?? '' })
  })
  return { rows, errors }
}

// ---------------------------------------------------------------------------------------------
// Export DHCP Windows : Export-DhcpServer -File dhcp.xml (analyse tolérante : noms de balises sans casse)
export interface DhcpPlanScope {
  cidr: string; name: string; leaseTime: number; enabled: boolean
  pools: Array<{ start: string; end: string }>
  options: { routers?: string[]; dnsServers?: string[]; domainName?: string; ntpServers?: string[]; domainSearch?: string[]; tftpServer?: string; bootFile?: string }
  reservations: Array<{ mac: string; ip: string; hostname: string | null; description: string | null }>
  exclusions: Array<{ start: string; end: string }>
}
export interface DhcpPlan { scopes: DhcpPlanScope[]; warnings: Array<{ scope?: string; code: string; detail?: string }> }

const ARR = new Set(['scope', 'reservation', 'optionvalue', 'iprange', 'value', 'filter'])
export const lc = (o: any): any => {
  if (Array.isArray(o)) return o.map(lc)
  if (o && typeof o === 'object') return Object.fromEntries(Object.entries(o).map(([k, v]) => [k.toLowerCase(), lc(v)]))
  return o
}
export const arr = (x: any): any[] => (x === undefined || x === null || x === '' ? [] : Array.isArray(x) ? x : [x])
const str = (x: any): string => (x === undefined || x === null ? '' : String(x).trim())

export function parseWindowsLease(s: string): number | null {
  const m = s.match(/^(?:(\d+)\.)?(\d+):(\d+):(\d+)$/)
  if (!m) return /^\d+$/.test(s) ? Number(s) : null
  return Number(m[1] ?? 0) * 86400 + Number(m[2]) * 3600 + Number(m[3]) * 60 + Number(m[4])
}

/** Retire les plages exclues d'une plage d'adresses IPv4 : renvoie les sous-plages restantes. */
export function subtractRanges(start: bigint, end: bigint, excl: Array<[bigint, bigint]>): Array<[bigint, bigint]> {
  let out: Array<[bigint, bigint]> = [[start, end]]
  for (const [a, b] of excl) {
    const next: Array<[bigint, bigint]> = []
    for (const [s, e] of out) {
      if (b < s || a > e) { next.push([s, e]); continue }
      if (a > s) next.push([s, a - 1n])
      if (b < e) next.push([b + 1n, e])
    }
    out = next
  }
  return out
}

const OPT: Record<string, keyof DhcpPlanScope['options']> = { '3': 'routers', '6': 'dnsServers', '15': 'domainName', '42': 'ntpServers', '119': 'domainSearch', '66': 'tftpServer', '67': 'bootFile' }
const OPT_ARRAY = new Set(['routers', 'dnsServers', 'ntpServers', 'domainSearch'])

export function parseDhcpExport(xml: string): DhcpPlan {
  const plan: DhcpPlan = { scopes: [], warnings: [] }
  let doc: any
  // l'analyseur est tolérant : on valide d'abord la forme du document
  if (XMLValidator.validate(xml) !== true) { plan.warnings.push({ code: 'xml_invalid' }); return plan }
  try {
    doc = lc(new XMLParser({ ignoreAttributes: true, removeNSPrefix: true, parseTagValue: false, trimValues: true, isArray: (n) => ARR.has(n.toLowerCase()) }).parse(xml))
  } catch { plan.warnings.push({ code: 'xml_invalid' }); return plan }
  const root = doc?.dhcpserver
  const v4 = root?.ipv4
  if (!v4) { plan.warnings.push({ code: 'no_ipv4_section' }); return plan }
  const global = readOptions(arr(v4.optionvalues?.optionvalue), plan, undefined)
  for (const sc of arr(v4.scopes?.scope)) {
    const id = str(sc.scopeid), mask = str(sc.subnetmask)
    const label = id || '?'
    const ip = parseIp(id), m = parseIp(mask)
    if (!ip || ip.v !== 4 || !m || m.v !== 4) { plan.warnings.push({ scope: label, code: 'scope_invalid' }); continue }
    const maskBits = (m.n.toString(2).match(/1/g) ?? []).length
    const net = parseCidr(`${id}/${maskBits}`)
    if (!net) { plan.warnings.push({ scope: label, code: 'scope_invalid' }); continue }
    const start = parseIp(str(sc.startrange)), end = parseIp(str(sc.endrange))
    const excl: Array<[bigint, bigint]> = arr(sc.exclusionranges?.iprange).flatMap((r) => {
      const a = parseIp(str(r.startrange)), b = parseIp(str(r.endrange))
      return a && b ? [[a.n, b.n] as [bigint, bigint]] : []
    })
    const pools = start && end ? subtractRanges(start.n, end.n, excl).map(([a, b]) => ({ start: ipToString({ v: 4, n: a }), end: ipToString({ v: 4, n: b }) })) : []
    const options = { ...global, ...readOptions(arr(sc.optionvalues?.optionvalue), plan, label) }
    const reservations: DhcpPlanScope['reservations'] = []
    for (const r of arr(sc.reservations?.reservation)) {
      const rip = parseIp(str(r.ipaddress)), mac = normMac(str(r.clientid))
      if (!rip || rip.v !== 4 || !mac) { plan.warnings.push({ scope: label, code: 'reservation_invalid', detail: str(r.clientid) }); continue }
      reservations.push({ mac, ip: ipToString(rip), hostname: str(r.name).toLowerCase().split('.')[0]!.replace(/[^a-z0-9-]/g, '') || null, description: str(r.description) || null })
    }
    plan.scopes.push({
      cidr: cidrToString(net), name: str(sc.name) || label, leaseTime: parseWindowsLease(str(sc.leaseduration)) ?? 86400,
      enabled: str(sc.state).toLowerCase() !== 'inactive', pools, options, reservations,
      exclusions: excl.map(([a, b]) => ({ start: ipToString({ v: 4, n: a }), end: ipToString({ v: 4, n: b }) })),
    })
  }
  return plan
}

function readOptions(vals: any[], plan: DhcpPlan, scope: string | undefined): DhcpPlanScope['options'] {
  const out: any = {}
  for (const o of vals) {
    const id = str(o.optionid)
    const key = OPT[id]
    const values = arr(o.value).map(str).filter(Boolean)
    if (!key) { plan.warnings.push({ scope, code: 'option_unmapped', detail: id }); continue }
    out[key] = OPT_ARRAY.has(key) ? values : values[0]
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Authentification Active Directory (LDAPS)
export interface AdSettings {
  enabled: boolean; urls: string[]; baseDn: string; bindDn: string; bindPasswordEnc?: string
  userAttr: 'sAMAccountName' | 'userPrincipalName'; groupMap: Array<{ groupDn: string; role: Role; spaceIds?: number[] }>
  nestedGroups: boolean; tlsRejectUnauthorized: boolean; caPem?: string
}
export const AD_DEFAULTS: AdSettings = { enabled: false, urls: [], baseDn: '', bindDn: '', userAttr: 'sAMAccountName', groupMap: [], nestedGroups: true, tlsRejectUnauthorized: true }

export interface LdapLike {
  bind(dn: string, pw: string): Promise<unknown>
  search(base: string, opts: { scope: 'sub' | 'base' | 'one'; filter: string; attributes: string[]; sizeLimit?: number; paged?: boolean }): Promise<{ searchEntries: any[] }>
  unbind(): Promise<unknown>
}
export const escapeFilter = (v: string) => v.replace(/[\\*()\0]/g, (c) => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'))
const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 }
const NESTED = '1.2.840.113556.1.4.1941'
const dnNorm = normDn

export function defaultLdapFactory(s: AdSettings): (url: string) => LdapLike {
  return (url) => new Client({ url, timeout: 8000, connectTimeout: 5000, tlsOptions: { rejectUnauthorized: s.tlsRejectUnauthorized, ...(s.caPem ? { ca: s.caPem } : {}) } }) as unknown as LdapLike
}

/** Périmètre délégué : null = tout ; sinon union des espaces IPAM des groupes qui donnent le rôle retenu (un groupe sans périmètre lève la restriction). */
export function delegatedSpaces(role: Role, groups: Array<{ spaceIds?: number[] }>): number[] | null {
  if (role === 'admin' || !groups.length || groups.some((g) => !g.spaceIds?.length)) return null
  return [...new Set(groups.flatMap((g) => g.spaceIds!))].sort((a, b) => a - b)
}

export type AdResult = { ok: true; dn: string; displayName: string; username: string; role: Role; spaceIds: number[] | null } | { ok: false; reason: 'disabled' | 'empty_password' | 'service_bind' | 'not_found' | 'bad_credentials' | 'no_group' | 'unreachable' }

export async function authenticateAd(username: string, password: string, s: AdSettings, bindPassword: string, factory: (url: string) => LdapLike): Promise<AdResult> {
  if (!s.enabled || !s.urls.length) return { ok: false, reason: 'disabled' }
  // une liaison LDAP sans mot de passe réussit comme « anonyme » : on la refuse avant tout
  if (!password) return { ok: false, reason: 'empty_password' }
  if (!/^[\w.@\- ]{1,256}$/.test(username)) return { ok: false, reason: 'not_found' }
  let lastErr: 'service_bind' | 'unreachable' = 'unreachable'
  for (const url of s.urls) {
    const svc = factory(url)
    try {
      try { await svc.bind(s.bindDn, bindPassword) } catch { lastErr = 'service_bind'; continue }
      const found = await svc.search(s.baseDn, { scope: 'sub', filter: `(&(objectClass=user)(!(objectClass=computer))(${s.userAttr}=${escapeFilter(username)}))`, attributes: ['dn', 'displayName', 'memberOf', s.userAttr], sizeLimit: 2 })
      if (found.searchEntries.length !== 1) return { ok: false, reason: 'not_found' }
      const e = found.searchEntries[0]!
      const dn = String(e.dn)
      const groups = arr(e.memberOf).map((g) => dnNorm(String(g)))
      let role: Role | null = null
      const matched: Array<{ role: Role; spaceIds?: number[] }> = []
      for (const m of s.groupMap) {
        let member = groups.includes(dnNorm(m.groupDn))
        if (!member && s.nestedGroups) {
          const n = await svc.search(s.baseDn, { scope: 'sub', filter: `(&(distinguishedName=${escapeFilter(dn)})(memberOf:${NESTED}:=${escapeFilter(m.groupDn)}))`, attributes: ['dn'], sizeLimit: 1 })
          member = n.searchEntries.length > 0
        }
        if (member) matched.push(m)
        if (member && (!role || RANK[m.role] > RANK[role])) role = m.role
      }
      // authentification de l'utilisateur sur une connexion distincte
      const usr = factory(url)
      try { await usr.bind(dn, password) } catch { return { ok: false, reason: 'bad_credentials' } } finally { await usr.unbind().catch(() => undefined) }
      if (!role) return { ok: false, reason: 'no_group' }
      const spaceIds = delegatedSpaces(role, matched.filter((m) => m.role === role))
      return { ok: true, dn, spaceIds, displayName: String(arr(e.displayName)[0] ?? username), username: String(arr(e[s.userAttr])[0] ?? username), role }
    } catch { lastErr = 'unreachable' } finally { await svc.unbind().catch(() => undefined) }
  }
  return { ok: false, reason: lastErr }
}
