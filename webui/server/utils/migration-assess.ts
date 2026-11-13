// Évaluation de compatibilité d'une migration depuis DNS / DHCP Windows Server (0.12.1). Analyse PURE, en lecture seule :
// ce que l'import reprend tel quel (ok), ce qui demande un geste ou une adaptation (adapted), ce qui n'est pas pris en charge (unsupported).
import { XMLParser, XMLValidator } from 'fast-xml-parser'
import { arr, csvObjects, lc, parseDhcpExport } from './ad'

export type Level = 'ok' | 'adapted' | 'unsupported'
export const ASSESS_CODES = [
  'dhcp_scopes', 'dhcp_reservations', 'dhcp_invalid', 'dhcp_options', 'dhcp_policies', 'dhcp_classes', 'dhcp_filters', 'dhcp_failover', 'dhcp_superscopes', 'dhcp_ipv6', 'dhcp_leases',
  'dns_primary', 'dns_reverse', 'dns_ds', 'dns_secondary', 'dns_stub', 'dns_forwarder', 'dns_signed', 'dns_secure_update', 'dns_ad_critical',
] as const
export type AssessCode = (typeof ASSESS_CODES)[number]
export interface AssessFinding { area: 'dhcp' | 'dns'; code: AssessCode; level: Level; count: number; detail?: string }
export interface Assessment { findings: AssessFinding[]; summary: Record<Level, number>; verdict: 'ready' | 'review' | 'blocked'; errors: string[] }

/** Nombre d'éléments portant ce nom, à n'importe quelle profondeur (tolérant : la forme exacte de l'export varie selon la version de Windows). */
export function countKey(tree: any, name: string): number {
  let n = 0
  const walk = (o: any) => {
    if (Array.isArray(o)) return o.forEach(walk)
    if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) { if (k === name) n += arr(v).filter((x) => x !== '' && x !== undefined && x !== null).length; walk(v) }
  }
  walk(tree)
  return n
}

const add = (out: AssessFinding[], area: 'dhcp' | 'dns', code: AssessCode, level: Level, count: number, detail?: string) => { if (count > 0) out.push({ area, code, level, count, ...(detail ? { detail } : {}) }) }

export function assessDhcp(xml: string, out: AssessFinding[], errors: string[]): void {
  if (XMLValidator.validate(xml) !== true) { errors.push('dhcp_xml_invalid'); return }
  const plan = parseDhcpExport(xml)
  if (!plan.scopes.length && plan.warnings.some((w) => w.code === 'no_ipv4_section')) { errors.push('dhcp_no_ipv4'); return }
  let tree: any = {}
  try { tree = lc(new XMLParser({ ignoreAttributes: true, removeNSPrefix: true, parseTagValue: false, trimValues: true }).parse(xml)) } catch { /* déjà validé */ }
  add(out, 'dhcp', 'dhcp_scopes', 'ok', plan.scopes.length)
  add(out, 'dhcp', 'dhcp_reservations', 'ok', plan.scopes.reduce((n, s) => n + s.reservations.length, 0))
  add(out, 'dhcp', 'dhcp_invalid', 'adapted', plan.warnings.filter((w) => w.code === 'scope_invalid' || w.code === 'reservation_invalid').length)
  const unmapped = [...new Set(plan.warnings.filter((w) => w.code === 'option_unmapped').map((w) => w.detail ?? ''))].filter(Boolean)
  add(out, 'dhcp', 'dhcp_options', 'adapted', unmapped.length, unmapped.slice(0, 20).join(', '))
  const v4 = tree?.dhcpserver?.ipv4 ?? {}
  add(out, 'dhcp', 'dhcp_policies', 'adapted', countKey(v4, 'policy'))
  add(out, 'dhcp', 'dhcp_classes', 'adapted', countKey(v4, 'class'))
  add(out, 'dhcp', 'dhcp_filters', 'adapted', countKey(v4, 'filter'))
  add(out, 'dhcp', 'dhcp_failover', 'adapted', countKey(v4, 'failover') + countKey(v4, 'relationship'))
  add(out, 'dhcp', 'dhcp_superscopes', 'adapted', countKey(v4, 'superscope'))
  add(out, 'dhcp', 'dhcp_ipv6', 'unsupported', countKey(tree?.dhcpserver ?? {}, 'ipv6') ? Math.max(1, countKey(tree.dhcpserver.ipv6 ?? {}, 'scope')) : 0)
  add(out, 'dhcp', 'dhcp_leases', 'unsupported', countKey(tree?.dhcpserver ?? {}, 'lease'))
}

const yes = (s: string | undefined) => /^(true|vrai|1|yes|oui)$/i.test((s ?? '').trim())
export function assessDnsZones(csv: string, out: AssessFinding[], errors: string[]): void {
  const rows = csvObjects(csv)
  if (!rows.length || !('zonename' in rows[0]!)) { errors.push('dns_csv_invalid'); return }
  const zones = rows.filter((r) => r.zonename && !/^(trustanchors|\.)$/i.test(r.zonename))
  const type = (r: Record<string, string>) => (r.zonetype ?? '').toLowerCase()
  const prim = zones.filter((r) => type(r) === 'primary')
  add(out, 'dns', 'dns_primary', 'ok', prim.filter((r) => !yes(r.isdsintegrated) && !yes(r.isreverselookupzone)).length)
  add(out, 'dns', 'dns_reverse', 'ok', prim.filter((r) => yes(r.isreverselookupzone)).length)
  add(out, 'dns', 'dns_ds', 'adapted', prim.filter((r) => yes(r.isdsintegrated)).length)
  add(out, 'dns', 'dns_secondary', 'adapted', zones.filter((r) => type(r) === 'secondary').length)
  add(out, 'dns', 'dns_stub', 'unsupported', zones.filter((r) => type(r) === 'stub').length)
  add(out, 'dns', 'dns_forwarder', 'adapted', zones.filter((r) => type(r) === 'forwarder').length)
  add(out, 'dns', 'dns_signed', 'unsupported', zones.filter((r) => yes(r.issigned)).length)
  add(out, 'dns', 'dns_secure_update', 'adapted', prim.filter((r) => /secure/i.test(r.dynamicupdate ?? '')).length)
  add(out, 'dns', 'dns_ad_critical', 'adapted', zones.filter((r) => /(^|\.)_msdcs(\.|$)/i.test(r.zonename!)).length)
}

export function assess(input: { dhcp?: string; zones?: string }): Assessment {
  const findings: AssessFinding[] = [], errors: string[] = []
  if (input.dhcp?.trim()) assessDhcp(input.dhcp, findings, errors)
  if (input.zones?.trim()) assessDnsZones(input.zones, findings, errors)
  const summary: Record<Level, number> = { ok: 0, adapted: 0, unsupported: 0 }
  for (const f of findings) summary[f.level] += 1
  const verdict = errors.length && !findings.length ? 'blocked' : summary.unsupported ? 'review' : 'ready'
  return { findings, summary, verdict, errors }
}
