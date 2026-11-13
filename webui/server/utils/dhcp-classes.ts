// Classes de clients DHCP (0.12.8) : équivalent Kea des classes fabricant / utilisateur, des filtres MAC « refuser » et de l'option 43 de Windows.
import { z } from 'zod'
import { normMac } from './net'

export const KIND = ['vendor', 'user', 'mac'] as const
export type ClassKind = (typeof KIND)[number]
export interface DhcpClass { name: string; kind: ClassKind; match: string; action: 'assign' | 'drop'; option43: string | null; tftp_server: string | null; boot_file: string | null; enabled: boolean }

/** Option 43 saisie en hexadécimal (séparateurs « : », « - » ou espaces tolérés) → hexadécimal minuscule continu. */
export function normHex(s: string): string | null {
  const h = s.replace(/[\s:-]/g, '').toLowerCase()
  return /^([0-9a-f]{2}){1,255}$/.test(h) ? h : null
}
/** OUI (3 octets) ou adresse complète (6 octets) → « aa:bb:cc » ou « aa:bb:cc:dd:ee:ff ». */
export function normMatchMac(s: string): string | null {
  const h = s.replace(/[\s:.-]/g, '').toLowerCase()
  if (!/^([0-9a-f]{2}){3}$|^([0-9a-f]{2}){6}$/.test(h)) return null
  if (h.length === 12) return normMac(h)
  return h.match(/../g)!.join(':')
}
const TEXT = /^[\x20-\x7e]{1,64}$/

const base = z.object({
  name: z.string().trim().toLowerCase().regex(/^[a-z][a-z0-9-]{0,40}$/).refine((n) => n !== 'drop', 'reserved'),
  kind: z.enum(KIND), match: z.string().trim().min(1).max(64),
  action: z.enum(['assign', 'drop']).default('assign'),
  option43: z.string().trim().max(600).nullish(), tftp_server: z.string().trim().max(253).regex(/^[A-Za-z0-9._-]*$/).nullish(), boot_file: z.string().trim().max(255).regex(/^[\w./-]*$/).nullish(),
  enabled: z.boolean().default(true), comment: z.string().trim().max(500).nullish(),
})
export const classBody = base.transform((b, ctx) => {
  let match: string | null
  if (b.kind === 'mac') match = normMatchMac(b.match)
  else match = TEXT.test(b.match) && !/['\\]/.test(b.match) ? b.match : null
  if (!match) { ctx.addIssue({ code: 'custom', path: ['match'], message: 'match' }); return z.NEVER }
  let option43: string | null = null
  if (b.option43) {
    option43 = normHex(b.option43)
    if (!option43) { ctx.addIssue({ code: 'custom', path: ['option43'], message: 'option43' }); return z.NEVER }
  }
  if (b.action === 'drop' && (option43 || b.tftp_server || b.boot_file)) { ctx.addIssue({ code: 'custom', path: ['action'], message: 'drop_options' }); return z.NEVER }
  return { ...b, match, option43, tftp_server: b.tftp_server || null, boot_file: b.boot_file || null, comment: b.comment || null }
})

/** Expression Kea « test » d'une classe (comparaison par début de chaîne pour fabricant / utilisateur, OUI ou adresse pour MAC). */
export function classTest(kind: ClassKind, match: string): string {
  if (kind === 'mac') {
    const hex = match.replace(/:/g, '')
    return hex.length === 6 ? `substring(pkt4.mac,0,3) == 0x${hex}` : `pkt4.mac == 0x${hex}`
  }
  return `substring(option[${kind === 'vendor' ? 60 : 77}].text,0,${match.length}) == '${match}'`
}

/** Entrée « client-classes » de la configuration Kea. Les règles « refuser » sont réunies dans la classe spéciale DROP. */
export function keaClasses(rows: DhcpClass[]): any[] {
  const on = rows.filter((r) => r.enabled)
  const out: any[] = []
  for (const r of on.filter((x) => x.action === 'assign')) {
    const od: any[] = []
    if (r.option43) od.push({ code: 43, space: 'dhcp4', 'csv-format': false, data: r.option43 })
    if (r.tftp_server) od.push({ name: 'tftp-server-name', data: r.tftp_server })
    if (r.boot_file) od.push({ name: 'boot-file-name', data: r.boot_file })
    out.push({ name: r.name, test: classTest(r.kind, r.match), ...(od.length ? { 'option-data': od } : {}) })
  }
  const drops = on.filter((x) => x.action === 'drop')
  if (drops.length) out.push({ name: 'DROP', test: drops.map((d) => `(${classTest(d.kind, d.match)})`).join(' or ') })
  return out
}

// ---- Import depuis l'export Windows (Export-DhcpServer) : classes fabricant / utilisateur et filtres MAC « refuser » ----
import { XMLParser, XMLValidator } from 'fast-xml-parser'
import { arr, lc } from './ad'

export interface ClassPlanItem { source: 'class' | 'filter'; name: string; kind: ClassKind | null; match: string; action: 'assign' | 'drop'; status: 'create' | 'exists' | 'skip'; reason?: string }
const s = (x: unknown) => (x === undefined || x === null ? '' : String(x).trim())
const slug = (n: string) => { const v = n.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 41); return /^[a-z]/.test(v) ? v : `c-${v}`.slice(0, 41) }
const decodeHex = (h: string): string | null => {
  const x = h.replace(/[\s:-]/g, '')
  if (!/^([0-9a-fA-F]{2})+$/.test(x)) return null
  const t = Buffer.from(x, 'hex').toString('latin1').replace(/\0+$/, '')
  return TEXT.test(t) && !/['\\]/.test(t) ? t : null
}

/** Analyse tolérante : les balises sont cherchées où qu'elles soient dans la section IPv4. */
export function planWindowsClasses(xml: string, existing: Set<string>): { items: ClassPlanItem[]; errors: string[] } {
  if (XMLValidator.validate(xml) !== true) return { items: [], errors: ['dhcp_xml_invalid'] }
  let doc: any
  try { doc = lc(new XMLParser({ ignoreAttributes: true, removeNSPrefix: true, parseTagValue: false, trimValues: true }).parse(xml)) } catch { return { items: [], errors: ['dhcp_xml_invalid'] } }
  const v4 = doc?.dhcpserver?.ipv4
  if (!v4) return { items: [], errors: ['dhcp_no_ipv4'] }
  const raw: Array<{ key: 'class' | 'filter'; node: any; parent: string }> = []
  const walk = (o: any, parent: string) => {
    if (Array.isArray(o)) return o.forEach((x) => walk(x, parent))
    if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) {
      if (k === 'class' || k === 'filter') for (const n of arr(v)) if (n && typeof n === 'object') raw.push({ key: k, node: n, parent })
      walk(v, k)
    }
  }
  walk(v4, '')
  const items: ClassPlanItem[] = [], used = new Set(existing)
  const push = (i: Omit<ClassPlanItem, 'status'> & { status?: ClassPlanItem['status'] }) => {
    if (i.reason) { items.push({ ...i, status: 'skip' } as ClassPlanItem); return }
    if (used.has(i.name)) { items.push({ ...i, status: 'exists' }); return }
    used.add(i.name); items.push({ ...i, status: 'create' })
  }
  for (const { key, node, parent } of raw) {
    if (key === 'class') {
      const nm = s(node.name), type = `${s(node.type)} ${s(node.isvendor)}`.toLowerCase()
      const kind: ClassKind = /vendor|true/.test(type) ? 'vendor' : 'user'
      const text = node.asciidata ? s(node.asciidata) : decodeHex(s(node.data))
      const name = slug(nm || 'classe')
      if (!nm) continue
      if (!text || !TEXT.test(text) || /['\\]/.test(text)) push({ source: 'class', name, kind, match: '', action: 'assign', reason: 'class_data' })
      else push({ source: 'class', name, kind, match: text, action: 'assign' })
    } else {
      const list = (s(node.list) || s(node.type) || parent).toLowerCase()
      const macRaw = s(node.macaddress ?? node.mac ?? node.address ?? node.clientid).replace(/\*+$/, '')
      const mac = normMatchMac(macRaw)
      if (list.includes('allow')) push({ source: 'filter', name: slug(`allow-${macRaw}`), kind: 'mac', match: macRaw, action: 'assign', reason: 'allow_list' })
      else if (!mac) push({ source: 'filter', name: slug(`deny-${macRaw || 'x'}`), kind: 'mac', match: macRaw, action: 'drop', reason: 'mac_invalid' })
      else push({ source: 'filter', name: slug(`deny-${mac}`), kind: 'mac', match: mac, action: 'drop' })
    }
  }
  return { items, errors: [] }
}
