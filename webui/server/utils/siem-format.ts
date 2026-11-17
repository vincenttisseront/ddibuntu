// Formats d'export vers un SIEM : syslog RFC 5424 / RFC 3164, CEF (ArcSight), LEEF 2.0 (QRadar), JSON. Fonctions pures, testées sans réseau.
export const SIEM_FORMATS = ['rfc5424', 'rfc3164', 'cef', 'leef', 'json'] as const
export type SiemFormat = (typeof SIEM_FORMATS)[number]
export const SIEM_SOURCES = ['audit', 'dns_queries', 'dns_blocked', 'alerts', 'deployments'] as const
export type SiemSource = (typeof SIEM_SOURCES)[number]

/** Événement normalisé : `severity` à l'échelle syslog (0 = urgence … 7 = débogage). `fields` ne contient que des chaînes ou des nombres. */
export interface SiemEvent {
  source: SiemSource | 'test'; id: number | null; at: Date; severity: number
  event: string                    // identifiant court de l'événement (ex. « audit.token_create », « dns.blocked »)
  message: string                  // phrase lisible
  fields: Record<string, string | number | null | undefined>
}
export interface Ctx { host: string; version: string; facility: number }

const clean = (v: unknown): string => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ')
const keyOf = (k: string): string => k.replace(/[^A-Za-z0-9_]/g, '_')
const defined = (f: SiemEvent['fields']): Array<[string, string | number]> => Object.entries(f).filter(([, v]) => v !== null && v !== undefined && v !== '') as Array<[string, string | number]>

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const pri = (c: Ctx, e: SiemEvent) => c.facility * 8 + Math.min(7, Math.max(0, e.severity))
const hostTok = (h: string) => (h.replace(/[^\x21-\x7e]/g, '') || '-').slice(0, 255)

export function rfc5424(e: SiemEvent, c: Ctx): string {
  const sd = defined(e.fields).map(([k, v]) => ` ${keyOf(k).slice(0, 32)}="${clean(v).replace(/[\\"\]]/g, '\\$&')}"`).join('')
  const msgid = keyOf(e.event).slice(0, 32) || '-'
  return `<${pri(c, e)}>1 ${e.at.toISOString()} ${hostTok(c.host)} ddibuntu - ${msgid} [ddibuntu@32473 source="${e.source}"${sd}] ${clean(e.message)}`
}

export function rfc3164(e: SiemEvent, c: Ctx): string {
  const d = e.at, day = String(d.getUTCDate()).padStart(2, ' '), t = d.toISOString().slice(11, 19)
  const kv = defined(e.fields).map(([k, v]) => `${keyOf(k)}=${/\s/.test(clean(v)) ? `"${clean(v).replace(/"/g, "'")}"` : clean(v)}`).join(' ')
  return `<${pri(c, e)}>${MON[d.getUTCMonth()]} ${day} ${t} ${hostTok(c.host)} ddibuntu: ${clean(e.message)}${kv ? ' ' + kv : ''}`
}

// CEF : sévérité 0-10 ; en-tête échappé (\ et |), extension échappée (\ et =) ; clés standard quand elles existent (src, suser, act, request…).
const cefHead = (s: string) => clean(s).replace(/[\\|]/g, '\\$&')
const cefExt = (s: unknown) => clean(s).replace(/[\\=]/g, '\\$&')
const CEF_SEV = [10, 10, 9, 7, 6, 4, 3, 1]
const CEF_KEYS: Record<string, string> = { client: 'src', user: 'suser', action: 'act', domain: 'request', ip: 'src', node: 'dvchost', outcome: 'outcome', reason: 'reason', category: 'cat', status: 'cs2', qtype: 'cs1', entity: 'cs3', entity_id: 'cs4', rule: 'cs5', subject: 'cs6', detail: 'msg' }
const CEF_LABELS: Record<string, string> = { cs1: 'queryType', cs2: 'status', cs3: 'entity', cs4: 'entityId', cs5: 'rule', cs6: 'subject' }
export function cef(e: SiemEvent, c: Ctx): string {
  const ext: string[] = [`rt=${e.at.getTime()}`, `dvchost=${cefExt(c.host)}`, `msg=${cefExt(e.message)}`, `cs7=${cefExt(e.source)}`, 'cs7Label=source']
  const seen = new Set<string>()
  for (const [k, v] of defined(e.fields)) {
    const ck = CEF_KEYS[k] ?? `cs8`   // champs sans équivalent : regroupés dans cs8 (« k=v »)
    if (ck === 'cs8') { ext.push(`flexString=${cefExt(`${k}=${v}`)}`); continue }
    if (seen.has(ck) || ['dvchost', 'msg'].includes(ck)) continue
    seen.add(ck); ext.push(`${ck}=${cefExt(v)}`)
    if (CEF_LABELS[ck]) ext.push(`${ck}Label=${CEF_LABELS[ck]}`)
  }
  return `CEF:0|DDI-Buntu|DDI-Buntu|${cefHead(c.version || '0')}|${cefHead(e.event)}|${cefHead(e.message).slice(0, 120)}|${CEF_SEV[Math.min(7, Math.max(0, e.severity))]}|${ext.join(' ')}`
}

// LEEF 2.0 : séparateur d'attributs explicite (« ^ », x5e) ; il est retiré des valeurs.
export function leef(e: SiemEvent, c: Ctx): string {
  const v = (x: unknown) => clean(x).replace(/\^/g, ' ')
  const attrs = [`devTime=${e.at.toISOString()}`, 'devTimeFormat=yyyy-MM-dd\'T\'HH:mm:ss.SSSX', `sev=${Math.min(7, Math.max(0, e.severity))}`, `identHostName=${v(c.host)}`, `msg=${v(e.message)}`, `source=${v(e.source)}`,
    ...defined(e.fields).map(([k, x]) => `${keyOf(k)}=${v(x)}`)]
  return `LEEF:2.0|DDI-Buntu|DDI-Buntu|${clean(c.version || '0').replace(/\|/g, ' ')}|${clean(e.event).replace(/\|/g, ' ')}|^|${attrs.join('^')}`
}

export function json(e: SiemEvent, c: Ctx): string {
  const o: Record<string, unknown> = { timestamp: e.at.toISOString(), host: c.host, app: 'ddibuntu', version: c.version, source: e.source, event: e.event, severity: e.severity, message: e.message }
  for (const [k, v] of defined(e.fields)) if (!(k in o)) o[k] = v
  return JSON.stringify(o)
}

export function formatEvent(f: SiemFormat, e: SiemEvent, c: Ctx): string {
  return f === 'rfc5424' ? rfc5424(e, c) : f === 'rfc3164' ? rfc3164(e, c) : f === 'cef' ? cef(e, c) : f === 'leef' ? leef(e, c) : json(e, c)
}

/** Transport flux TCP/TLS : un message par ligne, ou « comptage d'octets » (RFC 6587) pour les collecteurs qui l'exigent. */
export function frame(lines: string[], framing: 'newline' | 'octet'): Buffer {
  return Buffer.concat(lines.map((l) => (framing === 'octet' ? Buffer.from(`${Buffer.byteLength(l)} ${l}`) : Buffer.from(l + '\n'))))
}
