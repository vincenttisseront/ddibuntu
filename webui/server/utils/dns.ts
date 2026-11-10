// Enregistrements DNS : types pris en charge, validation et normalisation par type, rendu et analyse
// de fichiers de zone (BIND, export Windows « dnscmd /ZoneExport » compris).
import { ipToString, isValidDnsName, parseIp } from './net'

export const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'DNAME', 'MX', 'NS', 'PTR', 'TXT', 'SRV', 'CAA', 'NAPTR', 'SSHFP', 'TLSA', 'HTTPS', 'SVCB', 'HINFO', 'RP', 'DS'] as const
export type RecordType = (typeof RECORD_TYPES)[number]
export const isRecordType = (t: string): t is RecordType => (RECORD_TYPES as readonly string[]).includes(t)

export type R = { ok: true; value: string } | { ok: false; error: string }
const ok = (value: string): R => ({ ok: true, value })
const bad = (type: string, why = 'invalid'): R => ({ ok: false, error: `rdata_${why}:${type}` })
const int = (s: string | undefined, min: number, max: number): number | null => {
  if (s === undefined || !/^\d{1,10}$/.test(s)) return null
  const n = Number(s)
  return n >= min && n <= max ? n : null
}

export interface Tok { v: string; q: boolean }
/** Découpe en mots, en respectant les chaînes entre guillemets (échappements \" \\ et \DDD). */
export function tokenize(s: string): Tok[] | null {
  const out: Tok[] = []
  let i = 0
  while (i < s.length) {
    const ch = s[i]!
    if (/\s/.test(ch)) { i++; continue }
    if (ch === '"') {
      const bytes: number[] = []
      let closed = false
      i++
      while (i < s.length) {
        const c = s[i]!
        if (c === '\\') {
          const d = s.slice(i + 1, i + 4)
          if (/^\d{3}$/.test(d)) { bytes.push(Number(d) & 0xff); i += 4; continue }
          bytes.push(...Buffer.from(s[i + 1] ?? '')); i += 2; continue
        }
        if (c === '"') { closed = true; i++; break }
        bytes.push(...Buffer.from(c)); i++
      }
      if (!closed) return null
      out.push({ v: Buffer.from(bytes).toString('utf8'), q: true })
    } else {
      let v = ''
      while (i < s.length && !/\s/.test(s[i]!)) { v += s[i]; i++ }
      out.push({ v, q: false })
    }
  }
  return out
}
const quote = (s: string) => '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'
const asciiOnly = (s: string) => /^[\x20-\x7e]*$/.test(s)

/** Cible de nom : « @ », « . », étiquette relative (sans point) ou nom absolu (point final ajouté). */
export function normTarget(input: string): string | null {
  const t = input.trim().toLowerCase()
  if (t === '@' || t === '.') return t
  const name = t.endsWith('.') ? t.slice(0, -1) : t
  if (!isValidDnsName(name, false)) return null
  return name.includes('.') || t.endsWith('.') ? name + '.' : name
}

/** Nom d'enregistrement relatif à la zone (« @ » pour le sommet). null si hors zone ou invalide. */
export function toRelativeName(input: string, zone: string): string | null {
  const n = input.trim().toLowerCase()
  const z = zone.toLowerCase()
  if (n === '@' || n === '' || n === z || n === z + '.') return '@'
  let rel = n
  if (n.endsWith('.' + z + '.')) rel = n.slice(0, -(z.length + 2))
  else if (n.endsWith('.' + z)) rel = n.slice(0, -(z.length + 1))
  else if (n.endsWith('.')) return null
  return isValidDnsName(rel, true) ? rel : null
}

export function normalizeRdata(type: RecordType, input: string): R {
  const s = input.trim()
  if (!s) return bad(type, 'empty')
  switch (type) {
    case 'A': { const ip = parseIp(s); return ip && ip.v === 4 ? ok(ipToString(ip)) : bad(type) }
    case 'AAAA': { const ip = parseIp(s); return ip && ip.v === 6 ? ok(ipToString(ip)) : bad(type) }
    case 'CNAME': case 'DNAME': case 'NS': case 'PTR': {
      const t = normTarget(s)
      if (!t) return bad(type)
      if (type === 'NS' && parseIp(t.replace(/\.$/, ''))) return bad(type)
      return ok(t)
    }
    case 'MX': {
      const p = s.split(/\s+/)
      const pref = int(p[0], 0, 65535), t = p.length === 2 ? normTarget(p[1]!) : null
      return pref !== null && t ? ok(`${pref} ${t}`) : bad(type)
    }
    case 'TXT':
      if (/[\u0000-\u001f\u007f]/.test(s) || Buffer.byteLength(s) > 60000) return bad(type)
      return ok(s)
    case 'SRV': {
      const p = s.split(/\s+/)
      const a = [0, 1, 2].map((i) => int(p[i], 0, 65535)), t = p.length === 4 ? normTarget(p[3]!) : null
      return a.every((x) => x !== null) && t ? ok(`${a[0]} ${a[1]} ${a[2]} ${t}`) : bad(type)
    }
    case 'CAA': {
      const m = s.match(/^(\d+)\s+([A-Za-z0-9]{1,15})\s+(.+)$/s)
      if (!m) return bad(type)
      const flags = int(m[1], 0, 255)
      let value = m[3]!.trim()
      if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1).replace(/\\(["\\])/g, '$1')
      if (flags === null || !value || !asciiOnly(value)) return bad(type)
      return ok(`${flags} ${m[2]!.toLowerCase()} ${value}`)
    }
    case 'NAPTR': {
      const t = tokenize(s)
      if (!t || t.length !== 6) return bad(type)
      const order = int(t[0]!.v, 0, 65535), pref = int(t[1]!.v, 0, 65535), repl = normTarget(t[5]!.v)
      if (order === null || pref === null || !repl || ![2, 3, 4].every((i) => asciiOnly(t[i]!.v))) return bad(type)
      return ok(`${order} ${pref} ${quote(t[2]!.v)} ${quote(t[3]!.v)} ${quote(t[4]!.v)} ${repl}`)
    }
    case 'SSHFP': {
      const p = s.split(/\s+/)
      const alg = int(p[0], 1, 255), fpt = int(p[1], 1, 2), fp = (p[2] ?? '').toLowerCase()
      const len = fpt === 1 ? 40 : 64
      return p.length === 3 && alg !== null && fpt !== null && /^[0-9a-f]+$/.test(fp) && fp.length === len ? ok(`${alg} ${fpt} ${fp}`) : bad(type)
    }
    case 'TLSA': {
      const p = s.split(/\s+/)
      const u = int(p[0], 0, 3), se = int(p[1], 0, 1), m = int(p[2], 0, 2), d = (p[3] ?? '').toLowerCase()
      return p.length === 4 && u !== null && se !== null && m !== null && /^([0-9a-f]{2})+$/.test(d) ? ok(`${u} ${se} ${m} ${d}`) : bad(type)
    }
    case 'HTTPS': case 'SVCB': {
      const p = s.split(/\s+/)
      const prio = int(p[0], 0, 65535), t = p[1] ? normTarget(p[1]) : null
      const params = p.slice(2)
      if (prio === null || !t || !params.every((x) => /^[a-z0-9-]+(=[^\s"]+)?$/.test(x))) return bad(type)
      return ok([prio, t, ...params].join(' '))
    }
    case 'HINFO': {
      const t = tokenize(s)
      if (!t || t.length !== 2 || !t.every((x) => asciiOnly(x.v) && x.v.length <= 255)) return bad(type)
      return ok(`${quote(t[0]!.v)} ${quote(t[1]!.v)}`)
    }
    case 'RP': {
      const p = s.split(/\s+/)
      const a = p.length === 2 ? normTarget(p[0]!) : null, b = p.length === 2 ? normTarget(p[1]!) : null
      return a && b ? ok(`${a} ${b}`) : bad(type)
    }
    case 'DS': {
      const p = s.split(/\s+/)
      const tag = int(p[0], 0, 65535), alg = int(p[1], 0, 255), dt = int(p[2], 0, 255), d = (p[3] ?? '').toLowerCase()
      return p.length === 4 && tag !== null && alg !== null && dt !== null && /^([0-9a-f]{2})+$/.test(d) ? ok(`${tag} ${alg} ${dt} ${d}`) : bad(type)
    }
  }
}

/** Texte de la partie droite dans un fichier de zone. */
export function renderRdata(type: string, rdata: string): string {
  if (type === 'TXT') {
    const bytes = Buffer.from(rdata, 'utf8')
    const chunks: string[] = []
    for (let i = 0; i < Math.max(bytes.length, 1); i += 255) {
      let o = ''
      for (const b of bytes.subarray(i, i + 255)) o += b >= 0x20 && b < 0x7f && b !== 0x22 && b !== 0x5c ? String.fromCharCode(b) : '\\' + String(b).padStart(3, '0')
      chunks.push(`"${o}"`)
    }
    return chunks.join(' ')
  }
  if (type === 'CAA') {
    const m = rdata.match(/^(\d+)\s+(\S+)\s+(.*)$/s)!
    return `${m[1]} ${m[2]} ${quote(m[3]!)}`
  }
  return rdata
}

/** Règles de coexistence : un CNAME est seul à son nom et ne peut pas être au sommet de la zone. */
export function conflictError(existing: Array<{ id: number; name: string; type: string }>, cand: { name: string; type: string }, selfId?: number): string | null {
  const same = existing.filter((r) => r.id !== selfId && r.name.toLowerCase() === cand.name.toLowerCase())
  if (cand.type === 'CNAME') {
    if (cand.name === '@') return 'cname_apex'
    if (same.length) return 'cname_conflict'
  } else if (same.some((r) => r.type === 'CNAME')) return 'cname_conflict'
  return null
}

/** Enregistrements dont la modification peut casser un domaine Active Directory. */
export function isAdCritical(name: string, type: string): boolean {
  if (/(^|\.)(_msdcs|_sites|domaindnszones|forestdnszones)(\.|$)/i.test(name)) return true
  return type === 'SRV' && /^_(ldap|kerberos|kpasswd|gc)\./i.test(name)
}

// ---- Zone ----
export interface ZoneInfo {
  name: string; default_ttl: number; serial: number | string
  soa_mname: string | null; soa_rname: string | null
  soa_refresh: number; soa_retry: number; soa_expire: number; soa_minimum: number
}
export interface RecInfo { name: string; type: string; ttl: number | null; rdata: string; disabled?: boolean }

export function nextSerial(current: number, now = new Date()): number {
  const y = now.getUTCFullYear() * 10000 + (now.getUTCMonth() + 1) * 100 + now.getUTCDate()
  return Math.max(current + 1, y * 100)
}

export function renderZone(z: ZoneInfo, records: RecInfo[]): string {
  const mname = z.soa_mname ? (normTarget(z.soa_mname) ?? `ns1.${z.name}.`) : `ns1.${z.name}.`
  const rname = z.soa_rname ? (normTarget(z.soa_rname.replace('@', '.')) ?? `hostmaster.${z.name}.`) : `hostmaster.${z.name}.`
  const lines = [
    `$ORIGIN ${z.name}.`, `$TTL ${z.default_ttl}`,
    `@ IN SOA ${mname.endsWith('.') || mname === '@' ? mname : mname + '.' + z.name + '.'} ${rname.endsWith('.') ? rname : rname + '.' + z.name + '.'} ( ${z.serial} ${z.soa_refresh} ${z.soa_retry} ${z.soa_expire} ${z.soa_minimum} )`,
  ]
  const order = (r: RecInfo) => (r.name === '@' ? 0 : 1) + (r.type === 'NS' ? 0 : 0.5)
  for (const r of [...records].filter((x) => !x.disabled).sort((a, b) => order(a) - order(b) || a.name.localeCompare(b.name) || a.type.localeCompare(b.type))) {
    lines.push(`${r.name} ${r.ttl ?? ''} IN ${r.type} ${renderRdata(r.type, r.rdata)}`.replace(/ {2,}/, ' '))
  }
  return lines.join('\n') + '\n'
}

// ---- Analyse d'un fichier de zone ----
export interface ParsedRecord { name: string; type: RecordType; ttl: number | null; rdata: string; line: number }
export interface ParsedSoa { mname: string; rname: string; serial: number; refresh: number; retry: number; expire: number; minimum: number }
export interface Warn { line: number; code: string; detail?: string }
export interface ParsedZone { records: ParsedRecord[]; soa: ParsedSoa | null; warnings: Warn[]; skipped: number; defaultTtl: number | null }

export function parseTtl(s: string): number | null {
  if (/^\d+$/.test(s)) return Number(s)
  if (!/^(\d+[smhdw])+$/i.test(s)) return null
  const mult: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }
  let t = 0
  for (const m of s.matchAll(/(\d+)([smhdw])/gi)) t += Number(m[1]) * mult[m[2]!.toLowerCase()]!
  return t
}

/** Noms contenus dans la partie droite, par type : indices des jetons à rendre absolus. */
const NAME_FIELDS: Record<string, number[]> = { NS: [0], CNAME: [0], DNAME: [0], PTR: [0], MX: [1], SRV: [3], RP: [0, 1], NAPTR: [5], HTTPS: [1], SVCB: [1], SOA: [0, 1] }

export function parseZoneFile(text: string, zone: string): ParsedZone {
  const z = zone.toLowerCase().replace(/\.$/, '')
  const res: ParsedZone = { records: [], soa: null, warnings: [], skipped: 0, defaultTtl: null }
  let origin = z + '.'
  let lastOwner = '@'
  let defTtl: number | null = null
  const abs = (n: string): string => (n === '@' ? origin : n.endsWith('.') ? n : n + '.' + origin)

  // 1. lignes logiques : commentaires retirés, parenthèses jointes
  const logical: Array<{ text: string; line: number; indented: boolean }> = []
  let buf = '', depth = 0, startLine = 0, indented = false
  text.replace(/\r/g, '').split('\n').forEach((raw, idx) => {
    let out = '', inQ = false
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i]!
      if (c === '"' && raw[i - 1] !== '\\') inQ = !inQ
      if (!inQ && c === ';') break
      if (!inQ && c === '(') { depth++; out += ' '; continue }
      if (!inQ && c === ')') { depth = Math.max(0, depth - 1); out += ' '; continue }
      out += c
    }
    if (!buf) { startLine = idx + 1; indented = /^\s/.test(raw) }
    buf += ' ' + out
    if (depth === 0) {
      const t = buf.replace(/\[Aging:\d+\]/gi, ' ').trim()
      if (t) logical.push({ text: t, line: startLine, indented })
      buf = ''
    }
  })

  // 2. interprétation
  for (const l of logical) {
    const toks = tokenize(l.text)
    if (!toks || !toks.length) { res.warnings.push({ line: l.line, code: 'syntax' }); res.skipped++; continue }
    const first = toks[0]!.v
    if (first.startsWith('$')) {
      const d = first.toUpperCase()
      if (d === '$ORIGIN' && toks[1]) origin = toks[1].v.endsWith('.') ? toks[1].v.toLowerCase() : toks[1].v.toLowerCase() + '.' + origin
      else if (d === '$TTL' && toks[1]) { const t = parseTtl(toks[1].v); if (t !== null) { defTtl = t; res.defaultTtl = t } }
      else res.warnings.push({ line: l.line, code: 'unsupported_directive', detail: first })
      continue
    }
    let i = 0
    let owner = lastOwner
    if (!l.indented) { owner = toks[0]!.v.toLowerCase(); i = 1 }
    let ttl: number | null = null
    let type = ''
    while (i < toks.length) {
      const v = toks[i]!.v
      if (ttl === null && parseTtl(v) !== null && !/^[A-Za-z]+$/.test(v)) { ttl = parseTtl(v); i++; continue }
      if (/^(IN|CH|HS)$/i.test(v)) { if (v.toUpperCase() !== 'IN') { type = '#class'; break } i++; continue }
      type = v.toUpperCase(); i++; break
    }
    if (!type || type === '#class') { res.warnings.push({ line: l.line, code: 'syntax' }); res.skipped++; continue }
    lastOwner = owner
    const rd = toks.slice(i)
    const fields = NAME_FIELDS[type] ?? []
    const conv = rd.map((t, k) => (fields.includes(k) && !t.q && t.v !== '.' ? abs(t.v.toLowerCase()) : t.v))

    if (type === 'SOA') {
      if (conv.length >= 7) {
        const n = conv.slice(2, 7).map((x) => parseTtl(x))
        if (n.every((x) => x !== null)) res.soa = { mname: conv[0]!, rname: conv[1]!, serial: n[0]!, refresh: n[1]!, retry: n[2]!, expire: n[3]!, minimum: n[4]! }
      }
      continue
    }
    if (!isRecordType(type)) { res.warnings.push({ line: l.line, code: 'unsupported_type', detail: type }); res.skipped++; continue }

    // nom du propriétaire relatif à la zone
    const full = abs(owner).toLowerCase()
    let name: string
    if (full === z + '.') name = '@'
    else if (full.endsWith('.' + z + '.')) name = full.slice(0, -(z.length + 2))
    else { res.warnings.push({ line: l.line, code: 'out_of_zone', detail: owner }); res.skipped++; continue }
    if (name !== '@' && !isValidDnsName(name, true)) { res.warnings.push({ line: l.line, code: 'invalid_name', detail: name }); res.skipped++; continue }

    let norm: R
    if (type === 'TXT') norm = normalizeRdata('TXT', rd.map((t) => t.v).join(''))
    else if (['CAA', 'NAPTR', 'HINFO'].includes(type)) norm = normalizeRdata(type, rd.map((t, k) => (t.q ? quote(t.v) : conv[k]!)).join(' '))
    else norm = normalizeRdata(type, conv.join(' '))
    if (!norm.ok) { res.warnings.push({ line: l.line, code: norm.error }); res.skipped++; continue }
    res.records.push({ name, type, ttl: ttl ?? null, rdata: norm.value, line: l.line })
  }
  void defTtl
  // doublons exacts
  const seen = new Set<string>()
  res.records = res.records.filter((r) => { const k = `${r.name}|${r.type}|${r.rdata}`; if (seen.has(k)) return false; seen.add(k); return true })
  return res
}
