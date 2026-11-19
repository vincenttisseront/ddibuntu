// Journal des authentifications RADIUS de CE nœud (0.14.18) : lecture du fichier écrit par FreeRADIUS (linelog, voir ddibuntu-radius) et des
// lignes utiles du journal technique (équipement inconnu, alertes TLS envoyées par le poste). Aucune base de données : le fichier est la source,
// la console le lit en lecture seule (groupe ddiconsole) et ne garde en mémoire que le résultat du dernier fichier lu.
import { promises as fs } from 'node:fs'
import type { FileHandle } from 'node:fs/promises'
import path from 'node:path'
import { cfg } from './config'

export type JournalKind = 'accept' | 'reject' | 'diag'
export interface JournalEvent {
  at: number                       // ms depuis 1970
  kind: JournalKind
  user: string                     // nom présenté par le poste (identité externe EAP)
  client: string                   // équipement (nom du client RADIUS) ; vide pour une alerte d'équipement inconnu
  nas: string                      // adresse de l'équipement
  mac: string                      // Calling-Station-Id (MAC du poste)
  called: string                   // Called-Station-Id (MAC de la borne:SSID)
  nasId: string
  subject: string; issuer: string; serial: string; expires: string   // certificat présenté
  upn: string; dns: string         // identités portées par le certificat
  identity: string                 // identité retenue : « user:… » ou « computer:… »
  decision: string                 // règle qui a accepté (« regle N : nom »)
  reason: string                   // texte brut du refus (ou de la ligne de diagnostic)
  why: string                      // motif classé (clé i18n radius.journal.why_*) ; « ok » pour une acceptation
  selftest: boolean                // requête de l'onglet « Tester une requête » de la console
}

const FIELDS = 18
const MAX_VAL = 300
/** Décode les valeurs de %{escape:} : « =XX » est un octet hexadécimal (UTF-8) ; les caractères de contrôle sont neutralisés. */
export function decodeVal(s: string): string {
  const d = s.replace(/(?:=[0-9A-Fa-f]{2})+/g, (m) => Buffer.from(m.replace(/=/g, ''), 'hex').toString('utf8'))
  // eslint-disable-next-line no-control-regex
  return d.replace(/[\u0000-\u001f\u007f]/g, '·').slice(0, MAX_VAL)
}

/** Classe le texte d'un refus (ou d'une alerte TLS) dans un motif connu de l'interface. */
export function classify(reason: string): string {
  const r = reason.toLowerCase()
  if (!r) return 'unknown'
  if (r.includes('certificate revoked')) return 'revoked'
  if (r.includes('certificate has expired') || r.includes('certificate is not yet valid')) return 'cert_expired'
  if (r.includes('unable to get local issuer') || r.includes('unknown ca') || r.includes('self signed') || r.includes('self-signed')) return 'unknown_ca'
  if (r.includes('unsuitable certificate purpose') || r.includes('unsupported certificate')) return 'purpose'
  if (r.includes('certificate unknown') || r.includes('bad certificate')) return 'cert_refused'
  if (r.includes('handshake failure') || r.includes('no certificate') || r.includes('peer did not return a certificate')) return 'no_cert'
  if (r.includes('protocol version')) return 'tls_version'
  if (r.includes('no mutually acceptable types') || r.includes('peer nak')) return 'eap_method'   // le poste propose une autre méthode que EAP-TLS (PEAP-MSCHAPv2, EAP-TTLS…)
  if (r.includes('sans identite')) return 'no_identity'
  if (r.includes('identite du certificat vide')) return 'no_identity'
  if (r.includes('compte introuvable')) return 'account_missing'
  if (r.includes('compte desactive')) return 'account_disabled'
  if (r.includes('compte verrouille')) return 'account_locked'
  if (r.includes('compte expire')) return 'account_expired'
  if (r.includes('annuaire indisponible') || r.includes('attributs du compte')) return 'directory_down'
  if (/regle \d+ : refus/.test(r)) return 'rule_deny'
  if (r.includes('aucune regle')) return 'no_rule'
  if (r.includes('unknown client') || r.includes('equipement inconnu')) return 'unknown_client'
  if (r.includes('identifiant non pris en charge')) return 'identity_unsupported'
  if (r.includes('domaine inconnu')) return 'domain_unknown'
  if (r.includes('nom netbios')) return 'netbios_missing'
  if (r.includes('wrong_password') || r.includes('password is incorrect') || r.includes('invalid credentials') || r.includes('bind as user failed') || r.includes('logon failure')) return 'bad_password'
  return 'other'
}

/** Une ligne du journal d'authentifications (format « v1 », 18 champs séparés par « | ») ; null si elle n'a pas ce format. */
export function parseAuthLine(line: string): JournalEvent | null {
  const p = line.replace(/\r?\n$/, '').split('|')
  if (p.length !== FIELDS || p[0] !== 'v1') return null
  const secs = Number(p[1])
  if (!Number.isFinite(secs) || secs <= 0) return null
  if (p[2] !== 'accept' && p[2] !== 'reject') return null
  const v = p.map(decodeVal)
  const e: JournalEvent = {
    at: Math.round(secs * 1000), kind: p[2], user: v[3]!, client: v[4]!, nas: v[5]!, mac: v[6]!, called: v[7]!, nasId: v[8]!,
    subject: v[9]!, issuer: v[10]!, serial: v[11]!, expires: v[12]!, upn: v[13]!, dns: v[14]!, identity: v[15]!, decision: v[16]!, reason: v[17]!,
    why: p[2] === 'accept' ? 'ok' : classify(v[17]!), selftest: v[4] === 'ddi-selftest',
  }
  return e
}

const empty = (at: number, why: string, reason: string, extra: Partial<JournalEvent> = {}): JournalEvent => ({
  at, kind: 'diag', user: '', client: '', nas: '', mac: '', called: '', nasId: '', subject: '', issuer: '', serial: '', expires: '', upn: '', dns: '', identity: '', decision: '',
  reason: decodeVal(reason), why, selftest: false, ...extra,
})
const LOGLINE = /^(\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) : (\w+): (.*)$/
/** Lignes utiles du journal technique de FreeRADIUS : équipement inconnu (paquet ignoré) et alertes TLS envoyées par le poste ; null pour les autres. */
export function parseTechLine(line: string): JournalEvent | null {
  const m = LOGLINE.exec(line.replace(/\r?\n$/, ''))
  if (!m) return null
  const at = Date.parse(m[1]!)
  if (!Number.isFinite(at)) return null
  const body = m[3]!
  const u = /from unknown client (\S+) port (\d+)/.exec(body)
  if (u) return empty(at, 'unknown_client', body, { nas: decodeVal(u[1]!) })
  // la ligne « Login incorrect (… Alert read:… ): [poste] » reprend la même alerte : seule la ligne d'erreur du démon compte (le texte finit après l'alerte)
  const a = /Alert (read|write):(fatal|warning):([A-Za-z0-9 _-]+)\s*$/i.exec(body)
  if (a && a[1]!.toLowerCase() === 'read') return empty(at, classify(a[3]!) === 'other' ? 'tls_alert' : classify(a[3]!), a[3]!.trim())
  return null
}

interface Cached { key: string; events: JournalEvent[]; truncated: boolean }
const cache = new Map<string, Cached>()

/** Fin d'un fichier : au plus `max` octets, sans la première ligne si elle est coupée. null si le fichier est absent ou illisible. */
async function tail(file: string, max: number): Promise<{ text: string; key: string; truncated: boolean } | null> {
  let h: FileHandle | undefined
  try {
    h = await fs.open(file, 'r')
    const st = await h.stat()
    const key = `${st.mtimeMs}:${st.size}:${st.ino}`
    const start = Math.max(0, st.size - max)
    const buf = Buffer.alloc(st.size - start)
    const got = buf.length ? (await h.read(buf, 0, buf.length, start)).bytesRead : 0
    let text = buf.subarray(0, got).toString('utf8')   // si le fichier a été tronqué pendant la lecture : pas d'octets nuls en fin
    if (start > 0) { const i = text.indexOf('\n'); text = i < 0 ? '' : text.slice(i + 1) }
    return { text, key, truncated: start > 0 }
  } catch { return null } finally { await h?.close().catch(() => undefined) }
}

async function load(name: string, max: number, parse: (l: string) => JournalEvent | null): Promise<Cached | null> {
  const file = path.join(cfg().radiusAuthLogDir, name)
  const t = await tail(file, max)
  if (!t) return null
  const hit = cache.get(file)
  if (hit && hit.key === t.key) return hit
  const events: JournalEvent[] = []
  for (const l of t.text.split('\n')) { if (!l) continue; const e = parse(l); if (e) events.push(e) }
  const c = { key: t.key, events, truncated: t.truncated }
  cache.set(file, c)
  return c
}

export interface JournalQuery { kind?: JournalKind; q?: string; since?: number; limit: number; selftest?: boolean }
export interface JournalResult {
  available: boolean                 // le fichier d'authentifications existe et est lisible
  events: JournalEvent[]
  counts: { accept: number; reject: number; diag: number; since: number }   // sur 24 h, hors tests de la console
  reasons: { why: string; n: number }[]                                       // refus des 24 h par motif, du plus fréquent au plus rare
  truncated: boolean                 // le fichier est plus long que la fenêtre lue
  oldest: number | null              // heure du plus ancien événement lu
}

const DAY = 24 * 3600_000
const hay = (e: JournalEvent) => [e.user, e.client, e.nas, e.mac, e.called, e.nasId, e.subject, e.issuer, e.serial, e.upn, e.dns, e.identity, e.decision, e.reason, e.why].join('\n').toLowerCase()

export async function readJournal(q: JournalQuery, now = Date.now()): Promise<JournalResult> {
  const auth = await load('radius-auth.log', cfg().radiusAuthLogMaxBytes, parseAuthLine)
  const tech = await load('radius.log', 2_000_000, parseTechLine)
  const all = [...(auth?.events ?? []), ...(tech?.events ?? [])].sort((a, b) => b.at - a.at)
  const counts = { accept: 0, reject: 0, diag: 0, since: now - DAY }
  const why = new Map<string, number>()
  for (const e of all) {
    if (e.at < now - DAY || e.selftest) continue
    counts[e.kind]++
    if (e.kind === 'reject') why.set(e.why, (why.get(e.why) ?? 0) + 1)
  }
  const needle = q.q?.trim().toLowerCase()
  const events = all.filter((e) => (q.selftest || !e.selftest) && (!q.kind || e.kind === q.kind) && (q.since === undefined || e.at >= q.since) && (!needle || hay(e).includes(needle))).slice(0, q.limit)
  return {
    available: auth !== null, events, counts,
    reasons: [...why].map(([w, n]) => ({ why: w, n })).sort((a, b) => b.n - a.n),
    truncated: auth?.truncated ?? false, oldest: all.length ? all[all.length - 1]!.at : null,
  }
}
