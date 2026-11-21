// Certificat HTTPS de la console, automatique et identique sur tous les nœuds (0.21.0).
//
// Le leader fait émettre par la PKI du DDI un certificat dont le SAN couvre tous les noms sous lesquels la console est jointe (nom virtuel du cluster, nœuds, IP),
// le renouvelle avant l'échéance ou quand les noms changent, et le range en base (clé chiffrée) : la base est répliquée, tous les nœuds le voient.
// Chaque nœud le dépose dans un dossier que la console peut écrire, puis se relance ; « console-start » l'utilise s'il est valide, sinon il garde le
// certificat auto-signé de l'installation. Les décisions sont des fonctions pures ; les effets (base, PKI, disque, redémarrage) sont injectés.
import { createPrivateKey, X509Certificate } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'
import { DNS_RE, SAN_MAX } from './pki-certs'
import { ipToString, parseIp } from './net'

export const TLS_KEY = 'console_tls'
export const RENEW_DAYS = 30
export const RETRY_AFTER_FAILURE_S = 900
export const FILE_CRT = 'console.crt'
export const FILE_KEY = 'console.key'
export const FILE_MARK = '.installed'

export interface TlsCert { pem: string; chain: string; keyEnc: string; serial: string; notAfter: number; dns: string[]; ip: string[]; at: number }
export interface TlsResult { at: number; ok: boolean; message: string }
export interface TlsState { auto: boolean; ca: string; names: string[]; cert: TlsCert | null; last: TlsResult | null }
export const EMPTY_TLS: TlsState = { auto: false, ca: '', names: [], cert: null, last: null }

export const tlsBody = z.object({
  auto: z.boolean(),
  ca: z.string().trim().max(80),
  names: z.array(z.string().trim().toLowerCase().regex(DNS_RE)).max(SAN_MAX.dns),
}).strict()

const isStr = (v: unknown): v is string => typeof v === 'string'
const strList = (v: unknown, max: number) => (Array.isArray(v) ? v.filter(isStr).map((s) => s.slice(0, 253)).slice(0, max) : [])

/** Lit l'état enregistré : tout ce qui est illisible est ignoré (jamais d'exception pour une valeur abîmée). */
export function parseTls(raw: unknown): TlsState {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, any>
  const c = r.cert
  const cert: TlsCert | null = c && isStr(c.pem) && isStr(c.chain) && isStr(c.keyEnc) && typeof c.notAfter === 'number'
    ? { pem: c.pem, chain: c.chain, keyEnc: c.keyEnc, serial: isStr(c.serial) ? c.serial.slice(0, 64) : '', notAfter: c.notAfter, dns: strList(c.dns, 16), ip: strList(c.ip, 8), at: typeof c.at === 'number' ? c.at : 0 }
    : null
  const l = r.last
  return {
    auto: r.auto === true, ca: isStr(r.ca) ? r.ca.slice(0, 80) : '', names: strList(r.names, SAN_MAX.dns), cert,
    last: l && typeof l.at === 'number' ? { at: l.at, ok: l.ok === true, message: isStr(l.message) ? l.message.slice(0, 300) : '' } : null,
  }
}

export interface NodeLite { name: string; ip: string; host?: string }
export interface Wanted { dns: string[]; ip: string[]; truncated: boolean }
const uniq = <T>(a: T[]) => [...new Set(a)]

/** Noms et adresses à couvrir : ceux de l'administrateur d'abord (nom virtuel du cluster), puis le nom de la console vue des postes, puis chaque nœud (nom et hôte) ; adresses : virtuelle puis nœuds. */
export function wantedNames(state: Pick<TlsState, 'names'>, enrollHost: string, nodes: NodeLite[], vip: string | null): Wanted {
  const dnsAll = uniq([...state.names, enrollHost, ...nodes.flatMap((n) => [n.host ?? '', n.name])].map((s) => s.trim().toLowerCase()).filter((s) => s && DNS_RE.test(s)))
  const ipAll = uniq([vip ?? '', ...nodes.map((n) => n.ip)].map((s) => { const p = s ? parseIp(s) : null; return p ? ipToString(p) : '' }).filter(Boolean))
  return { dns: dnsAll.slice(0, SAN_MAX.dns), ip: ipAll.slice(0, SAN_MAX.ip), truncated: dnsAll.length > SAN_MAX.dns || ipAll.length > SAN_MAX.ip }
}

/** Noms DNS et IP du SAN d'un certificat (PEM). */
export function certNames(pem: string): { dns: string[]; ip: string[]; selfSigned: boolean; notAfter: number; subject: string; fingerprint: string } | null {
  try {
    const x = new X509Certificate(pem)
    const dns: string[] = [], ip: string[] = []
    for (const part of (x.subjectAltName ?? '').split(/,\s*/)) {
      const m = /^(DNS|IP Address):(.*)$/.exec(part.trim())
      if (!m) continue
      if (m[1] === 'DNS') dns.push(m[2]!.toLowerCase())
      else { const p = parseIp(m[2]!); if (p) ip.push(ipToString(p)) }
    }
    return { dns, ip, selfSigned: x.subject === x.issuer, notAfter: Date.parse(x.validTo), subject: x.subject.replace(/\n/g, ', ').slice(0, 200), fingerprint: x.fingerprint256.replace(/:/g, '').toLowerCase() }
  } catch { return null }
}

export type IssueDecision = { act: false; reason: 'disabled' | 'no_ca' | 'current' | 'wait' | 'no_names' } | { act: true; reason: 'first' | 'names' | 'expiry' }

/** Faut-il (re)faire émettre un certificat ? Seulement le leader appelle ceci. */
export function issueDecision(state: TlsState, want: Wanted, now: number): IssueDecision {
  if (!state.auto) return { act: false, reason: 'disabled' }
  if (!state.ca) return { act: false, reason: 'no_ca' }
  if (want.dns.length === 0) return { act: false, reason: 'no_names' }
  const reason = !state.cert ? 'first'
    : (want.dns.some((d) => !state.cert!.dns.includes(d)) || want.ip.some((i) => !state.cert!.ip.includes(i))) ? 'names'
    : (state.cert.notAfter - now * 1000 < RENEW_DAYS * 86_400_000) ? 'expiry' : null
  if (!reason) return { act: false, reason: 'current' }
  if (state.last && !state.last.ok && now - state.last.at < RETRY_AFTER_FAILURE_S) return { act: false, reason: 'wait' }
  return { act: true, reason }
}

export const fingerprintOf = (pem: string): string | null => certNames(pem)?.fingerprint ?? null
/** Premier certificat d'un texte PEM (le certificat de la console est « feuille + chaîne »). */
export function firstCert(pem: string): string {
  const a = pem.indexOf('-----BEGIN CERTIFICATE-----'), b = pem.indexOf('-----END CERTIFICATE-----', a)
  return a >= 0 && b > a ? pem.slice(a, b + 25) + '\n' : ''
}

export type InstallDecision = 'none' | 'current' | 'install' | 'invalid'
/** Ce nœud sert-il déjà le certificat de la base ? Un certificat expiré ou dont les noms ne couvrent rien n'est jamais installé. */
export function installDecision(state: TlsState, servedPem: string, now: number): InstallDecision {
  if (!state.cert) return 'none'
  const want = certNames(state.cert.pem)
  if (!want || want.notAfter <= now * 1000) return 'invalid'
  const served = fingerprintOf(firstCert(servedPem))
  return served && served === want.fingerprint ? 'current' : 'install'
}

export interface Deps {
  now: () => number
  inRecovery: () => Promise<boolean>
  load: () => Promise<TlsState>
  save: (s: TlsState) => Promise<void>
  cluster: () => Promise<{ nodes: NodeLite[]; vip: string | null } | null>
  enrollHost: () => Promise<string>
  issue: (ca: string, cn: string, dns: string[], ip: string[]) => Promise<{ certPem: string; chainPem: string; keyPem: string; serial: string }>
  encrypt: (s: string) => string
  decrypt: (s: string) => string
  servedPem: () => string
  dir: string
  /** Relance du processus pour servir le nouveau certificat (la console redémarre sous systemd). */
  restart: () => void
  log: (m: string) => void
}

/** Émet (ou renouvelle) et enregistre. Rend le nouvel état ; en cas d'échec, mémorise le motif pour la prochaine tentative (délai) et l'écran. */
export async function issueAndSave(d: Deps, state: TlsState, want: Wanted): Promise<TlsState> {
  const now = d.now()
  try {
    const x = await d.issue(state.ca, want.dns[0]!, want.dns, want.ip)
    const c = certNames(x.certPem)
    if (!c) throw new Error('certificat reçu illisible')
    const cert = new X509Certificate(x.certPem)
    if (!cert.checkPrivateKey(createPrivateKey(x.keyPem))) throw new Error('le certificat reçu ne correspond pas à la clé')
    const next: TlsState = { ...state, cert: { pem: x.certPem, chain: x.chainPem, keyEnc: d.encrypt(x.keyPem), serial: x.serial, notAfter: c.notAfter, dns: c.dns, ip: c.ip, at: now }, last: { at: now, ok: true, message: '' } }
    await d.save(next)
    d.log(`certificat HTTPS de la console émis (série ${x.serial}, ${c.dns.length} nom(s))`)
    return next
  } catch (e: any) {
    const next: TlsState = { ...state, last: { at: now, ok: false, message: String(e?.message ?? e).slice(0, 300) } }
    await d.save(next).catch(() => undefined)
    d.log(`émission du certificat HTTPS de la console impossible : ${next.last!.message}`)
    return next
  }
}

/** Dépose le certificat de la base dans le dossier du nœud (clé 0600, écriture atomique). La clé est vérifiée contre le certificat avant tout dépôt. */
export async function writeFiles(d: Pick<Deps, 'dir' | 'decrypt'>, cert: TlsCert): Promise<void> {
  const keyPem = d.decrypt(cert.keyEnc)
  if (!new X509Certificate(firstCert(cert.pem)).checkPrivateKey(createPrivateKey(keyPem))) throw new Error('clé et certificat ne correspondent pas')
  await fs.mkdir(d.dir, { recursive: true, mode: 0o700 })
  const put = async (name: string, text: string, mode: number) => {
    const tmp = join(d.dir, `.${name}.${process.pid}`)
    await fs.writeFile(tmp, text, { mode }); await fs.rename(tmp, join(d.dir, name))
  }
  await put(FILE_KEY, keyPem, 0o600)
  await put(FILE_CRT, cert.pem.trim() + '\n' + cert.chain.trim() + '\n', 0o644)
  await put(FILE_MARK, (fingerprintOf(firstCert(cert.pem)) ?? '') + '\n', 0o600)
}

/** Empreinte du certificat déjà déposé sur ce nœud (marque écrite avec les fichiers). */
export async function installedMark(dir: string): Promise<string> {
  try { return (await fs.readFile(join(dir, FILE_MARK), 'utf8')).trim() } catch { return '' }
}

let busy = false
/** Une passe : le leader émet si besoin ; tous les nœuds installent le certificat de la base s'ils ne le servent pas encore. Rend un mot court (journal, tests). */
export async function consoleTlsTick(d: Deps): Promise<string> {
  if (busy) return 'busy'
  busy = true
  try {
    const leader = !(await d.inRecovery())
    let state = await d.load()
    if (leader) {
      const cl = await d.cluster()
      const want = wantedNames(state, await d.enrollHost(), cl?.nodes ?? [], cl?.vip ?? null)
      const dec = issueDecision(state, want, d.now())
      if (dec.act) state = await issueAndSave(d, state, want)
    }
    const act = installDecision(state, d.servedPem(), d.now())
    if (act !== 'install') return act
    // déjà déposé mais pas servi : « console-start » l'a refusé (clé qui ne correspond pas, échéance proche) ; relancer en boucle n'y changerait rien
    if ((await installedMark(d.dir)) === fingerprintOf(firstCert(state.cert!.pem))) { d.log('le certificat HTTPS de la console est déposé mais non servi (refusé au démarrage) : pas de nouvelle relance'); return 'refused' }
    await writeFiles(d, state.cert!)
    d.log('certificat HTTPS de la console déposé : relance pour le servir')
    d.restart()
    return 'installed'
  } catch (e: any) {
    d.log(`certificat HTTPS de la console : ${e?.message ?? e}`)
    return 'error'
  } finally { busy = false }
}
