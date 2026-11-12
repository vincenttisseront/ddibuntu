// Générateurs de configuration : BIND (options, zones, RPZ) et Kea DHCPv4, avec validation par les
// binaires réels (named-checkzone, named-checkconf, kea-dhcp4 -t) avant tout déploiement.
import { execFile } from 'node:child_process'
import { promises as fs } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'
import { cfg } from './config'
import { renderZone } from './dns'
import type { RecInfo, ZoneInfo } from './dns'
import { isValidDnsName } from './net'
import type { ViewInfo } from './views'

export const ZONES_DIR = '@ZONESDIR@'

export interface DnsSettings {
  listenOn: string[]; allowRecursion: string[]; allowQuery: string[]; forwarders: string[]
  dnssecValidation: 'auto' | 'no'; queryLog: boolean; ddnsKeyFile: string
  rpzEnabled: boolean; rpzZone: string; rpzAction: 'nxdomain' | 'nodata' | 'sinkhole'; sinkhole4: string; sinkhole6: string
  /** Limitation de débit des réponses (RRL) : désactivée par défaut ; « log-only » journalise sans rien bloquer (essai à blanc). */
  rrlEnabled: boolean; rrlResponsesPerSecond: number; rrlWindow: number; rrlSlip: number; rrlLogOnly: boolean; rrlExempt: string[]
  /** Domaine Kerberos configuré par root (ddibuntu-ad) : jamais saisi ici, relu de son état publié. Vide = aucune mise à jour sécurisée possible. */
  kerberosRealm?: string
}
export const DNS_DEFAULTS: DnsSettings = {
  listenOn: [], allowRecursion: ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], allowQuery: [], forwarders: [],
  dnssecValidation: 'auto', queryLog: true, ddnsKeyFile: '/etc/bind/ddi-ddns.key',
  rpzEnabled: false, rpzZone: 'rpz.ddibuntu.local', rpzAction: 'nxdomain', sinkhole4: '0.0.0.0', sinkhole6: '::',
  rrlEnabled: false, rrlResponsesPerSecond: 20, rrlWindow: 15, rrlSlip: 2, rrlLogOnly: true, rrlExempt: ['127.0.0.0/8', '::1'],
}
const acl = (l: string[], fallback = 'any') => (l.length ? l.map((x) => `${x};`).join(' ') : `${fallback};`)

export interface ZoneRow extends ZoneInfo {
  type: 'primary' | 'secondary' | 'forward'; masters: string[]; forwarders: string[]; allow_transfer: string[]
  ddns_enabled: boolean; disabled: boolean; ddns_secure?: 'ms-self' | 'krb5-self' | 'both' | null
  /** Nom de la vue (null = pas de vue : tant qu'aucune vue n'existe, la configuration est celle d'avant les vues). */
  view?: string | null
}

export function renderNamedOptions(s: DnsSettings, anyDdns: boolean): string {
  const l = [
    '// Généré par DDI-Buntu — ne pas modifier à la main.',
    anyDdns ? `include "${s.ddnsKeyFile}";` : '',
    'options {',
    '  directory "/var/cache/bind";',
    `  listen-on { ${acl(s.listenOn)} };`,
    `  listen-on-v6 { any; };`,
    '  recursion yes;',
    `  allow-recursion { ${acl(s.allowRecursion, 'none')} };`,
    `  allow-query { ${acl(s.allowQuery)} };`,
    // BIND autorise par défaut le transfert de zone à tout le monde : refusé partout, sauf liste explicite par zone (et clé TSIG du cluster, ajoutée par root)
    '  allow-transfer { none; };',
    s.forwarders.length ? `  forwarders { ${acl(s.forwarders)} };` : '',
    `  dnssec-validation ${s.dnssecValidation};`,
    '  check-names primary warn;',
    // sans « querylog yes », BIND n'écrit AUCUNE requête dans le canal de journalisation déclaré plus bas
    s.queryLog ? '  querylog yes;' : '  querylog no;',
    // une seule ligne : ddibuntu-reload (et la transformation du secondaire) relisent ce fichier ligne à ligne
    s.rrlEnabled ? `  rate-limit { responses-per-second ${s.rrlResponsesPerSecond}; window ${s.rrlWindow}; slip ${s.rrlSlip}; log-only ${s.rrlLogOnly ? 'yes' : 'no'};${s.rrlExempt.length ? ` exempt-clients { ${acl(s.rrlExempt)} };` : ''} };` : '',
    s.rpzEnabled ? `  response-policy { zone "${s.rpzZone}" policy given; } qname-wait-recurse no;` : '',
    '};',
    s.queryLog ? 'logging {\n  channel ddi_queries { file "/var/log/named/query.log" versions 3 size 50m; severity info; print-time iso8601-utc; };\n  category queries { ddi_queries; };\n  category rpz { ddi_queries; };\n  category rpz-passthru { ddi_queries; };\n};' : '',
  ]
  return l.filter(Boolean).join('\n') + '\n'
}

/** Octrois « update-policy » d'une zone : la clé DDNS (si activée) et, quand root a configuré un domaine Kerberos, les mises à jour sécurisées des clients. */
export function secureGrants(z: Pick<ZoneRow, 'ddns_enabled' | 'ddns_secure'>, realm: string): string[] {
  if (!z.ddns_secure || !/^[A-Z0-9]([A-Z0-9.-]{0,60}[A-Z0-9])?$/.test(realm)) return []
  const g: string[] = []
  if (z.ddns_enabled) g.push('grant ddi-ddns zonesub ANY')
  if (z.ddns_secure === 'ms-self' || z.ddns_secure === 'both') g.push(`grant ${realm} ms-self . A AAAA`)
  if (z.ddns_secure === 'krb5-self' || z.ddns_secure === 'both') g.push(`grant ${realm} krb5-self . A AAAA`)
  return g
}

/** Nom du fichier de zone : « db.<zone> » sans vue ; « db.<vue>.<zone> » avec vues (une même zone peut exister dans plusieurs vues ; un nom de vue ne contient pas de point). */
export const zoneBase = (z: Pick<ZoneRow, 'name' | 'view'>): string => `db.${z.view ? z.view + '.' : ''}${z.name.replace(/\.$/, '')}`

/** Fichier de la zone de politique de réponse : « db.rpz » sans vue, « db.rpz-<vue> » avec vues. */
export const rpzBase = (view?: string): string => (view ? `db.rpz-${view}` : 'db.rpz')

function zoneStatement(z: ZoneRow, s: DnsSettings): string | null {
  if (z.disabled) return null
  const n = z.name.replace(/\.$/, '')
  if (!isValidDnsName(n, false) && !/^[a-z0-9_-]+$/i.test(n)) return null
  const file = `${ZONES_DIR}/${zoneBase(z)}`
  if (z.type === 'primary') {
    const props = [`type primary;`, `file "${file}";`, 'notify yes;']
    if (z.allow_transfer.length) props.push(`allow-transfer { ${acl(z.allow_transfer)} };`)
    const grants = secureGrants(z, s.kerberosRealm ?? '')
    // « allow-update » et « update-policy » s'excluent dans BIND : la clé DDNS (Kea) devient alors un octroi de la politique
    if (grants.length) props.push(`update-policy { ${grants.join('; ')}; };`)
    else if (z.ddns_enabled) props.push('allow-update { key "ddi-ddns"; };')
    return `zone "${n}" { ${props.join(' ')} };`
  }
  if (z.type === 'secondary') return `zone "${n}" { type secondary; primaries { ${acl(z.masters)} }; file "${file}"; };`
  return `zone "${n}" { type forward; forward only; forwarders { ${acl(z.forwarders)} }; };`
}

/**
 * Sans vue : une zone par ligne. Avec vues : chaque vue ouvre un bloc dont l'en-tête tient sur des lignes de forme fixe (ddibuntu-reload les relit
 * ligne à ligne pour dériver le secondaire), les zones restent une par ligne, à la marge, et le bloc se ferme par « }; ».
 */
export function renderNamedZones(zones: ZoneRow[], s: DnsSettings, views: ViewInfo[] = []): string {
  const out: string[] = ['// Généré par DDI-Buntu — ne pas modifier à la main.']
  const rpzFor = (view?: string) => (s.rpzEnabled ? `zone "${s.rpzZone}" { type primary; file "${ZONES_DIR}/${rpzBase(view)}"; allow-query { none; }; };` : '')
  if (!views.length) {
    for (const z of zones) { const l = zoneStatement(z, s); if (l) out.push(l) }
    if (s.rpzEnabled) out.push(rpzFor())
    return out.join('\n') + '\n'
  }
  for (const v of [...views].sort((a, b) => a.position - b.position)) {
    out.push(`view "${v.name}" {`, `  match-clients { ${acl(v.match_clients, 'none')} };`)
    if (v.match_destinations.length) out.push(`  match-destinations { ${acl(v.match_destinations)} };`)
    // « recursion no » avec le « allow-recursion » global donne un avertissement de BIND : la liste est vidée pour cette vue
    out.push(v.recursion ? '  recursion yes;' : '  recursion no;', ...(v.recursion ? [] : ['  allow-recursion { none; };']))
    for (const z of zones) if (z.view === v.name) { const l = zoneStatement(z, s); if (l) out.push(l) }
    // la zone de politique de réponse (filtrage) doit exister dans CHAQUE vue ; un fichier par vue (le secondaire ne peut pas écrire deux zones dans le même fichier)
    if (s.rpzEnabled) out.push(rpzFor(v.name))
    out.push('};')
  }
  return out.join('\n') + '\n'
}

export function renderRpz(opts: { zone: string; serial: number; action: 'nxdomain' | 'nodata' | 'sinkhole'; sinkhole4?: string; sinkhole6?: string }, blocked: Iterable<string>, allowed: Iterable<string>): string {
  const allow = new Set(allowed)
  const lines = [`$ORIGIN ${opts.zone}.`, '$TTL 300', `@ IN SOA localhost. root.localhost. ( ${opts.serial} 3600 600 86400 300 )`, '@ IN NS localhost.']
  const target = (d: string) => {
    if (opts.action === 'sinkhole') return [`${d} IN A ${opts.sinkhole4 ?? '0.0.0.0'}`, `*.${d} IN A ${opts.sinkhole4 ?? '0.0.0.0'}`, `${d} IN AAAA ${opts.sinkhole6 ?? '::'}`, `*.${d} IN AAAA ${opts.sinkhole6 ?? '::'}`]
    const rhs = opts.action === 'nodata' ? '*.' : '.'
    return [`${d} IN CNAME ${rhs}`, `*.${d} IN CNAME ${rhs}`]
  }
  for (const d of allow) lines.push(`${d} IN CNAME rpz-passthru.`, `*.${d} IN CNAME rpz-passthru.`)
  for (const d of blocked) if (!allow.has(d)) lines.push(...target(d))
  return lines.join('\n') + '\n'
}

export interface KeaScope {
  id: number; cidr: string; enabled: boolean; leaseTime: number
  options: { routers?: string[]; dnsServers?: string[]; domainName?: string; domainSearch?: string[]; ntpServers?: string[]; tftpServer?: string; bootFile?: string; custom?: Array<{ code: number; name: string; type: string; value: string }> }
  pools: Array<{ start: string; end: string }>
  reservations: Array<{ mac: string; ip: string; hostname: string | null }>
}
export interface KeaSettings { interfaces: string[]; ddns: boolean; socket: string; lease: { type: 'memfile' | 'postgresql'; name: string; user?: string; password?: string; host?: string }; globalOptions: KeaScope['options'] }
export const KEA_DEFAULTS: KeaSettings = { interfaces: ['*'], ddns: false, socket: '/run/kea/kea4-ctrl-socket', lease: { type: 'postgresql', name: 'ddibuntu', user: 'kea', host: '127.0.0.1' }, globalOptions: {} }

export function renderKea(s: KeaSettings, scopes: KeaScope[]): string {
  const defs: any[] = []
  const subnets = scopes.filter((x) => x.enabled).map((sc) => {
    const o = { ...s.globalOptions, ...Object.fromEntries(Object.entries(sc.options).filter(([, v]) => v !== undefined && v !== '' && !(Array.isArray(v) && !v.length))) } as KeaScope['options']
    const od: any[] = []
    const add = (name: string, data: string | undefined) => { if (data) od.push({ name, data }) }
    add('routers', o.routers?.join(', ')); add('domain-name-servers', o.dnsServers?.join(', ')); add('domain-name', o.domainName)
    add('domain-search', o.domainSearch?.join(', ')); add('ntp-servers', o.ntpServers?.join(', '))
    add('tftp-server-name', o.tftpServer); add('boot-file-name', o.bootFile)
    for (const c of o.custom ?? []) {
      if (!defs.some((d) => d.code === c.code)) defs.push({ name: c.name, code: c.code, type: c.type, space: 'dhcp4' })
      od.push({ name: c.name, data: c.value })
    }
    return {
      id: sc.id, subnet: sc.cidr, 'valid-lifetime': sc.leaseTime,
      pools: sc.pools.map((p) => ({ pool: `${p.start} - ${p.end}` })),
      'option-data': od,
      reservations: sc.reservations.map((r) => ({ 'hw-address': r.mac, 'ip-address': r.ip, ...(r.hostname ? { hostname: r.hostname } : {}) })),
    }
  })
  const lease: any = s.lease.type === 'memfile'
    ? { type: 'memfile', persist: true, name: s.lease.name }
    : { type: 'postgresql', name: s.lease.name, user: s.lease.user, password: s.lease.password ?? '', host: s.lease.host ?? '127.0.0.1' }
  const conf = {
    Dhcp4: {
      'interfaces-config': { interfaces: s.interfaces },
      'control-socket': { 'socket-type': 'unix', 'socket-name': s.socket },
      'lease-database': lease,
      'valid-lifetime': 86400,
      authoritative: true,
      ...(s.ddns ? { 'dhcp-ddns': { 'enable-updates': true } } : {}),
      ...(defs.length ? { 'option-def': defs } : {}),
      subnet4: subnets,
      loggers: [{ name: 'kea-dhcp4', output_options: [{ output: 'stdout' }], severity: 'INFO' }],
    },
  }
  return JSON.stringify(conf, null, 2) + '\n'
}

// ---- Fichiers, validation, déploiement ----
export interface OutFile { path: string; content: string; mode: number; kind: 'zone' | 'named' | 'kea' | 'rpz' }
export interface CheckResult { name: string; ok: boolean | null; output: string; note?: 'deferred' }

export function zoneFile(z: ZoneRow, records: RecInfo[]): OutFile {
  return { path: `zones/${zoneBase(z)}`, content: renderZone(z, records), mode: 0o644, kind: 'zone' }
}

const sub = (t: string, zonesDir: string) => t.split(ZONES_DIR).join(zonesDir)
function run(bin: string, args: string[]): Promise<{ code: number | null; out: string; missing: boolean }> {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: 60_000, maxBuffer: 4 * 1024 * 1024 }, (err: any, stdout, stderr) => {
      if (err?.code === 'ENOENT') return resolve({ code: null, out: 'binaire absent', missing: true })
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, out: `${stdout}${stderr}`.trim().slice(0, 4000), missing: false })
    })
  })
}

/** Valide l'ensemble des fichiers dans un dossier temporaire avec les outils officiels. */
export async function validateFiles(files: OutFile[]): Promise<CheckResult[]> {
  const c = cfg()
  const dir = await fs.mkdtemp(join(tmpdir(), 'ddi-check-'))
  const results: CheckResult[] = []
  try {
    const zdir = join(dir, 'zones')
    await fs.mkdir(zdir, { recursive: true })
    for (const f of files) {
      const p = join(dir, f.path)
      await fs.mkdir(dirname(p), { recursive: true })
      await fs.writeFile(p, sub(f.content, zdir))
    }
    for (const f of files.filter((x) => x.kind === 'zone' || x.kind === 'rpz')) {
      const m = f.content.match(/^\$ORIGIN (\S+?)\.?$/m)
      const zone = m ? m[1]! : 'unknown'
      const r = await run(c.namedCheckzone, ['-k', 'warn', zone, join(dir, f.path)])
      results.push({ name: `named-checkzone ${zone}`, ok: r.missing ? null : r.code === 0, output: r.out })
    }
    const named = files.filter((x) => x.kind === 'named')
    if (named.length) {
      const key = join(dir, 'ddi-ddns.key')
      await fs.writeFile(key, 'key "ddi-ddns" { algorithm hmac-sha256; secret "c2VjcmV0LWRlLXRlc3Qtc2VjcmV0LWRlLXRlc3Q="; };\n')
      const wrapper = join(dir, 'named.conf')
      const body = named.map((f) => sub(f.content, zdir).replace(/include "[^"]*\.key";/, `include "${key}";`).replace(/^(\s*directory )"[^"]*";/m, `$1"${dir}";`)).join('\n')
      await fs.writeFile(wrapper, body)
      const r = await run(c.namedCheckconf, [wrapper])
      results.push({ name: 'named-checkconf', ok: r.missing ? null : r.code === 0, output: r.out })
    }
    for (const f of files.filter((x) => x.kind === 'kea')) {
      const p = join(dir, f.path)
      // la validation n'ouvre pas la vraie base : on teste la même configuration avec un fichier de baux local
      const testConf = JSON.parse(f.content)
      testConf.Dhcp4['lease-database'] = { type: 'memfile', persist: false }
      testConf.Dhcp4['control-socket']['socket-name'] = join(dir, 'kea.sock')
      await fs.writeFile(p, JSON.stringify(testConf))
      const r = await run(c.keaDhcp4, ['-t', p])
      // Le profil AppArmor d'Ubuntu n'autorise Kea à lire que /etc/kea : hors de là, « -t » échoue sans juger la configuration.
      // Verdict inconnu (null) plutôt que faux : ddibuntu-reload (root) refait la vérification, depuis /etc/kea.
      const blocked = r.code !== 0 && /Unable to open file/.test(r.out)
      results.push({ name: 'kea-dhcp4 -t', ok: r.missing || blocked ? null : r.code === 0, output: blocked ? '' : r.out, ...(blocked ? { note: 'deferred' as const } : {}) })
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
  return results
}

/** Écriture atomique (fichier temporaire puis renommage). Les fichiers de secrets sont en 0640. */
export async function deployFiles(files: OutFile[], target: string, runtimeZonesDir?: string): Promise<Record<string, string>> {
  const sums: Record<string, string> = {}
  const zdir = runtimeZonesDir || join(target, 'zones')   // chemin écrit dans named.conf ; les fichiers restent déposés sous target/
  await fs.mkdir(join(target, 'zones'), { recursive: true })
  for (const f of files) {
    const p = join(target, f.path)
    await fs.mkdir(dirname(p), { recursive: true })
    const tmp = `${p}.${process.pid}.tmp`
    const content = sub(f.content, zdir)
    await fs.writeFile(tmp, content, { mode: f.mode })
    await fs.rename(tmp, p)
    sums[f.path] = createHash('sha256').update(content).digest('hex')
  }
  return sums
}
