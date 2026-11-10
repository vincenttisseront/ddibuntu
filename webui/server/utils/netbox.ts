// Import depuis NetBox (API REST) : client HTTPS prudent, normalisation, plan (aperçu sans écriture), application.
import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import { isIP } from 'node:net'
import { cfg } from './config'
import { cidrContainsIp, cidrToString, isValidDnsName, normIp, parseCidr, parseIp } from './net'

export class NetboxError extends Error { constructor(public code: string, public status = 502) { super(code) } }
export type AddrStatus = 'used' | 'reserved' | 'dhcp' | 'gateway' | 'infra'
export type Mode = 'add' | 'sync' | 'sync_overwrite'
export interface NetboxSettings {
  url: string; tlsVerify: boolean; caPem?: string; tokenEnc?: string
  include: { vlans: boolean; prefixes: boolean; addresses: boolean }; mode: Mode; prune: boolean; includeContainers: boolean
}
export const NB_DEFAULTS: NetboxSettings = { url: '', tlsVerify: true, include: { vlans: true, prefixes: true, addresses: true }, mode: 'add', prune: false, includeContainers: false }

// ---------------------------------------------------------------------------------------------
// Client HTTP
// Adresses refusées comme destination (contrôle à la CONNEXION, donc sans fenêtre pour un « DNS rebinding ») : boucle locale,
// lien local (dont 169.254.169.254, métadonnées cloud), non spécifiée, multicast, réservée. Les réseaux privés sont permis : NetBox est interne.
const FORBIDDEN = ['0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4', '::/128', '::1/128', 'fe80::/10', 'ff00::/8']
export function isForbiddenTarget(addr: string, allowLoopback = false): boolean {
  const ip = parseIp(addr)
  if (!ip) return true
  if (ip.v === 6 && (ip.n >> 32n) === 0xffffn) return isForbiddenTarget(`${(ip.n >> 24n) & 255n}.${(ip.n >> 16n) & 255n}.${(ip.n >> 8n) & 255n}.${ip.n & 255n}`, allowLoopback)
  return FORBIDDEN.some((c) => !(allowLoopback && (c === '127.0.0.0/8' || c === '::1/128')) && cidrContainsIp(parseCidr(c)!, ip))
}

export function parseBaseUrl(raw: string): URL {
  let u: URL
  try { u = new URL(raw.trim()) } catch { throw new NetboxError('netbox_url_invalid', 400) }
  if (u.username || u.password || (u.protocol !== 'https:' && u.protocol !== 'http:')) throw new NetboxError('netbox_url_invalid', 400)
  // le jeton circulerait en clair : HTTPS obligatoire (HTTP seulement en mode test)
  if (u.protocol === 'http:' && !cfg().testMode) throw new NetboxError('netbox_https_required', 400)
  u.search = ''; u.hash = ''
  u.pathname = u.pathname.replace(/\/api\/?$/, '/')
  if (!u.pathname.endsWith('/')) u.pathname += '/'
  const lit = u.hostname.replace(/^\[|\]$/g, '')
  if (isIP(lit) && isForbiddenTarget(lit, cfg().allowPrivateFetch)) throw new NetboxError('netbox_url_forbidden', 400)
  return u
}

interface GetOpts { token: string; ca?: string; verify: boolean; timeoutMs?: number; maxBytes?: number }
export function getJson(u: URL, o: GetOpts): Promise<any> {
  const allowLoopback = cfg().allowPrivateFetch
  const lookup: any = (host: string, options: any, cb: any) => {
    dns.lookup(host, { all: true, ...(typeof options === 'object' ? options : {}) }, (err, addrs: any) => {
      if (err) return cb(err)
      const list = Array.isArray(addrs) ? addrs : [{ address: addrs, family: 4 }]
      if (list.some((a: any) => isForbiddenTarget(a.address, allowLoopback))) return cb(Object.assign(new Error('forbidden'), { code: 'NB_FORBIDDEN' }))
      if (options?.all) return cb(null, list)
      cb(null, list[0].address, list[0].family)
    })
  }
  const lib = u.protocol === 'https:' ? https : http
  const max = o.maxBytes ?? 64 * 1024 * 1024
  return new Promise((resolve, reject) => {
    let settled = false
    const ok = (v: any) => { if (!settled) { settled = true; resolve(v) } }, ko = (e: NetboxError) => { if (!settled) { settled = true; reject(e) } }
    const auth = o.token.startsWith('nbt_') ? `Bearer ${o.token}` : `Token ${o.token}`
    const req = lib.request(u, { method: 'GET', lookup, timeout: o.timeoutMs ?? 30000, ...(u.protocol === 'https:' ? { rejectUnauthorized: o.verify, ...(o.ca ? { ca: o.ca } : {}) } : {}),
      headers: { authorization: auth, accept: 'application/json', 'user-agent': 'ddibuntu-console' } }, (res) => {
      const st = res.statusCode ?? 0
      res.on('error', () => ko(new NetboxError('netbox_unreachable')))
      if (st >= 300 && st < 400) { res.resume(); return ko(new NetboxError('netbox_redirect')) }   // jamais suivi : le jeton ne doit pas changer de destinataire
      if (st === 401 || st === 403) { res.resume(); return ko(new NetboxError('netbox_auth', 401)) }
      if (st === 404) { res.resume(); return ko(new NetboxError('netbox_not_found', 404)) }
      if (st !== 200) { res.resume(); return ko(new NetboxError('netbox_http')) }
      const chunks: Buffer[] = []; let size = 0
      res.on('data', (d: Buffer) => { size += d.length; if (size > max) { ko(new NetboxError('netbox_too_large')); res.destroy(); req.destroy(); return } chunks.push(d) })
      res.on('end', () => { try { ok(JSON.parse(Buffer.concat(chunks).toString('utf8'))) } catch { ko(new NetboxError('netbox_bad_response')) } })
    })
    req.on('timeout', () => { ko(new NetboxError('netbox_timeout')); req.destroy() })
    req.on('error', (e: any) => {
      const c = String(e?.code ?? '')
      if (c === 'NB_FORBIDDEN') return ko(new NetboxError('netbox_url_forbidden', 400))
      if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME|ERR_TLS|DEPTH_ZERO/.test(c)) return ko(new NetboxError('netbox_tls'))
      ko(new NetboxError('netbox_unreachable'))
    })
    req.end()
  })
}

/** Toutes les pages d'une liste : « next » n'est suivi que s'il reste sur la MÊME origine (le jeton n'est jamais envoyé ailleurs). */
export async function fetchAll(base: URL, path: string, o: GetOpts, maxObjects = 500_000): Promise<any[]> {
  const out: any[] = []
  let next: URL | null = new URL(`api/${path}/?limit=1000`, base)
  for (let page = 0; next && page < 1000; page++) {
    const j: any = await getJson(next, o)
    if (!Array.isArray(j?.results)) throw new NetboxError('netbox_bad_response')
    out.push(...j.results)
    if (out.length > maxObjects) throw new NetboxError('netbox_too_large')
    if (!j.next) break
    let n: URL
    try { n = new URL(String(j.next), base) } catch { throw new NetboxError('netbox_bad_response') }
    if (n.origin !== base.origin) throw new NetboxError('netbox_bad_next')
    next = n
  }
  return out
}

export async function netboxVersion(base: URL, o: GetOpts): Promise<string> {
  const j = await getJson(new URL('api/status/', base), o)
  return String(j?.['netbox-version'] ?? '').slice(0, 40)
}

// ---------------------------------------------------------------------------------------------
// Normalisation des objets NetBox (v3 et v4)
export interface NbVlan { ext: string; vid: number; name: string; description: string }
export interface NbPrefix { ext: string; cidr: string; name: string; description: string; site: string | null; vid: number | null; tags: string[]; container: boolean }
export interface NbAddress { ext: string; ip: string; hostname: string | null; status: AddrStatus; description: string }
export interface NbData { vlans: NbVlan[]; prefixes: NbPrefix[]; addresses: NbAddress[]; skipped: Record<string, number> }
const str = (v: unknown, max = 500) => String(v ?? '').trim().slice(0, max)

export function normalizeNetbox(raw: { vlans: any[]; prefixes: any[]; addresses: any[] }): NbData {
  const skipped: Record<string, number> = {}
  const bump = (k: string) => { skipped[k] = (skipped[k] ?? 0) + 1 }
  const vlans: NbVlan[] = [], vids = new Set<number>()
  for (const v of raw.vlans) {
    const vid = Number(v?.vid)
    if (!Number.isInteger(vid) || vid < 1 || vid > 4094) { bump('vlan_invalid'); continue }
    if (vids.has(vid)) { bump('vlan_duplicate'); continue }   // NetBox autorise le même VID dans plusieurs groupes ; ici il est unique
    vids.add(vid); vlans.push({ ext: str(v.id, 40), vid, name: str(v.name, 200) || `VLAN ${vid}`, description: str(v.description) })
  }
  const prefixes: NbPrefix[] = [], seen = new Set<string>()
  for (const p of raw.prefixes) {
    const c = parseCidr(str(p?.prefix, 60), false)
    if (!c) { bump('prefix_invalid'); continue }
    const cidr = cidrToString(c)
    if (seen.has(cidr)) { bump('prefix_duplicate'); continue }   // même préfixe dans plusieurs VRF : le premier est retenu
    seen.add(cidr)
    const vrf = str(p.vrf?.name, 100)
    const desc = [str(p.description), vrf ? `[VRF ${vrf}]` : ''].filter(Boolean).join(' ')
    const vid = Number(p.vlan?.vid)
    prefixes.push({ ext: str(p.id, 40), cidr, name: (str(p.description, 200) || cidr), description: desc, site: str(p.scope?.name ?? p.site?.name, 200) || null,
      vid: Number.isInteger(vid) ? vid : null, tags: (Array.isArray(p.tags) ? p.tags : []).map((t: any) => str(t?.slug, 60)).filter(Boolean).slice(0, 20), container: str(p.status?.value ?? p.status) === 'container' })
  }
  const ips = new Set<string>(), outA: NbAddress[] = []
  for (const a of raw.addresses) {
    const m = /^(.+)\/(\d{1,3})$/.exec(str(a?.address, 80))
    const ip = m ? normIp(m[1]!) : null
    if (!ip) { bump('address_invalid'); continue }
    if (ips.has(ip)) { bump('address_duplicate'); continue }
    ips.add(ip)
    const st = str(a.status?.value ?? a.status), role = str(a.role?.value ?? a.role)
    const status: AddrStatus = role === 'gateway' ? 'gateway' : ['loopback', 'vip', 'vrrp', 'hsrp', 'glbp', 'carp', 'anycast'].includes(role) ? 'infra' : st === 'reserved' ? 'reserved' : st === 'dhcp' ? 'dhcp' : 'used'
    const dnsName = str(a.dns_name, 253).toLowerCase().replace(/\.$/, '')
    const ao = a.assigned_object
    const owner = [ao?.device?.name ?? ao?.virtual_machine?.name, ao?.name].filter(Boolean).join(' / ')
    outA.push({ ext: str(a.id, 40), ip, hostname: dnsName && isValidDnsName(dnsName, false) ? dnsName : null, status, description: str(a.description) || str(owner, 200) })
  }
  return { vlans, prefixes, addresses: outA, skipped }
}

// ---------------------------------------------------------------------------------------------
// Plan : ce qui serait créé / modifié / conservé, calculé sans rien écrire
export interface Existing {
  vlans: Map<number, { id: number; name: string; description: string | null; source: string }>
  subnets: Map<string, { id: number; name: string; description: string | null; site: string | null; vid: number | null; tags: string[]; source: string }>
  addresses: Map<string, { id: number; status: string; hostname: string | null; description: string | null; source: string }>
}
export interface PlanOpts { include: NetboxSettings['include']; mode: Mode; prune: boolean; includeContainers: boolean }
export interface Counts { created: number; updated: number; unchanged: number; kept_manual: number; existing: number }
export interface NbPlan {
  vlans: Array<{ op: 'create' | 'update'; row: NbVlan; id?: number }>
  subnets: Array<{ op: 'create' | 'update'; row: NbPrefix; id?: number }>
  addresses: Array<{ op: 'create' | 'update'; row: NbAddress; id?: number; subnetCidr: string }>
  prune: { vlans: number[]; addresses: number[] }
  stats: { vlans: Counts; subnets: Counts; addresses: Counts & { no_subnet: number }; pruned: { vlans: number; addresses: number }; stale_subnets: number; skipped: Record<string, number> }
  samples: { vlans: string[]; subnets: string[]; addresses: string[] }
}
const zero = (): Counts => ({ created: 0, updated: 0, unchanged: 0, kept_manual: 0, existing: 0 })
const eq = (a: string | null | undefined, b: string | null | undefined) => (a ?? '') === (b ?? '')
function decide(mode: Mode, ex: { source: string } | undefined, changed: boolean): 'create' | 'update' | 'unchanged' | 'kept_manual' | 'existing' {
  if (!ex) return 'create'
  if (mode === 'add') return 'existing'
  if (ex.source === 'netbox' || mode === 'sync_overwrite') return changed || ex.source !== 'netbox' ? 'update' : 'unchanged'
  return 'kept_manual'   // ligne saisie à la main : jamais écrasée sans le mode « écraser »
}

export function planNetbox(data: NbData, ex: Existing, o: PlanOpts): NbPlan {
  const plan: NbPlan = { vlans: [], subnets: [], addresses: [], prune: { vlans: [], addresses: [] },
    stats: { vlans: zero(), subnets: zero(), addresses: { ...zero(), no_subnet: 0 }, pruned: { vlans: 0, addresses: 0 }, stale_subnets: 0, skipped: { ...data.skipped } }, samples: { vlans: [], subnets: [], addresses: [] } }
  const count = (c: Counts, d: ReturnType<typeof decide>) => { if (d === 'create') c.created++; else if (d === 'update') c.updated++; else c[d]++ }
  if (o.include.vlans) {
    for (const v of data.vlans) {
      const e = ex.vlans.get(v.vid), d = decide(o.mode, e, !!e && (!eq(e.name, v.name) || !eq(e.description, v.description)))
      count(plan.stats.vlans, d)
      if (d === 'create' || d === 'update') { plan.vlans.push({ op: d, row: v, id: e?.id }); if (d === 'create' && plan.samples.vlans.length < 8) plan.samples.vlans.push(`VLAN ${v.vid} ${v.name}`) }
    }
    if (o.prune && o.mode !== 'add') { const have = new Set(data.vlans.map((v) => v.vid)); for (const [vid, e] of ex.vlans) if (e.source === 'netbox' && !have.has(vid)) plan.prune.vlans.push(e.id) }
  }
  const prefixes = o.include.prefixes ? data.prefixes.filter((p) => o.includeContainers || !p.container) : []
  if (o.include.prefixes) {
    plan.stats.skipped.containers = data.prefixes.length - prefixes.length
    for (const p of prefixes) {
      const e = ex.subnets.get(p.cidr)
      const d = decide(o.mode, e, !!e && (!eq(e.name, p.name) || !eq(e.description, p.description) || !eq(e.site, p.site) || (e.vid ?? null) !== p.vid || e.tags.join(',') !== p.tags.join(',')))
      count(plan.stats.subnets, d)
      if (d === 'create' || d === 'update') { plan.subnets.push({ op: d, row: p, id: e?.id }); if (d === 'create' && plan.samples.subnets.length < 8) plan.samples.subnets.push(p.cidr) }
    }
    const have = new Set(data.prefixes.map((p) => p.cidr))
    for (const [cidr, e] of ex.subnets) if (e.source === 'netbox' && !have.has(cidr)) plan.stats.stale_subnets++   // signalés, jamais supprimés (cascade)
  }
  if (o.include.addresses) {
    // sous-réseau d'une adresse : le plus précis parmi ceux qui existent et ceux que ce plan crée
    const all = [...new Set([...ex.subnets.keys(), ...(o.include.prefixes ? prefixes.map((p) => p.cidr) : [])])]
      .map((k) => ({ k, c: parseCidr(k, false)! })).filter((x) => x.c).sort((a, b) => b.c.prefix - a.c.prefix)
    for (const a of data.addresses) {
      const ip = parseIp(a.ip)!
      const sn = all.find((s) => s.c.v === ip.v && cidrContainsIp(s.c, ip))
      if (!sn) { plan.stats.addresses.no_subnet++; continue }
      const e = ex.addresses.get(a.ip)
      const d = decide(o.mode, e, !!e && (e.status !== a.status || !eq(e.hostname, a.hostname) || !eq(e.description, a.description)))
      count(plan.stats.addresses, d)
      if (d === 'create' || d === 'update') { plan.addresses.push({ op: d, row: a, id: e?.id, subnetCidr: sn.k }); if (d === 'create' && plan.samples.addresses.length < 8) plan.samples.addresses.push(a.ip) }
    }
    if (o.prune && o.mode !== 'add') { const have = new Set(data.addresses.map((a) => a.ip)); for (const [ip, e] of ex.addresses) if (e.source === 'netbox' && !have.has(ip)) plan.prune.addresses.push(e.id) }
  }
  plan.stats.pruned = { vlans: plan.prune.vlans.length, addresses: plan.prune.addresses.length }
  return plan
}

export interface Q { query: (text: string, params?: any[]) => Promise<{ rows: any[] }> }
export async function loadExisting(cl: Q): Promise<Existing> {
  const ex: Existing = { vlans: new Map(), subnets: new Map(), addresses: new Map() }
  for (const r of (await cl.query('select id, vlan_id, name, description, source from vlans')).rows) ex.vlans.set(r.vlan_id, r)
  for (const r of (await cl.query('select s.id, text(s.cidr) as c, s.name, s.description, s.site, v.vlan_id as vid, s.tags, s.source from subnets s left join vlans v on v.id = s.vlan_id')).rows) ex.subnets.set(r.c, { ...r, vid: r.vid ?? null })
  for (const r of (await cl.query('select id, host(ip) as ip, status, hostname, description, source from addresses')).rows) if (!ex.addresses.has(r.ip)) ex.addresses.set(r.ip, r)
  return ex
}

export async function applyNetbox(cl: Q, plan: NbPlan): Promise<void> {
  const vlanId = new Map<number, number>((await cl.query('select id, vlan_id from vlans')).rows.map((r: any) => [r.vlan_id as number, r.id as number]))
  for (const o of plan.vlans) {
    if (o.op === 'create') vlanId.set(o.row.vid, (await cl.query("insert into vlans (vlan_id, name, description, source, external_id) values ($1,$2,$3,'netbox',$4) returning id", [o.row.vid, o.row.name, o.row.description || null, o.row.ext])).rows[0].id)
    else await cl.query("update vlans set name = $2, description = $3, source = 'netbox', external_id = $4 where id = $1", [o.id, o.row.name, o.row.description || null, o.row.ext])
  }
  if (plan.prune.vlans.length) await cl.query('delete from vlans where id = any($1)', [plan.prune.vlans])
  const subnetId = new Map<string, number>((await cl.query('select id, text(cidr) as c from subnets')).rows.map((r: any) => [r.c as string, r.id as number]))
  for (const o of plan.subnets) {
    const vid = o.row.vid !== null ? (vlanId.get(o.row.vid) ?? null) : null
    if (o.op === 'create') {
      const r = await cl.query("insert into subnets (cidr, name, description, site, vlan_id, tags, source, external_id) values ($1,$2,$3,$4,$5,$6,'netbox',$7) on conflict (cidr) do nothing returning id", [o.row.cidr, o.row.name, o.row.description || null, o.row.site, vid, o.row.tags, o.row.ext])
      if (r.rows[0]) subnetId.set(o.row.cidr, r.rows[0].id)
    } else await cl.query("update subnets set name = $2, description = $3, site = $4, vlan_id = $5, tags = $6, source = 'netbox', external_id = $7, updated_at = now() where id = $1", [o.id, o.row.name, o.row.description || null, o.row.site, vid, o.row.tags, o.row.ext])
  }
  for (const o of plan.addresses) {
    const sid = subnetId.get(o.subnetCidr)
    if (!sid) continue
    if (o.op === 'create') await cl.query("insert into addresses (subnet_id, ip, status, hostname, description, source, external_id) values ($1,$2,$3,$4,$5,'netbox',$6) on conflict (subnet_id, ip) do nothing", [sid, o.row.ip, o.row.status, o.row.hostname, o.row.description || null, o.row.ext])
    else await cl.query("update addresses set status = $2, hostname = $3, description = $4, source = 'netbox', external_id = $5, updated_at = now() where id = $1", [o.id, o.row.status, o.row.hostname, o.row.description || null, o.row.ext])
  }
  if (plan.prune.addresses.length) await cl.query('delete from addresses where id = any($1)', [plan.prune.addresses])
}
