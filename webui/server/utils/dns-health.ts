// Contrôle de cohérence DNS ↔ IPAM (0.10.1). Analyse PURE (testable sans base) : les données sont lues par chargeHealth(), le résultat est un
// rapport de constats + un score par zone ; la correction (fixFinding) ne s'applique qu'à un constat recalculé au moment de l'appel.
import type { PoolClient } from 'pg'
import { query, tx } from './db'
import { cnameTarget, fqdnOf, stripDot } from './aliases'
import { cidrContainsIp, parseCidr, parseIp, ptrName } from './net'

export type HealthKind = 'orphan_ptr' | 'a_no_ptr' | 'a_no_ipam' | 'ip_no_name' | 'dangling_cname'
export const HEALTH_KINDS: HealthKind[] = ['orphan_ptr', 'a_no_ptr', 'a_no_ipam', 'ip_no_name', 'dangling_cname']

export interface HZone { id: number; name: string; type: string; view_id: number | null; disabled: boolean }
export interface HRec { id: number; zone_id: number; name: string; type: string; rdata: string; disabled: boolean; source: string; protected: boolean }
export interface HAddr { subnet_id: number; ip: string; hostname: string | null; zone_id: number | null }
export interface HSubnet { id: number; cidr: string }
export interface HealthData { zones: HZone[]; records: HRec[]; addresses: HAddr[]; subnets: HSubnet[] }

export interface Finding {
  key: string; kind: HealthKind; zone_id: number | null; zone: string | null
  name: string; detail: string; fixable: boolean
  /** Action proposée, pour l'affichage : delete | create_ptr | create_address | create_a | disable */
  fix: 'delete' | 'create_ptr' | 'create_address' | 'create_a' | 'disable'
  /** Paramètres propres au correctif (jamais lus du client). */
  p: Record<string, string | number | null>
}
export interface ZoneScore { zone_id: number; zone: string; records: number; issues: number; score: number }
export interface HealthReport { findings: Finding[]; zones: ZoneScore[]; score: number; counts: Record<HealthKind, number> }

const REV4 = '.in-addr.arpa'
/** Adresse IPv4 portée par un nom PTR complet (« 4.3.2.1.in-addr.arpa ») ; null sinon (IPv6 : hors périmètre). */
export function ptrToIp(fqdn: string): string | null {
  if (!fqdn.endsWith(REV4)) return null
  const p = fqdn.slice(0, -REV4.length).split('.')
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null
  return p.reverse().join('.')
}

const viewKey = (v: number | null) => v ?? 0

export function analyzeHealth(d: HealthData): HealthReport {
  const zones = new Map(d.zones.map((z) => [z.id, z]))
  const live = d.records.filter((r) => !r.disabled && zones.get(r.zone_id) && !zones.get(r.zone_id)!.disabled)
  const primary = (r: HRec) => zones.get(r.zone_id)!.type === 'primary'
  const fq = (r: HRec) => fqdnOf(r.name, zones.get(r.zone_id)!.name)
  const subs = d.subnets.map((s) => ({ id: s.id, c: parseCidr(s.cidr) })).filter((s) => s.c && s.c.v === 4) as Array<{ id: number; c: NonNullable<ReturnType<typeof parseCidr>> }>
  const inManaged = (ip: string) => { const p = parseIp(ip); return !!p && subs.some((s) => cidrContainsIp(s.c, p)) }

  // Index : (vue, nom complet) → enregistrements ; (vue, ip) → noms A portés.
  const byName = new Map<string, HRec[]>()
  const aByIp = new Map<string, HRec[]>()
  for (const r of live) {
    if (!primary(r)) continue
    const k = `${viewKey(zones.get(r.zone_id)!.view_id)}|${fq(r)}`
    byName.set(k, [...(byName.get(k) ?? []), r])
    if (r.type === 'A') { const kk = `${viewKey(zones.get(r.zone_id)!.view_id)}|${r.rdata}`; aByIp.set(kk, [...(aByIp.get(kk) ?? []), r]) }
  }
  const reverse = d.zones.filter((z) => z.type === 'primary' && !z.disabled && z.name.toLowerCase().endsWith(REV4))
  const ptrIndex = new Map<string, HRec[]>()   // (vue, ip) → PTR
  const addrByIp = new Map(d.addresses.map((a) => [a.ip, a]))
  const out: Finding[] = []
  const zname = (id: number) => zones.get(id)!.name

  for (const r of live) {
    const z = zones.get(r.zone_id)!
    if (!primary(r)) continue
    if (r.type === 'PTR' && z.name.toLowerCase().endsWith(REV4)) {
      const ip = ptrToIp(fqdnOf(r.name, z.name))
      if (ip) { const k = `${viewKey(z.view_id)}|${ip}`; ptrIndex.set(k, [...(ptrIndex.get(k) ?? []), r]) }
    }
  }

  for (const r of live) {
    const z = zones.get(r.zone_id)!
    if (!primary(r)) continue
    if (r.source === 'dhcp') continue   // gérés par la synchronisation des baux
    const vk = viewKey(z.view_id)
    if (r.type === 'PTR' && z.name.toLowerCase().endsWith(REV4)) {
      const ip = ptrToIp(fqdnOf(r.name, z.name)), tgt = stripDot(r.rdata)
      if (!ip) continue
      const ok = (aByIp.get(`${vk}|${ip}`) ?? []).some((a) => fq(a) === tgt)
      if (!ok) out.push({ key: `orphan_ptr:${r.id}`, kind: 'orphan_ptr', zone_id: z.id, zone: z.name, name: `${ip} → ${tgt}`, detail: `Aucun enregistrement A ${tgt} ne porte ${ip}`, fixable: !r.protected, fix: 'delete', p: { rec: r.id } })
    } else if (r.type === 'A') {
      if (!reverse.some((rz) => (rz.view_id ?? null) === (z.view_id ?? null) && ptrName(parseIp(r.rdata) ?? { v: 4, n: 0n }).endsWith('.' + rz.name.toLowerCase()))) { /* pas de zone inverse : rien à reprocher */ } else if (!(ptrIndex.get(`${vk}|${r.rdata}`) ?? []).some((p) => stripDot(p.rdata) === fq(r))) {
        out.push({ key: `a_no_ptr:${r.id}`, kind: 'a_no_ptr', zone_id: z.id, zone: z.name, name: `${fq(r)} (${r.rdata})`, detail: `Pas de PTR ${r.rdata} → ${fq(r)}`, fixable: true, fix: 'create_ptr', p: { rec: r.id } })
      }
      if (inManaged(r.rdata) && !addrByIp.has(r.rdata)) {
        out.push({ key: `a_no_ipam:${r.id}`, kind: 'a_no_ipam', zone_id: z.id, zone: z.name, name: `${fq(r)} (${r.rdata})`, detail: `${r.rdata} est dans un réseau géré mais n'a pas de fiche IPAM`, fixable: true, fix: 'create_address', p: { rec: r.id } })
      }
    } else if (r.type === 'CNAME') {
      const t = cnameTarget(r.rdata, z.name)
      if (!t) continue
      const inZone = d.zones.some((x) => x.type === 'primary' && !x.disabled && (x.view_id ?? null) === (z.view_id ?? null) && (t === x.name.toLowerCase() || t.endsWith('.' + x.name.toLowerCase())))
      if (inZone && !byName.has(`${vk}|${t}`)) out.push({ key: `dangling_cname:${r.id}`, kind: 'dangling_cname', zone_id: z.id, zone: z.name, name: `${fq(r)} → ${t}`, detail: `La cible ${t} n'existe pas`, fixable: !r.protected, fix: 'disable', p: { rec: r.id } })
    }
  }

  // Adresses IPAM nommées mais absentes du DNS (A portant cette IP, dans n'importe quelle vue).
  const publishedIps = new Set(live.filter((r) => r.type === 'A').map((r) => r.rdata))
  for (const a of d.addresses) {
    if (!a.hostname || parseIp(a.ip)?.v !== 4 || publishedIps.has(a.ip)) continue
    const zid = a.zone_id && zones.get(a.zone_id)?.type === 'primary' && !zones.get(a.zone_id)!.disabled ? a.zone_id : null
    out.push({ key: `ip_no_name:${a.ip}`, kind: 'ip_no_name', zone_id: zid, zone: zid ? zname(zid) : null, name: `${a.ip} (${a.hostname})`, detail: zid ? `${a.hostname} n'est publié dans aucune zone` : `${a.hostname} n'est pas publié et le réseau n'a pas de zone DNS`, fixable: !!zid, fix: 'create_a', p: { ip: a.ip, host: a.hostname, zone: zid, subnet: a.subnet_id } })
  }

  const counts = Object.fromEntries(HEALTH_KINDS.map((k) => [k, 0])) as Record<HealthKind, number>
  for (const f of out) counts[f.kind]++
  const per = new Map<number, number>(); for (const f of out) if (f.zone_id) per.set(f.zone_id, (per.get(f.zone_id) ?? 0) + 1)
  const recCount = new Map<number, number>(); for (const r of live) recCount.set(r.zone_id, (recCount.get(r.zone_id) ?? 0) + 1)
  const zs: ZoneScore[] = d.zones.filter((z) => z.type === 'primary' && !z.disabled).map((z) => {
    const n = recCount.get(z.id) ?? 0, i = per.get(z.id) ?? 0
    return { zone_id: z.id, zone: z.name, records: n, issues: i, score: i === 0 ? 100 : Math.max(0, Math.round(100 - (100 * i) / Math.max(n, i))) }
  }).sort((a, b) => a.score - b.score || a.zone.localeCompare(b.zone))
  const total = zs.reduce((s, z) => s + z.records, 0), bad = out.length
  const score = bad === 0 ? 100 : Math.max(0, Math.round(100 - (100 * bad) / Math.max(total, bad)))
  return { findings: out, zones: zs, score, counts }
}

export async function chargeHealth(): Promise<HealthData> {
  const [zones, records, addresses, subnets] = await Promise.all([
    query("select id, name, type, view_id, disabled from dns_zones"),
    query("select id, zone_id, name, type, rdata, disabled, source, protected from dns_records"),
    query("select a.subnet_id, host(a.ip) as ip, nullif(a.hostname, '') as hostname, t.dns_zone_id as zone_id from addresses a join subnets s on s.id = a.subnet_id left join network_templates t on t.id = s.template_id where family(a.ip) = 4"),
    query("select id, text(cidr) as cidr from subnets where kind <> 'container'"),
  ])
  return { zones: zones as HZone[], records: records as HRec[], addresses: addresses as HAddr[], subnets: subnets as HSubnet[] }
}
export async function healthReport(): Promise<HealthReport> { return analyzeHealth(await chargeHealth()) }

/** Applique le correctif d'un constat (recalculé à l'instant : un constat devenu faux est ignoré). Retourne l'état : done | gone | unfixable. */
export async function fixFinding(cl: PoolClient, f: Finding, touched: Set<number>): Promise<'done' | 'gone' | 'unfixable'> {
  if (!f.fixable) return 'unfixable'
  const dirty = (id: number | null | undefined) => { if (id) touched.add(id) }
  const rec = f.p.rec == null ? null : (await cl.query('select r.id, r.zone_id, r.name, r.type, r.rdata, z.name as zone, z.view_id from dns_records r join dns_zones z on z.id = r.zone_id where r.id = $1', [f.p.rec])).rows[0]
  switch (f.fix) {
    case 'delete': {
      if (!rec) return 'gone'
      await cl.query('delete from dns_records where id = $1', [rec.id]); dirty(rec.zone_id); return 'done'
    }
    case 'disable': {
      if (!rec) return 'gone'
      await cl.query('update dns_records set disabled = true, updated_at = now() where id = $1', [rec.id]); dirty(rec.zone_id); return 'done'
    }
    case 'create_ptr': {
      if (!rec) return 'gone'
      const ip = parseIp(rec.rdata); if (!ip) return 'unfixable'
      const ptr = ptrName(ip)
      const rz = (await cl.query("select id, name from dns_zones where type = 'primary' and not disabled and $1 like '%.' || lower(name) order by (view_id is not distinct from $2) desc, length(name) desc limit 1", [ptr, rec.view_id])).rows[0]
      if (!rz) return 'unfixable'
      const fqn = fqdnOf(rec.name, rec.zone)
      await cl.query("insert into dns_records (zone_id, name, type, rdata) values ($1,$2,'PTR',$3) on conflict do nothing", [rz.id, ptr.slice(0, -(rz.name.length + 1)), `${fqn}.`])
      dirty(rz.id); return 'done'
    }
    case 'create_address': {
      if (!rec) return 'gone'
      const sub = (await cl.query('select id from subnets where kind <> \'container\' and cidr >>= $1::inet order by masklen(cidr) desc limit 1', [rec.rdata])).rows[0]
      if (!sub) return 'unfixable'
      const label = rec.name === '@' ? null : (rec.name.includes('.') ? rec.name.split('.')[0] : rec.name)
      await cl.query("insert into addresses (subnet_id, ip, status, hostname, description) values ($1,$2,'used',$3,'créée par le contrôle de cohérence DNS') on conflict do nothing", [sub.id, rec.rdata, label]); return 'done'
    }
    case 'create_a': {
      const zone = Number(f.p.zone), host = String(f.p.host ?? ''), ip = String(f.p.ip ?? '')
      if (!zone || !host || !parseIp(ip)) return 'unfixable'
      const still = (await cl.query('select 1 from addresses where host(ip) = $1 and hostname = $2', [ip, host])).rows[0]
      if (!still) return 'gone'
      await cl.query("insert into dns_records (zone_id, name, type, rdata) values ($1,$2,'A',$3) on conflict do nothing", [zone, host, ip])
      const z = (await cl.query('select name, view_id from dns_zones where id = $1', [zone])).rows[0]
      const ptr = ptrName(parseIp(ip)!)
      const rz = (await cl.query("select id, name from dns_zones where type = 'primary' and not disabled and $1 like '%.' || lower(name) order by (view_id is not distinct from $2) desc, length(name) desc limit 1", [ptr, z.view_id])).rows[0]
      if (rz) { await cl.query("insert into dns_records (zone_id, name, type, rdata) values ($1,$2,'PTR',$3) on conflict do nothing", [rz.id, ptr.slice(0, -(rz.name.length + 1)), `${host}.${z.name}.`]); dirty(rz.id) }
      dirty(zone); return 'done'
    }
  }
}

export async function applyFixes(keys: string[]): Promise<{ done: number; gone: number; unfixable: number }> {
  const rep = await healthReport(), want = new Set(keys)
  const todo = rep.findings.filter((f) => want.has(f.key))
  const res = { done: 0, gone: want.size - todo.length, unfixable: 0 }
  await tx(async (cl) => {
    const touched = new Set<number>()
    for (const f of todo) res[await fixFinding(cl, f, touched)]++
    if (touched.size) await cl.query('update dns_zones set dirty = true, updated_at = now() where id = any($1::int[])', [[...touched]])
  })
  return res
}
