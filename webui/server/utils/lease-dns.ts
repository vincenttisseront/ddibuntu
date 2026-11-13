// Synchronisation bail DHCP → DNS (0.10.0). Réconciliation idempotente : à chaque passage, les enregistrements A + PTR « dynamiques » (source = 'dhcp')
// sont comparés à ce que les baux actifs imposent ; l'écart est appliqué. Un enregistrement saisi à la main n'est JAMAIS modifié ni écrasé.
// Réglage COMMUN au cluster (table « settings », clé « lease_dns »). Désactiver la fonction retire les enregistrements dynamiques.
import { getSetting, inRecovery, setSetting, tx } from './db'
import { cidrContainsIp, parseCidr, parseIp, ptrName } from './net'
import { activeLeases } from './leasetrace'

export interface LeaseDnsConf { enabled: boolean }
export const LEASE_DNS_DEFAULT: LeaseDnsConf = { enabled: false }
export const parseLeaseDns = (raw: unknown): LeaseDnsConf => ({ enabled: !!(raw && typeof raw === 'object' && (raw as Record<string, unknown>).enabled === true) })
export async function leaseDnsConf(): Promise<LeaseDnsConf> { return parseLeaseDns(await getSetting<unknown>('lease_dns', null).catch(() => null)) }
export async function saveLeaseDnsConf(c: LeaseDnsConf): Promise<void> { await setSetting('lease_dns', { enabled: !!c.enabled }) }

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
/** Nom relatif à utiliser dans la zone pour le nom d'hôte d'un bail ; null si inutilisable. Un domaine étranger à la zone est ignoré (premier label). */
export function leaseLabel(hostname: string | null | undefined, zoneName: string): string | null {
  let h = String(hostname ?? '').trim().toLowerCase().replace(/\.$/, '')
  const z = zoneName.toLowerCase().replace(/\.$/, '')
  if (!h) return null
  if (h.endsWith('.' + z)) h = h.slice(0, -(z.length + 1))
  if (h.includes('.')) h = h.split('.')[0]!
  return LABEL.test(h) ? h : null
}

export interface DynRec { zone_id: number; name: string; type: 'A' | 'PTR'; rdata: string }
export interface ExistingDyn extends DynRec { id: number }
const key = (r: DynRec) => `${r.zone_id}|${r.name.toLowerCase()}|${r.type}|${r.rdata.toLowerCase()}`
/** Écart entre ce que les baux imposent et ce qui existe déjà en source « dhcp ». */
export function planLeaseDns(desired: DynRec[], existing: ExistingDyn[]): { add: DynRec[]; del: ExistingDyn[] } {
  const want = new Map(desired.map((r) => [key(r), r])), have = new Map(existing.map((r) => [key(r), r]))
  return { add: [...want].filter(([k]) => !have.has(k)).map(([, r]) => r), del: [...have].filter(([k]) => !want.has(k)).map(([, r]) => r) }
}

export interface LeaseDnsResult { skipped?: string; leases: number; added: number; removed: number; conflicts: number; nozone: number; static: number }

export async function reconcileLeaseDns(): Promise<LeaseDnsResult> {
  const res: LeaseDnsResult = { leases: 0, added: 0, removed: 0, conflicts: 0, nozone: 0, static: 0 }
  if (await inRecovery()) return { ...res, skipped: 'replica' }
  const conf = await leaseDnsConf()
  const act = conf.enabled ? await activeLeases().catch(() => null) : []
  if (act === null) return { ...res, skipped: 'unavailable' }
  return tx(async (cl) => {
    const subs = (await cl.query(`select text(s.cidr) as cidr, t.dns_zone_id from subnets s join network_templates t on t.id = s.template_id where s.kind <> 'container' and t.dns_zone_id is not null`)).rows
      .map((r) => ({ c: parseCidr(r.cidr), zone: r.dns_zone_id as number })).filter((r) => r.c && r.c.v === 4) as Array<{ c: NonNullable<ReturnType<typeof parseCidr>>; zone: number }>
    subs.sort((a, b) => b.c.prefix - a.c.prefix)
    const zones = new Map<number, { id: number; name: string; view_id: number | null }>()
    for (const z of (await cl.query("select id, name, view_id from dns_zones where type = 'primary' and not disabled")).rows) zones.set(z.id, z)
    const rzones = [...zones.values()].sort((a, b) => b.name.length - a.name.length)
    const staticIps = new Set((await cl.query("select host(ip) as ip from addresses where hostname is not null and hostname <> ''")).rows.map((r) => r.ip as string))
    const manual = await cl.query("select zone_id, lower(name) as name, type from dns_records where source = 'manual' and type in ('A','AAAA','CNAME','PTR')")
    const manualKeys = new Set(manual.rows.map((r) => `${r.zone_id}|${r.name}|${r.type}`))
    const hasManual = (zone: number, name: string, types: string[]) => types.some((t) => manualKeys.has(`${zone}|${name}|${t}`))

    const desired: DynRec[] = [], taken = new Set<string>()
    for (const l of [...act].sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }))) {
      if (!l.hostname) continue
      res.leases++
      const ip = parseIp(l.ip)
      const sub = ip ? subs.find((s) => cidrContainsIp(s.c, ip)) : null
      const zone = sub ? zones.get(sub.zone) : null
      if (!ip || !zone) { res.nozone++; continue }
      if (staticIps.has(l.ip)) { res.static++; continue }
      const label = leaseLabel(l.hostname, zone.name)
      if (!label) continue
      const tk = `${zone.id}|${label}`
      if (taken.has(tk) || hasManual(zone.id, label, ['A', 'AAAA', 'CNAME'])) { res.conflicts++; continue }
      taken.add(tk)
      desired.push({ zone_id: zone.id, name: label, type: 'A', rdata: l.ip })
      const ptr = ptrName(ip)
      const rz = rzones.find((z) => ptr.endsWith('.' + z.name.toLowerCase()) && (z.view_id ?? null) === (zone.view_id ?? null)) ?? rzones.find((z) => ptr.endsWith('.' + z.name.toLowerCase()))
      if (rz) {
        const pn = ptr.slice(0, -(rz.name.length + 1))
        if (!hasManual(rz.id, pn, ['PTR'])) desired.push({ zone_id: rz.id, name: pn, type: 'PTR', rdata: `${label}.${zone.name}.` })
      }
    }
    const existing = (await cl.query("select id, zone_id, name, type, rdata from dns_records where source = 'dhcp'")).rows as ExistingDyn[]
    const { add, del } = planLeaseDns(desired, existing)
    const touched = new Set<number>()
    if (del.length) { await cl.query('delete from dns_records where id = any($1::int[])', [del.map((r) => r.id)]); del.forEach((r) => touched.add(r.zone_id)) }
    for (const r of add) {
      const n = (await cl.query("insert into dns_records (zone_id, name, type, rdata, source, comment) values ($1,$2,$3,$4,'dhcp','bail DHCP') on conflict do nothing", [r.zone_id, r.name, r.type, r.rdata])).rowCount ?? 0
      if (n) { res.added++; touched.add(r.zone_id) }
    }
    res.removed = del.length
    if (touched.size) await cl.query('update dns_zones set dirty = true, updated_at = now() where id = any($1::int[])', [[...touched]])
    return res
  })
}
