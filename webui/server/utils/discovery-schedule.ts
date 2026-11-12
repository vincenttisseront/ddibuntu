// Découverte planifiée : scan périodique des sous-réseaux choisis. Aucune adresse n'est CRÉÉE automatiquement : on met à jour « vu le »
// des adresses connues (ce qui alimente la détection des fantômes) et on COMPTE les hôtes inconnus de l'IPAM pour l'alerte d'hygiène.
import { z } from 'zod'
import { getSetting, query, setSetting } from './db'
import { cfg } from './config'
import { isValidDnsName, normMac } from './net'
import { DiscoveryError, PORT_PRESETS, classify, discoverHosts, enumerateTargets, pingWorks, realDeps, runningJob } from './discovery'
import type { KnownAddr } from './discovery'
import { leaseMap } from './leasemap'

export const ScheduleBody = z.object({
  enabled: z.boolean(), intervalHours: z.number().int().min(1).max(168),
  subnetIds: z.array(z.number().int().positive()).max(50),   // vide = tous les sous-réseaux IPv4 (dans la limite de 4096 adresses par passage)
  methods: z.object({ tcp: z.boolean(), icmp: z.boolean(), arp: z.boolean(), reverse: z.boolean(), leases: z.boolean() }),
  autoGhost: z.boolean(), ghostDays: z.number().int().min(1).max(3650),   // bascule automatique « utilisée » ⇄ « fantôme » ; ghostDays sert aussi à l'alerte
}).strict()
export type Schedule = z.infer<typeof ScheduleBody>
export interface LastRun { at: number; ok: boolean; scanned: number; alive: number; known: number; unknown: number; macChanged: number; unreachable: number; error?: string }

export const DEFAULT_SCHEDULE: Schedule = { enabled: false, intervalHours: 24, subnetIds: [], methods: { tcp: false, icmp: true, arp: true, reverse: true, leases: true }, autoGhost: false, ghostDays: 30 }
export const getSchedule = async (): Promise<Schedule> => ({ ...DEFAULT_SCHEDULE, ...(await getSetting<Partial<Schedule>>('discovery_schedule', {})) })
export const getLastRun = (): Promise<LastRun | null> => getSetting<LastRun | null>('discovery_schedule_last', null)

let running = false
export const scheduleRunning = () => running

/** Un passage planifié. Retourne le résumé (aussi enregistré). */
export async function runScheduled(sch?: Schedule): Promise<LastRun> {
  const s = sch ?? await getSchedule()
  running = true
  const t0 = Math.floor(Date.now() / 1000)
  try {
    if (runningJob()) throw new DiscoveryError('discovery_running')
    const all = await query<any>("select id, text(cidr) as c from subnets where family(cidr) = 4 and kind = 'network'" + (s.subnetIds.length ? ' and id = any($1)' : ''), s.subnetIds.length ? [s.subnetIds] : [])
    // dans la limite de la découverte : on prend les sous-réseaux dans l'ordre tant que le total tient
    const subs: any[] = []; let total = 0
    for (const r of all) { const n = enumerateTargets([r.c], cfg().allowPrivateFetch).ips.length; if (total + n > 4096) continue; subs.push(r); total += n }
    if (!subs.length) throw new DiscoveryError('discovery_empty')
    const targets = enumerateTargets(subs.map((r) => r.c), cfg().allowPrivateFetch)
    const methods = { ...s.methods }; if (methods.icmp && !(await pingWorks())) methods.icmp = false
    const found = await discoverHosts({ targets: targets.ips, ports: PORT_PRESETS.basic!, methods, concurrency: 32, timeoutMs: 800 }, realDeps(leaseMap))
    const byCidr = new Map<string, number>(subs.map((r) => [r.c as string, r.id as number]))
    const known = await query<KnownAddr>('select id, subnet_id, host(ip) as ip, hostname, mac::text as mac, status from addresses where subnet_id = any($1)', [subs.map((r) => r.id)])
    const res = classify(found, known, (ip) => byCidr.get(targets.subnetOf.get(ip)!)!)
    let knownN = 0, unknownN = 0, macN = 0
    for (const h of res.hosts) {
      if (h.status === 'new') { unknownN++; continue }
      if (!h.known) continue
      knownN++; if (h.status === 'mac_changed') macN++
      const nm = (h.ptr ?? h.leaseName)?.toLowerCase()
      await query('update addresses set last_seen = now(), mac = coalesce(mac, $2::macaddr), hostname = coalesce(hostname, $3) where id = $1',
        [h.known.id, h.mac && normMac(h.mac), nm && isValidDnsName(nm, false) ? nm : null])
    }
    // joignabilité : une adresse connue qui ne répond à aucune sonde ACTIVE est « injoignable » ; avec les seules méthodes passives (baux, DNS inverse)
    // l'absence de preuve n'est pas une preuve d'absence : on ne note alors que les hôtes qui répondent
    const alive = found.filter((h) => h.alive).map((h) => h.ip)
    const probing = methods.tcp || methods.icmp || methods.arp
    const unreach = probing
      ? (await query<any>('update addresses set reachable = (host(ip) = any($2)), checked_at = now() where subnet_id = any($1) returning reachable', [subs.map((r) => r.id), alive])).filter((r) => !r.reachable).length
      : (await query<any>('update addresses set reachable = true, checked_at = now() where subnet_id = any($1) and host(ip) = any($2) returning 1', [subs.map((r) => r.id), alive]), 0)
    const last: LastRun = { at: t0, ok: true, scanned: targets.ips.length, alive: found.filter((h) => h.alive).length, known: knownN, unknown: unknownN, macChanged: macN, unreachable: unreach }
    await setSetting('discovery_schedule_last', last)
    if (s.autoGhost) await applyGhosting(s.ghostDays)
    return last
  } catch (e: any) {
    const last: LastRun = { at: t0, ok: false, scanned: 0, alive: 0, known: 0, unknown: 0, macChanged: 0, unreachable: 0, error: e instanceof DiscoveryError ? e.code : 'discovery_failed' }
    if (!(e instanceof DiscoveryError)) console.error('[discovery-schedule]', e?.message ?? e)
    await setSetting('discovery_schedule_last', last)
    return last
  } finally { running = false }
}

/** Faut-il lancer un passage maintenant ? (pur, testable) */
export const isDue = (s: Schedule, last: LastRun | null, nowSec: number): boolean =>
  s.enabled && (!last || nowSec - last.at >= s.intervalHours * 3600)

/** Bascule automatique : « utilisée » non vue depuis `days` jours → « fantôme » ; « fantôme » revue depuis → « utilisée ».
 *  Une adresse jamais vérifiée n'est pas jugée (pas de preuve) ; sans « vue le », la date de création sert de référence une fois vérifiée. */
export async function applyGhosting(days: number): Promise<{ ghosted: number; revived: number }> {
  const ref = 'coalesce(last_seen, created_at)'
  const g = await query<any>(`update addresses set status = 'ghost', updated_at = now() where status = 'used' and checked_at is not null and ${ref} < now() - make_interval(days => $1) returning 1`, [days])
  const r = await query<any>(`update addresses set status = 'used', updated_at = now() where status = 'ghost' and last_seen is not null and last_seen >= now() - make_interval(days => $1) returning 1`, [days])
  return { ghosted: g.length, revived: r.length }
}
