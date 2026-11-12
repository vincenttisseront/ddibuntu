// Contrôle d'UNE adresse de l'IPAM : nom DNS (PTR, avec confirmation par l'enregistrement direct) et test de présence (TCP / ICMP / ARP / baux).
// Sert à « valider que l'hôte n'existe pas » avant de libérer une adresse, ou à retrouver le nom d'un hôte inconnu. Ne modifie ni le nom ni le statut.
import { Resolver } from 'node:dns/promises'
import { audit, fail, intParam, route } from '../utils/router'
import { one, query } from '../utils/db'
import { PORT_PRESETS, discoverHosts, pingWorks, realDeps } from '../utils/discovery'
import { leaseMap } from '../utils/leasemap'
import { allowAddress } from '../utils/scope'

export const registered = true

const forward = async (name: string): Promise<string[]> => {
  try { const r = new Resolver({ timeout: 1500, tries: 1 }); r.setServers(['127.0.0.1']); return await r.resolve4(name) } catch { return [] }
}

route('POST', '/ipam/addresses/:id/check', 'operator', async (c) => {
  const id = intParam(c, 'id')
  await allowAddress(c, id)
  const a = await one<any>('select a.id, host(a.ip) as ip, a.hostname, a.mac::text as mac, family(a.ip) as fam from addresses a where a.id = $1', [id])
  if (!a) fail(404, 'not_found')
  if (a.fam !== 4) fail(400, 'ipv4_only')
  const deps = realDeps(leaseMap)
  const methods = { tcp: true, icmp: await pingWorks(), arp: true, reverse: false, leases: true }
  const [found, ptr] = await Promise.all([
    discoverHosts({ targets: [a.ip], ports: PORT_PRESETS.basic!, methods, concurrency: 1, timeoutMs: 1200 }, deps),
    deps.reverse(a.ip),
  ])
  const h = found[0] ?? null
  const ptrForward = ptr ? await forward(ptr) : null
  const hostnameForward = a.hostname ? await forward(a.hostname) : null
  const alive = !!h
  // « réponse » prouve la présence ; « silence » ne prouve l'absence que de façon probable (pare-feu possible)
  const verdict = alive ? 'alive' : ptr ? 'dns_only' : 'absent'
  if (alive) await query('update addresses set reachable = true, checked_at = now(), last_seen = now(), mac = coalesce(mac, $2::macaddr), updated_at = now() where id = $1', [id, h!.mac])
  else await query('update addresses set reachable = false, checked_at = now() where id = $1', [id])
  await audit(c, 'address_check', 'address', id, { ip: a.ip, verdict })
  return {
    ip: a.ip, hostname: a.hostname, verdict, alive, via: h?.via ?? [], ports: h?.ports ?? [], mac: h?.mac ?? null, leaseName: h?.leaseName ?? null,
    ptr, ptrMatchesIp: ptr ? !!ptrForward?.includes(a.ip) : null, hostnameIps: hostnameForward, hostnameMatchesIp: a.hostname ? !!hostnameForward?.includes(a.ip) : null,
    methods: Object.entries(methods).filter(([k, v]) => v && ['tcp', 'icmp', 'arp'].includes(k)).map(([k]) => k),
  }
})
