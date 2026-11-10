// Découverte réseau : lancement, suivi, annulation, import des hôtes choisis. Un seul travail à la fois ; sous-réseaux déjà déclarés uniquement.
import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { one, query, tx } from '../utils/db'
import { cfg } from '../utils/config'
import { isValidDnsName, normMac } from '../utils/net'
import { DiscoveryError, PORT_PRESETS, classify, discoverHosts, enumerateTargets, jobs, pingWorks, realDeps, runningJob, sweepJobs } from '../utils/discovery'
import type { Job, KnownAddr } from '../utils/discovery'
import { preImportSnapshot, record } from './importer'

const leaseMap = async () => {
  const out = new Map<string, { mac: string; hostname: string | null }>()
  const t = await one<any>("select to_regclass('public.lease4') is not null as ok")
  if (!t?.ok) return out
  try {
    for (const r of await query<any>(`select ((address >> 24) & 255) || '.' || ((address >> 16) & 255) || '.' || ((address >> 8) & 255) || '.' || (address & 255) as ip, encode(hwaddr, 'hex') as mac, hostname from lease4 where expire > now()`))
      out.set(r.ip, { mac: (r.mac as string).match(/.{2}/g)?.join(':') ?? '', hostname: r.hostname || null })
  } catch { /* table de baux indisponible */ }
  return out
}

route('GET', '/discovery/capabilities', 'operator', async () => ({ icmp: await pingWorks(), maxTargets: 4096, presets: PORT_PRESETS }))

const startBody = z.object({
  subnet_ids: z.array(z.number().int().positive()).min(1).max(50),
  methods: z.object({ tcp: z.boolean(), icmp: z.boolean(), arp: z.boolean(), reverse: z.boolean(), leases: z.boolean() }),
  ports: z.union([z.enum(['basic', 'windows', 'web', 'infra']), z.array(z.number().int().min(1).max(65535)).min(1).max(20)]).default('basic'),
  timeoutMs: z.number().int().min(200).max(3000).default(800),
})

route('POST', '/discovery/start', 'operator', async (c) => {
  const b = await c.body(startBody)
  sweepJobs()
  if (runningJob()) fail(409, 'discovery_running')
  const subs = await query<any>('select id, text(cidr) as c from subnets where id = any($1)', [b.subnet_ids])
  if (subs.length !== new Set(b.subnet_ids).size) fail(404, 'not_found')
  let targets
  try { targets = enumerateTargets(subs.map((s) => s.c), cfg().allowPrivateFetch) } catch (e) { if (e instanceof DiscoveryError) fail(400, e.code); throw e }
  if (!targets.ips.length) fail(400, 'discovery_empty')
  const subnetByCidr = new Map<string, number>(subs.map((s) => [s.c as string, s.id as number]))
  const ports = Array.isArray(b.ports) ? b.ports : PORT_PRESETS[b.ports]!
  const job: Job = { id: randomUUID(), user: c.user!.username, state: 'running', startedAt: Date.now(), total: targets.ips.length, done: 0, alive: 0, warnings: targets.skipped, stop: false }
  if (b.methods.icmp && !(await pingWorks())) { b.methods.icmp = false; job.warnings.push('icmp_unavailable') }
  jobs.set(job.id, job)
  await audit(c, 'discovery_start', 'discovery', job.id, { subnets: subs.map((s) => s.c), methods: b.methods, ports: b.methods.tcp ? ports : [] })
  // exécution en arrière-plan : la requête rend la main tout de suite, l'interface interroge l'avancement
  void (async () => {
    try {
      const found = await discoverHosts({ targets: targets.ips, ports, methods: b.methods, concurrency: 64, timeoutMs: b.timeoutMs }, realDeps(leaseMap),
        (d, a) => { job.done = d; job.alive = a }, () => job.stop)
      const known = await query<KnownAddr>('select id, subnet_id, host(ip) as ip, hostname, mac::text as mac, status from addresses where subnet_id = any($1)', [subs.map((s) => s.id)])
      job.result = classify(found, known, (ip) => subnetByCidr.get(targets.subnetOf.get(ip)!)!)
      job.state = job.stop ? 'cancelled' : 'done'
    } catch (e: any) { job.state = 'error'; job.error = 'discovery_failed'; console.error('[discovery]', e?.message) }
  })()
  return { id: job.id, total: job.total, warnings: job.warnings }
})

const getJob = (id: string): Job => { const j = jobs.get(id); if (!j) fail(404, 'not_found'); return j }
route('GET', '/discovery/:id', 'operator', async (c) => {
  const j = getJob(c.params.id!)
  return { id: j.id, state: j.state, total: j.total, done: j.done, alive: j.alive, warnings: j.warnings, error: j.error, result: j.state === 'running' ? undefined : j.result }
})
route('POST', '/discovery/:id/cancel', 'operator', async (c) => { const j = getJob(c.params.id!); j.stop = true; return { ok: true } })

route('POST', '/discovery/:id/commit', 'operator', async (c) => {
  const j = getJob(c.params.id!)
  if (j.state !== 'done' && j.state !== 'cancelled') fail(409, 'discovery_running')
  const b = await c.body(z.object({ ips: z.array(z.string().max(45)).max(4096), updateKnown: z.boolean().default(false) }))
  const pick = new Set(b.ips), hosts = (j.result?.hosts ?? [])
  const snapshotId = await preImportSnapshot(c, `avant import de la découverte (${pick.size} adresse(s))`)
  const out = { created: 0, updated: 0, skipped: 0, snapshotId }
  await tx(async (cl) => {
    for (const h of hosts) {
      if (h.status === 'new' && pick.has(h.ip)) {
        const name = h.ptr ?? h.leaseName, host = name && isValidDnsName(name.toLowerCase(), false) ? name.toLowerCase() : null
        const r = await cl.query("insert into addresses (subnet_id, ip, status, hostname, mac, description, source, last_seen) values ($1,$2,'used',$3,$4,$5,'discovery',now()) on conflict (subnet_id, ip) do nothing",
          [h.subnetId, h.ip, host, h.mac && normMac(h.mac), `découvert le ${new Date().toISOString().slice(0, 10)}`])
        if (r.rowCount) out.created++; else out.skipped++
      } else if (h.known && b.updateKnown) {
        // adresses connues : on note qu'elles répondent, et on complète sans jamais remplacer ce qui est déjà saisi
        const r = await cl.query('update addresses set last_seen = now(), mac = coalesce(mac, $2::macaddr), hostname = coalesce(hostname, $3), updated_at = now() where id = $1',
          [h.known.id, h.mac && normMac(h.mac), (h.ptr ?? h.leaseName) && isValidDnsName((h.ptr ?? h.leaseName)!.toLowerCase(), false) ? (h.ptr ?? h.leaseName)!.toLowerCase() : null])
        out.updated += r.rowCount ?? 0
      }
    }
  })
  await record(c, 'discovery', undefined, out, snapshotId)
  await audit(c, 'discovery_import', 'discovery', j.id, out)
  return out
})

export const registered = true
