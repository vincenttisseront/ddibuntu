// Construction, validation et déploiement de la configuration DNS/DHCP à partir de la base.
import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { cfg } from './config'
import { decryptSecret } from './auth'
import { getSetting, one, query, tx } from './db'
import { nextSerial } from './dns'
import { captureSnapshot } from './snapshots'
import { resetPending } from './filterstate'
import { DNS_DEFAULTS, KEA_DEFAULTS, deployFiles, renderKea, renderNamedOptions, renderNamedZones, renderRpz, validateFiles, zoneFile } from './render'
import type { CheckResult, DnsSettings, KeaScope, KeaSettings, OutFile, ZoneRow } from './render'

export async function loadDns(): Promise<DnsSettings> { return { ...DNS_DEFAULTS, ...(await getSetting<Partial<DnsSettings>>('dns', {})) } }
export async function loadKea(): Promise<any> { return { ...KEA_DEFAULTS, ...(await getSetting<any>('dhcp', {})) } }

export async function buildConfig(): Promise<{ files: OutFile[]; bumps: Array<{ id: number; serial: number }>; warnings: string[] }> {
  const dns = await loadDns()
  const warnings: string[] = []
  const zones = await query<any>(`select id, name, type, masters, forwarders, allow_transfer, ddns_enabled, disabled, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire,
    soa_minimum, default_ttl, serial::text as serial, dirty from dns_zones order by name`)
  const files: OutFile[] = []
  const bumps: Array<{ id: number; serial: number }> = []
  for (const z of zones) {
    if (z.type !== 'primary' || z.disabled) continue
    const recs = await query<any>('select name, type, ttl, rdata, disabled from dns_records where zone_id = $1', [z.id])
    const serial = z.dirty ? nextSerial(Number(z.serial)) : Number(z.serial)
    if (z.dirty) bumps.push({ id: z.id, serial })
    if (!recs.some((r) => r.type === 'NS' && r.name === '@' && !r.disabled)) warnings.push(`zone_without_ns:${z.name}`)
    files.push(zoneFile({ ...z, serial } as ZoneRow, recs))
  }
  if (dns.rpzEnabled) {
    const blocked = (await query<any>('select distinct e.domain from block_entries e join block_lists l on l.id = e.list_id where l.enabled')).map((r) => r.domain as string)
    for (const r of await query<any>("select domain from filter_rules where action = 'block'")) blocked.push(r.domain)
    const allowed = (await query<any>("select domain from filter_rules where action = 'allow'")).map((r) => r.domain as string)
    files.push({ path: 'zones/db.rpz', content: renderRpz({ zone: dns.rpzZone, serial: Math.floor(Date.now() / 1000), action: dns.rpzAction, sinkhole4: dns.sinkhole4, sinkhole6: dns.sinkhole6 }, new Set(blocked), allowed), mode: 0o644, kind: 'rpz' })
  }
  const anyDdns = zones.some((z) => z.ddns_enabled && !z.disabled)
  files.push({ path: 'named.conf.options', content: renderNamedOptions(dns, anyDdns), mode: 0o644, kind: 'named' })
  files.push({ path: 'named.conf.zones', content: renderNamedZones(zones as ZoneRow[], dns), mode: 0o644, kind: 'named' })

  const ks: KeaSettings = await loadKea()
  const lease = { ...ks.lease }
  const enc = (ks.lease as any).passwordEnc
  if (lease.type === 'postgresql') lease.password = enc ? decryptSecret(enc) : cfg().keaDbPassword
  const scopes = await query<any>('select d.id, text(s.cidr) as cidr, d.enabled, d.lease_time, d.options from dhcp_scopes d join subnets s on s.id = d.subnet_id order by s.cidr')
  const kscopes: KeaScope[] = []
  for (const sc of scopes) {
    const pools = await query<any>('select host(start_ip) as start, host(end_ip) as "end" from dhcp_pools where scope_id = $1 order by start_ip', [sc.id])
    const res = await query<any>('select mac::text as mac, host(ip) as ip, hostname from dhcp_reservations where scope_id = $1 order by ip', [sc.id])
    if (sc.enabled && !pools.length) warnings.push(`scope_without_pool:${sc.cidr}`)
    kscopes.push({ id: sc.id, cidr: sc.cidr, enabled: sc.enabled, leaseTime: sc.lease_time, options: sc.options, pools, reservations: res })
  }
  files.push({ path: 'kea-dhcp4.conf', content: renderKea({ ...ks, lease }, kscopes), mode: 0o640, kind: 'kea' })
  return { files, bumps, warnings }
}

export interface ApplyOutcome { ok: boolean; deployed: boolean; results: CheckResult[]; warnings: string[]; files: string[] }
export async function applyConfig(opts: { deploy: boolean; username: string | null }): Promise<ApplyOutcome> {
  const { files, bumps, warnings } = await buildConfig()
  const results = await validateFiles(files)
  const ok = results.length > 0 && results.every((r) => r.ok === true)
  let deployed = false
  if (opts.deploy && ok) {
    const sums = await deployFiles(files, cfg().generatedDir, cfg().zonesRuntimeDir || undefined)
    await tx(async (cl) => {
      for (const b of bumps) await cl.query('update dns_zones set serial = $2, dirty = false where id = $1', [b.id, b.serial])
      // point de restauration de l'état qui vient d'être déployé : « revenir à ce déploiement » est possible à tout moment
      const snap = await captureSnapshot('deploy', 'état déployé', opts.username, cl)
      await cl.query('insert into deployments (username, ok, files, results, snapshot_id) values ($1,$2,$3::jsonb,$4::jsonb,$5)', [opts.username, true, JSON.stringify(sums), JSON.stringify(results), snap])
    })
    // le marqueur déclenche l'application privilégiée (unité systemd .path) : écrit en dernier
    await fs.writeFile(join(cfg().generatedDir, '.deployed'), `${Date.now()}\n`)
    await resetPending()
    deployed = true
  } else if (opts.deploy) {
    await one('insert into deployments (username, ok, files, results) values ($1,$2,$3::jsonb,$4::jsonb) returning id', [opts.username, false, '{}', JSON.stringify(results)])
  }
  return { ok, deployed, results, warnings, files: files.map((f) => f.path) }
}
