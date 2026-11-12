// Construction, validation et déploiement de la configuration DNS/DHCP à partir de la base.
import { promises as fs } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { readAdState } from './adkrb'
import { cfg } from './config'
import { decryptSecret } from './auth'
import { getSetting, one, query, tx } from './db'
import { nextSerial } from './dns'
import { captureSnapshot } from './snapshots'
import { resetPending } from './filterstate'
import { fail } from './router'
import { uncoveredLocal } from './views'
import type { ViewInfo } from './views'
import { DNS_DEFAULTS, KEA_DEFAULTS, deployFiles, renderKea, renderNamedOptions, renderNamedZones, renderRpz, rpzBase, validateFiles, zoneFile } from './render'
import type { CheckResult, DnsSettings, KeaScope, KeaSettings, OutFile, ZoneRow } from './render'

export async function loadDns(): Promise<DnsSettings> { return { ...DNS_DEFAULTS, ...(await getSetting<Partial<DnsSettings>>('dns', {})) } }
export async function loadKea(): Promise<any> { return { ...KEA_DEFAULTS, ...(await getSetting<any>('dhcp', {})) } }

export async function loadViews(): Promise<ViewInfo[]> {
  return (await query<any>('select id, name, position, match_clients, match_destinations, recursion from dns_views order by position, id')) as ViewInfo[]
}

export async function buildConfig(): Promise<{ files: OutFile[]; bumps: Array<{ id: number; serial: number }>; warnings: string[] }> {
  // le domaine Kerberos vient de l'état publié par root, jamais d'un réglage de la console : le rendu ne peut pas diverger de ce que root acceptera
  const dns: DnsSettings = { ...(await loadDns()), kerberosRealm: (await readAdState())?.realm ?? '' }
  const warnings: string[] = []
  const views = await loadViews()
  const zones = await query<any>(`select z.id, z.name, z.type, z.masters, z.forwarders, z.allow_transfer, z.ddns_enabled, z.ddns_secure, z.disabled, z.soa_mname, z.soa_rname, z.soa_refresh, z.soa_retry, z.soa_expire,
    z.soa_minimum, z.default_ttl, z.serial::text as serial, z.dirty, v.name as view from dns_zones z left join dns_views v on v.id = z.view_id order by z.name, v.position`)
  // BIND n'admet pas de zone hors vue dès qu'une vue existe : l'API l'empêche, et le rendu le vérifie une seconde fois (base modifiée à la main, restauration…)
  if (views.length && zones.some((z) => !z.view)) fail(409, 'zones_without_view')
  if (!views.length && zones.some((z) => z.view)) fail(409, 'zones_without_view')
  if (views.length) for (const ip of uncoveredLocal(views)) warnings.push(`view_local_uncovered:${ip}`)
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
    const rpzContent = renderRpz({ zone: dns.rpzZone, serial: Math.floor(Date.now() / 1000), action: dns.rpzAction, sinkhole4: dns.sinkhole4, sinkhole6: dns.sinkhole6 }, new Set(blocked), allowed)
    for (const base of views.length ? views.map((v) => rpzBase(v.name)) : [rpzBase()]) files.push({ path: `zones/${base}`, content: rpzContent, mode: 0o644, kind: 'rpz' })
  }
  const anyDdns = zones.some((z) => z.ddns_enabled && !z.disabled)
  files.push({ path: 'named.conf.options', content: renderNamedOptions(dns, anyDdns), mode: 0o644, kind: 'named' })
  files.push({ path: 'named.conf.zones', content: renderNamedZones(zones as ZoneRow[], dns, views), mode: 0o644, kind: 'named' })

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

/** Génération de configuration : compteur monotone tenu par des déclencheurs en base (toute écriture qui change DNS/DHCP/filtrage l'incrémente). */
export interface ConfigState { generation: number; deployed: number; pending: boolean; changed_at: string | null; deployed_at: string | null }
export async function configState(): Promise<ConfigState> {
  const r = await one<any>(`select (select generation::text from config_generation where id = 1) as g, (select changed_at from config_generation where id = 1) as at,
    coalesce((select max(generation) from deployments where ok and generation is not null), 0)::text as d,
    (select at from deployments where ok and generation is not null order by id desc limit 1) as dat`)
  const generation = Number(r?.g ?? 0), deployed = Number(r?.d ?? 0)
  return { generation, deployed, pending: generation > deployed, changed_at: r?.at ?? null, deployed_at: r?.dat ?? null }
}

// Copie des configurations pour le(s) nœud(s) secondaire(s) : sans mot de passe, baux en fichier local (le bloc HA est ajouté par root sur chaque nœud).
// Les fichiers BIND servent à dériver la configuration du secondaire ; les zones, elles, sont transférées (AXFR/IXFR signé TSIG), jamais copiées ici.
async function storeForFollowers(cl: { query: (t: string, p?: unknown[]) => Promise<unknown> }, files: OutFile[], generation: number): Promise<void> {
  const put = async (name: string, content: string) => {
    const sha = createHash('sha256').update(content).digest('hex')
    await cl.query(`insert into rendered_configs (name, content, generation, sha256) values ($1, $2, $3, $4)
      on conflict (name) do update set content = excluded.content, generation = excluded.generation, sha256 = excluded.sha256, deployed_at = now()`, [name, content, generation, sha])
  }
  const k = files.find((x) => x.kind === 'kea')
  if (k) {
    const d = JSON.parse(k.content)
    if (d?.Dhcp4) d.Dhcp4['lease-database'] = { type: 'memfile', persist: true, name: '/var/lib/kea/kea-leases4.csv', 'lfc-interval': 3600 }
    await put('kea-dhcp4.conf', JSON.stringify(d, null, 2) + '\n')
  }
  for (const f of files) if (f.kind === 'named' && (f.path === 'named.conf.options' || f.path === 'named.conf.zones')) await put(f.path, f.content)
}

export interface ApplyOutcome { ok: boolean; deployed: boolean; results: CheckResult[]; warnings: string[]; files: string[]; generation: number }
export async function applyConfig(opts: { deploy: boolean; username: string | null }): Promise<ApplyOutcome> {
  // lue AVANT le rendu : une modification survenue pendant le rendu laisse la configuration « en attente » (jamais l'inverse)
  const generation = (await configState()).generation
  const { files, bumps, warnings } = await buildConfig()
  const results = await validateFiles(files)
  // le serveur doit se résoudre lui-même : sans vue pour 127.0.0.1 / ::1, contrôles de santé et mises à jour locales échoueraient
  const unc = warnings.filter((w) => w.startsWith('view_local_uncovered:')).map((w) => w.split(':').slice(1).join(':'))
  if (unc.length) results.push({ name: 'vues DNS : couverture locale', ok: false, output: `aucune vue ne répond à ${unc.join(', ')} : ajoutez ces adresses (ou « localhost ») à la liste des clients d'une vue` })
  const ok = results.length > 0 && results.every((r) => r.ok === true || r.note === 'deferred')   // « différé » : ddibuntu-reload (root) tranche à l'application
  let deployed = false
  if (opts.deploy && ok) {
    const sums = await deployFiles(files, cfg().generatedDir, cfg().zonesRuntimeDir || undefined)
    await tx(async (cl) => {
      for (const b of bumps) await cl.query('update dns_zones set serial = $2, dirty = false where id = $1', [b.id, b.serial])
      // point de restauration de l'état qui vient d'être déployé : « revenir à ce déploiement » est possible à tout moment
      const snap = await captureSnapshot('deploy', 'état déployé', opts.username, cl)
      await cl.query('insert into deployments (username, ok, files, results, snapshot_id, generation) values ($1,$2,$3::jsonb,$4::jsonb,$5,$6)', [opts.username, true, JSON.stringify(sums), JSON.stringify(results), snap, generation])
      await storeForFollowers(cl, files, generation)
    })
    // le marqueur déclenche l'application privilégiée (unité systemd .path) : écrit en dernier
    await fs.writeFile(join(cfg().generatedDir, '.deployed'), `${Date.now()}\n`)
    await resetPending()
    deployed = true
  } else if (opts.deploy) {
    await one('insert into deployments (username, ok, files, results) values ($1,$2,$3::jsonb,$4::jsonb) returning id', [opts.username, false, '{}', JSON.stringify(results)])
  }
  return { ok, deployed, results, warnings, files: files.map((f) => f.path), generation }
}
