import { audit, fail, qstr, route } from '../utils/router'
import { one, query } from '../utils/db'
import { cfg } from '../utils/config'
import { applyConfig, buildConfig } from '../utils/apply'
import { capacity, parseCidr } from '../utils/net'
import { RECORD_TYPES } from '../utils/dns'
import { z } from 'zod'
import { reconcileDeployments, readReloadStatus } from '../utils/reload-status'
import { hostInfo } from '../utils/hostinfo'
import { ROLE_RANK } from '../utils/auth'
import { fileUpdateRequest, installedVersion, isBusy, readUpdateStatus } from '../utils/selfupdate'

route('GET', '/dashboard', 'viewer', async (c) => {
  const counts = await one<any>(`select (select count(*)::int from subnets) subnets, (select count(*)::int from addresses) addresses, (select count(*)::int from dns_zones) zones,
    (select count(*)::int from dns_records) records, (select count(*)::int from dhcp_scopes) scopes, (select count(*)::int from dhcp_reservations) reservations,
    (select count(*)::int from block_lists where enabled) lists, (select coalesce(sum(entries),0)::int from block_lists where enabled) blocked_domains,
    (select count(*)::int from dns_zones where dirty) dirty_zones`)
  const subs = await query<any>(`select s.id, text(s.cidr) as cidr, s.name, (select count(*)::int from addresses a where a.subnet_id = s.id) as used from subnets s`)
  const top = subs.map((s) => { const cap = capacity(parseCidr(s.cidr)!); return { ...s, capacity: cap > 1_000_000_000n ? null : Number(cap), percent: cap > 1_000_000_000n ? null : Math.round((s.used / Number(cap)) * 1000) / 10 } })
    .filter((s) => s.percent !== null).sort((a, b) => b.percent - a.percent).slice(0, 8)
  const byType = await query<any>('select type, count(*)::int as n from dns_records group by type order by n desc')
  const last = await one<any>('select id, at, ok, username from deployments order by id desc limit 1')
  const day = await query<any>("select kind, coalesce(sum(count),0)::bigint::text as n from dns_stats where bucket >= now() - interval '24 hours' group by kind")
  // état du système : lecture seule ; l'information de mise à jour n'est donnée qu'aux administrateurs
  const isAdmin = (ROLE_RANK[c.user?.role as keyof typeof ROLE_RANK] ?? 0) >= ROLE_RANK.admin
  const upd = isAdmin ? await readUpdateStatus() : null
  const system = { version: installedVersion(), host: await hostInfo(), lastApply: await readReloadStatus(), update: upd ? { available: upd.available, latest: upd.latest, busy: isBusy(upd), state: upd.state } : null }
  return { counts, top, byType, lastDeployment: last, day, system }
})

// Version et mise à jour disponible, pour la barre latérale (la mise à jour n'est révélée qu'aux administrateurs)
route('GET', '/about', 'viewer', async (c) => {
  const isAdmin = (ROLE_RANK[c.user?.role as keyof typeof ROLE_RANK] ?? 0) >= ROLE_RANK.admin
  const upd = isAdmin ? await readUpdateStatus() : null
  return { version: installedVersion(), hostname: (await hostInfo()).hostname, update: upd ? { available: upd.available, latest: upd.latest } : null }
})

route('GET', '/system/info', 'operator', async () => {
  const bins = [['named-checkzone', cfg().namedCheckzone], ['named-checkconf', cfg().namedCheckconf], ['kea-dhcp4', cfg().keaDhcp4]]
  const { execFile } = await import('node:child_process')
  const avail = await Promise.all(bins.map(([n, b]) => new Promise<{ name: string; ok: boolean }>((res) => execFile(b!, ['-V'], { timeout: 5000 }, (e: any) => res({ name: n!, ok: e?.code !== 'ENOENT' })))))
  const db = await one<any>('select version() as v, (select max(version) from schema_migrations) as schema')
  return { version: installedVersion() || '0.4.0', schema: db.schema, db: String(db.v).split(' ').slice(0, 2).join(' '), binaries: avail, recordTypes: RECORD_TYPES, generatedDir: cfg().generatedDir }
})

route('GET', '/system/render', 'operator', async () => {
  const { files, warnings } = await buildConfig()
  return { warnings, files: files.map((f) => ({ path: f.path, kind: f.kind, lines: f.content.split('\n').length, content: f.content.split('\n').slice(0, 400).join('\n'), truncated: f.content.split('\n').length > 400 })) }
})

// Valide toujours ; déploie seulement si tout est valide (et si demandé)
route('POST', '/system/apply', 'admin', async (c) => {
  const b = await c.body(z.object({ deploy: z.boolean().default(false) }))
  const r = await applyConfig({ deploy: b.deploy, username: c.user!.username })
  await audit(c, b.deploy ? 'config_deploy' : 'config_validate', 'config', undefined, { ok: r.ok, deployed: r.deployed })
  return r
})
route('GET', '/system/deployments', 'admin', async () => { await reconcileDeployments(); return { items: await query('select id, at, username, ok, applied, apply_message, snapshot_id, files, results from deployments order by id desc limit 30') } })

// Mises à jour en ligne (détection + installation depuis les releases GitHub signées, faites par root)
route('GET', '/system/update', 'admin', async () => { const st = await readUpdateStatus(); return { status: st, version: installedVersion(), busy: isBusy(st) } })
route('POST', '/system/update/check', 'admin', async (c) => {
  if (isBusy(await readUpdateStatus())) fail(409, 'update_busy')
  await fileUpdateRequest('check')
  await audit(c, 'update_check', 'system')
  return { requested: true }
})
route('POST', '/system/update/apply', 'admin', async (c) => {
  const b = await c.body(z.object({ version: z.string().regex(/^\d+\.\d+\.\d+$/) }))
  const st = await readUpdateStatus()
  if (isBusy(st)) fail(409, 'update_busy')
  // seule la version annoncée par la dernière recherche peut être demandée ; root la revérifie de son côté
  if (!st || !st.available || st.latest !== b.version) fail(409, 'update_unavailable')
  await fileUpdateRequest('apply', b.version)
  await audit(c, 'update_apply', 'system', undefined, { from: st.current, to: b.version })
  return { requested: true }
})
void fail; void qstr

// Valeur exportée et lue par le point d'entrée : empêche l'élimination du module par l'optimiseur
export const registered = true
