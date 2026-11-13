// Points de restauration des DONNÉES de configuration (IPAM, DNS, DHCP, règles de filtrage, paramètres DNS/DHCP).
// Un point est pris avant chaque déploiement et chaque import ; restaurer remplace ces tables dans UNE transaction
// (tout ou rien) et conserve d'abord l'état actuel dans un nouveau point : la restauration est elle-même réversible.
import type { PoolClient } from 'pg'
import { getPool, tx } from './db'
import { fail } from './router'
import { byCodeUnit } from './text'

// Ordre = dépendances (parents d'abord). Les listes de blocage (volumineuses, retéléchargeables), les utilisateurs,
// sessions, journaux, statistiques et baux Kea n'en font pas partie.
export const SNAPSHOT_TABLES = ['vlans', 'ipam_spaces', 'dns_views', 'dns_zones', 'dns_records', 'network_templates', 'subnets', 'ipam_pools', 'addresses', 'dhcp_scopes', 'dhcp_pools', 'dhcp_reservations', 'dhcp_classes', 'filter_rules'] as const
const SETTING_KEYS = ['dns', 'dhcp']
export type SnapshotKind = 'manual' | 'deploy' | 'pre-import' | 'pre-restore'
const KEEP = 40, KEEP_DEPLOY = 20
type Runner = Pick<PoolClient, 'query'>
const runner = (cl?: Runner): Runner => cl ?? getPool()

async function schemaVersion(r: Runner): Promise<number> { return (await r.query('select max(version)::int as v from schema_migrations')).rows[0].v as number }

export async function readState(r: Runner): Promise<Record<string, any>> {
  const data: Record<string, any> = {}
  for (const t of SNAPSHOT_TABLES) data[t] = (await r.query(`select coalesce(jsonb_agg(to_jsonb(x) order by x.id), '[]'::jsonb) as j from ${t} x`)).rows[0].j
  data.settings = (await r.query("select coalesce(jsonb_object_agg(key, value), '{}'::jsonb) as j from settings where key = any($1)", [SETTING_KEYS])).rows[0].j
  return data
}

export async function captureSnapshot(kind: SnapshotKind, label: string, username: string | null, cl?: Runner, prune = true): Promise<number> {
  const r = runner(cl)
  const data = await readState(r)
  const counts: Record<string, number> = {}
  for (const t of SNAPSHOT_TABLES) counts[t] = data[t].length
  const json = JSON.stringify(data)
  const id = (await r.query('insert into config_snapshots (username, kind, label, schema_version, counts, size, data) values ($1,$2,$3,$4,$5::jsonb,$6,$7::jsonb) returning id',
    [username, kind, label.slice(0, 200), await schemaVersion(r), JSON.stringify(counts), json.length, json])).rows[0].id as number
  // conservation : les 40 plus récents (hors épinglés, jamais supprimés) + ceux des 20 derniers déploiements
  if (prune) await r.query(`delete from config_snapshots where not pinned and id not in (select id from config_snapshots order by id desc limit ${KEEP})
    and id not in (select snapshot_id from deployments where snapshot_id is not null order by id desc limit ${KEEP_DEPLOY})`)
  return id
}

const LABELS: Record<string, (x: any) => string> = {
  vlans: (x) => `VLAN ${x.vlan_id} ${x.name}`, ipam_spaces: (x) => String(x.name), network_templates: (x) => String(x.name), ipam_pools: (x) => `${x.name} ${x.start_ip} – ${x.end_ip}`, subnets: (x) => String(x.cidr), addresses: (x) => String(x.ip), dns_zones: (x) => String(x.name),
  dns_views: (x) => String(x.name),
  dns_records: (x) => `${x.name} ${x.type} ${x.rdata}`, dhcp_scopes: (x) => `scope #${x.id}`, dhcp_pools: (x) => `${x.start_ip} – ${x.end_ip}`,
  dhcp_reservations: (x) => `${x.mac} → ${x.ip}`, dhcp_classes: (x) => String(x.name), filter_rules: (x) => `${x.action} ${x.domain}`,
}
// sérialisation stable (clés triées à tous les niveaux) pour comparer deux lignes ; les horodatages ne comptent pas comme un changement
const stable = (v: any): string => (v && typeof v === 'object' ? (Array.isArray(v) ? `[${v.map(stable).join(',')}]` : `{${Object.keys(v).sort(byCodeUnit).map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(',')}}`) : JSON.stringify(v))
const strip = (o: any) => { const { updated_at, created_at, ...rest } = o ?? {}; void updated_at; void created_at; return stable(rest) }

export interface TableDiff { removed: number; restored: number; changed: number; samples: { removed: string[]; restored: string[]; changed: string[] } }
/** Ce que fera la restauration : « removed » = présent maintenant et absent du point (sera supprimé), « restored » = l'inverse. */
export async function diffSnapshot(id: number): Promise<Record<string, TableDiff> | null> {
  const row = (await getPool().query('select data from config_snapshots where id = $1', [id])).rows[0]
  if (!row) return null
  const cur = await readState(getPool()), old = row.data as Record<string, any>
  const out: Record<string, TableDiff> = {}
  for (const t of SNAPSHOT_TABLES) {
    const a = new Map<number, any>((cur[t] as any[]).map((x) => [x.id, x])), b = new Map<number, any>(((old[t] ?? []) as any[]).map((x) => [x.id, x]))
    const d: TableDiff = { removed: 0, restored: 0, changed: 0, samples: { removed: [], restored: [], changed: [] } }
    const lab = LABELS[t]!
    for (const [k, x] of a) { if (!b.has(k)) { d.removed++; if (d.samples.removed.length < 8) d.samples.removed.push(lab(x)) } else if (strip(x) !== strip(b.get(k))) { d.changed++; if (d.samples.changed.length < 8) d.samples.changed.push(lab(b.get(k))) } }
    for (const [k, x] of b) if (!a.has(k)) { d.restored++; if (d.samples.restored.length < 8) d.samples.restored.push(lab(x)) }
    if (d.removed || d.restored || d.changed) out[t] = d
  }
  const sa = cur.settings ?? {}, sb = old.settings ?? {}
  const sd = SETTING_KEYS.filter((k) => JSON.stringify(sa[k] ?? null) !== JSON.stringify(sb[k] ?? null))
  if (sd.length) out.settings = { removed: 0, restored: 0, changed: sd.length, samples: { removed: [], restored: [], changed: sd } }
  return out
}

/** Remplace les tables de configuration par celles du point. Atomique ; l'état actuel est d'abord conservé (« pre-restore »). */
export async function restoreSnapshot(id: number, username: string | null): Promise<{ preSnapshot: number; counts: Record<string, number> }> {
  return tx(async (cl) => {
    const snap = (await cl.query('select schema_version, data from config_snapshots where id = $1 for share', [id])).rows[0]
    if (!snap) fail(404, 'not_found')
    // Ce format de données est celui de CETTE version du schéma : on ne tente pas de deviner pour un autre.
    if (snap.schema_version !== (await schemaVersion(cl))) fail(409, 'snapshot_schema_mismatch')
    // pas de purge pendant une restauration : elle pourrait supprimer le point en cours de restauration
    const preSnapshot = await captureSnapshot('pre-restore', `avant la restauration du point #${id}`, username, cl, false)
    const serials = new Map<string, bigint>((await cl.query(`select lower(z.name) || '|' || coalesce(v.name, '') as n, z.serial::text as s from dns_zones z left join dns_views v on v.id = z.view_id`)).rows.map((r: any) => [r.n as string, BigInt(r.s)]))
    for (const t of [...SNAPSHOT_TABLES].reverse()) await cl.query(`delete from ${t}`)
    const data = snap.data as Record<string, any>, counts: Record<string, number> = {}
    for (const t of SNAPSHOT_TABLES) {
      const rows = (data[t] ?? []) as any[]; counts[t] = rows.length
      if (rows.length) await cl.query(`insert into ${t} select * from jsonb_populate_recordset(null::${t}, $1::jsonb)`, [JSON.stringify(rows)])
      await cl.query(`select setval(pg_get_serial_sequence('${t}', 'id'), greatest((select coalesce(max(id), 0) from ${t}), 1), (select count(*) > 0 from ${t}))`)
    }
    // Un secondaire ignore une zone dont le numéro de série baisse : on repart de « plus grand que tout ce qui a été publié ».
    for (const [name, serial] of serials) await cl.query(`update dns_zones z set serial = greatest(z.serial, $2::bigint) + 1 where lower(z.name) || '|' || coalesce((select v.name from dns_views v where v.id = z.view_id), '') = $1`, [name, serial.toString()])
    await cl.query("update dns_zones set dirty = true where type = 'primary'")
    await cl.query('delete from settings where key = any($1)', [SETTING_KEYS])
    for (const k of SETTING_KEYS) if (data.settings?.[k] !== undefined) await cl.query('insert into settings (key, value) values ($1, $2::jsonb)', [k, JSON.stringify(data.settings[k])])
    return { preSnapshot, counts }
  })
}
