import { z } from 'zod'
import { audit, fail, intParam, route } from '../utils/router'
import { one, query } from '../utils/db'
import { captureSnapshot, diffSnapshot, restoreSnapshot } from '../utils/snapshots'
import { applyConfig } from '../utils/apply'
import { readReloadStatus, reconcileDeployments } from '../utils/reload-status'

const COLS = 'id, at, username, kind, label, counts, size, pinned'

route('GET', '/snapshots', 'operator', async () => ({ items: await query(`select ${COLS} from config_snapshots order by id desc limit 100`) }))

route('POST', '/snapshots', 'operator', async (c) => {
  const b = await c.body(z.object({ label: z.string().trim().max(200).default('') }))
  const id = await captureSnapshot('manual', b.label || 'point de restauration manuel', c.user!.username)
  await audit(c, 'snapshot_create', 'snapshot', id, { label: b.label })
  return { id }
})

route('PUT', '/snapshots/:id', 'admin', async (c) => {
  const id = intParam(c, 'id')
  const b = await c.body(z.object({ pinned: z.boolean().optional(), label: z.string().trim().max(200).optional() }))
  const r = await one(`update config_snapshots set pinned = coalesce($2, pinned), label = coalesce($3, label) where id = $1 returning ${COLS}`, [id, b.pinned ?? null, b.label ?? null])
  if (!r) fail(404, 'not_found')
  await audit(c, 'snapshot_update', 'snapshot', id, b)
  return r
})

route('DELETE', '/snapshots/:id', 'admin', async (c) => {
  const id = intParam(c, 'id')
  const r = await query('delete from config_snapshots where id = $1 returning id', [id])
  if (!r.length) fail(404, 'not_found')
  await audit(c, 'snapshot_delete', 'snapshot', id)
  return { ok: true }
})

// Ce que fera la restauration, avant de la confirmer
route('GET', '/snapshots/:id/diff', 'admin', async (c) => {
  const id = intParam(c, 'id')
  const meta = await one(`select ${COLS} from config_snapshots where id = $1`, [id])
  const diff = await diffSnapshot(id)
  if (!meta || !diff) fail(404, 'not_found')
  return { snapshot: meta, diff }
})

route('POST', '/snapshots/:id/restore', 'admin', async (c) => {
  const id = intParam(c, 'id')
  const b = await c.body(z.object({ deploy: z.boolean().default(false) }))
  const r = await restoreSnapshot(id, c.user!.username)
  await audit(c, 'snapshot_restore', 'snapshot', id, { preSnapshot: r.preSnapshot, deploy: b.deploy })
  // Les données sont revenues ; le déploiement (qui prend lui-même un point) est une seconde étape, validée par les outils officiels.
  const applied = b.deploy ? await applyConfig({ deploy: true, username: c.user!.username }) : null
  return { ...r, applied }
})

// Résultat réel du dernier rechargement privilégié (accepté, ou retour arrière automatique)
route('GET', '/system/reload-status', 'operator', async () => ({ status: await reconcileDeployments() ?? await readReloadStatus() }))

export const registered = true
