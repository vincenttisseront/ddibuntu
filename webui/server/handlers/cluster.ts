import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { inRecovery } from '../utils/db'
import { cfg } from '../utils/config'
import { actionRefusal, readClusterState, readSwitchoverResult, switchoverCandidates } from '../utils/cluster'

// Public et minimal : l'écran de connexion d'un nœud secondaire doit pouvoir l'expliquer (aucune adresse ni nom de nœud).
route('GET', '/cluster/role', 'public', async () => ({ replica: await inRecovery() }))

// État détaillé (lecture seule) : nœuds, leader, quorum, Kea HA, adresse virtuelle, rôle BIND.
route('GET', '/cluster/status', 'viewer', async () => {
  const state = await readClusterState()
  return { clustered: state !== null, replica: await inRecovery(), state, candidates: switchoverCandidates(state), result: await readSwitchoverResult() }
})

// Bascule contrôlée : la console ne fait que DÉPOSER une demande (un nom de nœud) ; root la valide de nouveau et l'exécute (ddibuntu-cluster request).
const Switchover = z.object({ candidate: z.string().regex(/^[a-z][a-z0-9-]{1,30}$/) }).strict()
route('POST', '/cluster/switchover', 'admin', async (c) => {
  const { candidate } = await c.body(Switchover)
  const st = await readClusterState()
  if (!st) fail(409, 'not_clustered')
  if (st.stale) fail(409, 'cluster_state_stale')
  if (!switchoverCandidates(st).includes(candidate)) fail(409, 'invalid_candidate')
  await fs.writeFile(join(cfg().generatedDir, '.cluster-switchover'), candidate + '\n', { mode: 0o640 })
  await audit(c, 'cluster.switchover', 'node', candidate)
  return { accepted: true }
})

// Actualisation immédiate de l'état (sondes etcd en direct) : root republie l'état dans la seconde. Sans effet sur le cluster.
async function drop(file: string, body: string): Promise<void> {
  const f = join(cfg().generatedDir, file)
  try { await fs.stat(f); fail(409, 'action_pending') } catch (e: any) { if (e?.code !== 'ENOENT') throw e }
  await fs.writeFile(f, body, { mode: 0o640, flag: 'wx' })
}
route('POST', '/cluster/refresh', 'operator', async () => {
  await drop('.cluster-action', JSON.stringify({ action: 'refresh' }))
  return { accepted: true }
})

// Opérations de reprise : retrait d'un nœud perdu, reprise de l'autorité de certification, reconstruction après perte du quorum.
// La confirmation saisie (nom du nœud / du nœud courant / du cluster) est revérifiée ici ET par root.
const NAME = z.string().regex(/^[a-z][a-z0-9-]{1,30}$/)
const Action = z.discriminatedUnion('action', [
  z.object({ action: z.literal('remove-node'), node: NAME, confirm: z.string().max(64) }).strict(),
  z.object({ action: z.literal('take-ca'), confirm: z.string().max(64) }).strict(),
  z.object({ action: z.literal('recover'), confirm: z.string().max(64) }).strict(),
])
route('POST', '/cluster/action', 'admin', async (c) => {
  const a = await c.body(Action)
  const st = await readClusterState()
  const refusal = actionRefusal(st, a)
  if (refusal) fail(409, refusal)
  await drop('.cluster-action', JSON.stringify(a))
  await audit(c, `cluster.${a.action}`, 'node', a.action === 'remove-node' ? a.node : (st?.node ?? ''))
  return { accepted: true }
})

export const registered = true
