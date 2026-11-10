import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { inRecovery } from '../utils/db'
import { cfg } from '../utils/config'
import { readClusterState, readSwitchoverResult, switchoverCandidates } from '../utils/cluster'

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

export const registered = true
