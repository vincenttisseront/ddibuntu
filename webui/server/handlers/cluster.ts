import { route } from '../utils/router'
import { inRecovery } from '../utils/db'
import { readClusterState } from '../utils/cluster'

// Public et minimal : l'écran de connexion d'un nœud secondaire doit pouvoir l'expliquer (aucune adresse ni nom de nœud).
route('GET', '/cluster/role', 'public', async () => ({ replica: await inRecovery() }))

// État détaillé (lecture seule) : nœuds, leader, quorum, Kea HA, adresse virtuelle, rôle BIND.
route('GET', '/cluster/status', 'viewer', async () => {
  const state = await readClusterState()
  return { clustered: state !== null, replica: await inRecovery(), state }
})

export const registered = true
