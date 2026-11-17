// Envoi périodique des journaux vers les SIEM configurés (DDI_SIEM_INTERVAL_MS, 0 = désactivé : les tests déclenchent l'envoi eux-mêmes).
// Seul le nœud principal envoie (la base d'un secondaire est en lecture seule et les curseurs y seraient perdus).
import { cfg } from '../utils/config'
import { inRecovery, isSchemaReady } from '../utils/db'
import { runSiem } from '../utils/siem'

export default defineNitroPlugin(() => {
  const every = cfg().siemIntervalMs
  if (every <= 0) return
  const tick = async () => {
    if (!isSchemaReady()) return
    try { if (!(await inRecovery())) await runSiem() } catch (e: any) { console.error('[siem]', e?.message ?? e) }
  }
  setTimeout(tick, Math.min(10_000, every)).unref()
  setInterval(tick, every).unref()
})
