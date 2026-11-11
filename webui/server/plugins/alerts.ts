// Évalue les alertes à intervalle régulier (DDI_ALERT_INTERVAL_MS, 0 = désactivé : les tests déclenchent l'évaluation eux-mêmes).
import { cfg } from '../utils/config'
import { inRecovery, isSchemaReady } from '../utils/db'
import { prune, runEvaluation } from '../utils/alert-engine'

export default defineNitroPlugin(() => {
  const every = cfg().alertIntervalMs
  if (every <= 0) return
  let lastPrune = 0, busy = false
  const tick = async () => {
    if (busy || !isSchemaReady()) return
    busy = true
    try {
      await runEvaluation()
      if (Date.now() - lastPrune > 3_600_000 && !(await inRecovery())) { lastPrune = Date.now(); await prune() }
    } catch (e: any) { console.error('[alerts]', e?.message ?? e) } finally { busy = false }
  }
  setTimeout(tick, Math.min(8000, every)).unref()   // premier passage peu après le démarrage
  setInterval(tick, every).unref()
})
