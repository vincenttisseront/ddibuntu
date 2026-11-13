// Historise les baux DHCP actifs à intervalle régulier (DDI_LEASETRACE_INTERVAL_MS, 0 = désactivé) ; primaire uniquement.
import { cfg } from '../utils/config'
import { inRecovery, isSchemaReady } from '../utils/db'
import { reconcileLeaseDns } from '../utils/lease-dns'
import { pruneTrace, snapshotLeases } from '../utils/leasetrace'

export default defineNitroPlugin(() => {
  const every = cfg().leaseTraceIntervalMs
  if (every <= 0) return
  let busy = false, lastPrune = 0
  const tick = async () => {
    if (busy || !isSchemaReady()) return
    busy = true
    try {
      await snapshotLeases()
      await reconcileLeaseDns()
      if (Date.now() - lastPrune > 3_600_000 && !(await inRecovery())) { lastPrune = Date.now(); await pruneTrace(cfg().leaseTraceRetentionDays) }
    } catch (e: any) { console.error('[leasetrace]', e?.message ?? e) } finally { busy = false }
  }
  setTimeout(tick, Math.min(10000, every)).unref()
  setInterval(tick, every).unref()
})
