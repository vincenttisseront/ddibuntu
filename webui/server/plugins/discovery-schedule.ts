// Lance la découverte planifiée quand elle est due (vérification chaque minute ; primaire uniquement, la base des secondaires est en lecture seule).
import { inRecovery, isSchemaReady } from '../utils/db'
import { applyGhosting, getLastRun, getSchedule, isDue, runScheduled } from '../utils/discovery-schedule'

export default defineNitroPlugin(() => {
  if (process.env.DDI_DISCOVERY_SCHEDULE_MS === '0') return
  let busy = false
  const tick = async () => {
    if (busy || !isSchemaReady()) return
    busy = true
    try {
      if (await inRecovery()) return
      const s = await getSchedule()
      if (isDue(s, await getLastRun(), Math.floor(Date.now() / 1000))) await runScheduled(s)
      if (s.autoGhost) await applyGhosting(s.ghostDays)   // à chaque minute : peu coûteux, et un changement de réglage s'applique sans attendre le prochain scan
    } catch (e: any) { console.error('[discovery-schedule]', e?.message ?? e) } finally { busy = false }
  }
  setTimeout(tick, 30_000).unref()
  setInterval(tick, Number(process.env.DDI_DISCOVERY_SCHEDULE_MS) || 60_000).unref()
})
