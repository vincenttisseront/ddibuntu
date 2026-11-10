import { requireSecret } from '../utils/config'
import { migrate } from '../utils/db'
import { purgeSessions } from '../utils/auth'

export default defineNitroPlugin(async () => {
  requireSecret()   // arrêt immédiat si la clé de chiffrement des secrets est absente
  for (let i = 1; i <= 10; i++) {
    try {
      const applied = await migrate()
      if (applied.length) console.log(`[db] migrations appliquées : ${applied.join(', ')}`)
      break
    } catch (e: any) {
      console.error(`[db] migration impossible (essai ${i}/10) : ${e?.message ?? e}`)
      if (i === 10) throw e
      await new Promise((r) => setTimeout(r, 2000))
    }
  }
  setInterval(() => purgeSessions().catch(() => undefined), 3_600_000).unref()
})
