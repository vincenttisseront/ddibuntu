import { requireSecret } from '../utils/config'
import { inRecovery, isSchemaReady, migrate, SchemaPendingError } from '../utils/db'
import { purgeSessions } from '../utils/auth'

export default defineNitroPlugin(async () => {
  requireSecret()   // arrêt immédiat si la clé de chiffrement des secrets est absente
  for (let i = 1; i <= 10; i++) {
    try {
      const applied = await migrate()
      if (applied.length) console.log(`[db] migrations appliquées : ${applied.join(', ')}`)
      break
    } catch (e: any) {
      if (e instanceof SchemaPendingError) { console.warn(`[db] ${e.message}`); break }   // secondaire en attente du leader : on ne plante pas, on attend (surveillance ci-dessous)
      console.error(`[db] migration impossible (essai ${i}/10) : ${e?.message ?? e}`)
      if (i === 10) throw e
      await new Promise((r) => setTimeout(r, 2000))
    }
  }
  // Mise à jour progressive : un secondaire mis à jour avant le leader attend que le leader applique les migrations ; un secondaire promu les applique lui-même.
  setInterval(() => { if (!isSchemaReady()) migrate().then((a) => { if (a.length) console.log(`[db] migrations appliquées : ${a.join(', ')}`) }).catch((e) => console.warn(`[db] ${e?.message ?? e}`)) }, 10_000).unref()
  setInterval(() => { inRecovery(0).then((r) => { if (!r) purgeSessions().catch(() => undefined) }).catch(() => undefined) }, 3_600_000).unref()
})
