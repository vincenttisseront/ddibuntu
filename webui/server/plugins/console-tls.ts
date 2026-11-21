// Certificat HTTPS de la console (0.21.0) : une passe toutes les minutes (le leader fait émettre ou renouveler, chaque nœud installe celui de la base).
// DDI_CONSOLE_TLS_MS=0 : désactivé (les tests déclenchent eux-mêmes).
import { isSchemaReady } from '../utils/db'
import { consoleTlsTick } from '../utils/console-tls'
import { realDeps } from '../handlers/consoletls'

export default defineNitroPlugin(() => {
  const every = process.env.DDI_CONSOLE_TLS_MS === undefined ? 60_000 : Number(process.env.DDI_CONSOLE_TLS_MS)
  if (!(every > 0)) return
  const tick = async () => {
    if (!isSchemaReady()) return
    try { await consoleTlsTick(realDeps()) } catch (e: any) { console.error('[console-tls]', e?.message ?? e) }
  }
  setTimeout(tick, Math.min(45_000, every)).unref()
  setInterval(tick, every).unref()
})
