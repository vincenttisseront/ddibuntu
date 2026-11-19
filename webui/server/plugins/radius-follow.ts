// RADIUS actif / passif (0.15.0) : sur le leader, rejoue le dernier déploiement quand le service ne tourne pas (bascule, redémarrage du service arrêté par « ddibuntu-radius align »).
// Toutes les 30 secondes ; sans effet hors cluster et sur un secondaire (la base y est en lecture seule).
import { isSchemaReady } from '../utils/db'
import { radiusFollowTick } from '../utils/radius-follow'

export default defineNitroPlugin(() => {
  if (process.env.DDI_RADIUS_FOLLOW_MS === '0') return
  let busy = false
  const tick = async () => {
    if (busy || !isSchemaReady()) return
    busy = true
    try { await radiusFollowTick() } catch (e: any) { console.error('[radius-follow]', e?.message ?? e) } finally { busy = false }
  }
  const every = Number(process.env.DDI_RADIUS_FOLLOW_MS) || 30_000
  setTimeout(tick, Math.min(45_000, every)).unref()
  setInterval(tick, every).unref()
})
