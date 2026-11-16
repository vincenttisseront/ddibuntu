// Tient les CRL du service RADIUS à jour (0.13.2) : toutes les heures, télécharge celles des autorités qui ont une adresse et, si EAP-TLS est déployé,
// les envoie à root quand elles ont changé (une CRL périmée fait REFUSER tous les certificats : il ne faut jamais la laisser expirer).
// Primaire uniquement : la base des nœuds secondaires est en lecture seule.
import { inRecovery, isSchemaReady } from '../utils/db'
import { pushCrlsIfNeeded, refreshAllCrls } from '../utils/radius-pki-store'

export default defineNitroPlugin(() => {
  if (process.env.DDI_RADIUS_CRL_MS === '0') return
  let busy = false
  const tick = async () => {
    if (busy || !isSchemaReady()) return
    busy = true
    try {
      if (await inRecovery()) return
      const r = await refreshAllCrls()
      const p = await pushCrlsIfNeeded()
      if (r.changed || r.failed || p === 'pushed') console.log(`[radius-crl] nouvelles : ${r.changed}, échecs : ${r.failed}, envoi à root : ${p}`)
    } catch (e: any) { console.error('[radius-crl]', e?.message ?? e) } finally { busy = false }
  }
  const every = Number(process.env.DDI_RADIUS_CRL_MS) || 3_600_000
  setTimeout(tick, Math.min(90_000, every)).unref()
  setInterval(tick, every).unref()
})
