// Publie dans l'Active Directory les autorités de la PKI du DDI (0.14.2), à intervalle régulier : dès qu'une autorité a son certificat elle est écrite, les échecs
// sont repris avec une attente croissante, et une fois par jour on vérifie que l'AD porte toujours ce qu'on y a mis. Sans effet tant que la publication n'est pas
// activée. Primaire uniquement : la base des nœuds secondaires est en lecture seule. DDI_PKI_AD_MS=0 : désactivé (les tests déclenchent eux-mêmes).
import { inRecovery, isSchemaReady } from '../utils/db'
import { runPublication } from '../utils/pki-ad-store'

export default defineNitroPlugin(() => {
  const every = process.env.DDI_PKI_AD_MS === undefined ? 30_000 : Number(process.env.DDI_PKI_AD_MS)
  if (!(every > 0)) return
  let busy = false
  const tick = async () => {
    if (busy || !isSchemaReady()) return
    busy = true
    try {
      if (await inRecovery()) return
      const r = await runPublication({ trigger: 'auto' })
      if (r.status === 'done') {
        const s = r.summary
        console.log(`[pki-ad] publiées : ${s.published}, inchangées : ${s.unchanged}, échecs : ${s.failed}, conflits : ${s.conflicts}, écarts : ${s.drift}${s.ok ? '' : ` (${s.reason})`}`)
      }
    } catch (e: any) { console.error('[pki-ad]', e?.message ?? e) } finally { busy = false }
  }
  setTimeout(tick, Math.min(15_000, every)).unref()
  setInterval(tick, every).unref()
})
