// Second facteur (0.17.0) : ce que les déploiements ont besoin de savoir du MFA (clients actifs marqués MFA + fournisseur + présence du module REST de FreeRADIUS).
import { query } from './db'
import { loadMfa } from './radius-mfa'
import type { MfaInput } from './radius-authz'
import { readRadiusStatus } from './radius'

/** Entrée MFA des contrôles et du dépôt. `restModule` : null = état de root inconnu (root refusera de toute façon si le module manque). */
export async function loadMfaInput(): Promise<MfaInput> {
  const rows = await query<{ name: string }>('select name from radius_clients where enabled and mfa order by name')
  const st = await readRadiusStatus()
  return { clients: rows.map((r) => r.name), settings: await loadMfa(), restModule: st ? st.restModule : null }
}
