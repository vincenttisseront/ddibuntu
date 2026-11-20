// Ce qui attend un déploiement (0.17.1) : la console compare l'état ENREGISTRÉ (clients, certificats, règles d'accès, annuaire, mot de passe, second facteur) à ce qui a été
// envoyé à root la dernière fois. Chaque morceau a sa propre empreinte à clé (jamais un secret en clair) : l'écran dit QUOI n'est pas déployé, pas seulement « quelque chose ».
import { createHmac } from 'node:crypto'
import { requireSecret } from './config'
import { decryptSecret } from './auth'
import { getSetting, query, setSetting } from './db'
import { buildDeposit, readiness } from './radius-pki'
import { loadPki } from './radius-pki-store'
import { getPushed } from './radius-rules-store'
import { readRadiusStatus } from './radius'

export const DEPLOY_PUSHED_KEY = 'radius_deploy_pushed'
export type PendingPart = 'clients' | 'pki' | 'rules'
export interface DeployParts { clients: string; pki: string }

const hm = (v: unknown) => createHmac('sha256', requireSecret()).update(JSON.stringify(v)).digest('hex')

/** Empreintes de l'état enregistré. Clients : tout ce qui part dans clients.conf (le secret seulement sous forme d'empreinte à clé). Certificats : le dépôt tel que root le recevrait. */
export async function deployParts(): Promise<DeployParts> {
  const rows = await query<any>('select name, address::text as address, secret_enc, enabled, mfa from radius_clients order by name')
  const pki = await loadPki(), r = readiness(pki)
  return {
    clients: hm(rows.map((c) => [c.name, c.address, hm(decryptSecret(c.secret_enc)), c.enabled === true, c.mfa === true])),
    pki: r.ready ? hm(buildDeposit(pki, decryptSecret(pki.server!.keyEnc))) : r.empty ? 'none' : 'incomplete',
  }
}
/** Appelé quand root a accepté un déploiement : ce qui est enregistré maintenant EST ce qui tourne. */
export async function markDeployed(): Promise<void> { await setSetting(DEPLOY_PUSHED_KEY, await deployParts()) }

/** `rulesPending` : la liste des règles / annuaire / mot de passe / second facteur diffère du déploiement (empreinte existante, voir radius-authz). */
export async function deployBrief(rulesPending: boolean): Promise<{ pending: boolean; parts: PendingPart[]; never: boolean }> {
  const cur = await deployParts()
  const stored = await getSetting<DeployParts | null>(DEPLOY_PUSHED_KEY, null)
  const parts: PendingPart[] = []
  let never = false
  if (!stored || typeof stored.clients !== 'string' || typeof stored.pki !== 'string') {
    // jamais déployé : seuls des clients actifs sont « à déployer » ; déjà déployé avant cette version : on part de l'état actuel (rien d'inventé en attente)
    if ((await getPushed()) === null) {
      never = true
      const n = await query<{ n: number }>('select count(*)::int as n from radius_clients where enabled')
      if ((n[0]?.n ?? 0) > 0) parts.push('clients')
      if (cur.pki !== 'none') parts.push('pki')
    } else if ((await readRadiusStatus())?.configured) await setSetting(DEPLOY_PUSHED_KEY, cur)
  } else {
    if (stored.clients !== cur.clients) parts.push('clients')
    if (stored.pki !== cur.pki) parts.push('pki')
  }
  if (rulesPending) parts.push('rules')
  return { pending: parts.length > 0, parts, never }
}
