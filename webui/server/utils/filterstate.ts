// État du filtrage : modifications en attente de déploiement, déploiement automatique (optionnel), pause du blocage.
import type { PoolClient } from 'pg'
import { getSetting, query, setSetting } from './db'
import { applyConfig, loadDns } from './apply'
import type { ApplyOutcome } from './apply'

export interface CockpitSettings { retentionDays: number; anonymize: 'none' | 'mask'; autoDeploy: boolean }
export const COCKPIT_DEFAULTS: CockpitSettings = { retentionDays: 7, anonymize: 'none', autoDeploy: false }
export const loadCockpit = async (): Promise<CockpitSettings> => ({ ...COCKPIT_DEFAULTS, ...(await getSetting<Partial<CockpitSettings>>('cockpit', {})) })

/** Une règle bascule dans l'autre sens : « autoriser » remplace « bloquer » pour le même domaine, et inversement. */
export async function applyRule(cl: Pick<PoolClient, 'query'>, domain: string, action: 'block' | 'allow', comment: string | null): Promise<'created' | 'exists' | 'replaced'> {
  const opposite = (await cl.query('delete from filter_rules where domain = $1 and action <> $2 returning id', [domain, action])).rowCount ?? 0
  const ins = await cl.query('insert into filter_rules (domain, action, comment) values ($1,$2,$3) on conflict (domain, action) do nothing returning id', [domain, action, comment])
  return ins.rowCount ? (opposite ? 'replaced' : 'created') : 'exists'
}

let timer: ReturnType<typeof setTimeout> | null = null, running = false
/** Compte une modification du filtrage (à déployer) ; déploie seul, après quelques secondes, si l'administrateur l'a demandé. */
export async function touchFilter(): Promise<void> {
  await query(`insert into settings (key, value) values ('filter_changes', '{"n":1}') on conflict (key) do update set value = jsonb_build_object('n', coalesce((settings.value->>'n')::int, 0) + 1), updated_at = now()`)
  if (!(await loadCockpit()).autoDeploy) return
  if (timer) clearTimeout(timer)
  timer = setTimeout(async () => {
    timer = null
    if (running) return
    running = true
    try { await applyConfig({ deploy: true, username: 'cockpit (déploiement automatique)' }) } catch (e: any) { console.error('[cockpit] déploiement automatique impossible :', e?.message) } finally { running = false }
  }, 3000)
  timer.unref?.()
}
export const pendingChanges = async (): Promise<number> => Number((await getSetting<{ n?: number }>('filter_changes', { n: 0 })).n ?? 0)
export const resetPending = () => query(`insert into settings (key, value) values ('filter_changes', '{"n":0}') on conflict (key) do update set value = '{"n":0}'::jsonb, updated_at = now()`)

/** Active ou coupe le blocage RPZ puis déploie (validé par les outils officiels, point de restauration compris). Annule le réglage si le déploiement échoue. */
export async function setBlocking(enabled: boolean, username: string): Promise<ApplyOutcome> {
  const before = await loadDns()
  await setSetting('dns', { ...before, rpzEnabled: enabled })
  const r = await applyConfig({ deploy: true, username })
  if (!r.deployed) await setSetting('dns', { ...before })
  return r
}
export interface Pause { until: string; by: string }
export const getPause = () => getSetting<Pause | null>('cockpit_pause', null)
/** Rétablit le blocage ; l'enregistrement de pause n'est effacé QU'APRÈS un déploiement réussi (sinon il reste, et on réessaie). */
export async function resumeBlocking(username: string): Promise<boolean> {
  const r = await setBlocking(true, username)
  if (r.deployed) await setSetting('cockpit_pause', null)
  return r.deployed
}
let lastResumeTry = 0
/** Fin de pause échue : le blocage est rétabli, même si la console a redémarré entre-temps ; nouvelle tentative toutes les 60 s en cas d'échec. */
export async function resumeIfExpired(): Promise<boolean> {
  const p = await getPause()
  if (!p || Date.parse(p.until) > Date.now() || Date.now() - lastResumeTry < 60_000) return false
  lastResumeTry = Date.now()
  const ok = await resumeBlocking('cockpit (fin de pause)')
  if (ok) lastResumeTry = 0
  else console.error('[cockpit] fin de pause : le déploiement a échoué, nouvelle tentative dans 60 s')
  return ok
}
