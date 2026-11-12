// Réglages de session COMMUNS à tous les nœuds du cluster (0.9.14) : stockés dans la table « settings » (clé « session »), donc répliqués avec la base.
// Sans valeur enregistrée, on retombe sur l'environnement du nœud (DDI_SESSION_HOURS / DDI_IDLE_MINUTES), comme avant. Lecture mise en cache 15 s.
import { cfg } from './config'
import { getSetting, setSetting } from './db'

export const SESSION_LIMITS = { hours: { min: 1, max: 72 }, idle: { min: 5, max: 1440 } } as const
export interface SessionSettings { hours: number; idleMinutes: number }

const clampInt = (v: unknown, min: number, max: number, d: number) => (typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max ? v : d)
export const envSessionDefaults = (): SessionSettings => {
  const c = cfg()
  return { hours: clampInt(c.sessionHours, SESSION_LIMITS.hours.min, SESSION_LIMITS.hours.max, 8), idleMinutes: clampInt(c.idleMinutes, SESSION_LIMITS.idle.min, SESSION_LIMITS.idle.max, 30) }
}
// valeur enregistrée relue strictement : tout champ hors bornes ou absent retombe sur le défaut du nœud (jamais de session « infinie » par erreur)
export function parseSessionSetting(raw: unknown, d: SessionSettings): SessionSettings {
  const o = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {}
  return { hours: clampInt(o.hours, SESSION_LIMITS.hours.min, SESSION_LIMITS.hours.max, d.hours), idleMinutes: clampInt(o.idleMinutes, SESSION_LIMITS.idle.min, SESSION_LIMITS.idle.max, d.idleMinutes) }
}

let cache: { at: number; v: SessionSettings; stored: boolean } | null = null
export async function sessionSettings(): Promise<SessionSettings & { stored: boolean }> {
  const now = Date.now()
  if (cache && now - cache.at < 15000) return { ...cache.v, stored: cache.stored }
  const d = envSessionDefaults()
  let raw: unknown = null
  try { raw = await getSetting<unknown>('session', null) } catch { raw = null }   // base indisponible : défaut du nœud, sans bloquer l'authentification
  cache = { at: now, v: parseSessionSetting(raw, d), stored: raw !== null }
  return { ...cache.v, stored: cache.stored }
}
export async function saveSessionSettings(s: SessionSettings): Promise<void> { await setSetting('session', s); cache = null }
export async function resetSessionSettings(): Promise<void> { const { query } = await import('./db'); await query("delete from settings where key = 'session'"); cache = null }
export const _resetSessionCache = () => { cache = null }
