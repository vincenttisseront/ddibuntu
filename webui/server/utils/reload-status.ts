// Résultat de la dernière application privilégiée (ddibuntu-reload) : écrit par root, lu par la console.
import { promises as fs } from 'node:fs'
import { cfg } from './config'
import { query } from './db'

export interface ReloadStatus { at: number; ok: boolean; message: string }
export async function readReloadStatus(): Promise<ReloadStatus | null> {
  try {
    const kv: Record<string, string> = {}
    for (const l of (await fs.readFile(cfg().reloadStatusFile, 'utf8')).split('\n')) { const i = l.indexOf('='); if (i > 0) kv[l.slice(0, i)] = l.slice(i + 1) }
    const at = Number(kv.at)
    if (!Number.isFinite(at) || at <= 0) return null
    return { at, ok: kv.ok === '1', message: (kv.message ?? '').slice(0, 300) }
  } catch { return null }
}
/** Rattache le résultat réel (rechargement accepté ou retour arrière automatique) aux déploiements qui l'attendent. */
export async function reconcileDeployments(): Promise<ReloadStatus | null> {
  const st = await readReloadStatus()
  if (st) await query('update deployments set applied = $1, apply_message = $2 where applied is null and ok and extract(epoch from at) <= $3', [st.ok, st.message, st.at])
  return st
}
