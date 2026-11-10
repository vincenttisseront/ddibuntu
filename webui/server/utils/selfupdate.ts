// Mises à jour en ligne : la console (sans privilège) ne fait que DÉPOSER une demande et LIRE l'état.
// Le téléchargement, la vérification de signature et l'installation sont faits par ddibuntu-selfupdate (root).
import { promises as fs, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { cfg } from './config'

export const VERSION_RE = /^\d+\.\d+\.\d+$/
export const BUSY_STATES = ['checking', 'downloading', 'verifying', 'backup', 'installing', 'restarting'] as const
const STATES = [...BUSY_STATES, 'idle', 'done', 'failed']
const STALE_SECONDS = 60 * 60

export interface UpdateStatus {
  current: string; latest: string; available: boolean; notes: string; url: string; publishedAt: string
  checkedAt: number; state: string; message: string; error: string; target: string; updatedAt: number
}

const str = (v: unknown, max: number) => (typeof v === 'string' ? v.replace(/\0/g, '').slice(0, max) : '')
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0)
const ver = (v: unknown) => (typeof v === 'string' && VERSION_RE.test(v) ? v : '')

/** Lit l'état écrit par root et le réduit à des types sûrs (le fichier n'est pas une source de confiance pour l'affichage). */
export async function readUpdateStatus(): Promise<UpdateStatus | null> {
  let d: any
  try { d = JSON.parse(await fs.readFile(cfg().updateStatusFile, 'utf8')) } catch { return null }
  if (!d || typeof d !== 'object') return null
  const url = str(d.url, 300)
  return {
    current: ver(d.current), latest: ver(d.latest), available: d.available === true && !!ver(d.latest),
    notes: str(d.notes, 4000), url: /^https:\/\/[^\s"'<>]+$/.test(url) ? url : '', publishedAt: str(d.published_at, 40),
    checkedAt: num(d.checked_at), state: STATES.includes(d.state) ? d.state : 'idle', message: str(d.message, 300), error: str(d.error, 300),
    target: ver(d.target), updatedAt: num(d.updated_at),
  }
}

/** Une opération est en cours si l'état est « actif » et récent (un état resté bloqué plus d'une heure est considéré périmé). */
export function isBusy(st: UpdateStatus | null, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
  return !!st && (BUSY_STATES as readonly string[]).includes(st.state) && nowSeconds - st.updatedAt < STALE_SECONDS
}

export function installedVersion(): string {
  try { return ver(readFileSync(cfg().versionFile, 'utf8').trim()) || '' } catch { return '' }
}

/** Dépose la demande (écriture atomique : renommage) ; ddibuntu-selfupdate la relit, la valide et la supprime. */
export async function fileUpdateRequest(action: 'check' | 'apply', version?: string): Promise<void> {
  if (action === 'apply' && !(version && VERSION_RE.test(version))) throw new Error('invalid_version')
  const dir = cfg().generatedDir
  const tmp = join(dir, `.update-request.${process.pid}.tmp`)
  await fs.writeFile(tmp, JSON.stringify(action === 'apply' ? { action, version } : { action }), { mode: 0o640 })
  await fs.rename(tmp, join(dir, '.update-request'))
}
