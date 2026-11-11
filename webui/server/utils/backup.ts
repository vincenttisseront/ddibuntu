// Sauvegardes de la base (PITR) : état publié par root (ddibuntu-backup), lu ici en lecture seule. La console ne sauvegarde ni ne restaure jamais elle-même :
// elle dépose une demande JSON que root revalide en entier (ddibuntu-backup request).
import { promises as fs } from 'node:fs'
import { cfg } from './config'

export const BACKUP_ID_RE = /^\d{8}T\d{6}Z$/
export const MIRROR_RE = /^\/[A-Za-z0-9._/@:+-]{1,200}$/

export interface BackupItem { id: string; node: string; startedAt: number; finishedAt: number; sizeBytes: number; timeline: number; walArchived: boolean }
export interface ArchiverState { archivedCount: number; lastArchivedWal: string | null; lastArchivedAt: number | null; failedCount: number; lastFailedWal: string | null; lastFailedAt: number | null }
export interface BackupStatus {
  at: number; ageSeconds: number; stale: boolean
  enabled: boolean; role: 'primary' | 'standby' | 'witness' | 'unknown'; node: string; hostname: string; cluster: string | null
  repo: string; keepFull: number; intervalHours: number; startHour: number; mirrorDir: string | null
  archiveMode: string | null; archiver: ArchiverState | null; diskFreeBytes: number; preRestoreDirs: number
  walFiles: number; walBytes: number; lastWalAt: number | null; pitrFrom: number | null; backups: BackupItem[]
  confirmWord: string
}
export interface BackupResult { at: number; action: string; ok: boolean; message: string; id: string | null }
export interface RestoreState { at: number; phase: string; message: string; active: boolean }

const MAX_AGE_SECONDS = 3600   // le minuteur republie toutes les 15 minutes
const str = (v: unknown, max = 128) => (typeof v === 'string' ? v.slice(0, max) : '')
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const nint = (v: unknown, d = 0) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : d)

export function parseBackupStatus(raw: string, nowSec = Date.now() / 1000): BackupStatus | null {
  let j: any
  try { j = JSON.parse(raw) } catch { return null }
  if (!j || typeof j !== 'object' || typeof j.enabled !== 'boolean' || !Array.isArray(j.backups)) return null
  const role = ['primary', 'standby', 'witness', 'unknown'].includes(j.role) ? j.role : 'unknown'
  const a = j.archiver && typeof j.archiver === 'object' ? j.archiver : null
  const backups: BackupItem[] = j.backups.slice(0, 64).filter((b: any) => b && typeof b.id === 'string' && BACKUP_ID_RE.test(b.id)).map((b: any) => ({
    id: b.id, node: str(b.node, 63), startedAt: nint(b.startedAt), finishedAt: nint(b.finishedAt), sizeBytes: nint(b.sizeBytes), timeline: nint(b.timeline), walArchived: b.walArchived === true,
  }))
  const at = nint(j.at)
  const age = Math.max(0, Math.round(nowSec - at))
  const cluster = typeof j.cluster === 'string' && j.cluster ? str(j.cluster, 63) : null
  const hostname = str(j.hostname, 63)
  return {
    at, ageSeconds: age, stale: age > MAX_AGE_SECONDS, enabled: j.enabled, role, node: str(j.node, 63), hostname, cluster,
    repo: str(j.repo, 200), keepFull: nint(j.keepFull, 3), intervalHours: nint(j.intervalHours, 24), startHour: nint(j.startHour, 2), mirrorDir: typeof j.mirrorDir === 'string' && j.mirrorDir ? str(j.mirrorDir, 200) : null,
    archiveMode: typeof j.archiveMode === 'string' ? str(j.archiveMode, 16) : null,
    archiver: a ? { archivedCount: nint(a.archived_count), lastArchivedWal: typeof a.last_archived_wal === 'string' ? str(a.last_archived_wal, 64) : null, lastArchivedAt: num(a.last_archived_at),
      failedCount: nint(a.failed_count), lastFailedWal: typeof a.last_failed_wal === 'string' ? str(a.last_failed_wal, 64) : null, lastFailedAt: num(a.last_failed_at) } : null,
    diskFreeBytes: nint(j.diskFreeBytes), preRestoreDirs: nint(j.preRestoreDirs), walFiles: nint(j.walFiles), walBytes: nint(j.walBytes), lastWalAt: num(j.lastWalAt), pitrFrom: num(j.pitrFrom),
    backups, confirmWord: cluster ?? hostname,
  }
}

export async function readBackupStatus(): Promise<BackupStatus | null> {
  try {
    const f = cfg().backupStatusFile
    const st = await fs.stat(f)
    if (!st.isFile() || st.size > 256 * 1024) return null
    return parseBackupStatus(await fs.readFile(f, 'utf8'))
  } catch { return null }
}
export async function readBackupResult(): Promise<BackupResult | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().backupResultFile, 'utf8'))
    if (typeof j?.at !== 'number') return null
    return { at: j.at, action: str(j.action, 24), ok: j.ok === true, message: str(j.message, 300), id: typeof j.id === 'string' && BACKUP_ID_RE.test(j.id) ? j.id : null }
  } catch { return null }
}
const ACTIVE_PHASES = new Set(['pausing', 'stopping', 'extracting', 'recovering', 'resuming', 'rollback'])
export async function readRestoreState(nowSec = Date.now() / 1000): Promise<RestoreState | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().backupRestoreFile, 'utf8'))
    if (typeof j?.at !== 'number' || typeof j?.phase !== 'string') return null
    // une phase « en cours » vieille de plus de 2 heures est un résidu (arrêt brutal) : elle ne bloque pas les demandes suivantes
    return { at: j.at, phase: str(j.phase, 24), message: str(j.message, 300), active: ACTIVE_PHASES.has(j.phase) && nowSec - j.at < 7200 }
  } catch { return null }
}

export type BackupAction =
  | { action: 'run' | 'verify' | 'prune' | 'enable' | 'disable' } | { action: 'verify'; id: string } | { action: 'delete'; id: string }
// Refus d'une action contre l'état publié par root (code d'erreur API 409), sinon null. root revalide tout de son côté.
export function actionRefusal(st: BackupStatus | null, a: BackupAction): string | null {
  if (!st) return 'backup_unavailable'
  if (st.role === 'witness') return 'backup_witness'
  if (a.action === 'enable') return null
  if (a.action === 'disable') return st.enabled ? null : 'backup_disabled'
  if (!st.enabled) return 'backup_disabled'
  if (a.action === 'run') return st.role === 'primary' ? null : 'backup_primary_only'
  if ((a.action === 'verify' || a.action === 'delete') && 'id' in a) {
    if (!st.backups.some((b) => b.id === a.id)) return 'backup_unknown'
    if (a.action === 'delete' && st.backups.length <= 1) return 'backup_last'
  }
  return null
}

export type RestoreRequest = { mode: 'latest' } | { mode: 'id'; id: string } | { mode: 'at'; at: string }
// Une restauration remplace la base : confirmation saisie, primaire seulement, aucune autre en cours, cible dans la fenêtre restaurable.
export function restoreRefusal(st: BackupStatus | null, r: RestoreRequest & { confirm: string }, restore: RestoreState | null, nowSec = Date.now() / 1000): string | null {
  if (!st) return 'backup_unavailable'
  if (st.role === 'witness') return 'backup_witness'
  if (!st.enabled) return 'backup_disabled'
  if (restore?.active) return 'restore_in_progress'
  if (st.role !== 'primary') return 'restore_primary_only'
  if (!st.backups.length) return 'no_backup'
  if (r.confirm !== st.confirmWord) return 'confirm_mismatch'
  if (r.mode === 'id' && !st.backups.some((b) => b.id === r.id)) return 'backup_unknown'
  if (r.mode === 'at') {
    const t = Date.parse(r.at) / 1000
    if (!Number.isFinite(t)) return 'time_invalid'
    if (t > nowSec) return 'time_in_future'
    if (st.pitrFrom !== null && t < st.pitrFrom) return 'time_before_first_backup'
  }
  return null
}
