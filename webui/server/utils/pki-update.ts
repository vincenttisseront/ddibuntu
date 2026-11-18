// Mises à jour de l'image d'EJBCA Community (0.14.7). Root (ddibuntu-pki) cherche les nouvelles versions sur Docker Hub (une fois par jour, ou à la demande), exécute la mise à jour
// (tirage, arrêt, sauvegarde de retour arrière, migration de la base par la nouvelle image, contrôles) et publie /run/ddibuntu/pki-update.json : cette console ne fait que le lire et
// déposer des demandes courtes (recherche, mise à jour vers une version, validation, retour arrière). Rien de ce fichier n'est repris tel quel : tout est borné et revalidé ici.
import { promises as fs } from 'node:fs'
import { z } from 'zod'
import { cfg } from './config'

const VERSION_RE = /^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}$/
/** Les notes de version sont publiées par Keyfactor : seule cette forme d'adresse est reprise (jamais un lien venu d'ailleurs). */
const NOTES_RE = /^https:\/\/docs\.keyfactor\.com\/ejbca\/latest\/ejbca-[0-9]{1,2}-[0-9]{1,2}-(release|upgrade)-notes$/

export const JOB_STATES = ['running', 'pending', 'validated', 'failed', 'rolled_back'] as const
export type JobState = (typeof JOB_STATES)[number]
export const STEP_STATUS = ['todo', 'running', 'done', 'failed'] as const
export type StepStatus = (typeof STEP_STATUS)[number]
export interface UpdateItem { tag: string; pushedAt: string; kind: 'patch' | 'minor' | 'major'; allowed: boolean; reason: string; digest: string; notes: { release?: string; upgrade?: string } }
export interface UpdateStep { id: string; status: StepStatus }
export interface UpdateCheck { id: string; ok: boolean; detail: string }
export interface UpdateJob {
  state: JobState; step: string; from: string; to: string; message: string; reason: string
  startedAt: number; finishedAt: number; updatedAt: number; certsAtBackup: number; casAtBackup: number; backupBytes: number
  steps: UpdateStep[]; checks: UpdateCheck[]; rollbackAvailable: boolean
}
export interface PkiUpdate {
  at: number; current: string; dbTag: string; checkedAt: number; checkError: string; latest: string | null; available: UpdateItem[]; job: UpdateJob | null
  /** Certificats émis depuis la sauvegarde de retour arrière (perdus si on revient en arrière) ; null si inconnu ou sans objet. */
  certsSince: number | null
}

const n = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : 0)
const s = (v: unknown, max: number) => String(v ?? '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, max)
const id = (v: unknown) => (typeof v === 'string' && /^[a-z_]{1,24}$/.test(v) ? v : '')

function parseItem(r: any): UpdateItem | null {
  if (!r || typeof r !== 'object' || typeof r.tag !== 'string' || !VERSION_RE.test(r.tag)) return null
  const notes: UpdateItem['notes'] = {}
  if (typeof r.notes?.release === 'string' && NOTES_RE.test(r.notes.release)) notes.release = r.notes.release
  if (typeof r.notes?.upgrade === 'string' && NOTES_RE.test(r.notes.upgrade)) notes.upgrade = r.notes.upgrade
  return { tag: r.tag, pushedAt: /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(r.pushedAt ?? '') ? r.pushedAt : '', kind: r.kind === 'major' || r.kind === 'minor' ? r.kind : 'patch',
    allowed: r.allowed === true, reason: /^[a-z_]{0,24}$/.test(r.reason ?? '') ? (r.reason ?? '') : '', digest: /^sha256:[0-9a-f]{64}$/.test(r.digest ?? '') ? r.digest : '', notes }
}
function parseJob(j: any): UpdateJob | null {
  if (!j || typeof j !== 'object' || !(JOB_STATES as readonly string[]).includes(j.state)) return null
  const steps = (Array.isArray(j.steps) ? j.steps : []).slice(0, 24).map((x: any) => ({ id: id(x?.id), status: (STEP_STATUS as readonly string[]).includes(x?.status) ? (x.status as StepStatus) : 'todo' })).filter((x: UpdateStep) => x.id)
  const checks = (Array.isArray(j.checks) ? j.checks : []).slice(0, 24).map((x: any) => ({ id: id(x?.id), ok: x?.ok === true, detail: s(x?.detail, 200) })).filter((x: UpdateCheck) => x.id)
  return { state: j.state, step: id(j.step), from: VERSION_RE.test(j.from ?? '') ? j.from : '', to: VERSION_RE.test(j.to ?? '') ? j.to : '', message: s(j.message, 300), reason: /^[a-z_]{0,24}$/.test(j.reason ?? '') ? (j.reason ?? '') : '',
    startedAt: n(j.startedAt), finishedAt: n(j.finishedAt), updatedAt: n(j.updatedAt), certsAtBackup: n(j.certsAtBackup), casAtBackup: n(j.casAtBackup), backupBytes: Math.max(0, n(j.backupBytes)), steps, checks,
    rollbackAvailable: j.rollbackAvailable === true }
}
export function parsePkiUpdate(j: any): PkiUpdate | null {
  if (!j || typeof j !== 'object' || typeof j.at !== 'number') return null
  const available = (Array.isArray(j.available) ? j.available : []).slice(0, 20).map(parseItem).filter((x: UpdateItem | null): x is UpdateItem => !!x)
  return { at: n(j.at), current: VERSION_RE.test(j.current ?? '') ? j.current : '', dbTag: VERSION_RE.test(j.dbTag ?? '') ? j.dbTag : '', checkedAt: n(j.checkedAt), checkError: /^[a-z_]{0,40}$/.test(j.checkError ?? '') ? (j.checkError ?? '') : '',
    latest: typeof j.latest === 'string' && VERSION_RE.test(j.latest) ? j.latest : null, available, job: parseJob(j.job), certsSince: Number.isInteger(j.certsSince) && j.certsSince >= 0 ? j.certsSince : null }
}
export async function readPkiUpdate(): Promise<PkiUpdate | null> {
  try { return parsePkiUpdate(JSON.parse(await fs.readFile(cfg().pkiUpdateFile, 'utf8'))) } catch { return null }
}
/** Une mise à jour est-elle en cours d'exécution chez root ? (état « running » publié) */
export async function pkiUpdateRunning(): Promise<boolean> { return (await readPkiUpdate())?.job?.state === 'running' }

export const updateApplyBody = z.object({ version: z.string().trim().regex(VERSION_RE) }).strict()
export const confirmBody = z.object({ confirm: z.literal(true) }).strict()
