import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { cfg } from '../utils/config'
import { backupActionRefusal, BACKUP_ID_RE, MIRROR_RE, readBackupResult, readBackupStatus, readRestoreState, restoreRefusal } from '../utils/backup'

// État de la base et des sauvegardes (lecture seule) : catalogue, fenêtre restaurable, archivage des journaux, dernière demande, restauration en cours.
route('GET', '/backup/status', 'operator', async () => ({ status: await readBackupStatus(), result: await readBackupResult(), restore: await readRestoreState() }))

// La console ne fait que DÉPOSER une demande ; root (ddibuntu-backup request) la valide de nouveau en entier avant d'agir.
async function drop(body: unknown): Promise<void> {
  try { await fs.writeFile(join(cfg().generatedDir, '.backup-request'), JSON.stringify(body), { mode: 0o640, flag: 'wx' }) } catch (e: any) { if (e?.code === 'EEXIST') fail(409, 'action_pending'); throw e }
}

route('POST', '/backup/refresh', 'operator', async () => { await drop({ action: 'refresh' }); return { accepted: true } })

const ID = z.string().regex(BACKUP_ID_RE)
const Action = z.union([
  z.object({ action: z.enum(['run', 'verify', 'prune', 'enable', 'disable']) }).strict(),
  z.object({ action: z.literal('verify'), id: ID }).strict(),
  z.object({ action: z.literal('delete'), id: ID }).strict(),
])
route('POST', '/backup/action', 'admin', async (c) => {
  const a = await c.body(Action)
  const refusal = backupActionRefusal(await readBackupStatus(), a)
  if (refusal) fail(409, refusal)
  await drop(a)
  await audit(c, `backup.${a.action}`, 'backup', 'id' in a ? a.id : '')
  return { accepted: true }
})

const Configure = z.object({
  keepFull: z.number().int().min(1).max(30), keepDays: z.number().int().min(0).max(365).optional(), verifyAfter: z.boolean().optional(), intervalHours: z.number().int().min(1).max(168), startHour: z.number().int().min(0).max(23),
  mirrorDir: z.string().max(200).refine((v) => v === '' || (MIRROR_RE.test(v) && !v.includes('..')), { message: 'mirror_invalid' }),
}).strict()
route('POST', '/backup/configure', 'admin', async (c) => {
  const b = await c.body(Configure)
  const st = await readBackupStatus()
  if (!st) fail(409, 'backup_unavailable')
  if (st.role === 'witness') fail(409, 'backup_witness')
  await drop({ action: 'configure', ...b })
  await audit(c, 'backup.configure', 'backup', '')
  return { accepted: true }
})

// Restauration : remplace la base (l'ancienne est conservée à côté). L'heure visée est en UTC, format ISO « AAAA-MM-JJThh:mm:ssZ ».
const Restore = z.discriminatedUnion('mode', [
  z.object({ mode: z.literal('latest'), confirm: z.string().max(64) }).strict(),
  z.object({ mode: z.literal('id'), id: ID, confirm: z.string().max(64) }).strict(),
  z.object({ mode: z.literal('at'), at: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/), confirm: z.string().max(64) }).strict(),
])
route('POST', '/backup/restore', 'admin', async (c) => {
  const b = await c.body(Restore)
  const refusal = restoreRefusal(await readBackupStatus(), b, await readRestoreState())
  if (refusal) fail(409, refusal)
  await drop(b)
  await audit(c, 'backup.restore', 'backup', b.mode === 'id' ? b.id : b.mode === 'at' ? b.at : 'latest')
  return { accepted: true }
})

export const registered = true
