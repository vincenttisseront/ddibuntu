// Lit en continu le journal des requêtes de BIND (lecture seule), applique la rétention et rétablit le blocage à la fin d'une pause.
import { promises as fs } from 'node:fs'
import { cfg } from '../utils/config'
import { getSetting, inRecovery, query, setSetting } from '../utils/db'
import { ingestLogText } from '../utils/ingest'
import { loadCockpit, resumeIfExpired } from '../utils/filterstate'

const CHUNK = 4 * 1024 * 1024
export default defineNitroPlugin(() => {
  const file = cfg().queryLogFile
  let pos: { ino: number; off: number } | null = null, busy = false, lastPrune = 0
  const tick = async () => {
    if (busy) return
    busy = true
    try {
      if (await inRecovery()) return    // secondaire : la base est en lecture seule (le journal local ne peut pas être enregistré)
      if (!pos) pos = await getSetting<{ ino: number; off: number }>('querylog_pos', { ino: 0, off: 0 })
      const st = await fs.stat(file).catch(() => null)
      if (st) {
        if (st.ino !== pos.ino || st.size < pos.off) pos = { ino: st.ino, off: pos.ino === 0 ? Math.max(0, st.size - 8 * 1024 * 1024) : 0 }   // rotation : on repart du début du nouveau fichier
        if (st.size > pos.off) {
          const fh = await fs.open(file, 'r')
          try {
            const len = Math.min(st.size - pos.off, CHUNK), buf = Buffer.alloc(len)
            await fh.read(buf, 0, len, pos.off)
            const end = buf.lastIndexOf(10) + 1    // seules les lignes complètes sont lues ; la fin attend le prochain passage
            if (end > 0) { await ingestLogText(buf.subarray(0, end).toString('utf8')); pos = { ino: st.ino, off: pos.off + end }; await setSetting('querylog_pos', pos) }
          } finally { await fh.close() }
        }
      }
      if (Date.now() - lastPrune > 3_600_000) {
        lastPrune = Date.now()
        const s = await loadCockpit()
        if (s.retentionDays > 0) await query("delete from dns_queries where at < now() - make_interval(days => $1)", [s.retentionDays])
      }
      await resumeIfExpired()
    } catch (e: any) { console.error('[querylog]', e?.message ?? e) } finally { busy = false }
  }
  setInterval(tick, cfg().queryLogIntervalMs).unref()
})
