// Informations système affichées sur le tableau de bord (lecture seule, sans privilège, sans commande externe).
import os from 'node:os'
import { promises as fs } from 'node:fs'
import { cfg } from './config'

export interface HostInfo { hostname: string; uptimeSeconds: number; load1: number; cpus: number; memPercent: number; diskPercent: number | null; diskFreeGb: number | null }

export const percent = (used: number, total: number) => (total > 0 ? Math.round((used / total) * 1000) / 10 : 0)

export async function hostInfo(): Promise<HostInfo> {
  let diskPercent: number | null = null, diskFreeGb: number | null = null
  try {
    const s = await fs.statfs(cfg().generatedDir)
    const total = s.blocks * s.bsize, free = s.bavail * s.bsize
    diskPercent = percent(total - free, total); diskFreeGb = Math.round((free / 1024 ** 3) * 10) / 10
  } catch { /* volume illisible : champ vide */ }
  const total = os.totalmem()
  return { hostname: os.hostname(), uptimeSeconds: Math.floor(os.uptime()), load1: Math.round(os.loadavg()[0]! * 100) / 100, cpus: os.cpus().length || 1, memPercent: percent(total - os.freemem(), total), diskPercent, diskFreeGb }
}
