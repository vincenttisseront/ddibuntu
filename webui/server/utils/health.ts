// Santé d'un nœud, collectée par root (ddibuntu-health) : services, base, disques, certificats, heure, charge. Lecture seule, aucun secret.
// Le fichier local sert à la console de ce nœud ; celui des AUTRES nœuds (arbitre compris) arrive par etcd, relayé dans l'état du cluster.
import { promises as fs } from 'node:fs'
import { cfg } from './config'

export interface ServiceHealth { name: string; state: string; expected: boolean }
export interface DiskHealth { mount: string; sizeBytes: number; availBytes: number }
export interface CertHealth { name: string; notAfter: number }
export interface NodeHealth {
  at: number; ageSeconds: number; stale: boolean
  node: string; cluster: string | null; role: string; hostname: string
  uptimeSeconds: number; load1: number; memory: { totalKb: number; availKb: number }
  services: ServiceHealth[]; postgres: boolean | null; disks: DiskHealth[]; certs: CertHealth[]; timeSynced: boolean | null
}

export const HEALTH_MAX_AGE_SECONDS = 180   // publiée chaque minute : au-delà de trois minutes, le nœud est considéré silencieux
const str = (v: unknown, max = 128) => (typeof v === 'string' ? v.slice(0, max) : '')
const nint = (v: unknown, d = 0) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : d)
const NAME_RE = /^[a-z0-9-]{1,32}$/, STATE_RE = /^[a-z-]{3,20}$/
const tri = (v: unknown): boolean | null => (v === true ? true : v === false ? false : null)

// Champs connus et bornés uniquement ; un objet mal formé est ignoré.
export function parseNodeHealth(j: any, nowSec = Date.now() / 1000): NodeHealth | null {
  if (!j || typeof j !== 'object' || typeof j.node !== 'string' || !/^[a-z0-9-]{1,31}$/.test(j.node)) return null
  const at = nint(j.at)
  const age = Math.max(0, Math.round(nowSec - at))
  const arr = (v: unknown, n: number): any[] => (Array.isArray(v) ? v.slice(0, n) : [])
  return {
    at, ageSeconds: age, stale: age > HEALTH_MAX_AGE_SECONDS,
    node: j.node, cluster: typeof j.cluster === 'string' && j.cluster ? str(j.cluster, 63) : null,
    role: ['data', 'witness', 'standalone'].includes(j.role) ? j.role : 'standalone', hostname: str(j.hostname, 63),
    uptimeSeconds: Math.max(0, nint(j.uptimeSeconds)), load1: typeof j.load1 === 'number' && Number.isFinite(j.load1) ? Math.max(0, j.load1) : 0,
    memory: { totalKb: Math.max(0, nint(j.memory?.totalKb)), availKb: Math.max(0, nint(j.memory?.availKb)) },
    services: arr(j.services, 32).filter((s) => s && NAME_RE.test(s.name ?? '') && STATE_RE.test(s.state ?? '')).map((s) => ({ name: s.name, state: s.state, expected: s.expected === true })),
    postgres: tri(j.postgres),
    disks: arr(j.disks, 16).filter((d) => d && typeof d.mount === 'string' && nint(d.sizeBytes) > 0).map((d) => ({ mount: str(d.mount, 100), sizeBytes: nint(d.sizeBytes), availBytes: Math.max(0, nint(d.availBytes)) })),
    certs: arr(j.certs, 16).filter((c) => c && NAME_RE.test(c.name ?? '') && nint(c.notAfter) > 0).map((c) => ({ name: c.name, notAfter: nint(c.notAfter) })),
    timeSynced: tri(j.timeSynced),
  }
}

export async function readLocalHealth(): Promise<NodeHealth | null> {
  try {
    const f = cfg().healthStatusFile
    const st = await fs.stat(f)
    if (!st.isFile() || st.size > 64 * 1024) return null
    return parseNodeHealth(JSON.parse(await fs.readFile(f, 'utf8')))
  } catch { return null }
}
