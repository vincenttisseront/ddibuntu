// État du cluster publié par root (ddibuntu-cluster follow, chaque minute) : fichier JSON sans secret, lu ici en lecture seule.
// La console ne pilote jamais le cluster : les demandes d'action passent par un fichier de demande traité par root (voir demandes de bascule).
import { promises as fs } from 'node:fs'
import { dirname, join } from 'node:path'
import { cfg } from './config'

export interface ClusterNode { name: string; ip: string; role: string; host?: string; state?: string; patroniRole?: string; lagBytes?: number | null; timeline?: number | null }
export interface ClusterState {
  cluster: string; node: string; nodeRole: string; localRole: 'leader' | 'replica' | 'unknown'; at: number; ageSeconds: number; stale: boolean
  etcd: { healthy: boolean; members: number }
  nodes: ClusterNode[]
  leader: string | null
  bind: 'primary' | 'secondary' | null
  kea: unknown
  vip: { address: string; iface: string; held: boolean } | null
}

const MAX_AGE_SECONDS = 180   // la minuterie publie chaque minute : au-delà de 3 minutes, l'information est périmée
const str = (v: unknown, max = 128) => (typeof v === 'string' ? v.slice(0, max) : '')

// Assainit le fichier : uniquement les champs connus, bornés ; un fichier mal formé est ignoré (jamais d'erreur côté appelant).
export function parseClusterState(raw: string, nowSec = Date.now() / 1000): ClusterState | null {
  let j: any
  try { j = JSON.parse(raw) } catch { return null }
  if (!j || typeof j !== 'object' || typeof j.node !== 'string') return null
  const members: any[] = Array.isArray(j.patroni?.members) ? j.patroni.members.slice(0, 16) : []
  const peers: any[] = Array.isArray(j.peers) ? j.peers.slice(0, 16) : []
  const nodes: ClusterNode[] = peers.map((p) => {
    const m = members.find((x) => x?.name === p?.name)
    return {
      name: str(p?.name, 63), ip: str(p?.ip, 45), role: str(p?.role, 16),
      ...(m ? { host: str(m.host, 63), state: str(m.state, 32), patroniRole: str(m.role, 32), lagBytes: Number.isFinite(m.lag) ? Number(m.lag) : null, timeline: Number.isFinite(m.timeline) ? Number(m.timeline) : null } : {}),
    }
  })
  const leader = members.find((m) => ['leader', 'master', 'primary'].includes(m?.role))?.name
  const at = Number(j.at) || 0
  const age = Math.max(0, Math.round(nowSec - at))
  const lr = j.local_role
  return {
    cluster: str(j.cluster, 63), node: str(j.node, 63), nodeRole: str(j.role, 16),
    localRole: lr === 'leader' || lr === 'replica' ? lr : 'unknown',
    at, ageSeconds: age, stale: age > MAX_AGE_SECONDS,
    etcd: { healthy: j.etcd?.healthy === true, members: Number(j.etcd?.members) || 0 },
    nodes, leader: typeof leader === 'string' ? str(leader, 63) : null,
    bind: j.bind === 'primary' || j.bind === 'secondary' ? j.bind : null,
    kea: j.kea ?? null,
    vip: j.vip && typeof j.vip.address === 'string' ? { address: str(j.vip.address, 64), iface: str(j.vip.iface, 32), held: j.vip.held === true } : null,
  }
}

export async function readClusterState(): Promise<ClusterState | null> {
  try {
    const st = await fs.stat(cfg().clusterStatusFile)
    if (!st.isFile() || st.size > 256 * 1024) return null
    return parseClusterState(await fs.readFile(cfg().clusterStatusFile, 'utf8'))
  } catch { return null }
}

export interface SwitchoverResult { at: number; candidate: string; ok: boolean; message: string }
export async function readSwitchoverResult(): Promise<SwitchoverResult | null> {
  try {
    const f = join(dirname(cfg().clusterStatusFile), 'cluster-result.json')
    const j = JSON.parse(await fs.readFile(f, 'utf8'))
    if (typeof j?.at !== 'number') return null
    return { at: j.at, candidate: str(j.candidate, 31), ok: j.ok === true, message: str(j.message, 200) }
  } catch { return null }
}

// Vérifie une demande de bascule contre l'état publié par root : un seul candidat possible = un secondaire de données en bonne santé.
export function switchoverCandidates(st: ClusterState | null): string[] {
  if (!st || st.stale || !st.etcd.healthy) return []
  return st.nodes.filter((n) => n.role === 'data' && n.name !== st.leader && n.patroniRole !== undefined && ['running', 'streaming'].includes(n.state ?? '')).map((n) => n.name)
}
