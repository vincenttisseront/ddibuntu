// Règles d'alerte : fonction PURE (aucun accès disque, base ou réseau) qui transforme une photographie de l'appliance en constats.
// Le moteur (alert-engine.ts) s'occupe du cycle de vie (ouverture, rappel, résolution), des silences et des notifications.
import type { ClusterState } from './cluster'
import type { NodeHealth } from './health'
import type { BackupResult, BackupStatus } from './backup'

export type Severity = 'critical' | 'warning' | 'info'
export const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 }

export interface Thresholds {
  diskWarn: number; diskCrit: number            // % utilisé
  certWarnDays: number; certCritDays: number    // jours avant l'échéance
  lagMiB: number                                 // retard de réplication (Mio)
  backupMaxAgeHours: number                      // 0 = 2 × l'intervalle des sauvegardes
  subnetWarn: number; subnetCrit: number         // % d'un sous-réseau utilisé
}
export const DEFAULT_THRESHOLDS: Thresholds = { diskWarn: 85, diskCrit: 95, certWarnDays: 30, certCritDays: 7, lagMiB: 64, backupMaxAgeHours: 0, subnetWarn: 90, subnetCrit: 98 }

export interface SubnetUsage { cidr: string; name: string; percent: number; used: number; capacity: number }
export interface Snapshot {
  now: number                                    // secondes epoch
  cluster: ClusterState | null
  localHealth: NodeHealth | null
  backup: BackupStatus | null
  backupResult: BackupResult | null
  subnets: SubnetUsage[]
  hygiene?: Hygiene                              // absent = non évalué (ex. nœud secondaire)
}
export interface Hygiene { ghosts: number; ghostDays: number; scanAt: number | null; unknown: number; macChanged: number }
export interface Memory { leader: string | null; leaderChangedAt: number | null }
export interface Finding { key: string; rule: string; severity: Severity; node: string; subject: string; params: Record<string, string | number> }

// Catalogue : identifiant → gravité par défaut (la gravité réelle d'un constat peut en différer : service secondaire, seuil critique…).
export const RULES: Record<string, Severity> = {
  'cluster.state_stale': 'critical', 'cluster.quorum_lost': 'critical', 'cluster.quorum_margin': 'warning', 'cluster.member_down': 'critical', 'cluster.no_leader': 'critical',
  'cluster.etcd_unhealthy': 'critical', 'cluster.replica_lag': 'warning', 'cluster.replica_unhealthy': 'warning', 'cluster.leader_changed': 'info', 'cluster.vip_not_held': 'warning',
  'node.health_stale': 'critical', 'node.service_down': 'critical', 'node.postgres_down': 'critical', 'node.disk_low': 'warning', 'node.cert_expiry': 'warning',
  'node.time_unsynced': 'warning', 'node.memory_low': 'warning',
  'backup.state_stale': 'warning', 'backup.none': 'warning', 'backup.too_old': 'warning', 'backup.archiver_failing': 'critical', 'backup.run_failed': 'warning',
  'ipam.subnet_full': 'warning', 'ipam.ghosts': 'info', 'ipam.unknown_hosts': 'warning', 'ipam.mac_changed': 'warning',
}
export const RULE_IDS = Object.keys(RULES)

// Services dont l'arrêt est critique (ce sont eux qui servent les clients ou portent les données) ; les autres ne déclenchent qu'un avertissement.
const CRITICAL_SERVICES = new Set(['console', 'dns', 'dhcp', 'postgresql', 'patroni', 'etcd'])
const TRANSIENT = new Set(['activating', 'reloading', 'deactivating'])
const LEADER_CHANGED_WINDOW_S = 3600

const f = (rule: string, severity: Severity, node = '', subject = '', params: Record<string, string | number> = {}): Finding => ({ key: `${rule}|${node}|${subject}`, rule, severity, node, subject, params })

// Santé de tous les nœuds connus : relayée par etcd (cluster) + fichier local ; pour un même nœud, le plus récent l'emporte.
export function mergedHealth(s: Snapshot): Record<string, NodeHealth> {
  const nodes: Record<string, NodeHealth> = { ...(s.cluster?.health ?? {}) }
  if (s.localHealth) { const cur = nodes[s.localHealth.node]; if (!cur || s.localHealth.at >= cur.at) nodes[s.localHealth.node] = s.localHealth }
  return nodes
}

export function evaluate(s: Snapshot, th: Thresholds, memory: Memory): { findings: Finding[]; memory: Memory } {
  const out: Finding[] = []
  const mem: Memory = { ...memory }
  const cl = s.cluster

  // ------------------------------------------------------------ cluster
  if (cl) {
    if (cl.stale) out.push(f('cluster.state_stale', 'critical', cl.node, '', { ageSeconds: cl.ageSeconds }))
    else {
      const q = cl.etcd.quorum
      if (q) {
        if (!q.hasQuorum) out.push(f('cluster.quorum_lost', 'critical', '', '', { healthy: q.healthy, needed: q.needed, voters: q.voters }))
        else if (q.tolerance === 0 && q.voters > 1) out.push(f('cluster.quorum_margin', 'warning', '', '', { healthy: q.healthy, needed: q.needed, voters: q.voters }))
        for (const m of q.members) {
          if (!m.reachable || !m.healthy) out.push(f('cluster.member_down', m.role === 'witness' ? 'warning' : 'critical', m.name, '', { role: m.role, reachable: m.reachable ? 1 : 0 }))
        }
      } else if (!cl.etcd.healthy) out.push(f('cluster.etcd_unhealthy', 'critical', cl.node))
      const dataNodes = cl.nodes.filter((n) => n.role === 'data')
      if (dataNodes.length > 0 && !cl.leader) out.push(f('cluster.no_leader', 'critical', '', '', { dataNodes: dataNodes.length }))
      for (const n of dataNodes) {
        if (n.patroniRole === undefined || n.name === cl.leader) continue
        if (typeof n.lagBytes === 'number' && n.lagBytes > th.lagMiB * 1024 * 1024) out.push(f('cluster.replica_lag', 'warning', n.name, '', { lagMiB: Math.round(n.lagBytes / 1048576) }))
        if (n.state && !['running', 'streaming'].includes(n.state)) out.push(f('cluster.replica_unhealthy', 'warning', n.name, '', { state: n.state }))
      }
      if (cl.vip && cl.localRole === 'leader' && !cl.vip.held) out.push(f('cluster.vip_not_held', 'warning', cl.node, '', { address: cl.vip.address }))
      // changement de leader : événement (mémorisé), actif une heure puis résolu seul
      if (cl.leader) {
        if (mem.leader && mem.leader !== cl.leader) { mem.leaderChangedAt = s.now; out.push(f('cluster.leader_changed', 'info', cl.leader, '', { from: mem.leader, to: cl.leader })) }
        else if (mem.leaderChangedAt && s.now - mem.leaderChangedAt < LEADER_CHANGED_WINDOW_S && mem.leader === cl.leader) out.push(f('cluster.leader_changed', 'info', cl.leader, '', { from: '', to: cl.leader }))
        mem.leader = cl.leader
      }
    }
  }
  if (mem.leaderChangedAt && s.now - mem.leaderChangedAt >= LEADER_CHANGED_WINDOW_S) mem.leaderChangedAt = null

  // ------------------------------------------------------------ santé des nœuds : relayée par etcd (cluster) + fichier local ; le plus récent l'emporte
  const nodes = mergedHealth(s)
  const age = (h: NodeHealth) => Math.max(0, Math.round(s.now - h.at))
  for (const [name, h] of Object.entries(nodes)) {
    const a = age(h)
    if (a > 180) { out.push(f('node.health_stale', h.role === 'witness' ? 'warning' : 'critical', name, '', { ageSeconds: a })); continue }   // données périmées : pas de constat dessus
    for (const sv of h.services) {
      if (!sv.expected || sv.state === 'active' || TRANSIENT.has(sv.state)) continue
      out.push(f('node.service_down', CRITICAL_SERVICES.has(sv.name) ? 'critical' : 'warning', name, sv.name, { state: sv.state }))
    }
    if (h.postgres === false) out.push(f('node.postgres_down', 'critical', name))
    for (const d of h.disks) {
      const used = Math.round(((d.sizeBytes - d.availBytes) / d.sizeBytes) * 1000) / 10
      if (used >= th.diskWarn) out.push(f('node.disk_low', used >= th.diskCrit ? 'critical' : 'warning', name, d.mount, { percent: used, freeMiB: Math.round(d.availBytes / 1048576) }))
    }
    for (const c of h.certs) {
      const days = Math.floor((c.notAfter - s.now) / 86400)
      if (days <= th.certWarnDays) out.push(f('node.cert_expiry', days <= th.certCritDays ? 'critical' : 'warning', name, c.name, { days }))
    }
    if (h.timeSynced === false) out.push(f('node.time_unsynced', 'warning', name))
    if (h.memory.totalKb > 0 && h.memory.availKb / h.memory.totalKb < 0.05) out.push(f('node.memory_low', 'warning', name, '', { percent: Math.round((1 - h.memory.availKb / h.memory.totalKb) * 1000) / 10 }))
  }

  // ------------------------------------------------------------ sauvegardes (nœuds porteurs d'une base ; l'état d'un arbitre ne compte pas)
  const b = s.backup
  if (b && b.enabled && b.role !== 'witness') {
    const node = b.node
    if (b.stale) out.push(f('backup.state_stale', 'warning', node, '', { ageSeconds: b.ageSeconds }))
    else {
      const max = (th.backupMaxAgeHours > 0 ? th.backupMaxAgeHours : Math.max(1, b.intervalHours) * 2) * 3600
      const last = b.backups.reduce((m, x) => Math.max(m, x.finishedAt), 0)
      if (b.backups.length === 0) out.push(f('backup.none', 'warning', node))
      else if (s.now - last > max) out.push(f('backup.too_old', s.now - last > 2 * max ? 'critical' : 'warning', node, '', { hours: Math.floor((s.now - last) / 3600), maxHours: Math.round(max / 3600) }))
      const a = b.archiver
      if (a && a.failedCount > 0 && a.lastFailedAt !== null && (a.lastArchivedAt === null || a.lastFailedAt > a.lastArchivedAt) && s.now - a.lastFailedAt < 86400) {
        out.push(f('backup.archiver_failing', 'critical', node, '', { failed: a.failedCount, wal: a.lastFailedWal ?? '' }))
      }
    }
  }
  const r = s.backupResult
  if (r && r.action === 'run' && !r.ok && s.now - r.at < 86400) out.push(f('backup.run_failed', 'warning', b?.node ?? '', '', { message: r.message.slice(0, 120) }))

  // ------------------------------------------------------------ IPAM : sous-réseaux presque pleins (les très petits sont ignorés : un /30 plein est normal)
  for (const u of s.subnets) {
    if (u.capacity < 16 || u.percent < th.subnetWarn) continue
    out.push(f('ipam.subnet_full', u.percent >= th.subnetCrit ? 'critical' : 'warning', '', u.cidr, { percent: u.percent, used: u.used, capacity: u.capacity, name: u.name }))
  }

  // ------------------------------------------------------------ IPAM : hygiène (adresses fantômes, hôtes inconnus, MAC changée) ; les deux derniers viennent de la découverte planifiée
  const hy = s.hygiene
  if (hy) {
    if (hy.ghosts > 0) out.push(f('ipam.ghosts', 'info', '', '', { count: hy.ghosts, days: hy.ghostDays }))
    if (hy.scanAt && s.now - hy.scanAt < 7 * 86400) {
      if (hy.unknown > 0) out.push(f('ipam.unknown_hosts', 'warning', '', '', { count: hy.unknown }))
      if (hy.macChanged > 0) out.push(f('ipam.mac_changed', 'warning', '', '', { count: hy.macChanged }))
    }
  }

  // un seul constat par clé (la première occurrence gagne)
  const seen = new Set<string>()
  return { findings: out.filter((x) => (seen.has(x.key) ? false : (seen.add(x.key), true))), memory: mem }
}
