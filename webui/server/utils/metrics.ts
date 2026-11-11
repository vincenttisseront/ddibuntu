// Export Prometheus (format texte 0.0.4) : état du cluster, santé de chaque nœud, sauvegardes, occupation des sous-réseaux, alertes.
// Chaque console exporte SA vue (état publié par root sur ce nœud) ; on interroge donc chaque nœud, ou l'adresse de service pour le leader.
import { mergedHealth } from './alert-rules'
import type { Snapshot } from './alert-rules'

const esc = (v: string | number) => String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')
const labels = (l: Record<string, string | number>) => { const k = Object.keys(l); return k.length ? '{' + k.map((n) => `${n}="${esc(l[n]!)}"`).join(',') + '}' : '' }

export function renderMetrics(s: Snapshot, summary: { critical: number; warning: number; info: number; silenced: number }, version: string): string {
  const out: string[] = []
  const seen = new Set<string>()
  const m = (name: string, help: string, type: 'gauge' | 'counter', value: number | boolean, l: Record<string, string | number> = {}) => {
    if (!seen.has(name)) { seen.add(name); out.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`) }
    out.push(`${name}${labels(l)} ${typeof value === 'boolean' ? (value ? 1 : 0) : Number.isFinite(value) ? value : 0}`)
  }
  const cl = s.cluster
  m('ddibuntu_info', 'Version et identité de ce nœud', 'gauge', 1, { version, node: cl?.node ?? s.localHealth?.node ?? '', cluster: cl?.cluster ?? '', role: cl?.nodeRole ?? 'standalone' })
  m('ddibuntu_clustered', '1 si ce serveur fait partie d\'un cluster', 'gauge', cl !== null)
  if (cl) {
    m('ddibuntu_cluster_state_age_seconds', 'Âge de l\'état du cluster publié par root', 'gauge', cl.ageSeconds)
    m('ddibuntu_cluster_etcd_healthy', 'etcd répond (1) ou non (0)', 'gauge', cl.etcd.healthy)
    m('ddibuntu_cluster_etcd_members', 'Membres etcd déclarés', 'gauge', cl.etcd.members)
    const q = cl.etcd.quorum
    if (q) {
      m('ddibuntu_cluster_quorum', '1 si le quorum etcd est présent', 'gauge', q.hasQuorum)
      m('ddibuntu_cluster_quorum_voters', 'Votants etcd', 'gauge', q.voters)
      m('ddibuntu_cluster_quorum_needed', 'Votants nécessaires au quorum', 'gauge', q.needed)
      m('ddibuntu_cluster_quorum_healthy', 'Votants sains', 'gauge', q.healthy)
      m('ddibuntu_cluster_quorum_tolerance', 'Pannes de membre encore tolérables', 'gauge', q.tolerance)
      for (const x of q.members) m('ddibuntu_cluster_member_up', 'Membre etcd joignable et sain', 'gauge', x.reachable && x.healthy, { node: x.name, role: x.role })
    }
    for (const n of cl.nodes) {
      if (n.patroniRole === undefined) continue
      m('ddibuntu_cluster_is_leader', '1 si le nœud est leader PostgreSQL', 'gauge', n.name === cl.leader, { node: n.name })
      if (typeof n.lagBytes === 'number') m('ddibuntu_cluster_replication_lag_bytes', 'Retard de réplication PostgreSQL', 'gauge', n.lagBytes, { node: n.name })
    }
    m('ddibuntu_cluster_has_leader', '1 si un leader PostgreSQL existe', 'gauge', !!cl.leader)
    if (cl.vip) m('ddibuntu_cluster_vip_held', 'Adresse de service portée par ce nœud', 'gauge', cl.vip.held)
  }
  for (const [name, h] of Object.entries(mergedHealth(s))) {
    const age = Math.max(0, Math.round(s.now - h.at))
    m('ddibuntu_node_health_age_seconds', 'Âge de la dernière santé publiée par le nœud', 'gauge', age, { node: name })
    m('ddibuntu_node_load1', 'Charge moyenne sur 1 minute', 'gauge', h.load1, { node: name })
    m('ddibuntu_node_uptime_seconds', 'Durée de fonctionnement', 'gauge', h.uptimeSeconds, { node: name })
    m('ddibuntu_node_memory_total_bytes', 'Mémoire totale', 'gauge', h.memory.totalKb * 1024, { node: name })
    m('ddibuntu_node_memory_available_bytes', 'Mémoire disponible', 'gauge', h.memory.availKb * 1024, { node: name })
    if (h.postgres !== null) m('ddibuntu_node_postgres_up', 'PostgreSQL répond', 'gauge', h.postgres, { node: name })
    if (h.timeSynced !== null) m('ddibuntu_node_time_synced', 'Horloge synchronisée', 'gauge', h.timeSynced, { node: name })
    for (const sv of h.services) m('ddibuntu_node_service_up', 'Service actif (1) ou non (0) ; seulement les services attendus sur ce nœud', 'gauge', sv.state === 'active', { node: name, service: sv.name, expected: sv.expected ? 'true' : 'false' })
    for (const d of h.disks) { m('ddibuntu_node_disk_size_bytes', 'Taille du système de fichiers', 'gauge', d.sizeBytes, { node: name, mount: d.mount }); m('ddibuntu_node_disk_avail_bytes', 'Espace disponible', 'gauge', d.availBytes, { node: name, mount: d.mount }) }
    for (const c of h.certs) m('ddibuntu_node_cert_expiry_seconds', 'Secondes avant l\'échéance du certificat (négatif : expiré)', 'gauge', c.notAfter - s.now, { node: name, cert: c.name })
  }
  const b = s.backup
  if (b && b.role !== 'witness') {
    m('ddibuntu_backup_enabled', 'Sauvegardes activées', 'gauge', b.enabled, { node: b.node })
    m('ddibuntu_backup_count', 'Sauvegardes complètes disponibles', 'gauge', b.backups.length, { node: b.node })
    m('ddibuntu_backup_last_success_timestamp_seconds', 'Date de la dernière sauvegarde réussie (0 : aucune)', 'gauge', b.backups.reduce((x, y) => Math.max(x, y.finishedAt), 0), { node: b.node })
    if (b.archiver) m('ddibuntu_backup_archiver_failed_total', 'Échecs cumulés de l\'archivage des journaux WAL', 'counter', b.archiver.failedCount, { node: b.node })
    if (b.pitrFrom) m('ddibuntu_backup_pitr_window_seconds', 'Étendue de la fenêtre de restauration à un instant donné', 'gauge', Math.max(0, s.now - b.pitrFrom), { node: b.node })
  }
  for (const u of s.subnets.slice(0, 500)) m('ddibuntu_subnet_utilization_ratio', 'Occupation d\'un sous-réseau (0 à 1)', 'gauge', u.percent / 100, { subnet: u.cidr })
  for (const sev of ['critical', 'warning', 'info'] as const) m('ddibuntu_alerts_firing', 'Alertes ouvertes non réduites au silence', 'gauge', summary[sev], { severity: sev })
  m('ddibuntu_alerts_silenced', 'Alertes ouvertes réduites au silence', 'gauge', summary.silenced)
  return out.join('\n') + '\n'
}
