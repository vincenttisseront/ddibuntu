// Texte des notifications (webhook, e-mail) : l'interface, elle, traduit côté navigateur à partir de l'identifiant de règle et des paramètres.
export type Lang = 'fr' | 'en'
type P = Record<string, any>
const T: Record<string, [(p: P, n: string, s: string) => string, (p: P, n: string, s: string) => string]> = {
  'cluster.state_stale': [(p, n) => `L’état du cluster n’est plus publié sur ${n} (depuis ${p.ageSeconds} s).`, (p, n) => `The cluster state has not been published on ${n} for ${p.ageSeconds} s.`],
  'cluster.quorum_lost': [(p) => `Quorum etcd PERDU : ${p.healthy} membre(s) sain(s) sur ${p.voters}, ${p.needed} nécessaires. Le cluster est en lecture seule.`, (p) => `etcd quorum LOST: ${p.healthy} healthy member(s) out of ${p.voters}, ${p.needed} needed. The cluster is read-only.`],
  'cluster.quorum_margin': [(p) => `Plus aucune marge de panne : ${p.healthy}/${p.voters} membres sains, ${p.needed} nécessaires pour garder le quorum.`, (p) => `No failure margin left: ${p.healthy}/${p.voters} healthy members, ${p.needed} needed to keep quorum.`],
  'cluster.member_down': [(_p, n) => `Le membre ${n} du cluster est injoignable ou en défaut.`, (_p, n) => `Cluster member ${n} is unreachable or unhealthy.`],
  'cluster.no_leader': [() => 'Aucun leader PostgreSQL : la base n’accepte plus d’écriture.', () => 'No PostgreSQL leader: the database no longer accepts writes.'],
  'cluster.etcd_unhealthy': [(_p, n) => `etcd ne répond pas sur ${n}.`, (_p, n) => `etcd is not answering on ${n}.`],
  'cluster.replica_lag': [(p, n) => `Retard de réplication de ${p.lagMiB} Mio sur ${n}.`, (p, n) => `Replication lag of ${p.lagMiB} MiB on ${n}.`],
  'cluster.replica_unhealthy': [(p, n) => `Le secondaire ${n} n’est pas en réplication (état : ${p.state}).`, (p, n) => `Replica ${n} is not replicating (state: ${p.state}).`],
  'cluster.leader_changed': [(p, n) => `Bascule : le leader est maintenant ${n}${p.from ? ` (avant : ${p.from})` : ''}.`, (p, n) => `Failover: the leader is now ${n}${p.from ? ` (was ${p.from})` : ''}.`],
  'cluster.vip_not_held': [(p, n) => `L’adresse de service ${p.address} n’est pas portée par ${n}, pourtant leader.`, (p, n) => `Service address ${p.address} is not held by ${n}, although it is the leader.`],
  'node.health_stale': [(p, n) => `Le nœud ${n} ne publie plus sa santé depuis ${p.ageSeconds} s (arrêté, isolé ou collecteur en panne).`, (p, n) => `Node ${n} has not published its health for ${p.ageSeconds} s (down, isolated or collector stopped).`],
  'node.service_down': [(p, n, s) => `Le service « ${s} » est à l’état « ${p.state} » sur ${n}.`, (p, n, s) => `Service "${s}" is "${p.state}" on ${n}.`],
  'node.postgres_down': [(_p, n) => `PostgreSQL ne répond pas sur ${n}.`, (_p, n) => `PostgreSQL is not answering on ${n}.`],
  'node.disk_low': [(p, n, s) => `Disque ${s} plein à ${p.percent} % sur ${n} (${p.freeMiB} Mio libres).`, (p, n, s) => `Disk ${s} is ${p.percent}% full on ${n} (${p.freeMiB} MiB free).`],
  'node.cert_expiry': [(p, n, s) => (p.days < 0 ? `Le certificat « ${s} » de ${n} a expiré depuis ${-p.days} j.` : `Le certificat « ${s} » de ${n} expire dans ${p.days} j.`), (p, n, s) => (p.days < 0 ? `Certificate "${s}" on ${n} expired ${-p.days} d ago.` : `Certificate "${s}" on ${n} expires in ${p.days} d.`)],
  'node.time_unsynced': [(_p, n) => `L’horloge de ${n} n’est pas synchronisée.`, (_p, n) => `The clock on ${n} is not synchronised.`],
  'node.memory_low': [(p, n) => `Mémoire utilisée à ${p.percent} % sur ${n}.`, (p, n) => `Memory ${p.percent}% used on ${n}.`],
  'backup.state_stale': [(p, n) => `L’état des sauvegardes de ${n} n’est plus publié (depuis ${p.ageSeconds} s).`, (p, n) => `Backup state of ${n} has not been published for ${p.ageSeconds} s.`],
  'backup.none': [(_p, n) => `Aucune sauvegarde de la base sur ${n}.`, (_p, n) => `No database backup on ${n}.`],
  'backup.too_old': [(p, n) => `Dernière sauvegarde de ${n} vieille de ${p.hours} h (maximum toléré : ${p.maxHours} h).`, (p, n) => `Last backup on ${n} is ${p.hours} h old (maximum allowed: ${p.maxHours} h).`],
  'backup.archiver_failing': [(p, n) => `L’archivage des journaux WAL échoue sur ${n} (${p.failed} échec(s), dernier : ${p.wal}) : la restauration à un instant donné est compromise.`, (p, n) => `WAL archiving is failing on ${n} (${p.failed} failure(s), last: ${p.wal}): point-in-time recovery is at risk.`],
  'backup.run_failed': [(p, n) => `La dernière sauvegarde a échoué sur ${n} : ${p.message}`, (p, n) => `The last backup failed on ${n}: ${p.message}`],
  'ipam.subnet_full': [(p, _n, s) => `Le sous-réseau ${s}${p.name ? ` (${p.name})` : ''} est utilisé à ${p.percent} % (${p.used}/${p.capacity}).`, (p, _n, s) => `Subnet ${s}${p.name ? ` (${p.name})` : ''} is ${p.percent}% used (${p.used}/${p.capacity}).`],
}
export function describe(rule: string, node: string, subject: string, params: P, lang: Lang): string {
  const t = T[rule]
  if (!t) return rule
  try { return t[lang === 'en' ? 1 : 0](params ?? {}, node || '?', subject) } catch { return rule }
}
export const SEVERITY_LABEL: Record<Lang, Record<string, string>> = { fr: { critical: 'CRITIQUE', warning: 'ALERTE', info: 'INFO' }, en: { critical: 'CRITICAL', warning: 'WARNING', info: 'INFO' } }
