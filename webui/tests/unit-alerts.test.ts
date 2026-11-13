import { describe, expect, it, vi } from 'vitest'

const osState = vi.hoisted(() => ({ fail: false }))
vi.mock('node:os', async (orig) => {
  const real: any = await orig()
  return { ...real, default: real, networkInterfaces: () => { if (osState.fail) throw Object.assign(new Error('uv_interface_addresses returned Unknown system error 97'), { code: 'ERR_SYSTEM_ERROR' }); return real.networkInterfaces() } }
})
import { parseClusterState, localAddresses } from '../server/utils/cluster'
import { parseNodeHealth } from '../server/utils/health'
import { DEFAULT_THRESHOLDS, evaluate, RULES } from '../server/utils/alert-rules'
import type { Memory, Snapshot } from '../server/utils/alert-rules'
import { describe as text } from '../server/utils/alert-text'
import { ConfigInput, configError, webhookUrlError } from '../server/utils/alert-config'
import { renderMetrics } from '../server/utils/metrics'
import { parseBackupStatus } from '../server/utils/backup'

const NOW = 1_800_000_000
const health = (node: string, over: Record<string, unknown> = {}) => ({
  at: NOW - 20, node, cluster: 'lab', role: 'data', hostname: node, uptimeSeconds: 5000, load1: 0.2, memory: { totalKb: 8_000_000, availKb: 6_000_000 },
  services: [{ name: 'console', state: 'active', expected: true }, { name: 'dns', state: 'active', expected: true }, { name: 'patroni', state: 'active', expected: true }],
  postgres: true, disks: [{ mount: '/', sizeBytes: 100e9, availBytes: 60e9 }], certs: [{ name: 'console', notAfter: NOW + 200 * 86400 }], timeSynced: true, ...over,
})
const clusterRaw = (over: Record<string, unknown> = {}) => ({
  cluster: 'lab', node: 'n1', role: 'data', local_role: 'leader', at: NOW - 10, bind: 'primary',
  etcd: { healthy: true, members: 3, quorum: { voters: 3, needed: 2, healthy: 3, hasQuorum: true, tolerance: 1, leader: 'n1', members: [
    { name: 'n1', ip: '10.9.0.1', role: 'data', reachable: true, healthy: true }, { name: 'n2', ip: '10.9.0.2', role: 'data', reachable: true, healthy: true }, { name: 'n3', ip: '10.9.0.3', role: 'witness', reachable: true, healthy: true }] } },
  peers: [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }],
  patroni: { members: [{ name: 'n1', role: 'leader', state: 'running', timeline: 3 }, { name: 'n2', role: 'replica', state: 'streaming', lag: 1024, timeline: 3 }] },
  vip: { address: '192.0.2.10/24', iface: 'ens192', held: true },
  health: { n1: health('n1'), n2: health('n2'), n3: health('n3', { role: 'witness', services: [{ name: 'etcd', state: 'active', expected: true }], postgres: null }) }, ...over,
})
const snap = (over: Partial<Snapshot> & { cluster?: any } = {}): Snapshot => {
  const { cluster, ...rest } = over
  return { now: NOW, cluster: cluster === undefined ? parseClusterState(JSON.stringify(clusterRaw()), NOW) : cluster === null ? null : parseClusterState(JSON.stringify(cluster), NOW), localHealth: null, backup: null, backupResult: null, subnets: [], ...rest }
}
const mem: Memory = { leader: null, leaderChangedAt: null }
const run = (s: Snapshot, m: Memory = mem, th = DEFAULT_THRESHOLDS) => evaluate(s, th, m)
const rules = (s: Snapshot, m: Memory = mem) => run(s, m).findings.map((f) => f.key).sort()

describe('santé de nœud : lecture bornée', () => {
  it('champs connus seulement, valeurs hors bornes écartées', () => {
    const h = parseNodeHealth({ ...health('n1'), services: [{ name: 'ok', state: 'active', expected: true }, { name: 'MAUVAIS NOM', state: 'active' }, { name: 'x', state: '<script>' }], secret: 'x', disks: [{ mount: '/', sizeBytes: 0, availBytes: 1 }], load1: 'abc' }, NOW)!
    expect(h.services).toEqual([{ name: 'ok', state: 'active', expected: true }]); expect(h.disks).toEqual([]); expect(h.load1).toBe(0); expect(h).not.toHaveProperty('secret')
  })
  it('nœud sans nom valide ou objet invalide : ignoré', () => {
    for (const bad of [null, [], 'x', { at: 1 }, { node: 'Pas Valide' }, { node: 'a'.repeat(40) }]) expect(parseNodeHealth(bad, NOW)).toBeNull()
  })
  it('périmé au-delà de 3 minutes', () => { expect(parseNodeHealth(health('n1', { at: NOW - 500 }), NOW)!.stale).toBe(true); expect(parseNodeHealth(health('n1'), NOW)!.stale).toBe(false) })
  it('relayée dans l’état du cluster : la clé doit être le nom du nœud qui publie', () => {
    const s = parseClusterState(JSON.stringify(clusterRaw({ health: { n1: health('n1'), n2: health('n1'), 'N X': health('n3'), n9: 'pas un objet' } })), NOW)!
    expect(Object.keys(s.health)).toEqual(['n1'])
  })
})

describe('règles : un cluster sain ne lève aucune alerte', () => {
  it('3 nœuds, quorum plein, tout actif', () => { expect(rules(snap())).toEqual([]) })
  it('serveur seul, tout va bien', () => { expect(rules(snap({ cluster: null, localHealth: parseNodeHealth(health('solo', { role: 'standalone' }), NOW)! }))).toEqual([]) })
  it('rien du tout (collecteur absent) : aucun constat inventé', () => { expect(rules(snap({ cluster: null }))).toEqual([]) })
})

describe('règles : cluster', () => {
  it('quorum perdu : critique', () => {
    const c = clusterRaw(); (c.etcd.quorum as any).hasQuorum = false; (c.etcd.quorum as any).healthy = 1
    const f = run(snap({ cluster: c })).findings.find((x) => x.rule === 'cluster.quorum_lost')!
    expect(f.severity).toBe('critical'); expect(f.params).toMatchObject({ healthy: 1, needed: 2, voters: 3 })
  })
  it('plus aucune marge : avertissement ; la perte d’un membre de données est critique, celle de l’arbitre un avertissement', () => {
    const c = clusterRaw(); const q = c.etcd.quorum as any; q.tolerance = 0; q.healthy = 2; q.members[2].reachable = false
    const f = run(snap({ cluster: c })).findings
    expect(f.find((x) => x.rule === 'cluster.quorum_margin')!.severity).toBe('warning')
    expect(f.find((x) => x.rule === 'cluster.member_down')).toMatchObject({ node: 'n3', severity: 'warning' })
    q.members[1].healthy = false
    expect(run(snap({ cluster: c })).findings.find((x) => x.rule === 'cluster.member_down' && x.node === 'n2')!.severity).toBe('critical')
  })
  it('aucun leader : critique', () => {
    const c = clusterRaw({ patroni: { members: [{ name: 'n1', role: 'replica', state: 'running' }, { name: 'n2', role: 'replica', state: 'running' }] } })
    expect(rules(snap({ cluster: c }))).toContain('cluster.no_leader||')
  })
  it('retard de réplication au-delà du seuil, secondaire hors réplication', () => {
    const c = clusterRaw({ patroni: { members: [{ name: 'n1', role: 'leader', state: 'running' }, { name: 'n2', role: 'replica', state: 'starting', lag: 200 * 1048576 }] } })
    const f = run(snap({ cluster: c })).findings
    expect(f.find((x) => x.rule === 'cluster.replica_lag')).toMatchObject({ node: 'n2', params: { lagMiB: 200 } }); expect(f.find((x) => x.rule === 'cluster.replica_unhealthy')).toMatchObject({ node: 'n2', params: { state: 'starting' } })
  })
  it('état du cluster périmé : une seule alerte (les autres règles ne se fient pas à une donnée périmée)', () => {
    const c = clusterRaw({ at: NOW - 900 }); (c.etcd.quorum as any).hasQuorum = false
    expect(rules(snap({ cluster: c })).filter((k) => k.startsWith('cluster.'))).toEqual(['cluster.state_stale|n1|'])
  })
  it('adresse de service non portée par le leader', () => {
    expect(rules(snap({ cluster: clusterRaw({ vip: { address: '192.0.2.10/24', iface: 'ens192', held: false } }) }))).toContain('cluster.vip_not_held|n1|')
    expect(rules(snap({ cluster: clusterRaw({ local_role: 'replica', vip: { address: '192.0.2.10/24', iface: 'ens192', held: false } }) }))).not.toContain('cluster.vip_not_held|n1|')   // un secondaire ne la porte pas : normal
  })
  it('changement de leader : événement mémorisé, actif une heure puis résolu seul', () => {
    const r1 = run(snap(), { leader: 'n2', leaderChangedAt: null })
    expect(r1.findings.find((x) => x.rule === 'cluster.leader_changed')).toMatchObject({ severity: 'info', node: 'n1', params: { from: 'n2', to: 'n1' } }); expect(r1.memory).toEqual({ leader: 'n1', leaderChangedAt: NOW })
    expect(rules(snap(), r1.memory)).toContain('cluster.leader_changed|n1|')                                     // toujours actif 10 minutes après
    expect(rules({ ...snap(), now: NOW + 3700 }, r1.memory)).not.toContain('cluster.leader_changed|n1|')          // plus d’une heure : résolu
    expect(run({ ...snap(), now: NOW + 3700 }, r1.memory).memory.leaderChangedAt).toBeNull()
    expect(rules(snap(), { leader: null, leaderChangedAt: null })).not.toContain('cluster.leader_changed|n1|')    // première observation : pas un changement
  })
})

describe('règles : nœuds', () => {
  const withHealth = (n: string, over: Record<string, unknown>) => snap({ cluster: clusterRaw({ health: { ...clusterRaw().health, [n]: health(n, over) } }) })
  it('service attendu arrêté : critique pour DNS, avertissement pour les autres ; un service transitoire ou non attendu est ignoré', () => {
    const f = run(withHealth('n2', { services: [{ name: 'dns', state: 'failed', expected: true }, { name: 'chrony', state: 'inactive', expected: true }, { name: 'dhcp', state: 'activating', expected: true }, { name: 'keepalived', state: 'inactive', expected: false }] })).findings
    expect(f.filter((x) => x.rule === 'node.service_down').map((x) => [x.node, x.subject, x.severity])).toEqual([['n2', 'dns', 'critical'], ['n2', 'chrony', 'warning']])
  })
  it('disque : 85 % avertissement, 95 % critique ; certificat : 30 jours avertissement, 7 jours critique, expiré critique', () => {
    expect(run(withHealth('n1', { disks: [{ mount: '/', sizeBytes: 100e9, availBytes: 10e9 }, { mount: '/var', sizeBytes: 100e9, availBytes: 3e9 }, { mount: '/srv', sizeBytes: 100e9, availBytes: 30e9 }] })).findings.filter((x) => x.rule === 'node.disk_low').map((x) => [x.subject, x.severity])).toEqual([['/', 'warning'], ['/var', 'critical']])
    const c = (days: number) => run(withHealth('n1', { certs: [{ name: 'console', notAfter: NOW + days * 86400 }] })).findings.find((x) => x.rule === 'node.cert_expiry')
    expect(c(200)).toBeUndefined(); expect(c(20)).toMatchObject({ severity: 'warning', params: { days: 20 } }); expect(c(5)!.severity).toBe('critical'); expect(c(-3)).toMatchObject({ severity: 'critical', params: { days: -3 } })
  })
  it('PostgreSQL, heure, mémoire', () => {
    const k = rules(withHealth('n2', { postgres: false, timeSynced: false, memory: { totalKb: 1000, availKb: 20 } }))
    expect(k).toEqual(expect.arrayContaining(['node.postgres_down|n2|', 'node.time_unsynced|n2|', 'node.memory_low|n2|']))
  })
  it('nœud silencieux (santé périmée) : critique, arbitre seulement avertissement ; ses autres constats ne sont pas évalués', () => {
    const f = run(snap({ cluster: clusterRaw({ health: { ...clusterRaw().health, n2: health('n2', { at: NOW - 900, postgres: false }), n3: health('n3', { at: NOW - 900, role: 'witness', services: [] }) } }) })).findings
    expect(f.filter((x) => x.rule.startsWith('node.')).map((x) => [x.rule, x.node, x.severity])).toEqual([['node.health_stale', 'n2', 'critical'], ['node.health_stale', 'n3', 'warning']])
  })
  it('la santé locale, plus récente, l’emporte sur celle relayée', () => {
    const s = snap({ localHealth: parseNodeHealth(health('n1', { at: NOW - 2, services: [{ name: 'dns', state: 'failed', expected: true }] }), NOW)! })
    expect(rules(s)).toContain('node.service_down|n1|dns')
  })
})

describe('règles : sauvegardes et IPAM', () => {
  const bk = (over: Record<string, unknown> = {}) => parseBackupStatus(JSON.stringify({
    at: NOW - 60, enabled: true, role: 'primary', node: 'n1', hostname: 'h', cluster: 'lab', repo: '/r', keepFull: 3, intervalHours: 24, startHour: 2, mirrorDir: null, archiveMode: 'on',
    archiver: { archived_count: 5, last_archived_wal: 'A', last_archived_at: NOW - 30, failed_count: 0, last_failed_wal: null, last_failed_at: null },
    diskFreeBytes: 1e9, preRestoreDirs: 0, walFiles: 1, walBytes: 1, lastWalAt: NOW, pitrFrom: NOW - 7200,
    backups: [{ id: '20261111T080000Z', node: 'n1', startedAt: NOW - 3700, finishedAt: NOW - 3600, sizeBytes: 5, timeline: 1, walArchived: true }], ...over }), NOW)!
  it('sauvegardes en bon état : rien', () => { expect(rules(snap({ backup: bk() }))).toEqual([]) })
  it('aucune sauvegarde, trop ancienne (avertissement puis critique), état périmé', () => {
    expect(rules(snap({ backup: bk({ backups: [] }) }))).toContain('backup.none|n1|')
    const old = (h: number) => run(snap({ backup: bk({ backups: [{ id: '20261111T080000Z', node: 'n1', startedAt: NOW - h * 3600 - 10, finishedAt: NOW - h * 3600, sizeBytes: 5, timeline: 1, walArchived: true }] }) })).findings.find((x) => x.rule === 'backup.too_old')
    expect(old(30)).toBeUndefined(); expect(old(60)!.severity).toBe('warning'); expect(old(120)!.severity).toBe('critical')
    expect(rules(snap({ backup: bk({ at: NOW - 7200 }) }))).toEqual(['backup.state_stale|n1|'])
  })
  it('contrôle d’intégrité en échec : critique pendant 14 jours, rétabli par un contrôle réussi', () => {
    const lv = (ok: boolean, age: number) => ({ lastVerify: { at: NOW - age, ok, backups: 2, badBackups: ok ? 0 : 1, badWal: 0 } })
    expect(run(snap({ backup: bk(lv(false, 600)) })).findings.find((x) => x.rule === 'backup.verify_failed')).toMatchObject({ severity: 'critical', node: 'n1', params: { bad: 1, badWal: 0 } })
    expect(rules(snap({ backup: bk(lv(true, 600)) }))).toEqual([]); expect(rules(snap({ backup: bk(lv(false, 15 * 86400)) }))).toEqual([])
  })
  it('archivage des WAL en échec : critique ; rétabli (un succès plus récent) : rien', () => {
    const failing = bk({ archiver: { archived_count: 5, last_archived_wal: 'A', last_archived_at: NOW - 600, failed_count: 3, last_failed_wal: 'B', last_failed_at: NOW - 60 } })
    expect(run(snap({ backup: failing })).findings.find((x) => x.rule === 'backup.archiver_failing')).toMatchObject({ severity: 'critical', params: { failed: 3, wal: 'B' } })
    const healed = bk({ archiver: { archived_count: 9, last_archived_wal: 'C', last_archived_at: NOW - 10, failed_count: 3, last_failed_wal: 'B', last_failed_at: NOW - 600 } })
    expect(rules(snap({ backup: healed }))).toEqual([])
  })
  it('sauvegarde désactivée, arbitre : aucune règle de sauvegarde', () => {
    expect(rules(snap({ backup: bk({ enabled: false, backups: [] }) }))).toEqual([]); expect(rules(snap({ backup: bk({ role: 'witness', backups: [] }) }))).toEqual([])
  })
  it('échec de la dernière sauvegarde (moins de 24 h)', () => {
    expect(rules(snap({ backupResult: { at: NOW - 100, action: 'run', ok: false, message: 'disque plein', id: null } }))).toContain('backup.run_failed||')
    expect(rules(snap({ backupResult: { at: NOW - 200000, action: 'run', ok: false, message: 'vieux', id: null } }))).toEqual([])
    expect(rules(snap({ backupResult: { at: NOW - 100, action: 'verify', ok: false, message: 'x', id: null } }))).toEqual([])
  })
  it('sous-réseaux presque pleins ; les très petits sont ignorés', () => {
    const f = run(snap({ subnets: [{ cidr: '10.0.0.0/24', name: 'LAN', percent: 91, used: 230, capacity: 254 }, { cidr: '10.0.1.0/24', name: 'DMZ', percent: 99, used: 250, capacity: 254 }, { cidr: '10.0.2.0/24', name: 'OK', percent: 50, used: 127, capacity: 254 }, { cidr: '10.9.9.0/30', name: 'p2p', percent: 100, used: 2, capacity: 2 }] })).findings
    expect(f.map((x) => [x.subject, x.severity])).toEqual([['10.0.0.0/24', 'warning'], ['10.0.1.0/24', 'critical']])
  })
  it('seuils personnalisés respectés', () => {
    expect(run(snap({ subnets: [{ cidr: '10.0.0.0/24', name: 'LAN', percent: 75, used: 190, capacity: 254 }] }), mem, { ...DEFAULT_THRESHOLDS, subnetWarn: 70 }).findings).toHaveLength(1)
  })
})

describe('catalogue', () => {
  it('chaque règle a un texte français ET anglais, jamais l’identifiant brut', () => {
    for (const id of Object.keys(RULES)) for (const l of ['fr', 'en'] as const) { const t = text(id, 'n1', 'sujet', { ageSeconds: 5, healthy: 1, needed: 2, voters: 3, lagMiB: 9, state: 'x', days: 3, percent: 90, freeMiB: 5, hours: 5, maxHours: 4, failed: 1, wal: 'W', message: 'm', used: 1, capacity: 2, name: 'N', from: 'a', to: 'b', address: '1.2.3.4' }, l); expect(t).not.toBe(id); expect(t.length).toBeGreaterThan(10) }
  })
  it('règle inconnue : l’identifiant', () => { expect(text('x.y', 'n', '', {}, 'fr')).toBe('x.y') })
})

describe('réglages', () => {
  const ok = { minSeverity: 'warning', repeatHours: 0, lang: 'fr', thresholds: DEFAULT_THRESHOLDS, webhook: { enabled: false, url: '' }, email: { enabled: false, host: '', port: 587, security: 'starttls', verifyCert: true, user: '', from: '', to: [] } }
  it('valide un réglage complet ; refuse les champs inconnus et les seuils incohérents', () => {
    expect(ConfigInput.safeParse(ok).success).toBe(true)
    expect(ConfigInput.safeParse({ ...ok, extra: 1 }).success).toBe(false)
    expect(ConfigInput.safeParse({ ...ok, thresholds: { ...DEFAULT_THRESHOLDS, diskWarn: 90, diskCrit: 80 } }).success).toBe(false)
    expect(ConfigInput.safeParse({ ...ok, thresholds: { ...DEFAULT_THRESHOLDS, certWarnDays: 5, certCritDays: 10 } }).success).toBe(false)
  })
  it('adresse du webhook : http(s) seulement, pas d’identifiants dans l’adresse, jamais les métadonnées des nuages', () => {
    expect(webhookUrlError('https://hooks.example.com/x')).toBeNull(); expect(webhookUrlError('http://10.0.0.5:8080/alert')).toBeNull()
    for (const bad of ['ftp://x/y', 'javascript:alert(1)', 'file:///etc/passwd', 'pas une url', 'https://user:pw@example.com/', 'http://169.254.169.254/latest/meta-data', 'http://[fe80::1]/x']) expect(webhookUrlError(bad), bad).not.toBeNull()
  })
  it('contrôles croisés des canaux activés', () => {
    const c = (over: any) => configError(ConfigInput.parse({ ...ok, ...over }))
    expect(c({ webhook: { enabled: true, url: 'ftp://x' } })).toBe('webhook_url_invalid')
    expect(c({ email: { ...ok.email, enabled: true, host: 'smtp.example.com', from: 'a@example.com', to: ['b@example.com'] } })).toBeNull()
    expect(c({ email: { ...ok.email, enabled: true, host: 'smtp.example.com', from: 'pas-une-adresse', to: ['b@example.com'] } })).toBe('email_from_invalid')
    expect(c({ email: { ...ok.email, enabled: true, host: 'smtp.example.com', from: 'a@example.com', to: [] } })).toBe('email_to_invalid')
    expect(c({ email: { ...ok.email, enabled: true, host: 'smtp.example.com', from: 'a@example.com', to: ['b@example.com'], user: 'u', security: 'none' } })).toBe('email_auth_requires_tls')
    expect(c({ email: { ...ok.email, enabled: true, host: 'bad host!', from: 'a@example.com', to: ['b@example.com'] } })).toBe('email_host_invalid')
  })
})

describe('export Prometheus', () => {
  const out = renderMetrics(snap({ subnets: [{ cidr: '10.0.0.0/24', name: 'LAN "x"', percent: 50, used: 127, capacity: 254 }] }), { critical: 1, warning: 2, info: 0, silenced: 3 }, '0.9.1')
  it('format texte : une ligne HELP/TYPE par métrique, valeurs numériques', () => {
    for (const l of out.trim().split('\n')) expect(l).toMatch(/^(# (HELP|TYPE) [a-z0-9_]+ .+|[a-z0-9_]+(\{.*\})? -?\d+(\.\d+)?)$/)
    expect(out.match(/# TYPE ddibuntu_node_load1 /g)).toHaveLength(1)
  })
  it('contenu : quorum, leader, santé par nœud, certificats, alertes', () => {
    expect(out).toContain('ddibuntu_cluster_quorum 1'); expect(out).toContain('ddibuntu_cluster_is_leader{node="n1"} 1'); expect(out).toContain('ddibuntu_cluster_is_leader{node="n2"} 0')
    expect(out).toContain('ddibuntu_node_service_up{node="n2",service="dns",expected="true"} 1'); expect(out).toContain('ddibuntu_alerts_firing{severity="critical"} 1'); expect(out).toContain('ddibuntu_alerts_silenced 3')
    expect(out).toMatch(/ddibuntu_node_cert_expiry_seconds\{node="n1",cert="console"\} 17280000/); expect(out).toContain('ddibuntu_subnet_utilization_ratio{subnet="10.0.0.0/24"} 0.5')
  })
  it('serveur seul : pas de série de cluster', () => { const o = renderMetrics(snap({ cluster: null }), { critical: 0, warning: 0, info: 0, silenced: 0 }, '0.9.1'); expect(o).toContain('ddibuntu_clustered 0'); expect(o).not.toContain('ddibuntu_cluster_quorum') })
})

describe('adresses locales (service durci sans AF_NETLINK)', () => {
  it('lecture normale : adresses IPv4 (boucle locale sur demande)', () => { osState.fail = false; expect(localAddresses(true).some((a) => a.address === '127.0.0.1')).toBe(true) })
  it('lecture impossible : liste vide, jamais d’exception (la page Cluster ne tombe plus en erreur 500)', () => {
    osState.fail = true
    try { expect(localAddresses(true)).toEqual([]); expect(localAddresses(false)).toEqual([]) } finally { osState.fail = false }
  })
})

describe('règles : retour à la normale', () => {
  const down = () => { const c = clusterRaw(); (c.etcd.quorum as any).members[1].healthy = false; return c }
  it('panne mémorisée, puis « resynchronisation en cours », puis « nœud revenu » (une heure), puis plus rien', () => {
    const r1 = run(snap({ cluster: down() }), { leader: 'n1', leaderChangedAt: null })
    expect(r1.memory.down).toEqual({ n2: NOW }); expect(rules(snap({ cluster: down() }), r1.memory)).not.toContain('cluster.node_recovered|n2|')
    // à l'instant t (secondes après NOW) : cluster et santés tous frais ; lag du secondaire n2
    const at = (t: number, lag: number) => ({ ...snap({ cluster: clusterRaw({ at: NOW + t, patroni: { members: [{ name: 'n1', role: 'leader', state: 'running' }, { name: 'n2', role: 'replica', state: 'streaming', lag }] },
      health: { n1: health('n1', { at: NOW + t - 5 }), n2: health('n2', { at: NOW + t - 5 }), n3: health('n3', { at: NOW + t - 5, role: 'witness', services: [{ name: 'etcd', state: 'active', expected: true }], postgres: null }) } }) }), now: NOW + t })
    const r2 = run(at(100, 50 * 1048576), r1.memory)
    expect(r2.findings.find((x) => x.rule === 'cluster.resync_in_progress')).toMatchObject({ node: 'n2', severity: 'info', params: { lagMiB: 50 } })
    expect(r2.memory.down).toBeUndefined(); expect(r2.memory.recovered).toEqual({ n2: { at: NOW + 100, downFor: 100 } })
    const r3 = run(at(150, 0), r2.memory)
    expect(r3.findings.find((x) => x.rule === 'cluster.node_recovered')).toMatchObject({ node: 'n2', params: { min: 2, synced: 1 } }); expect(r3.findings.some((x) => x.rule === 'cluster.resync_in_progress')).toBe(false)
    const r4 = run(at(4300, 0), r3.memory)
    expect(r4.memory.recovered).toBeUndefined(); expect(r4.findings.some((x) => x.rule === 'cluster.node_recovered')).toBe(false)
  })
  it('état du cluster périmé : la mémoire des pannes n’est pas modifiée', () => {
    const c = clusterRaw({ at: NOW - 900 }); const mem = { leader: 'n1', leaderChangedAt: null, down: { n2: NOW - 1000 } }
    expect(run(snap({ cluster: c }), mem).memory.down).toEqual({ n2: NOW - 1000 })
  })
  it('retour au nœud préféré : proposé seulement s’il est revenu, rattrapé et que le primaire est ailleurs', () => {
    const mk = (pref: string, lag = 0) => { const c = clusterRaw({ patroni: { members: [{ name: 'n1', role: 'replica', state: 'streaming', lag }, { name: 'n2', role: 'leader', state: 'running' }] } }); (c as any).preferred = { node: pref, at: NOW, by: 'admin' }; return c }
    const mem = { leader: 'n2', leaderChangedAt: null }
    expect(rules(snap({ cluster: mk('n1') }), mem)).toContain('cluster.failback_ready|n1|')
    expect(rules(snap({ cluster: mk('n2') }), mem)).not.toContain('cluster.failback_ready|n2|')        // déjà sur le préféré
    expect(rules(snap({ cluster: mk('n1', 80 * 1048576) }), mem)).not.toContain('cluster.failback_ready|n1|')   // pas rattrapé
  })
})
