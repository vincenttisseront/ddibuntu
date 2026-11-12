// État du cluster publié par root (ddibuntu-cluster follow, chaque minute) : fichier JSON sans secret, lu ici en lecture seule.
// La console ne pilote jamais le cluster : les demandes d'action passent par un fichier de demande traité par root (voir demandes de bascule).
import { networkInterfaces, hostname } from 'node:os'
import { existsSync, promises as fs } from 'node:fs'
import { dirname, join } from 'node:path'
import { cfg } from './config'
import { parseNodeHealth } from './health'
import type { NodeHealth } from './health'
import { cidrContainsIp, parseCidr, parseIp } from './net'

export interface ClusterNode { name: string; ip: string; role: string; host?: string; state?: string; patroniRole?: string; lagBytes?: number | null; timeline?: number | null }
export interface QuorumMember { name: string; ip: string; role: string; reachable: boolean; healthy: boolean; learner: boolean; isLeader: boolean; version: string; raftIndex: number | null; raftTerm: number | null; dbSize: number | null; latencyMs: number | null }
export interface Quorum { voters: number; needed: number; healthy: number; hasQuorum: boolean; tolerance: number; leader: string | null; members: QuorumMember[]; unknownToEtcd: string[] }
// Réglages communs (adresse virtuelle, réseau dédié) tels que publiés dans etcd et tels qu'appliqués sur ce nœud (révisions comparables).
export interface SettingsValue { rev: number; vip: string | null; vrid: number; iface: string | null; net: string | null }
export interface ClusterSettings { published: SettingsValue | null; applied: SettingsValue }
// Certificat de ce nœud et de l'autorité (jours restants), demande de renouvellement en cours ?
export interface ClusterPki { node: { notAfter: number; daysLeft: number; serial: string }; ca: { notAfter: number; daysLeft: number }; renewDays: number; pending: boolean }
// Consigne du nœud préféré du primaire (clé etcd /ddibuntu-cluster/preferred) : jamais appliquée automatiquement, seulement signalée.
export interface ClusterPreferred { node: string; at: number; by: string }
// Mise à jour du cluster nœud par nœud : ordre commun (etcd), versions de chaque nœud, avancement publié par chacun.
export interface ClusterUpdate { order: { target: string; at: number; by: string } | null; versions: Record<string, string>; states: Record<string, { state: string; at: number; msg: string }> }
export interface ClusterState {
  cluster: string; node: string; nodeRole: string; localRole: 'leader' | 'replica' | 'unknown'; at: number; ageSeconds: number; stale: boolean
  etcd: { healthy: boolean; members: number; quorum: Quorum | null }
  ca: { node: boolean; owner: string | null; escrow: boolean } | null
  nodes: ClusterNode[]
  leader: string | null
  bind: 'primary' | 'secondary' | null
  kea: unknown
  vip: { address: string; iface: string; held: boolean } | null
  health: Record<string, NodeHealth>   // santé de chaque nœud (arbitre compris), partagée par etcd et relayée par root
  settings: ClusterSettings | null
  pki: ClusterPki | null
  update: ClusterUpdate | null
  preferred: ClusterPreferred | null   // nœud où le primaire doit se trouver en temps normal (etcd, commun à tous les nœuds)
}

const MAX_AGE_SECONDS = 180   // la minuterie publie chaque minute : au-delà de 3 minutes, l'information est périmée
const str = (v: unknown, max = 128) => (typeof v === 'string' ? v.slice(0, max) : '')
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null)

// Quorum etcd mesuré en direct par root (sonde de chaque membre) : champs connus et bornés uniquement.
export function parseQuorum(q: any): Quorum | null {
  if (!q || typeof q !== 'object' || !Array.isArray(q.members)) return null
  return {
    voters: Number(q.voters) || 0, needed: Number(q.needed) || 0, healthy: Number(q.healthy) || 0, hasQuorum: q.hasQuorum === true,
    tolerance: Number.isFinite(q.tolerance) ? Number(q.tolerance) : 0, leader: typeof q.leader === 'string' && q.leader ? str(q.leader, 63) : null,
    members: q.members.slice(0, 16).map((m: any) => ({
      name: str(m?.name, 63), ip: str(m?.ip, 45), role: str(m?.role, 16), reachable: m?.reachable === true, healthy: m?.healthy === true, learner: m?.learner === true,
      isLeader: m?.isLeader === true, version: str(m?.version, 32), raftIndex: num(m?.raftIndex), raftTerm: num(m?.raftTerm), dbSize: num(m?.dbSize), latencyMs: num(m?.latencyMs),
    })),
    unknownToEtcd: Array.isArray(q.unknownToEtcd) ? q.unknownToEtcd.slice(0, 16).map((x: unknown) => str(x, 63)) : [],
  }
}

function parseHealthMap(raw: any, nowSec: number): Record<string, NodeHealth> {
  const out: Record<string, NodeHealth> = {}
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out
  for (const [name, v] of Object.entries(raw).slice(0, 16)) {
    const h = parseNodeHealth(v, nowSec)
    if (h && h.node === name) out[name] = h    // la clé doit être le nom du nœud qui publie (une valeur piégée ne se fait pas passer pour un autre)
  }
  return out
}

const int = (v: unknown, lo: number, hi: number, dflt: number) => (typeof v === 'number' && Number.isInteger(v) && v >= lo && v <= hi ? v : dflt)
function parseSettingsValue(v: any): SettingsValue | null {
  if (!v || typeof v !== 'object') return null
  return { rev: int(v.rev, 0, 999_999_999, 0), vip: typeof v.vip === 'string' && v.vip ? str(v.vip, 18) : null, vrid: int(v.vrid, 1, 255, 51), iface: typeof v.iface === 'string' && v.iface ? str(v.iface, 15) : null, net: typeof v.net === 'string' && v.net ? str(v.net, 18) : null }
}
export function parseSettings(j: any): ClusterSettings | null {
  const applied = parseSettingsValue(j?.applied)
  return applied ? { published: parseSettingsValue(j?.published), applied } : null
}
export function parsePki(j: any): ClusterPki | null {
  if (!j || typeof j !== 'object' || !j.node || !j.ca) return null
  const days = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? Math.max(-36500, Math.min(36500, Math.trunc(v))) : 0)
  return {
    node: { notAfter: num(j.node.notAfter) ?? 0, daysLeft: days(j.node.daysLeft), serial: str(j.node.serial, 64) },
    ca: { notAfter: num(j.ca.notAfter) ?? 0, daysLeft: days(j.ca.daysLeft) }, renewDays: int(j.renewDays, 1, 3650, 60), pending: j.pending === true,
  }
}

const VER_RE = /^\d+\.\d+\.\d+$/
const USTATES = ['waiting', 'requested', 'updating', 'done', 'failed']
export function parseUpdate(v: any, nodes: ClusterNode[]): ClusterUpdate | null {
  if (!v || typeof v !== 'object') return null
  const known = new Set(nodes.map((n) => n.name))
  const versions: Record<string, string> = {}
  if (v.versions && typeof v.versions === 'object' && !Array.isArray(v.versions)) for (const [k, x] of Object.entries(v.versions)) if (known.has(k) && typeof x === 'string' && VER_RE.test(x)) versions[k] = x
  const states: ClusterUpdate['states'] = {}
  if (v.states && typeof v.states === 'object' && !Array.isArray(v.states)) for (const [k, x] of Object.entries<any>(v.states)) if (known.has(k) && x && USTATES.includes(x.state)) states[k] = { state: x.state, at: num(x.at) ?? 0, msg: str(x.msg, 200) }
  const o = v.order
  const order = o && typeof o === 'object' && typeof o.target === 'string' && VER_RE.test(o.target) ? { target: o.target, at: num(o.at) ?? 0, by: typeof o.by === 'string' ? str(o.by, 31) : '' } : null
  return { order, versions, states }
}
// Plus ancienne et plus récente version parmi les nœuds ; homogène = une seule version et aucun nœud sans version connue
export function versionSpread(st: { nodes: ClusterNode[]; update: ClusterUpdate | null }): { homogeneous: boolean; versions: string[] } {
  const vs = st.nodes.map((n) => st.update?.versions[n.name] ?? '')
  const set = [...new Set(vs.filter(Boolean))].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
  return { homogeneous: set.length === 1 && vs.every(Boolean), versions: set }
}

// Le nœud préféré doit être un nœud de DONNÉES connu du registre ; sinon la consigne est ignorée (valeur piégée ou nœud retiré).
export function parsePreferred(v: any, nodes: ClusterNode[]): ClusterPreferred | null {
  if (!v || typeof v !== 'object' || typeof v.node !== 'string') return null
  const n = nodes.find((x) => x.name === v.node && x.role === 'data')
  return n ? { node: n.name, at: num(v.at) ?? 0, by: typeof v.by === 'string' ? str(v.by, 31) : '' } : null
}

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
    etcd: { healthy: j.etcd?.healthy === true, members: Number(j.etcd?.members) || 0, quorum: parseQuorum(j.etcd?.quorum) },
    ca: j.ca && typeof j.ca === 'object' ? { node: j.ca.node === true, owner: typeof j.ca.owner === 'string' && j.ca.owner ? str(j.ca.owner, 63) : null, escrow: j.ca.escrow === true } : null,
    nodes, leader: typeof leader === 'string' ? str(leader, 63) : null,
    bind: j.bind === 'primary' || j.bind === 'secondary' ? j.bind : null,
    kea: j.kea ?? null,
    vip: j.vip && typeof j.vip.address === 'string' ? { address: str(j.vip.address, 64), iface: str(j.vip.iface, 32), held: j.vip.held === true } : null,
    health: parseHealthMap(j.health, nowSec),
    settings: parseSettings(j.settings), pki: parsePki(j.pki), preferred: parsePreferred(j.preferred, nodes), update: parseUpdate(j.update, nodes),
  }
}

export async function readClusterState(): Promise<ClusterState | null> {
  try {
    const st = await fs.stat(cfg().clusterStatusFile)
    if (!st.isFile() || st.size > 256 * 1024) return null
    return parseClusterState(await fs.readFile(cfg().clusterStatusFile, 'utf8'))
  } catch { return null }
}

export interface SwitchoverResult { at: number; candidate: string; ok: boolean; message: string; action?: string }
export async function readSwitchoverResult(): Promise<SwitchoverResult | null> {
  try {
    const f = join(dirname(cfg().clusterStatusFile), 'cluster-result.json')
    const j = JSON.parse(await fs.readFile(f, 'utf8'))
    if (typeof j?.at !== 'number') return null
    return { at: j.at, candidate: str(j.candidate, 31), ok: j.ok === true, message: str(j.message, 300), ...(typeof j.action === 'string' && j.action ? { action: str(j.action, 24) } : {}) }
  } catch { return null }
}

// Vérifie une demande de bascule contre l'état publié par root : un seul candidat possible = un secondaire de données en bonne santé.
export function switchoverCandidates(st: ClusterState | null): string[] {
  if (!st || st.stale || !st.etcd.healthy) return []
  return st.nodes.filter((n) => n.role === 'data' && n.name !== st.leader && n.patroniRole !== undefined && ['running', 'streaming'].includes(n.state ?? '')).map((n) => n.name)
}

// Actions d'exploitation demandées par la console (jamais exécutées ici) : vérifications préalables contre l'état publié par root.
export type ClusterAction =
  | { action: 'remove-node'; node: string; confirm: string } | { action: 'take-ca'; confirm: string } | { action: 'recover'; confirm: string }
  | { action: 'set-vip'; vip: string; iface: string; vrid?: number; confirm: string } | { action: 'clear-vip'; confirm: string } | { action: 'vip-iface'; iface: string }
  | { action: 'set-net'; net: string; confirm: string } | { action: 'renew-cert' } | { action: 'change-ip'; ip: string; confirm: string }
  | { action: 'update-start'; version: string; confirm: string } | { action: 'update-cancel'; confirm: string }
  | { action: 'set-preferred'; node: string; confirm: string } | { action: 'clear-preferred'; confirm: string }
  | { action: 'drill-check'; node?: string } | { action: 'drill'; node?: string; back?: boolean; confirm: string }
// Contexte d'une demande que l'état du cluster seul ne dit pas : un test de bascule est-il en cours (marque etcd ou avancement vivant) ?
export interface ActionContext { drillBusy?: boolean }
const hostPart = (cidr: string) => cidr.split('/')[0]!
// Retourne le code d'erreur API (409) si la demande est incohérente avec l'état courant, sinon null. root revalide tout de son côté.
export function actionRefusal(st: ClusterState | null, a: ClusterAction, ctx: ActionContext = {}): string | null {
  if (!st) return 'not_clustered'
  if (st.nodeRole !== 'data') return 'action_data_node_only'
  const q = st.etcd.quorum
  const needQuorum = () => (st.stale || !q || !q.hasQuorum ? 'quorum_required' : null)
  // pendant un test de bascule, la topologie ne bouge pas (la reprise après perte du quorum reste possible : elle ne dépend pas de ce test)
  if (ctx.drillBusy && a.action !== 'recover' && a.action !== 'drill-check' && a.action !== 'renew-cert' && a.action !== 'vip-iface') return 'drill_active'
  if (a.action === 'drill-check') return st.stale ? 'cluster_state_stale' : null
  if (a.action === 'drill') {
    if (a.confirm !== st.cluster) return 'confirm_mismatch'
    if (st.stale) return 'cluster_state_stale'
    const nq = needQuorum(); if (nq) return nq
    const cands = switchoverCandidates(st)
    if (!cands.length || (a.node !== undefined && !cands.includes(a.node))) return 'invalid_candidate'
    return null
  }
  if (a.action === 'remove-node') {
    if (a.confirm !== a.node) return 'confirm_mismatch'
    if (a.node === st.node) return 'cannot_remove_self'
    if (!st.nodes.some((n) => n.name === a.node)) return 'unknown_node'
    return needQuorum()
  }
  if (a.action === 'take-ca') {
    if (a.confirm !== st.node) return 'confirm_mismatch'
    if (!st.ca || st.ca.node) return 'already_ca'
    if (!st.ca.escrow || !st.ca.owner) return 'no_escrow'
    return null
  }
  if (a.action === 'set-vip') {
    if (a.confirm !== st.cluster) return 'confirm_mismatch'
    if (st.nodes.some((n) => n.ip === hostPart(a.vip))) return 'vip_is_node'
    return needQuorum()
  }
  if (a.action === 'clear-vip') {
    if (a.confirm !== st.cluster) return 'confirm_mismatch'
    if (!st.vip) return 'no_vip'
    return needQuorum()
  }
  if (a.action === 'vip-iface') return st.vip ? null : 'no_vip'
  if (a.action === 'set-net') {
    if (a.confirm !== st.cluster) return 'confirm_mismatch'
    const net = parseCidr(a.net)
    if (!net || st.nodes.some((n) => { const ip = parseIp(n.ip); return !ip || !cidrContainsIp(net, ip) })) return 'nodes_outside_net'
    return needQuorum()
  }
  if (a.action === 'update-start') {
    if (a.confirm !== st.cluster) return 'confirm_mismatch'
    const nq = needQuorum(); if (nq) return nq
    if (st.update?.order) return 'update_running'
    const vs = st.nodes.map((n) => st.update?.versions[n.name])
    if (vs.some((v) => !v)) return 'versions_unknown'
    const cmp = (x: string, y: string) => x.localeCompare(y, undefined, { numeric: true })
    if (vs.some((v) => cmp(v!, a.version) > 0)) return 'node_newer'
    if (!vs.some((v) => cmp(v!, a.version) < 0)) return 'already_at_target'
    if (st.etcd.quorum && st.etcd.quorum.members.some((m) => !m.healthy)) return 'node_unhealthy'
    return null
  }
  if (a.action === 'update-cancel') {
    if (a.confirm !== st.cluster) return 'confirm_mismatch'
    if (!st.update?.order) return 'no_update'
    return needQuorum()
  }
  if (a.action === 'set-preferred') {
    if (a.confirm !== st.cluster) return 'confirm_mismatch'
    if (!st.nodes.some((n) => n.name === a.node && n.role === 'data')) return 'invalid_node'
    return needQuorum()
  }
  if (a.action === 'clear-preferred') {
    if (a.confirm !== st.cluster) return 'confirm_mismatch'
    if (!st.preferred) return 'no_preferred'
    return needQuorum()
  }
  if (a.action === 'renew-cert') return st.pki?.pending ? 'renew_pending' : null
  if (a.action === 'change-ip') {
    if (a.confirm !== st.node) return 'confirm_mismatch'
    if (st.localRole === 'leader') return 'is_leader'
    if (a.ip === st.nodes.find((n) => n.name === st.node)?.ip) return 'same_ip'
    if (st.nodes.some((n) => n.ip === a.ip)) return 'node_ip_taken'
    const net = st.settings?.applied.net ? parseCidr(st.settings.applied.net) : null
    const ip = parseIp(a.ip)
    if (net && ip && !cidrContainsIp(net, ip)) return 'ip_outside_net'
    const nq = needQuorum(); if (nq) return nq
    const me = q?.members.find((m) => m.name === st.node)
    if (q && me && !me.learner && q.healthy - 1 < q.needed) return 'quorum_margin_required'   // l'arrêt d'etcd pendant le changement ferait tomber le quorum
    return null
  }
  if (a.confirm !== st.cluster) return 'confirm_mismatch'
  if (!q || q.hasQuorum) return 'quorum_present'
  return null
}

// ---- assistants : création, lot d'enrôlement, rattachement (la console ne fait que déposer des demandes validées de nouveau par root)
export const NODE_NAME_RE = /^[a-z][a-z0-9-]{1,30}$/
export interface LocalAddress { iface: string; address: string; prefix: number }
// Adresses IPv4 des interfaces du serveur (la boucle locale n'est utile qu'aux tests).
// Ne lève jamais : sous un service durci (sans AF_NETLINK) la lecture échoue ; la liste est alors vide et les assistants acceptent la saisie libre (root revalide).
export function localAddresses(includeLoopback = false): LocalAddress[] {
  const out: LocalAddress[] = []
  let ifaces: ReturnType<typeof networkInterfaces>
  try { ifaces = networkInterfaces() } catch { return out }
  for (const [iface, list] of Object.entries(ifaces)) {
    for (const a of list ?? []) {
      if (a.family !== 'IPv4' || (a.internal && !includeLoopback)) continue
      const bits = a.netmask.split('.').reduce((n, o) => n + (Number(o) >>> 0).toString(2).replace(/0/g, '').length, 0)
      out.push({ iface, address: a.address, prefix: bits })
    }
  }
  return out
}
export function shortHostname(): string { return hostname().split('.')[0]!.toLowerCase() }
// Refus du lot : seul le nœud qui porte l'autorité en crée, quorum etcd présent (ajout de membre), nom et adresse libres.
export function bundleRefusal(st: ClusterState | null, name: string, ip: string): string | null {
  if (!st) return 'not_clustered'
  if (st.nodeRole !== 'data') return 'action_data_node_only'
  if (!st.ca?.node) return 'not_ca_node'
  if (st.stale || !st.etcd.quorum?.hasQuorum) return 'quorum_required'
  if (st.nodes.some((n) => n.name === name)) return 'node_name_taken'
  if (st.nodes.some((n) => n.ip === ip)) return 'node_ip_taken'
  return null
}

// Composants nécessaires à la création / au rattachement d'un cluster (même liste que le contrôle préalable de root). Recherche dans les dossiers
// habituels + PATH ; en mode test, jamais d'absence signalée (la machine d'essai n'a pas à les porter).
export const CLUSTER_TOOLS = ['etcd', 'etcdctl', 'patroni', 'patronictl'] as const
export const CLUSTER_INSTALL_CMD = 'apt install patroni etcd-server etcd-client python3-psycopg2 gnupg keepalived'
export function missingClusterTools(dirs: string[] = [...(process.env.PATH ?? '').split(':'), '/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'], exists: (p: string) => boolean = (p) => existsSync(p)): string[] {
  return CLUSTER_TOOLS.filter((t) => !dirs.some((d) => d && exists(`${d}/${t}`)))
}

// Tâche du cluster en attente d'exécution par root (fichiers de demande déposés par la console, pas encore consommés).
// Sert à dire à l'administrateur QUELLE opération est en cours, et depuis quand ; le contenu est assaini (jamais renvoyé tel quel).
export interface ClusterPending { kind: 'action' | 'setup' | 'switchover' | 'join'; action: string; node?: string; since: number }
const PENDING_FILES: Array<{ file: string; kind: ClusterPending['kind'] }> = [
  { file: '.cluster-setup', kind: 'setup' }, { file: '.cluster-action', kind: 'action' }, { file: '.cluster-switchover', kind: 'switchover' }, { file: 'cluster-join.bundle', kind: 'join' },
]
export async function readPending(dir: string): Promise<ClusterPending | null> {
  for (const { file, kind } of PENDING_FILES) {
    const f = `${dir}/${file}`
    let st
    try { st = await fs.stat(f) } catch { continue }
    let action = kind === 'join' ? 'join' : kind === 'switchover' ? 'switchover' : 'other', node: string | undefined
    if (kind === 'action' || kind === 'setup') {
      try {
        const j = JSON.parse((await fs.readFile(f, 'utf8')).slice(0, 4096))
        if (typeof j?.action === 'string' && /^[a-z][a-z-]{1,24}$/.test(j.action)) action = j.action
        const n = j?.node ?? j?.name
        if (typeof n === 'string' && /^[a-z][a-z0-9-]{1,30}$/.test(n)) node = n
      } catch { /* illisible : on garde « other » */ }
    } else if (kind === 'switchover') {
      try { const n = (await fs.readFile(f, 'utf8')).trim(); if (/^[a-z][a-z0-9-]{1,30}$/.test(n)) node = n } catch { /* ignoré */ }
    }
    return { kind, action, ...(node ? { node } : {}), since: Math.floor(st.mtimeMs / 1000) }
  }
  return null
}
// Annule les demandes que root n'a pas encore prises en charge (jamais une opération déjà commencée : root retire le fichier dès qu'il le lit).
export async function cancelPending(dir: string): Promise<number> {
  let n = 0
  for (const { file } of PENDING_FILES) { try { await fs.unlink(`${dir}/${file}`); n++ } catch (e: any) { if (e?.code !== 'ENOENT') throw e } }
  return n
}
