import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { setResponseHeader } from 'h3'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { inRecovery } from '../utils/db'
import { cfg } from '../utils/config'
import { randomBytes } from 'node:crypto'
import { actionRefusal, bundleRefusal, cancelPending, CLUSTER_INSTALL_CMD, readPending, localAddresses, missingClusterTools, NODE_NAME_RE, readClusterState, readSwitchoverResult, shortHostname, switchoverCandidates } from '../utils/cluster'
import { DRILL_ID_RE, drillBusy, readDrillCheck, readDrillLive, readDrills } from '../utils/drill'

// Public et minimal : l'écran de connexion d'un nœud secondaire doit pouvoir l'expliquer (aucune adresse ni nom de nœud).
route('GET', '/cluster/role', 'public', async () => ({ replica: await inRecovery() }))

// État détaillé (lecture seule) : nœuds, leader, quorum, Kea HA, adresse virtuelle, rôle BIND.
route('GET', '/cluster/status', 'viewer', async () => {
  const state = await readClusterState()
  // une demande de création/rattachement n'a plus de sens une fois le nœud en cluster : fichier resté d'une tentative précédente, il bloquerait les assistants (« opération en cours »)
  if (state !== null) await fs.unlink(join(cfg().generatedDir, '.cluster-setup')).catch(() => {})
  return {
    pending: await readPending(cfg().generatedDir).catch(() => null),
    clustered: state !== null, replica: await inRecovery().catch(() => false), state, candidates: switchoverCandidates(state), result: await readSwitchoverResult(),
    // hors cluster : de quoi remplir l'assistant de création (adresses réelles du serveur, nom de la machine)
    ...(state === null ? { setup: { hostname: shortHostname(), addresses: localAddresses(cfg().testMode), missing: cfg().testMode ? [] : missingClusterTools(), install: CLUSTER_INSTALL_CMD } } : {}),
    // dans un cluster : interfaces et adresses de CE serveur (formulaires de réglages) — liste vide si le service durci ne peut pas les lire
    ...(state !== null ? { local: { addresses: localAddresses(cfg().testMode) } } : {}),
  }
})

// Bascule contrôlée : la console ne fait que DÉPOSER une demande (un nom de nœud) ; root la valide de nouveau et l'exécute (ddibuntu-cluster request).
const Switchover = z.object({ candidate: z.string().regex(/^[a-z][a-z0-9-]{1,30}$/) }).strict()
route('POST', '/cluster/switchover', 'admin', async (c) => {
  const { candidate } = await c.body(Switchover)
  const st = await readClusterState()
  if (!st) fail(409, 'not_clustered')
  if (st.stale) fail(409, 'cluster_state_stale')
  if (!switchoverCandidates(st).includes(candidate)) fail(409, 'invalid_candidate')
  if (drillBusy(await readDrills(), await readDrillLive())) fail(409, 'drill_active')
  await fs.writeFile(join(cfg().generatedDir, '.cluster-switchover'), candidate + '\n', { mode: 0o640 })
  await audit(c, 'cluster.switchover', 'node', candidate)
  return { accepted: true }
})

// Actualisation immédiate de l'état (sondes etcd en direct) : root republie l'état dans la seconde. Sans effet sur le cluster.
async function drop(file: string, body: string): Promise<void> {
  const f = join(cfg().generatedDir, file)
  try { await fs.stat(f); fail(409, 'action_pending', undefined, { pending: await readPending(cfg().generatedDir).catch(() => null) }) } catch (e: any) { if (e?.code !== 'ENOENT') throw e }
  await fs.writeFile(f, body, { mode: 0o640, flag: 'wx' })
}
route('POST', '/cluster/refresh', 'operator', async () => {
  if ((await readClusterState()) === null) fail(409, 'not_clustered')   // hors cluster : l'unité de relecture de root n'est pas active, la demande ne serait jamais consommée
  // une demande est déjà en attente (root ne l'a pas encore relue) : l'actualisation viendra avec elle, ce n'est pas une erreur (pas de 409 dans la console du navigateur)
  try { await fs.stat(join(cfg().generatedDir, '.cluster-action')); return { accepted: true, pending: true } } catch (e: any) { if (e?.code !== 'ENOENT') throw e }
  await drop('.cluster-action', JSON.stringify({ action: 'refresh' }))
  return { accepted: true }
})

// Opérations de reprise : retrait d'un nœud perdu, reprise de l'autorité de certification, reconstruction après perte du quorum.
// La confirmation saisie (nom du nœud / du nœud courant / du cluster) est revérifiée ici ET par root.
const NAME = z.string().regex(NODE_NAME_RE)
const IPV4 = z.string().regex(/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/)
const CIDR = z.string().regex(/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/)
const IFACE = z.string().regex(/^[a-z][a-z0-9._-]{0,14}$/)
const CONFIRM = z.string().max(64)
const Action = z.discriminatedUnion('action', [
  z.object({ action: z.literal('remove-node'), node: NAME, confirm: CONFIRM }).strict(),
  z.object({ action: z.literal('take-ca'), confirm: CONFIRM }).strict(),
  z.object({ action: z.literal('recover'), confirm: CONFIRM }).strict(),
  // réglages communs et opérations propres à ce nœud (0.9.2) : adresse virtuelle, réseau dédié, certificat, adresse du nœud
  z.object({ action: z.literal('set-vip'), vip: CIDR, iface: IFACE, vrid: z.number().int().min(1).max(255).optional(), confirm: CONFIRM }).strict(),
  z.object({ action: z.literal('clear-vip'), confirm: CONFIRM }).strict(),
  z.object({ action: z.literal('vip-iface'), iface: IFACE }).strict(),
  z.object({ action: z.literal('set-net'), net: CIDR, confirm: CONFIRM }).strict(),
  z.object({ action: z.literal('renew-cert') }).strict(),
  // nœud préféré du primaire (0.9.11) : consigne commune publiée dans etcd (quorum exigé)
  // mise à jour du cluster nœud par nœud (0.9.13) : ordre commun publié dans etcd, chaque nœud l'applique à son tour
  z.object({ action: z.literal('update-start'), version: z.string().regex(/^\d+\.\d+\.\d+$/), confirm: CONFIRM }).strict(),
  z.object({ action: z.literal('update-cancel'), confirm: CONFIRM }).strict(),
  z.object({ action: z.literal('set-preferred'), node: NAME, confirm: CONFIRM }).strict(),
  z.object({ action: z.literal('clear-preferred'), confirm: CONFIRM }).strict(),
  z.object({ action: z.literal('change-ip'), ip: IPV4, confirm: CONFIRM }).strict(),
  // test de bascule guidé (0.9.3) : pré-contrôles seuls (lecture), puis bascule mesurée avec retour optionnel au primaire d'origine
  z.object({ action: z.literal('drill-check'), node: NAME.optional() }).strict(),
  z.object({ action: z.literal('drill'), node: NAME.optional(), back: z.boolean().optional(), confirm: CONFIRM }).strict(),
])
route('POST', '/cluster/action', 'admin', async (c) => {
  const a = await c.body(Action)
  const st = await readClusterState()
  const refusal = actionRefusal(st, a, { drillBusy: drillBusy(await readDrills(), await readDrillLive()) })
  if (refusal) fail(409, refusal)
  // l'interface doit exister sur CE serveur ; adresse du nœud : portée par ce serveur. Liste vide = lecture impossible ici (service durci) : root vérifie.
  const addrs = localAddresses(cfg().testMode)
  if ((a.action === 'set-vip' || a.action === 'vip-iface') && addrs.length && !new Set(addrs.map((x) => x.iface)).has(a.iface)) fail(409, 'iface_unknown')
  if (a.action === 'change-ip' && addrs.length && !addrs.some((x) => x.address === a.ip)) fail(409, 'ip_not_local')
  await drop('.cluster-action', JSON.stringify(a))
  await audit(c, `cluster.${a.action}`, 'node', a.action === 'remove-node' || a.action === 'set-preferred' ? a.node : a.action === 'update-start' ? a.version : a.action === 'drill' ? (a.node ?? '') : (st?.node ?? ''))
  return { accepted: true }
})

// Test de bascule : rapports conservés (10 derniers), pré-contrôles du dernier « drill-check », avancement du test en cours. Lecture seule.
route('GET', '/cluster/drills', 'viewer', async () => {
  const [drills, check, live] = await Promise.all([readDrills(), readDrillCheck(), readDrillLive()])
  return { drills, check, live, busy: drillBusy(drills, live) }
})
route('GET', '/cluster/drills/:id', 'viewer', async (c) => {
  const id = String(c.params.id ?? ''); if (!DRILL_ID_RE.test(id)) fail(404, 'not_found')
  const rep = (await readDrills())?.reports.find((r) => r.id === id); if (!rep) fail(404, 'not_found')
  setResponseHeader(c.event, 'Content-Disposition', `attachment; filename="ddibuntu-drill-${id}.json"`)
  return rep
})

// ---- Assistants (nœud hors cluster) : créer un cluster / rejoindre un cluster. root revalide chaque champ.
const Init = z.object({
  cluster: NAME, node: NAME, ip: IPV4, net: z.string().regex(/^[0-9.]+\/\d{1,2}$/).optional(), vip: IPV4.optional(), vipIface: z.string().regex(/^[A-Za-z0-9._-]{1,15}$/).optional(), vrid: z.number().int().min(1).max(255).optional(), confirm: z.string().max(64),
}).strict().refine((v) => (v.vip === undefined) === (v.vipIface === undefined), { message: 'vip_iface_together' }).refine((v) => v.net === undefined || Number(v.net.split('/')[1]) <= 32 && IPV4.safeParse(v.net.split('/')[0]).success, { message: 'net_invalid' })
async function standalone(): Promise<void> {
  if ((await readClusterState()) !== null) fail(409, 'already_clustered')
  if (await inRecovery()) fail(409, 'already_clustered')
}
route('POST', '/cluster/init', 'admin', async (c) => {
  const b = await c.body(Init)
  await standalone()
  if (b.confirm !== b.node) fail(409, 'confirm_mismatch')
  const addrs = localAddresses(cfg().testMode)
  if (addrs.length && !addrs.some((a) => a.address === b.ip)) fail(409, 'ip_not_local')   // liste vide = lecture impossible ici : root vérifie l'adresse
  if (addrs.length && b.vipIface && !new Set(addrs.map((a) => a.iface)).has(b.vipIface)) fail(409, 'iface_unknown')
  await drop('.cluster-setup', JSON.stringify({ action: 'init', ...b }))
  await audit(c, 'cluster.init', 'cluster', b.cluster)
  return { accepted: true }
})
// Le lot (chiffré) est transmis en base64 : quelques Ko ; la console le dépose à côté de la demande, root le consomme puis le détruit.
const Join = z.object({ bundle: z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/).min(100).max(400_000), pass: z.string().regex(/^[A-Za-z0-9]{24,64}$/), confirm: z.string().max(64) }).strict()
route('POST', '/cluster/join', 'admin', async (c) => {
  const b = await c.body(Join)
  await standalone()
  if (b.confirm !== shortHostname()) fail(409, 'confirm_mismatch')
  const dir = cfg().generatedDir, setup = join(dir, '.cluster-setup'), bf = join(dir, 'cluster-join.bundle')
  try { await fs.stat(setup); fail(409, 'action_pending', undefined, { pending: await readPending(dir).catch(() => null) }) } catch (e: any) { if (e?.code !== 'ENOENT') throw e }
  try { await fs.writeFile(bf, Buffer.from(b.bundle, 'base64'), { mode: 0o640, flag: 'wx' }) } catch (e: any) { if (e?.code === 'EEXIST') fail(409, 'action_pending'); throw e }
  try { await fs.writeFile(setup, JSON.stringify({ action: 'join', pass: b.pass, confirm: b.confirm }), { mode: 0o640, flag: 'wx' }) } catch (e) { await fs.rm(bf, { force: true }); throw e }
  await audit(c, 'cluster.join', 'node', b.confirm)
  return { accepted: true }
})

// ---- Ajouter un nœud : lot d'enrôlement chiffré, créé par le nœud qui porte l'autorité. La phrase de passe est tirée ICI, renvoyée une seule fois
// à l'administrateur, transmise à root dans la demande (supprimée aussitôt lue) ; elle n'est ni journalisée ni conservée.
const Bundle = z.object({ name: NAME, ip: IPV4, role: z.enum(['data', 'witness']) }).strict()
route('POST', '/cluster/bundle', 'admin', async (c) => {
  const b = await c.body(Bundle)
  const refusal = bundleRefusal(await readClusterState(), b.name, b.ip)
  if (refusal) fail(409, refusal)
  const pass = randomBytes(32).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 32)
  await drop('.cluster-action', JSON.stringify({ action: 'bundle', node: b.name, ip: b.ip, role: b.role, pass, confirm: b.name }))
  await audit(c, 'cluster.bundle', 'node', b.name)
  return { accepted: true, passphrase: pass }
})
route('GET', '/cluster/bundle/:name', 'admin', async (c) => {
  const name = NAME.safeParse(c.params.name); if (!name.success) fail(404, 'not_found')
  let data: Buffer
  try { data = await fs.readFile(join(cfg().generatedDir, `cluster-bundle-${name.data}.bundle`)) } catch (e: any) { if (e?.code === 'ENOENT') fail(404, 'not_found'); throw e }
  setResponseHeader(c.event, 'Content-Type', 'application/octet-stream')
  setResponseHeader(c.event, 'Content-Disposition', `attachment; filename="ddibuntu-${name.data}.bundle"`)
  await audit(c, 'cluster.bundle.download', 'node', name.data)
  return data
})
route('DELETE', '/cluster/bundle/:name', 'admin', async (c) => {
  const name = NAME.safeParse(c.params.name); if (!name.success) fail(404, 'not_found')
  await fs.rm(join(cfg().generatedDir, `cluster-bundle-${name.data}.bundle`), { force: true })
  return { deleted: true }
})

export const registered = true

// Annulation d'une demande restée en attente (root ne l'a pas lue : unité inactive, fichier ancien…). N'arrête jamais une opération en cours d'exécution.
route('DELETE', '/cluster/pending', 'admin', async (c) => {
  const n = await cancelPending(cfg().generatedDir)
  await audit(c, 'cluster.pending_cancel', 'cluster', undefined, { removed: n })
  return { removed: n }
})
