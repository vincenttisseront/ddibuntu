import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { setResponseHeader } from 'h3'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { inRecovery } from '../utils/db'
import { cfg } from '../utils/config'
import { randomBytes } from 'node:crypto'
import { actionRefusal, bundleRefusal, localAddresses, NODE_NAME_RE, readClusterState, readSwitchoverResult, shortHostname, switchoverCandidates } from '../utils/cluster'

// Public et minimal : l'écran de connexion d'un nœud secondaire doit pouvoir l'expliquer (aucune adresse ni nom de nœud).
route('GET', '/cluster/role', 'public', async () => ({ replica: await inRecovery() }))

// État détaillé (lecture seule) : nœuds, leader, quorum, Kea HA, adresse virtuelle, rôle BIND.
route('GET', '/cluster/status', 'viewer', async () => {
  const state = await readClusterState()
  return {
    clustered: state !== null, replica: await inRecovery(), state, candidates: switchoverCandidates(state), result: await readSwitchoverResult(),
    // hors cluster : de quoi remplir l'assistant de création (adresses réelles du serveur, nom de la machine)
    ...(state === null ? { setup: { hostname: shortHostname(), addresses: localAddresses(cfg().testMode) } } : {}),
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
  await fs.writeFile(join(cfg().generatedDir, '.cluster-switchover'), candidate + '\n', { mode: 0o640 })
  await audit(c, 'cluster.switchover', 'node', candidate)
  return { accepted: true }
})

// Actualisation immédiate de l'état (sondes etcd en direct) : root republie l'état dans la seconde. Sans effet sur le cluster.
async function drop(file: string, body: string): Promise<void> {
  const f = join(cfg().generatedDir, file)
  try { await fs.stat(f); fail(409, 'action_pending') } catch (e: any) { if (e?.code !== 'ENOENT') throw e }
  await fs.writeFile(f, body, { mode: 0o640, flag: 'wx' })
}
route('POST', '/cluster/refresh', 'operator', async () => {
  await drop('.cluster-action', JSON.stringify({ action: 'refresh' }))
  return { accepted: true }
})

// Opérations de reprise : retrait d'un nœud perdu, reprise de l'autorité de certification, reconstruction après perte du quorum.
// La confirmation saisie (nom du nœud / du nœud courant / du cluster) est revérifiée ici ET par root.
const NAME = z.string().regex(NODE_NAME_RE)
const Action = z.discriminatedUnion('action', [
  z.object({ action: z.literal('remove-node'), node: NAME, confirm: z.string().max(64) }).strict(),
  z.object({ action: z.literal('take-ca'), confirm: z.string().max(64) }).strict(),
  z.object({ action: z.literal('recover'), confirm: z.string().max(64) }).strict(),
])
route('POST', '/cluster/action', 'admin', async (c) => {
  const a = await c.body(Action)
  const st = await readClusterState()
  const refusal = actionRefusal(st, a)
  if (refusal) fail(409, refusal)
  await drop('.cluster-action', JSON.stringify(a))
  await audit(c, `cluster.${a.action}`, 'node', a.action === 'remove-node' ? a.node : (st?.node ?? ''))
  return { accepted: true }
})

// ---- Assistants (nœud hors cluster) : créer un cluster / rejoindre un cluster. root revalide chaque champ.
const IPV4 = z.string().regex(/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/)
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
  try { await fs.stat(setup); fail(409, 'action_pending') } catch (e: any) { if (e?.code !== 'ENOENT') throw e }
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
