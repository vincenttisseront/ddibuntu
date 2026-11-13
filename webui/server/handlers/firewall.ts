// Réseaux autorisés à administrer l'appliance (pare-feu de CE nœud). La console dépose une demande ; root revalide, applique avec retour arrière
// automatique (anti-verrouillage) et attend la confirmation donnée ici, depuis un poste qui a encore accès.
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { MAX_ADMIN_NETS, covers, depositFwRequest, fwRequestPending, normNets, readFwPending, readFwResult, readFwState } from '../utils/firewall'

async function view(c: any) {
  const st = await readFwState()
  return { ...st, pending: await readFwPending(), requestPending: await fwRequestPending(), result: await readFwResult(), me: c.ip ?? null, meCovered: covers(st.adminNets, c.ip), max: MAX_ADMIN_NETS }
}
async function deposit(c: any, req: Parameters<typeof depositFwRequest>[0], detail?: Record<string, unknown>) {
  if (await fwRequestPending()) fail(409, 'request_pending')
  const r = await depositFwRequest(req)
  await audit(c, `firewall.${req.action}`, 'firewall', undefined, detail)
  return { accepted: true, requestedAt: r.requestedAt }
}

route('GET', '/system/firewall', 'admin', async (c) => view(c))

const Nets = z.object({ nets: z.array(z.string().trim().min(1).max(64)).min(1).max(MAX_ADMIN_NETS), force: z.boolean().default(false) }).strict()
route('PUT', '/system/firewall/nets', 'admin', async (c) => {
  const b = await c.body(Nets)
  const nets = normNets(b.nets)
  if (!nets || !nets.length) fail(400, 'invalid_network')
  if (await readFwPending()) fail(409, 'firewall_pending')
  // garde-fou : ne pas se couper soi-même sans l'avoir voulu (le retour arrière automatique reste le filet de sécurité)
  if (!b.force && !covers(nets, c.ip)) fail(409, 'firewall_self_lockout')
  return deposit(c, { action: 'set', nets }, { nets, count: nets.length })
})
route('POST', '/system/firewall/confirm', 'admin', async (c) => {
  if (!(await readFwPending())) fail(409, 'firewall_nothing_pending')
  return deposit(c, { action: 'confirm' })
})
route('POST', '/system/firewall/rollback', 'admin', async (c) => {
  if (!(await readFwPending())) fail(409, 'firewall_nothing_pending')
  return deposit(c, { action: 'rollback' })
})

export const registered = true
