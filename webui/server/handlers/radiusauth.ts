// Identifiant et mot de passe (0.16.0) — réglages des méthodes PEAP-MSCHAPv2 / EAP-TTLS et jonction de CE nœud au domaine (administrateur).
// La console ne détient aucun secret de jonction : le compte qui joint le domaine est déposé une fois pour root, qui l'écrase aussitôt après usage ;
// seul le nom du compte est consigné au journal d'audit, jamais son mot de passe. Chaque nœud de données a son propre compte machine.
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { AUTH_KEY, authBody, loadAuth, NETBIOS_RE, saveAuth } from '../utils/radius-auth'
import { loadDir } from '../utils/radius-dir-store'
import { depositRadiusRequest, radiusRequestPending, readRadiusStatus } from '../utils/radius'
import { depositBusy } from '../utils/radius-follow'

export const registered = true
const CTRL = /[\x00-\x1f\x7f]/
const REALM_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,250}[A-Za-z0-9])?$/
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/
const secretStr = (max: number) => z.string().min(1).max(max).refine((v) => !CTRL.test(v), 'ctrl')
const creds = { user: secretStr(256).refine((v) => !v.includes('%'), 'user'), password: secretStr(256) }
const joinBody = z.object({
  realm: z.string().trim().min(3).max(253).refine((v) => REALM_RE.test(v) && v.includes('.'), 'realm'),
  netbios: z.string().trim().refine((v) => NETBIOS_RE.test(v), 'netbios'),
  servers: z.array(z.string().trim().refine((v) => HOST_RE.test(v), 'server')).min(1).max(5).optional(),
  ...creds,
}).strict()
const leaveBody = z.object({ user: creds.user.optional(), password: creds.password.optional(), realm: joinBody.shape.realm.optional(), netbios: joinBody.shape.netbios.optional(), servers: joinBody.shape.servers }).strict()

/** Contrôleurs de domaine : ceux de l'annuaire du service (adresses LDAPS) quand l'administrateur n'en donne pas. */
async function defaultServers(): Promise<string[]> {
  const urls = (await loadDir()).urls
  return [...new Set(urls.map((u) => u.replace(/^ldaps:\/\//, '').replace(/:\d+$/, '')))].filter((h) => HOST_RE.test(h)).slice(0, 5)
}

route('GET', '/radius/auth', 'admin', async () => ({ ...(await loadAuth()), servers: await defaultServers() }))

route('PUT', '/radius/auth', 'admin', async (c) => {
  const b = await c.body(authBody)
  const cur = await loadAuth()
  await saveAuth(b)
  await audit(c, 'radius_auth', 'settings', AUTH_KEY, { peap: b.peap, ttls: b.ttls, netbios: b.netbios, changed: cur.peap !== b.peap || cur.ttls !== b.ttls || cur.netbios !== b.netbios })
  return { ok: true }
})

async function send(c: Parameters<Parameters<typeof route>[3]>[0], req: Parameters<typeof depositRadiusRequest>[0], detail: Record<string, unknown>) {
  if ((await radiusRequestPending()) || (await depositBusy())) fail(409, 'request_pending')
  const r = await depositRadiusRequest(req)
  await audit(c, `radius.${req.action}`, 'radius', undefined, detail)
  return { accepted: true, requestedAt: r.requestedAt }
}

// Joindre CE nœud au domaine. Le résultat arrive par l'état publié par root (action « join »), comme un déploiement.
route('POST', '/radius/join', 'admin', async (c) => {
  const b = await c.body(joinBody)
  const servers = b.servers ?? await defaultServers()
  if (!servers.length) fail(400, 'radius_join_servers')
  const { user, password, ...rest } = b
  const out = await send(c, { action: 'join', join: { ...rest, servers, user, password } }, { realm: b.realm, netbios: b.netbios, servers, account: user })
  const cur = await loadAuth()
  if (cur.netbios !== b.netbios) await saveAuth({ ...cur, netbios: b.netbios })   // le même nom sert aux identifiants « DOMAINE\compte » (mémorisé seulement si la demande est partie)
  return out
})

// Retirer la jonction de CE nœud. Avec un compte, le compte machine est aussi supprimé de l'annuaire ; sans compte, il y reste (à supprimer à la main).
route('POST', '/radius/leave', 'admin', async (c) => {
  const b = await c.body(leaveBody)
  if ((b.user === undefined) !== (b.password === undefined)) fail(400, 'radius_leave_creds')
  const st = await readRadiusStatus()
  const servers = b.servers ?? await defaultServers()
  const withAccount = b.user !== undefined
  if (withAccount && (!servers.length || !(b.realm ?? st?.winbind.realm) || !(b.netbios ?? st?.winbind.netbios))) fail(400, 'radius_join_servers')
  const join = withAccount ? { realm: (b.realm ?? st!.winbind.realm), netbios: (b.netbios ?? st!.winbind.netbios), servers, user: b.user!, password: b.password! } : undefined
  return send(c, { action: 'leave', ...(join ? { join } : {}) }, { withAccount, account: b.user ?? null })
})
