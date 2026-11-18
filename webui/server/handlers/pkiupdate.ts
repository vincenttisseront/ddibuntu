// Mises à jour d'EJBCA Community (0.14.7) : voir utils/pki-update.ts. La console ne fait que déposer des demandes courtes que root revalide ; la mise à jour dure plusieurs minutes
// (tirage, sauvegarde, migration de la base, contrôles) : le dépôt rend la main aussitôt, l'écran suit l'avancement dans l'état publié par root.
import { audit, fail, route } from '../utils/router'
import { depositPkiRequest, imageOf, pkiRequestPending, readPkiStatus } from '../utils/pki'
import { confirmBody, readPkiUpdate, updateApplyBody } from '../utils/pki-update'
import type { PkiRequest } from '../utils/pki'

export const registered = true

async function deposit(c: Parameters<Parameters<typeof route>[3]>[0], req: PkiRequest, detail?: Record<string, unknown>) {
  if (await pkiRequestPending()) fail(409, 'request_pending')
  const r = await depositPkiRequest(req)
  await audit(c, `pki.${req.action}`, 'pki', undefined, detail)
  return { accepted: true, requestedAt: r.requestedAt }
}

route('GET', '/pki/update', 'admin', async () => {
  const [status, update, pending] = await Promise.all([readPkiStatus(), readPkiUpdate(), pkiRequestPending()])
  return {
    installed: !!status?.installed, version: status?.version ?? '', state: status?.state ?? 'absent', hasRecovery: !!status?.recovery, casCount: status?.casCount ?? null,
    update, requestPending: pending,
  }
})

route('POST', '/pki/update/check', 'admin', async (c) => {
  if (!(await readPkiStatus())?.installed) fail(409, 'pki_not_installed')
  return deposit(c, { action: 'update_check' })
})

// Mise à jour vers une version que root a lui-même proposée (liste publiée) et jugée permise : la console ne fait que le dire à l'administrateur, root revérifie tout.
route('POST', '/pki/update/apply', 'admin', async (c) => {
  const b = await c.body(updateApplyBody)
  const st = await readPkiStatus()
  if (!st?.installed) fail(409, 'pki_not_installed')
  if (st.state !== 'healthy') fail(409, 'pki_update_not_healthy')
  const u = await readPkiUpdate()
  if (u?.job?.state === 'pending') fail(409, 'pki_update_pending')
  if (u?.job?.state === 'failed' && u.job.rollbackAvailable) fail(409, 'pki_update_rollback_first')
  const item = u?.available.find((x) => x.tag === b.version)
  if (!item) fail(409, 'pki_update_unknown_version')
  if (!item.allowed) fail(409, 'pki_update_refused', undefined, { reason: item.reason })
  return deposit(c, { action: 'update_apply', image: imageOf(b.version) }, { from: st.version, to: b.version, kind: item.kind })
})

route('POST', '/pki/update/validate', 'admin', async (c) => {
  const u = await readPkiUpdate()
  if (u?.job?.state !== 'pending') fail(409, 'pki_update_none')
  return deposit(c, { action: 'update_validate' }, { to: u.job.to })
})

// Le retour arrière remet la base et les fichiers d'avant la mise à jour : les certificats émis depuis ne sont plus connus d'EJBCA. Confirmation explicite.
route('POST', '/pki/update/rollback', 'admin', async (c) => {
  await c.body(confirmBody)
  const u = await readPkiUpdate()
  if (!u?.job || !u.job.rollbackAvailable || !['pending', 'failed'].includes(u.job.state)) fail(409, 'pki_update_none')
  return deposit(c, { action: 'update_rollback' }, { from: u.job.from, to: u.job.to, certsSince: u.certsSince })
})
