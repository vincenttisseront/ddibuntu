// Classes de clients DHCP (0.12.8) : fabricant (option 60), utilisateur (option 77), préfixe ou adresse MAC ; option 43, rejet par MAC.
import { audit, fail, intParam, route } from '../utils/router'
import { one, query } from '../utils/db'
import { classBody } from '../utils/dhcp-classes'

export const registered = true
const COLS = 'id, name, kind, match, action, option43, tftp_server, boot_file, enabled, comment, created_at, updated_at'

route('GET', '/dhcp/classes', 'viewer', async () => ({ items: await query(`select ${COLS} from dhcp_classes order by name`) }))

route('POST', '/dhcp/classes', 'operator', async (c) => {
  const b = await c.body(classBody)
  const r = await one<any>('insert into dhcp_classes (name, kind, match, action, option43, tftp_server, boot_file, enabled, comment) values ($1,$2,$3,$4,$5,$6,$7,$8,$9) returning id',
    [b.name, b.kind, b.match, b.action, b.option43, b.tftp_server, b.boot_file, b.enabled, b.comment])
  await audit(c, 'dhcp_class_create', 'dhcp_class', r.id, { name: b.name, kind: b.kind, action: b.action })
  return { id: r.id }
})

route('PUT', '/dhcp/classes/:id', 'operator', async (c) => {
  const id = intParam(c, 'id'), b = await c.body(classBody)
  const r = await one<any>('update dhcp_classes set name=$2, kind=$3, match=$4, action=$5, option43=$6, tftp_server=$7, boot_file=$8, enabled=$9, comment=$10, updated_at=now() where id=$1 returning id',
    [id, b.name, b.kind, b.match, b.action, b.option43, b.tftp_server, b.boot_file, b.enabled, b.comment])
  if (!r) fail(404, 'not_found')
  await audit(c, 'dhcp_class_update', 'dhcp_class', id, { name: b.name })
  return { ok: true }
})

route('DELETE', '/dhcp/classes/:id', 'operator', async (c) => {
  const id = intParam(c, 'id')
  const r = await one<any>('delete from dhcp_classes where id = $1 returning name', [id])
  if (!r) fail(404, 'not_found')
  await audit(c, 'dhcp_class_delete', 'dhcp_class', id, { name: r.name })
  return { ok: true }
})
