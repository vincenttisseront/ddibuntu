// Labels IPAM : catalogue (couleur, description, usage), renommage / suppression propagés, pose et retrait en masse.
import { z } from 'zod'
import { audit, fail, intParam, route } from '../utils/router'
import { one, query, tx } from '../utils/db'
import { denyScoped } from '../utils/scope'
import { colorS, ensureLabels, LABELLED, LABEL_RE, labelsS, normLabel, type LabelKind } from '../utils/labels'

const nameS = z.string().max(80).transform(normLabel).refine((v) => LABEL_RE.test(v), 'label')
const descS = z.string().max(200).nullable().optional()
const TABLES = Object.values(LABELLED)
const ALIAS: Record<string, string> = { subnets: 'subnets', addresses: 'addresses', vlans: 'vlans', ipam_spaces: 'spaces' }
const usage = TABLES.map((t) => `(select count(*)::int from ${t} o where l.name = any(o.tags)) as ${ALIAS[t]}`).join(', ')

route('GET', '/ipam/labels', 'viewer', async () => {
  // catalogue + labels présents sur des objets mais absents du catalogue (restauration d'un point plus ancien, par exemple)
  const items = await query<any>(`select l.id, l.name, l.color, l.description, ${usage} from (
      select id, name, color, description from ipam_labels
      union all select null, d.n, null, null from (select distinct x as n from (${TABLES.map((t) => `select unnest(tags) x from ${t}`).join(' union all ')}) u) d
        where not exists (select 1 from ipam_labels c where c.name = d.n)) l order by l.name`)
  return { items: items.map((l) => ({ ...l, total: l.subnets + l.addresses + l.vlans + l.spaces })) }
})

route('POST', '/ipam/labels', 'operator', async (c) => {
  denyScoped(c)
  const b = await c.body(z.object({ name: nameS, color: colorS.nullable().optional(), description: descS }))
  if (await one('select 1 from ipam_labels where name = $1', [b.name])) fail(409, 'label_exists')
  const r = await one<any>('insert into ipam_labels (name, color, description) values ($1,$2,$3) returning id', [b.name, b.color ?? null, b.description ?? null])
  await audit(c, 'label_create', 'label', r.id, { name: b.name })
  return { id: r.id }
})

route('PUT', '/ipam/labels/:id', 'operator', async (c) => {
  denyScoped(c)
  const id = intParam(c, 'id')
  const b = await c.body(z.object({ name: nameS.optional(), color: colorS.nullable().optional(), description: descS }))
  await tx(async (cl) => {
    const cur = (await cl.query('select name from ipam_labels where id = $1 for update', [id])).rows[0]
    if (!cur) fail(404, 'not_found')
    if (b.name && b.name !== cur.name) {
      if ((await cl.query('select 1 from ipam_labels where name = $1', [b.name])).rowCount) fail(409, 'label_exists')
      for (const t of TABLES) await cl.query(`update ${t} set tags = array(select distinct case when x = $1 then $2 else x end from unnest(tags) x) where $1 = any(tags)`, [cur.name, b.name])
    }
    await cl.query('update ipam_labels set name = coalesce($2, name), color = case when $3::boolean then $4 else color end, description = case when $5::boolean then $6 else description end where id = $1',
      [id, b.name ?? null, b.color !== undefined, b.color ?? null, b.description !== undefined, b.description ?? null])
  })
  await audit(c, 'label_update', 'label', id, b.name ? { name: b.name } : undefined)
  return { ok: true }
})

route('DELETE', '/ipam/labels/:id', 'operator', async (c) => {
  denyScoped(c)
  const id = intParam(c, 'id')
  await tx(async (cl) => {
    const cur = (await cl.query('select name from ipam_labels where id = $1 for update', [id])).rows[0]
    if (!cur) fail(404, 'not_found')
    for (const t of TABLES) await cl.query(`update ${t} set tags = array_remove(tags, $1) where $1 = any(tags)`, [cur.name])
    await cl.query('delete from ipam_labels where id = $1', [id])
  })
  await audit(c, 'label_delete', 'label', id)
  return { ok: true }
})

// Pose / retrait de labels sur plusieurs objets d'un même type (ex. étiqueter 40 adresses d'un coup)
route('POST', '/ipam/labels/assign', 'operator', async (c) => {
  denyScoped(c)
  const b = await c.body(z.object({ kind: z.enum(['subnet', 'address', 'vlan', 'space']), ids: z.array(z.number().int()).min(1).max(5000), add: labelsS.default([]), remove: labelsS.default([]) }))
  if (!b.add.length && !b.remove.length) fail(400, 'nothing_to_do')
  const t = LABELLED[b.kind as LabelKind]
  const n = await tx(async (cl) => {
    await ensureLabels(b.add, cl)
    const r = await cl.query(`update ${t} set tags = array(select x from unnest(coalesce(tags, '{}') || $2::text[]) with ordinality as u(x, o) where not (x = any($3::text[])) group by x order by min(o))
      where id = any($1::int[]) returning id`, [b.ids, b.add, b.remove])
    return r.rowCount ?? 0
  })
  await audit(c, 'label_assign', b.kind, undefined, { count: n, add: b.add, remove: b.remove })
  return { updated: n }
})

export const registered = true
