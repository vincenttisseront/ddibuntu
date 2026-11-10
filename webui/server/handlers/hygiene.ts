// Hygiène de l'IPAM : adresses « fantômes » (allouées mais plus vues par la découverte depuis longtemps) et leur libération.
// Seules les adresses déjà vues au moins une fois par une découverte peuvent être jugées silencieuses : une adresse saisie à la
// main et jamais scannée n'est pas un fantôme, on ne sait simplement rien d'elle.
import { z } from 'zod'
import { audit, fail, qint, route } from '../utils/router'
import { query, tx } from '../utils/db'

export const registered = true

const GHOST_STATUS = ['used', 'dhcp']
const GHOST_LIMIT = 500

route('GET', '/ipam/ghosts', 'viewer', async (c) => {
  const days = qint(c, 'days', 30, 1, 3650), subnet = qint(c, 'subnet_id', 0, 0, 2_000_000_000)
  const where = `a.status = any($2) and a.last_seen is not null and a.last_seen < now() - make_interval(days => $1) and ($3::int = 0 or a.subnet_id = $3)`
  const total = (await query<any>(`select count(*)::int as n from addresses a where ${where}`, [days, GHOST_STATUS, subnet]))[0]!.n
  const items = await query<any>(`select a.id, a.subnet_id, host(a.ip) as ip, a.status, a.hostname, a.mac::text as mac, a.last_seen, text(s.cidr) as cidr, s.name as network,
      floor(extract(epoch from now() - a.last_seen) / 86400)::int as silent_days
    from addresses a join subnets s on s.id = a.subnet_id where ${where} order by a.last_seen, a.ip limit ${GHOST_LIMIT}`, [days, GHOST_STATUS, subnet])
  return { days, total, shown: items.length, limit: GHOST_LIMIT, items }
})

const releaseBody = z.object({ ids: z.array(z.number().int().positive()).min(1).max(GHOST_LIMIT), days: z.number().int().min(1).max(3650) })
// Le critère est revérifié au moment de la libération : une adresse revue entre-temps, ou modifiée, n'est jamais supprimée.
route('POST', '/ipam/ghosts/release', 'operator', async (c) => {
  const b = await c.body(releaseBody)
  const ids = [...new Set(b.ids)]
  const gone = await tx(async (cl) => (await cl.query(
    `delete from addresses where id = any($1) and status = any($2) and last_seen is not null and last_seen < now() - make_interval(days => $3)
     returning id, subnet_id, host(ip) as ip`, [ids, GHOST_STATUS, b.days])).rows)
  if (!gone.length && ids.length) fail(409, 'ghost_none_released')
  await audit(c, 'ghost_release', 'address', undefined, { days: b.days, requested: ids.length, released: gone.length, ips: gone.slice(0, 50).map((r: any) => r.ip) })
  return { released: gone.length, skipped: ids.length - gone.length }
})
