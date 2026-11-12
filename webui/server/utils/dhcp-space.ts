// DHCP multi-espaces : Kea n'a qu'un seul espace d'adressage. Des réseaux de plusieurs espaces IPAM peuvent donc être servis, tant que
// leurs plages ne se chevauchent pas (même CIDR répété dans deux espaces = refus). Le contrôle vaut pour toute étendue ACTIVE.
import { query } from './db'
import { fail } from './router'

type Run = (sql: string, args: unknown[]) => Promise<any[]>
const viaPool: Run = (sql, args) => query(sql, args)

/** Refuse (409 dhcp_overlap) si le réseau chevauche un réseau déjà servi (étendue active) d'un AUTRE espace. `space` : espace envisagé (déménagement). */
export async function assertNoDhcpOverlap(subnetId: number, space?: number | null, run: Run = viaPool): Promise<void> {
  const r = await run(
    `select text(o.cidr) as cidr, sp.name as space from subnets s
       join subnets o on o.id <> s.id and o.space_id <> coalesce($2::int, s.space_id) and o.cidr && s.cidr
       join dhcp_scopes d on d.subnet_id = o.id and d.enabled
       join ipam_spaces sp on sp.id = o.space_id
      where s.id = $1 limit 1`, [subnetId, space ?? null])
  if (r.length) fail(409, 'dhcp_overlap', 'dhcp_overlap', { cidr: r[0].cidr, space: r[0].space })
}
