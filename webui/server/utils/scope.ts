// Délégation par périmètre : un utilisateur dont « spaceIds » n'est pas nul n'écrit que dans ces espaces IPAM (et nulle part ailleurs).
import { one } from './db'
import { fail } from './router'

type Ctx = { user: { spaceIds?: number[] | null } | null }
const list = (c: Ctx): number[] | null => c.user?.spaceIds ?? null

/** Refuse (403 out_of_scope) un utilisateur restreint pour tout ce qui est global ou hors de ses espaces. */
export function denyScoped(c: Ctx) { if (list(c)) fail(403, 'out_of_scope') }
export function allowSpace(c: Ctx, spaceId: number | null | undefined) { const l = list(c); if (l && !l.includes(spaceId ?? 1)) fail(403, 'out_of_scope') }
const via = async (c: Ctx, sql: string, id: number) => { if (!list(c)) return; const r = await one<{ space_id: number }>(sql, [id]); if (r) allowSpace(c, r.space_id) }
export const allowSubnet = (c: Ctx, id: number) => via(c, 'select space_id from subnets where id = $1', id)
export const allowAddress = (c: Ctx, id: number) => via(c, 'select s.space_id from addresses a join subnets s on s.id = a.subnet_id where a.id = $1', id)
export const allowPool = (c: Ctx, id: number) => via(c, 'select s.space_id from ipam_pools p join subnets s on s.id = p.subnet_id where p.id = $1', id)
