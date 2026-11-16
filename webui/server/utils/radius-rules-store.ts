// Règles d'accès RADIUS : lecture en base, compilation et état de déploiement (0.13.3).
import { getSetting, query, setSetting } from './db'
import { rowToRule, compileRules } from './radius-rules'
import type { ClientInfo, CompiledRule, RuleRow } from './radius-rules'
import type { Usage } from './radius'

const COLS = 'id, rank, name, enabled, action, conds, reply, comment, created_at, updated_at'
/** Empreinte de ce qui a été envoyé à root la dernière fois (`none` = aucune règle). */
export const PUSHED_KEY = 'radius_authz_pushed'

export async function loadRules(): Promise<RuleRow[]> {
  return (await query<any>(`select ${COLS} from radius_rules order by rank, id`)).map(rowToRule)
}
export async function loadClientInfos(): Promise<ClientInfo[]> {
  return (await query<any>('select name, usage, enabled from radius_clients order by name')).map((c) => ({ name: String(c.name), usage: c.usage as Usage, enabled: c.enabled === true }))
}
export async function loadCompiled(): Promise<{ rows: RuleRow[]; clients: ClientInfo[]; compiled: CompiledRule[] }> {
  const [rows, clients] = await Promise.all([loadRules(), loadClientInfos()])
  return { rows, clients, compiled: compileRules(rows, clients) }
}
export const getPushed = () => getSetting<string | null>(PUSHED_KEY, null)
export const setPushed = (digest: string) => setSetting(PUSHED_KEY, digest)
/** Noms de clients cités par une règle mais qui n'existent plus (la règle ne s'applique alors qu'aux clients restants, ou jamais s'il n'en reste aucun). */
export function unknownClients(rows: RuleRow[], clients: ClientInfo[]): Array<{ id: number; names: string[] }> {
  const known = new Set(clients.map((c) => c.name))
  return rows.map((r) => ({ id: r.id, names: r.conds.clients.filter((n) => !known.has(n)) })).filter((x) => x.names.length)
}
