// Vue cible d'une opération qui crée ou retrouve une zone « par son nom » (assistants AD, import) : sans vue, aucune ; avec des vues, celle
// qui est indiquée, à défaut la première (celle que servent en général les clients internes).
import { one } from './db'
import { fail } from './router'

export async function viewTarget(given?: number | null): Promise<number | null> {
  const n = (await one<any>('select count(*)::int n from dns_views'))!.n as number
  if (!n) { if (given) fail(400, 'view_not_found'); return null }
  if (given) { if (!(await one('select 1 from dns_views where id = $1', [given]))) fail(400, 'view_not_found'); return given }
  return (await one<any>('select id from dns_views order by position, id limit 1'))!.id as number
}
