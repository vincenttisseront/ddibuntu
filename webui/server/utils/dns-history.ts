// Historique des enregistrements DNS (0.10.3) : avant / après de chaque création, modification, suppression ou retour arrière.
export interface RecSnap { name: string; type: string; ttl: number | null; rdata: string; comment: string | null; protected: boolean; disabled: boolean }
export const recSnap = (r: any): RecSnap => ({ name: r.name, type: r.type, ttl: r.ttl ?? null, rdata: r.rdata, comment: r.comment ?? null, protected: !!r.protected, disabled: !!r.disabled })
export const HISTORY_KEEP = 500
type Runner = { query: (q: string, p?: unknown[]) => Promise<any> }

export async function logHistory(cl: Runner, zoneId: number, recordId: number | null, username: string | null, action: 'create' | 'update' | 'delete' | 'revert', before: RecSnap | null, after: RecSnap | null): Promise<void> {
  await cl.query('insert into dns_record_history (zone_id, record_id, username, action, before, after) values ($1,$2,$3,$4,$5::jsonb,$6::jsonb)', [zoneId, recordId, username, action, before && JSON.stringify(before), after && JSON.stringify(after)])
  await cl.query('delete from dns_record_history where zone_id = $1 and id not in (select id from dns_record_history where zone_id = $1 order by id desc limit $2)', [zoneId, HISTORY_KEEP])
}

/** Différence par lignes, sans tenir compte de l'ordre ni de la ligne SOA (le numéro de série change à chaque publication). */
export function lineDiff(deployed: string, current: string): { added: string[]; removed: string[] } {
  const lines = (t: string) => t.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith(';') && !/\bSOA\b/.test(l))
  const count = (a: string[]) => { const m = new Map<string, number>(); for (const l of a) m.set(l, (m.get(l) ?? 0) + 1); return m }
  const a = count(lines(deployed)), b = count(lines(current))
  const added: string[] = [], removed: string[] = []
  for (const [l, n] of b) for (let i = 0; i < n - (a.get(l) ?? 0); i++) added.push(l)
  for (const [l, n] of a) for (let i = 0; i < n - (b.get(l) ?? 0); i++) removed.push(l)
  return { added, removed }
}
