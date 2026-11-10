// Du journal BIND aux statistiques (agrégats par minute) ET au journal des requêtes du cockpit (une ligne par requête).
import { query, tx } from './db'
import { normDomain } from './net'
import { parseBindLog } from './querylog'
import type { LogEvent } from './querylog'
import { loadCockpit } from './filterstate'

export interface QueryRow { at: Date; client: string; domain: string; qtype: string; status: 'allowed' | 'blocked'; reason: string; category: string }

/** Une requête et sa réécriture RPZ forment UNE ligne : la ligne « query » est enrichie par la ligne « rpz » qui la suit. */
export function mergeEvents(events: LogEvent[]): QueryRow[] {
  const rows: QueryRow[] = [], open = new Map<string, QueryRow & { done?: boolean }>()
  for (const e of events) {
    const key = `${e.client}|${e.domain}`
    if (e.kind === 'query') { const r = { at: e.at, client: e.client, domain: e.domain, qtype: e.qtype, status: 'allowed' as const, reason: '', category: '' }; rows.push(r); open.set(key, r); continue }
    const r = open.get(key)
    const target = r && !r.done && Math.abs(e.at.getTime() - r.at.getTime()) <= 5000 ? r : (rows[rows.push({ at: e.at, client: e.client, domain: e.domain, qtype: '', status: 'allowed', reason: '', category: '' }) - 1]!)
    if (e.kind === 'blocked') target.status = 'blocked'; else target.reason = 'whitelist'
    ;(target as any).done = true
  }
  return rows
}

type Why = { kind: 'allow_rule' | 'block_rule' | 'list'; source: string; category: string }
/** Pourquoi : même précédence que RPZ et que /filter/check (le plus spécifique l'emporte ; « autoriser » gagne à égalité). */
export async function explain(domains: string[]): Promise<Map<string, Why>> {
  const chain = (d: string) => { const l = d.split('.'); return l.slice(0, -1).map((_, i) => l.slice(i).join('.')) }
  const all = [...new Set(domains.flatMap(chain))]
  const byDomain = new Map<string, Why[]>()
  const add = (d: string, w: Why) => { const a = byDomain.get(d) ?? []; a.push(w); byDomain.set(d, a) }
  for (let i = 0; i < all.length; i += 5000) {
    const part = all.slice(i, i + 5000)
    for (const r of await query<any>('select domain, action from filter_rules where domain = any($1)', [part])) add(r.domain, { kind: r.action === 'allow' ? 'allow_rule' : 'block_rule', source: '', category: '' })
    for (const r of await query<any>('select e.domain, l.name, l.category from block_entries e join block_lists l on l.id = e.list_id where l.enabled and e.domain = any($1)', [part])) add(r.domain, { kind: 'list', source: r.name, category: r.category })
  }
  const out = new Map<string, Why>()
  for (const d of new Set(domains)) for (const c of chain(d)) {
    const m = byDomain.get(c)
    if (m?.length) { out.set(d, m.find((x) => x.kind === 'allow_rule') ?? m.find((x) => x.kind === 'block_rule') ?? m[0]!); break }
  }
  return out
}

export function maskClient(ip: string): string {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip.replace(/\.\d+$/, '.0')
  const g = ip.split(':'); return g.length > 4 ? `${g.slice(0, 4).join(':')}::` : ip
}

export async function storeQueries(rows: QueryRow[], anonymize: 'none' | 'mask'): Promise<number> {
  if (!rows.length) return 0
  const blocked = [...new Set(rows.filter((r) => r.status === 'blocked').map((r) => r.domain))]
  const why = blocked.length ? await explain(blocked) : new Map<string, Why>()
  for (const r of rows) {
    if (r.status === 'blocked') { const w = why.get(r.domain); r.reason = !w ? 'unknown' : w.kind === 'list' ? `list:${w.source}` : 'blacklist'; r.category = w?.kind === 'list' ? w.category : '' }
    if (anonymize === 'mask') r.client = maskClient(r.client)
  }
  for (let i = 0; i < rows.length; i += 5000) {
    const p = rows.slice(i, i + 5000)
    await query('insert into dns_queries (at, client, domain, qtype, status, reason, category) select * from unnest($1::timestamptz[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])',
      [p.map((r) => r.at.toISOString()), p.map((r) => r.client), p.map((r) => r.domain), p.map((r) => r.qtype), p.map((r) => r.status), p.map((r) => r.reason), p.map((r) => r.category)])
  }
  return rows.length
}

/** Texte de journal BIND -> statistiques par minute (comme avant) + journal des requêtes (si la rétention n'est pas nulle). */
export async function ingestLogText(text: string): Promise<{ events: number; buckets: number; stored: number }> {
  const events = parseBindLog(text)
  const counted = events.filter((e) => e.kind !== 'passthru')
  const blockedDomains = [...new Set(counted.filter((e) => e.kind === 'blocked').map((e) => e.domain))].slice(0, 5000)
  // catégorie d'un blocage : celle de la liste qui le porte, y compris quand c'est le domaine PARENT qui figure dans la liste
  const cat = new Map<string, string>()
  if (blockedDomains.length) for (const [d, w] of await explain(blockedDomains)) if (w.kind === 'list') cat.set(d, w.category)
  const buckets = new Map<string, number>()
  for (const e of counted) {
    const minute = new Date(Math.floor(e.at.getTime() / 60000) * 60000).toISOString()
    const k = `${minute}|${e.kind}|${e.kind === 'blocked' ? (cat.get(e.domain) ?? 'rule') : ''}`
    buckets.set(k, (buckets.get(k) ?? 0) + 1)
  }
  await tx(async (cl) => {
    for (const [k, n] of buckets) {
      const [bucket, kind, key] = k.split('|')
      await cl.query('insert into dns_stats (bucket, kind, key, count) values ($1,$2,$3,$4) on conflict (bucket, kind, key) do update set count = dns_stats.count + excluded.count', [bucket, kind, key, n])
    }
  })
  const s = await loadCockpit()
  const stored = s.retentionDays > 0 ? await storeQueries(mergeEvents(events).filter((r) => normDomain(r.domain)), s.anonymize) : 0
  return { events: events.length, buckets: buckets.size, stored }
}
