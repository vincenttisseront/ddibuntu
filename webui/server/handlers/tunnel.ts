// Détection de tunnels et d'exfiltration DNS à partir du journal des requêtes (dns_queries).
// Heuristique, pas une preuve : un client qui interroge beaucoup de sous-noms distincts, longs et aléatoires, sous un même domaine
// ressemble à un tunnel (iodine, dnscat2, dns2tcp) ou à de l'exfiltration. Les domaines autorisés explicitement (règle « autoriser »)
// sont ignorés : c'est la façon de faire taire un faux positif connu (CDN, antivirus, DNSBL).
import { qint, route } from '../utils/router'
import { query } from '../utils/db'

export const registered = true

export interface TunnelStats { subs: number; avgLen: number; maxLabel: number; rareShare: number; entropy: number | null }
export interface TunnelVerdict { score: number; severity: 'high' | 'medium' | 'low'; reasons: string[] }

/** Entropie de Shannon (bits par caractère) d'une chaîne. */
export function shannon(s: string): number {
  if (!s) return 0
  const m = new Map<string, number>()
  for (const ch of s) m.set(ch, (m.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of m.values()) { const p = n / s.length; h -= p * Math.log2(p) }
  return h
}
/** Entropie moyenne des étiquettes longues (≥ 12 caractères) : les noms courts ont mécaniquement peu d'entropie, ils sont écartés. */
export function labelEntropy(subdomains: string[]): number | null {
  const e: number[] = []
  for (const sd of subdomains) for (const l of sd.split('.')) if (l.length >= 12) e.push(shannon(l.toLowerCase()))
  return e.length ? e.reduce((a, b) => a + b, 0) / e.length : null
}

export function scoreTunnel(s: TunnelStats): TunnelVerdict {
  const reasons: string[] = []
  let score = 0
  const add = (pts: number, r: string) => { score += pts; reasons.push(r) }
  if (s.subs >= 100) add(3, 'many_subdomains'); else if (s.subs >= 40) add(2, 'many_subdomains'); else if (s.subs >= 15) add(1, 'some_subdomains')
  if (s.avgLen >= 30) add(2, 'long_names'); else if (s.avgLen >= 20) add(1, 'long_names')
  if (s.maxLabel >= 50) add(1, 'long_label')
  if (s.entropy != null) { if (s.entropy >= 3.6) add(2, 'high_entropy'); else if (s.entropy >= 3.3) add(1, 'high_entropy') }
  if (s.rareShare >= 0.5) add(1, 'rare_types')
  return { score, severity: score >= 6 ? 'high' : score >= 4 ? 'medium' : 'low', reasons }
}

// Domaine « enregistrable » approché : deux dernières étiquettes, trois si le suffixe ressemble à co.uk / com.au.
const PARENT_SQL = `case when domain ~ '\\.(co|com|org|net|gov|edu|ac)\\.[a-z]{2}$' then substring(domain from '([^.]+\\.[^.]+\\.[^.]+)$') else substring(domain from '([^.]+\\.[^.]+)$') end`

route('GET', '/filter/tunnel', 'viewer', async (c) => {
  const hours = qint(c, 'hours', 24, 1, 168)
  const rows = await query<any>(`with q as (select client, domain, qtype, ${PARENT_SQL} as parent from dns_queries
      where at >= now() - make_interval(hours => $1) and domain like '%.%' and domain not like '%.arpa' and domain not like '%.local')
    select client, parent, count(*)::int as n, count(distinct domain)::int as subs, avg(length(domain) - length(parent) - 1)::float8 as avg_len,
      max(length(split_part(domain, '.', 1)))::int as max_label,
      (count(*) filter (where qtype in ('TXT','NULL','CNAME','MX','ANY'))::float8 / count(*)) as rare_share
    from q where parent is not null and domain <> parent group by client, parent having count(distinct domain) >= 15 order by subs desc, n desc limit 100`, [hours])
  const allow = (await query<any>("select domain from filter_rules where action = 'allow'")).map((r) => r.domain as string)
  const kept = rows.filter((r) => !allow.some((a) => r.parent === a || r.parent.endsWith(`.${a}`)))
  const items: any[] = []
  for (const r of kept.slice(0, 40)) {
    const sample = (await query<any>(`select distinct domain from dns_queries where client = $1 and at >= now() - make_interval(hours => $2) and (domain like $3 escape '\\') and domain <> $4 limit 40`,
      [r.client, hours, `%.${r.parent.replace(/[%_\\]/g, '\\$&')}`, r.parent])).map((x) => (x.domain as string).slice(0, -(r.parent.length + 1)))
    const stats: TunnelStats = { subs: r.subs, avgLen: Math.round(r.avg_len * 10) / 10, maxLabel: r.max_label, rareShare: Math.round(r.rare_share * 100) / 100, entropy: labelEntropy(sample) }
    const v = scoreTunnel(stats)
    if (v.score >= 3) items.push({ client: r.client, domain: r.parent, queries: r.n, ...stats, entropy: stats.entropy == null ? null : Math.round(stats.entropy * 100) / 100, ...v })
  }
  items.sort((a, b) => b.score - a.score || b.subs - a.subs)
  return { hours, items }
})
