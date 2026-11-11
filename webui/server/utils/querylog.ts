// Analyse des journaux BIND (requêtes et réécritures RPZ) pour les statistiques de blocage.
export interface LogEvent { at: Date; kind: 'query' | 'blocked' | 'passthru'; domain: string; client: string; qtype: string }

export function parseBindLog(text: string, fallbackNow = new Date()): LogEvent[] {
  const out: LogEvent[] = []
  for (const line of text.split('\n')) {
    if (!line.includes('client ')) continue
    const ts = line.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?Z?/)
    const at = ts ? new Date(`${ts[1]}T${ts[2]}Z`) : fallbackNow
    if (Number.isNaN(at.getTime())) continue
    const client = line.match(/client (?:@0x[0-9a-f]+ )?([0-9a-f.:]+)#\d+/i)?.[1] ?? ''
    const rpz = line.match(/rpz (?:QNAME|IP|NSDNAME|NSIP|CLIENT-IP) (NXDOMAIN|NODATA|PASSTHRU|DROP|TCP-ONLY|LOCAL-DATA|CNAME)\b.*?rewrite ([^/\s]+)\//)
    if (rpz) { out.push({ at, kind: rpz[1] === 'PASSTHRU' ? 'passthru' : 'blocked', domain: rpz[2]!.toLowerCase().replace(/\.$/, ''), client, qtype: '' }); continue }
    const q = line.match(/\): (?:view \S+: )?query: (\S+) IN (\S+)/)
    if (q) out.push({ at, kind: 'query', domain: q[1]!.toLowerCase().replace(/\.$/, ''), client, qtype: q[2]!.toUpperCase().slice(0, 12) })
  }
  return out
}
