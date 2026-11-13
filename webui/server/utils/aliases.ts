// Alias (CNAME) d'une adresse IPAM (0.9.53). Aucun lien stocké : une adresse a pour noms les enregistrements A/AAAA qui portent son IP ;
// ses alias sont les CNAME (de la même vue DNS) qui pointent, directement ou en chaîne, vers l'un de ces noms. Tout est recalculé à la lecture,
// donc rien à garder cohérent quand un nom change côté DNS. Fonctions pures (testées sans base).
export interface AliasRec { id: number; zoneId: number; zone: string; view: number | null; name: string; rdata: string; ttl: number | null; comment: string | null; disabled: boolean; protected: boolean }
export interface Alias { rec: AliasRec; fqdn: string; target: string; depth: number }

export const MAX_CHAIN = 8
const lc = (s: string) => s.toLowerCase()
/** Nom complet (minuscules, sans point final) d'un enregistrement relatif à sa zone. */
export const fqdnOf = (name: string, zone: string): string => (name === '@' ? lc(zone) : lc(`${name}.${zone}`))
/** Nom complet visé par un CNAME : « @ » = sommet de la zone, nom absolu (point final) tel quel, étiquette seule relative à la zone ; « . » (racine) = aucun. */
export function cnameTarget(rdata: string, zone: string): string | null {
  const t = rdata.trim()
  if (t === '.' || t === '') return null
  if (t === '@') return lc(zone)
  if (t.endsWith('.')) return lc(t.slice(0, -1))
  return lc(`${t}.${zone}`)
}
export const stripDot = (s: string) => lc(s.trim().replace(/\.$/, ''))

const key = (view: number | null, fq: string) => `${view ?? 0}|${fq}`
/** Index « cible → CNAME qui la visent », par vue. */
function byTarget(cnames: AliasRec[]): Map<string, Alias[]> {
  const m = new Map<string, Alias[]>()
  for (const r of cnames) {
    const t = cnameTarget(r.rdata, r.zone); if (!t) continue
    const k = key(r.view, t), a: Alias = { rec: r, fqdn: fqdnOf(r.name, r.zone), target: t, depth: 0 }
    m.set(k, [...(m.get(k) ?? []), a])
  }
  return m
}

/** Tous les alias (profondeur 1 = alias direct d'un nom de l'hôte, 2 = alias d'un alias…) des noms `hosts` dans la vue `view`. Chaînes bornées, boucles ignorées. */
export function collectAliases(hosts: string[], view: number | null, cnames: AliasRec[]): Alias[] {
  const idx = byTarget(cnames), out: Alias[] = [], seen = new Set<number>()
  let frontier = hosts.map(lc)
  for (let depth = 1; depth <= MAX_CHAIN && frontier.length; depth++) {
    const next: string[] = []
    for (const f of frontier) for (const a of idx.get(key(view, f)) ?? []) {
      if (seen.has(a.rec.id)) continue
      seen.add(a.rec.id); out.push({ ...a, depth }); next.push(a.fqdn)
    }
    frontier = next
  }
  return out
}

/** Longueur de la chaîne de CNAME qui part de `fq` (0 si `fq` n'est pas un CNAME) ; -1 en cas de boucle. */
export function chainLength(fq: string, view: number | null, cnames: AliasRec[]): number {
  const own = new Map<string, string>()
  for (const r of cnames) { const t = cnameTarget(r.rdata, r.zone); if (t && r.view === view) own.set(fqdnOf(r.name, r.zone), t) }
  let cur = lc(fq), n = 0; const seen = new Set<string>()
  while (own.has(cur)) { if (seen.has(cur)) return -1; seen.add(cur); cur = own.get(cur)!; n++; if (n > 64) return -1 }
  return n
}
/** Un nouvel alias `alias` → `target` boucle-t-il (la chaîne de `target` repasse par `alias`) ou dépasse-t-il la longueur permise ? */
export function aliasProblem(alias: string, target: string, view: number | null, cnames: AliasRec[], ignoreId?: number): 'cname_self' | 'cname_loop' | 'cname_chain_too_long' | null {
  const a = lc(alias), t = lc(target)
  if (a === t) return 'cname_self'
  const rest = ignoreId === undefined ? cnames : cnames.filter((r) => r.id !== ignoreId)
  const own = new Map<string, string>()
  for (const r of rest) { const x = cnameTarget(r.rdata, r.zone); if (x && r.view === view) own.set(fqdnOf(r.name, r.zone), x) }
  let cur = t, n = 1; const seen = new Set<string>()
  while (own.has(cur)) { if (cur === a || seen.has(cur)) return 'cname_loop'; seen.add(cur); cur = own.get(cur)!; n++; if (cur === a) return 'cname_loop'; if (n > MAX_CHAIN) return 'cname_chain_too_long' }
  return n > MAX_CHAIN ? 'cname_chain_too_long' : null
}

/** Zone (même vue) qui contient le nom saisi : suffixe le plus long ; null si aucun. */
export function zoneForName<Z extends { name: string; view: number | null }>(input: string, view: number | null, zones: Z[]): Z | null {
  const n = stripDot(input); let best: Z | null = null
  for (const z of zones) {
    if (z.view !== view) continue
    const zn = lc(z.name)
    if ((n === zn || n.endsWith('.' + zn)) && (!best || zn.length > best.name.length)) best = z
  }
  return best
}
