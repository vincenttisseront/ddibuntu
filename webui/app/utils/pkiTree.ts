// Arbre des autorités de la PKI (0.14.13) : chaque autorité est rattachée à celle qui l'a signée (racine du DDI par son nom, racine HORS LIGNE par « extRoot »).
// Une racine auto-signée, ou une autorité dont le signeur est introuvable, est une tête d'arbre. Pur et borné : aucun cycle ne peut boucler (une autorité n'est placée qu'une fois).
export interface PkiTreeCa { name: string; kind: string; signedBy?: string; extRoot?: string }
export interface PkiTreeRow<T extends PkiTreeCa = PkiTreeCa> { ca: T; depth: number; last: boolean; guides: boolean[] }

const rank: Record<string, number> = { root: 0, extroot: 1, issuing: 2, unknown: 3 }
const byRank = (a: PkiTreeCa, b: PkiTreeCa) => (rank[a.kind] ?? 9) - (rank[b.kind] ?? 9) || a.name.localeCompare(b.name)

export function parentName(c: PkiTreeCa, names: Set<string>): string | null {
  if (c.kind === 'extroot' || !c.signedBy || c.signedBy === 'self') return null
  const p = c.signedBy === 'external' ? c.extRoot : c.signedBy
  return p && p !== c.name && names.has(p) ? p : null
}

export function pkiTreeRows<T extends PkiTreeCa>(cas: T[]): PkiTreeRow<T>[] {
  const names = new Set(cas.map((c) => c.name))
  const kids = new Map<string, T[]>()
  const heads: T[] = []
  for (const c of cas) {
    const p = parentName(c, names)
    if (p) kids.set(p, [...(kids.get(p) ?? []), c]); else heads.push(c)
  }
  const out: PkiTreeRow<T>[] = []
  const seen = new Set<string>()
  const walk = (c: T, depth: number, last: boolean, guides: boolean[]) => {
    if (seen.has(c.name)) return
    seen.add(c.name)
    out.push({ ca: c, depth, last, guides })
    const sub = [...(kids.get(c.name) ?? [])].sort(byRank)
    sub.forEach((k, i) => walk(k, depth + 1, i === sub.length - 1, [...guides, !last]))
  }
  const top = [...heads].sort(byRank)
  top.forEach((c, i) => walk(c, 0, i === top.length - 1, []))
  // Une boucle de signatures (A signe B, B signe A) ne laisse aucune tête : on n'en perd aucune autorité, elles sont posées à la racine de l'arbre.
  for (const c of [...cas].sort(byRank)) walk(c, 0, true, [])
  return out
}
