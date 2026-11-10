// Lien profond : ?nom=ID dans l'URL pré-sélectionne un élément (résultats de la recherche globale).
// Appliqué au chargement puis à chaque changement de l'URL ; ignore toute valeur qui n'est pas un entier positif.
export function useQueryId(name: string, apply: (id: number) => void) {
  const route = useRoute()
  const run = (v: unknown) => { const s = Array.isArray(v) ? v[0] : v; if (typeof s === 'string' && /^\d{1,9}$/.test(s) && Number(s) > 0) apply(Number(s)) }
  run(route.query[name])
  watch(() => route.query[name], run)
}
