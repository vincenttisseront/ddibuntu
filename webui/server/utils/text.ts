// Petits utilitaires de texte, linéaires (pas d'expressions régulières à retour arrière).

/** Comparateur par unités de code UTF-16 : même ordre que le tri par défaut de JavaScript (donc stable pour les empreintes), mais explicite. */
export const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0)

/** Retire les « / » finaux (équivalent de .replace(/\/+$/, '') sans risque de backtracking). */
export function trimTrailingSlashes(s: string): string {
  let e = s.length
  while (e > 0 && s.charCodeAt(e - 1) === 47) e--
  return s.slice(0, e)
}

/** Normalise un DN LDAP pour comparaison : espaces autour des « , » et des « = » retirés, minuscules. */
export function normDn(s: string): string {
  return s.split(',').map((p) => p.split('=').map((x) => x.trim()).join('=')).join(',').toLowerCase()
}

/** Retire un commentaire de fin de ligne introduit par « # » précédé d'un espace (équivalent de /\s+#.*$/). */
export function stripTrailingComment(line: string): string {
  for (let i = 1; i < line.length; i++) if (line[i] === '#' && /\s/.test(line[i - 1]!)) return line.slice(0, i).trimEnd()
  return line
}
