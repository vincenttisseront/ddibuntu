// Champs calculés d'un formulaire : un champ déclaré avec `autoFrom` + `autoFn` suit sa source (ex. format de nom ← règle de nommage)
// tant que l'utilisateur ne l'a pas modifié lui-même ; vide à l'ouverture, il est rempli aussitôt.
interface AutoField { key: string; autoFrom?: string; autoFn?: (v: string) => string }
export function useAutoFields(fields: () => AutoField[], state: Record<string, any>) {
  const last: Record<string, string> = {}
  const derive = (f: AutoField) => (f.autoFn ? f.autoFn(String(state[f.autoFrom!] ?? '')) : '')
  function sync() {
    for (const f of fields()) {
      if (!f.autoFrom || !f.autoFn) continue
      const d = derive(f)
      if (!state[f.key] || state[f.key] === last[f.key]) { state[f.key] = d; last[f.key] = d }
    }
  }
  /** À appeler après l'initialisation de `state` (ouverture du formulaire). */
  function reset() { for (const k of Object.keys(last)) delete last[k]; sync() }
  watch(() => fields().filter((f) => f.autoFrom).map((f) => state[f.autoFrom!]).join('\u0000'), sync)
  return { reset }
}
