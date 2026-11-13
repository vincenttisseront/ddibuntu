// Génération de noms d'hôtes (0.10.5) : format à jetons, appliqué à une adresse. Rien d'une expression régulière saisie par l'utilisateur.
//   {ip}   10-1-2-3        {o1}..{o4}  octet (« {o4:3} » = sur 3 chiffres)   {vlan}  numéro de VLAN   {site}  site du réseau
export const FORMAT_MAX = 100
const TOKEN = /\{(ip|o[1-4]|vlan|site)(?::(\d))?\}/g
export function formatError(f: string): string | null {
  if (!f || f.length > FORMAT_MAX) return 'format_length'
  if (!/^[A-Za-z0-9{}:._-]+$/.test(f)) return 'format_chars'
  const rest = f.replace(TOKEN, '')
  if (/[{}:]/.test(rest)) return 'format_token'
  return null
}
export interface NameCtx { ip: string; vlan: number | null; site: string | null }
/** Nom généré (minuscules, caractères sûrs) ou null si le résultat n'est pas un nom d'hôte valide (jeton sans valeur, trop long…). */
export function formatName(f: string, c: NameCtx): string | null {
  const o = c.ip.split('.')
  let missing = false
  const out = f.replace(TOKEN, (_m, k: string, w?: string) => {
    let v: string | null
    if (k === 'ip') v = c.ip.replace(/\./g, '-')
    else if (k === 'vlan') v = c.vlan === null ? null : String(c.vlan)
    else if (k === 'site') v = c.site ? c.site.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') : null
    else v = o[Number(k[1]) - 1] ?? null
    if (!v) { missing = true; return '' }
    return w && /^\d+$/.test(v) ? v.padStart(Number(w), '0') : v
  }).toLowerCase()
  return !missing && /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(out) ? out : null
}
