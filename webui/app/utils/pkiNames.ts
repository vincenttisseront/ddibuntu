// Noms proposés par défaut dans les formulaires de la PKI (0.14.14) : un nom cohérent avec ce qu'on crée (profil, domaine du DDI, numéro libre), que l'utilisateur
// remplace comme il veut. Pur : aucune dépendance à Vue, testable seul.

/** Domaine déduit du nom public de la PKI : « pki.lab.test » → « lab.test ». Rien si le nom n'a pas de point. */
export function domainOf(host?: string | null): string {
  const h = String(host ?? '').trim().toLowerCase().replace(/\.$/, '')
  const i = h.indexOf('.')
  return i > 0 && i < h.length - 1 && /^[a-z0-9.-]+$/.test(h) ? h.slice(i + 1) : ''
}

/** Premier numéro libre (à partir de 1) : `make(n)` donne le nom candidat, `taken` les noms déjà pris (casse ignorée). */
export function freeNumber(make: (n: number) => string, taken: Iterable<string>): number {
  const used = new Set([...taken].map((x) => String(x).toLowerCase()))
  let n = 1
  while (used.has(make(n).toLowerCase()) && n < 999) n++
  return n
}

/** Noms alternatifs proposés d'après le nom (CN) : un nom complet (avec un point) devient le nom DNS ; pour un utilisateur, « nom@domaine » devient l'identifiant UPN. */
export function suggestSans(profile: string, cn: string, domain: string): { dns: string; upn: string } {
  const v = cn.trim()
  if (profile === 'user') return { dns: '', upn: v && domain && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(v) && !v.includes('@') ? `${v}@${domain}` : '' }
  return { dns: /^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9-]+)+$/.test(v) ? v.toLowerCase() : '', upn: '' }
}

/** Nom d'un serveur, poste ou équipement : « serveur-01.lab.test » ; pour un utilisateur, pas de domaine : « utilisateur-01 ». */
export function suggestCertName(prefix: string, domain: string, withDomain: boolean, taken: Iterable<string>): string {
  const make = (n: number) => `${prefix}-${String(n).padStart(2, '0')}${withDomain && domain ? `.${domain}` : ''}`
  return make(freeNumber(make, taken)).slice(0, 63)
}

/** Nom de l'autorité (identifiant) et nom courant (CN) proposés à la création : DDI-Issuing-1 / « DDI Issuing CA 1 ». */
export function suggestCaNames(kind: 'root' | 'issuing', takenNames: Iterable<string>): { name: string; cn: string } {
  const word = kind === 'root' ? 'Root' : 'Issuing'
  const n = freeNumber((i) => `DDI-${word}-${i}`, takenNames)
  return { name: `DDI-${word}-${n}`, cn: `DDI ${word} CA ${n}` }
}

/** Nom d'une autorité reprise d'un PKCS#12. */
export function suggestImportName(takenNames: Iterable<string>): string {
  return `Imported-CA-${freeNumber((i) => `Imported-CA-${i}`, takenNames)}`
}

/** Nom courant (CN) d'une demande de certificat (PEM en texte, ou DER) ; null si absent ou illisible. Simple lecture, sans vérifier la demande : root la revalide. */
export function csrCommonName(input: string | Uint8Array): string | null {
  let u: Uint8Array
  try {
    if (typeof input === 'string') {
      const b = input.replace(/-----(BEGIN|END)[^-]*-----/g, '').replace(/\s+/g, '')
      if (!b || b.length > 24000 || !/^[A-Za-z0-9+/=]+$/.test(b)) return null
      u = Uint8Array.from(atob(b), (c) => c.charCodeAt(0))
    } else u = input
  } catch { return null }
  // OID 2.5.4.3 (commonName) = 06 03 55 04 03, suivi du type de chaîne puis de sa longueur. Le sujet vient avant les extensions : la première occurrence est la bonne.
  for (let i = 0; i + 7 < u.length; i++) {
    if (u[i] !== 0x06 || u[i + 1] !== 0x03 || u[i + 2] !== 0x55 || u[i + 3] !== 0x04 || u[i + 4] !== 0x03) continue
    const tag = u[i + 5]!
    let len = u[i + 6]!, at = i + 7
    if (len === 0x81) { len = u[at]!; at++ } else if (len & 0x80) return null
    if (![0x0c, 0x13, 0x16, 0x14].includes(tag) || !len || at + len > u.length) return null
    const s = new TextDecoder().decode(u.subarray(at, at + len))
    // eslint-disable-next-line no-control-regex
    return s.length <= 64 && !/[\u0000-\u001f,+=\\"<>;/]/.test(s) ? s : null
  }
  return null
}
