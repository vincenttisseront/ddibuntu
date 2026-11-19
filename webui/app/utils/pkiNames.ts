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

/** Nom du serveur RADIUS du DDI : « radius.lab.test » (un seul certificat pour les deux nœuds), « radius » sans domaine connu. */
export function suggestRadiusName(domain: string): string { return domain ? `radius.${domain}` : 'radius' }

export interface DnParts { cn: string; o: string; ou: string; c: string }

/** Premiers CN, O, OU et C d'un nom distinctif écrit « CN=…,OU=…,O=…,C=… » (virgules échappées par une barre oblique inverse comprises). */
export function dnParts(dn: string | null | undefined): DnParts {
  const out: DnParts = { cn: '', o: '', ou: '', c: '' }
  for (const part of String(dn ?? '').match(/(?:\\.|[^,\\])+/g) ?? []) {
    const m = part.trim().match(/^([A-Za-z]+)=(.*)$/s)
    const k = m?.[1]?.toLowerCase() as keyof DnParts | undefined
    if (k && k in out && !out[k]) out[k] = m![2]!.replace(/\\(.)/g, '$1').trim()
  }
  return out
}

const ATTR: Record<keyof DnParts, number> = { cn: 0x03, c: 0x06, o: 0x0a, ou: 0x0b }

/** Nom courant, organisation, unité et pays du sujet d'une demande de certificat (PEM en texte, ou DER). Simple lecture, sans vérifier la demande : root la revalide.
 *  Une valeur absente, illisible ou contenant un séparateur de nom distinctif est laissée vide. */
export function csrSubject(input: string | Uint8Array): Partial<DnParts> {
  let u: Uint8Array
  try {
    if (typeof input === 'string') {
      const b = input.replace(/-----(BEGIN|END)[^-]*-----/g, '').replace(/\s+/g, '')
      if (!b || b.length > 24000 || !/^[A-Za-z0-9+/=]+$/.test(b)) return {}
      u = Uint8Array.from(atob(b), (c) => c.charCodeAt(0))
    } else u = input
  } catch { return {} }
  const out: Partial<DnParts> = {}
  // OID 2.5.4.x = 06 03 55 04 xx, suivi du type de chaîne puis de sa longueur. Le sujet précède les extensions : la première occurrence est la bonne.
  for (const [k, last] of Object.entries(ATTR) as [keyof DnParts, number][]) {
    for (let i = 0; i + 7 < u.length; i++) {
      if (u[i] !== 0x06 || u[i + 1] !== 0x03 || u[i + 2] !== 0x55 || u[i + 3] !== 0x04 || u[i + 4] !== last) continue
      const tag = u[i + 5]!
      let len = u[i + 6]!, at = i + 7
      if (len === 0x81) { len = u[at]!; at++ } else if (len & 0x80) break
      if (![0x0c, 0x13, 0x16, 0x14].includes(tag) || !len || at + len > u.length) break
      const v = new TextDecoder().decode(u.subarray(at, at + len))
      // eslint-disable-next-line no-control-regex
      if (v.length <= 64 && !/[\u0000-\u001f,+=\\"<>;/]/.test(v) && (k !== 'c' || /^[A-Za-z]{2}$/.test(v))) out[k] = k === 'c' ? v.toUpperCase() : v
      break
    }
  }
  return out
}

/** Nom courant d'une demande de certificat ; null si absent ou illisible. */
export function csrCommonName(input: string | Uint8Array): string | null { return csrSubject(input).cn ?? null }
