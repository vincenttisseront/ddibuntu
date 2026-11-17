// Lien entre l'accès réseau (RADIUS, EAP-TLS) et la PKI du DDI (0.14.3) : « Utiliser la PKI du DDI ». Les autorités et leurs CRL sont LUES en local, dans ce que root
// publie (pki-cas.json, pki-ca/<nom>/…) : pas de téléchargement, donc ni dépendance au DNS ni règle de pare-feu, et la CRL suit celle d'EJBCA. Une autorité de
// confiance venue du DDI porte l'étiquette `ddi` (nom de l'autorité côté PKI) ; la tâche horaire des CRL les relit sur place avant de tenter l'adresse.
import { createHash } from 'node:crypto'
import { applyCrl, addCas, normCrlUrl, parseCert, parseCrl, PkiError, splitCerts } from './radius-pki'
import type { PkiState } from './radius-pki'
import { readCaFile } from './pki-ca'
import type { PkiCa } from './pki-ca'

/** Empreinte SHA-256 du DER du certificat : celle que root publie pour chaque autorité. */
export function derSha256(pem: string): string { return createHash('sha256').update(parseCert(pem).x.raw).digest('hex') }

/** Autorités du DDI qu'on peut proposer comme chaîne de confiance : émettrices actives gérées par le DDI, avec leur certificat publié. */
export const trustable = (cas: PkiCa[]): PkiCa[] => cas.filter((c) => c.kind === 'issuing' && c.state === 'active' && c.managed && c.files.cert)

/** Ajoute à la liste de confiance l'autorité émettrice et sa chaîne (celle que root publie), marque chaque autorité venue du DDI et retient son adresse de CRL. */
export function applyDdiTrust(s: PkiState, text: string, published: PkiCa[]): { state: PkiState; added: number; skipped: number; names: string[] } {
  const bySha = new Map(published.map((c) => [c.sha256, c]))
  const wanted = new Set(splitCerts(text).map(derSha256))
  const r = addCas(s, text)
  const fresh = new Set(r.added)
  const names: string[] = []
  const cas = r.state.cas.map((c) => {
    const ddi = bySha.get(derSha256(c.pem))
    if (!ddi || !wanted.has(ddi.sha256)) return c
    const y = { ...c, ddi: ddi.name }
    if (fresh.has(c.id)) y.name = ddi.name.slice(0, 80)
    const u = ddi.crlUrl ? normCrlUrl(ddi.crlUrl) : null
    if (u && !y.crlUrl) y.crlUrl = u
    names.push(ddi.name)
    return y
  })
  return { state: { ...r.state, cas }, added: r.added.length, skipped: r.skipped, names }
}

/** Relit sur place la CRL publiée par root pour chaque autorité venue du DDI. Une CRL absente n'est pas une erreur (l'adresse prend le relais) ; une CRL illisible
 *  ou périmée est mémorisée sur l'autorité (la CRL en place est conservée). */
export async function syncDdiCrls(s: PkiState, published: PkiCa[], read: (name: string) => Promise<Buffer | null> = (n) => readCaFile(n, 'crl')): Promise<{ state: PkiState; changed: number; failed: number; missing: string[] }> {
  let state = s, changed = 0, failed = 0
  const missing: string[] = []
  for (const ca of s.cas.filter((c) => c.ddi)) {
    const pub = published.find((p) => p.name === ca.ddi && p.files.crl)
    const raw = pub ? await read(pub.name) : null
    if (!raw) { missing.push(ca.ddi!); continue }
    try {
      const parsed = await parseCrl(raw, state)
      if (parsed.caId !== ca.id) throw new PkiError('crl_wrong_issuer')
      const r = applyCrl(state, parsed, 'upload')
      state = r.state; if (r.changed) changed++
    } catch (e) {
      const code = e instanceof PkiError ? e.code : 'crl_invalid'
      if (code === 'crl_older') continue
      failed++
      state = { ...state, cas: state.cas.map((c) => (c.id === ca.id ? { ...c, crlError: { at: Date.now(), code } } : c)) }
    }
  }
  return { state, changed, failed, missing }
}
