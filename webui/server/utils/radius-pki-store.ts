// État de la PKI RADIUS en base (réglage « radius_pki ») : lecture, écriture et sérialisation des modifications (routes, tâche planifiée des CRL).
import { getSetting, setSetting } from './db'
import { crlSetDigest, PKI_DEFAULTS, PKI_KEY, readiness, refreshCrl } from './radius-pki'
import { depositRadiusRequest, radiusRequestPending, readRadiusStatus } from './radius'
import { readPkiCas } from './pki-ca'
import { syncDdiCrls } from './radius-ddi'
import type { PkiState } from './radius-pki'

export const loadPki = async (): Promise<PkiState> => ({ ...PKI_DEFAULTS, ...(await getSetting<PkiState>(PKI_KEY, PKI_DEFAULTS)) })
export const savePki = (s: PkiState) => setSetting(PKI_KEY, s)
let chain: Promise<unknown> = Promise.resolve()
/** Lecture-modification-écriture sérialisée : deux requêtes simultanées ne s'écrasent pas. */
export function withPki<T>(fn: () => Promise<T>): Promise<T> {
  const run = chain.then(fn, fn)
  chain = run.catch(() => undefined)
  return run
}


/** Télécharge les CRL de toutes les autorités qui ont une adresse. Renvoie le nombre de CRL nouvelles et celui des échecs. */
export async function refreshAllCrls(fetchFn: typeof fetch = fetch): Promise<{ changed: number; failed: number }> {
  let changed = 0, failed = 0
  // autorités venues de la PKI du DDI : CRL relue sur place (ce que root publie) ; l'adresse ne sert que si elle n'est pas disponible
  const local = new Set<string>()
  const pub = (await readPkiCas())?.cas
  if (pub && (await loadPki()).cas.some((c) => c.ddi)) {
    await withPki(async () => {
      const r = await syncDdiCrls(await loadPki(), pub)
      await savePki(r.state)
      changed += r.changed; failed += r.failed
      for (const c of r.state.cas) if (c.ddi && !r.missing.includes(c.ddi)) local.add(c.id)   // fichier présent (même illisible) : la PKI du DDI est la source, l'adresse ne dirait rien de plus
    })
  }
  for (const ca of (await loadPki()).cas.filter((c) => c.crlUrl && !local.has(c.id))) {
    await withPki(async () => {
      const r = await refreshCrl(await loadPki(), ca.id, fetchFn)
      await savePki(r.state)
      if (r.error) failed++; else if (r.changed) changed++
    })
  }
  return { changed, failed }
}

/** Envoie à root les CRL actuelles si EAP-TLS est déployé avec vérification de révocation et si elles ont changé depuis le dernier envoi
 *  (root redémarre alors le service : FreeRADIUS ne relit pas les CRL à chaud, voir ddibuntu-radius). Sans effet sinon. */
export async function pushCrlsIfNeeded(): Promise<'pushed' | 'unchanged' | 'pending' | 'not_deployed' | 'not_ready'> {
  const st = await readRadiusStatus()
  if (!st?.eap.enabled || !st.eap.checkCrl) return 'not_deployed'
  return withPki(async () => {
    const s = await loadPki()
    if (!s.checkCrl || !readiness(s).ready) return 'not_ready'
    const digest = crlSetDigest(s)
    if (s.crlPushed === digest) return 'unchanged'
    if (await radiusRequestPending()) return 'pending'
    const crls: Record<string, string> = {}
    for (const c of s.cas) if (c.crl) crls[`${c.id}.pem`] = c.crl.pem
    await depositRadiusRequest({ action: 'crl', crls })
    await savePki({ ...s, crlPushed: digest })
    return 'pushed'
  })
}
