// Accès réseau × PKI du DDI (0.14.3) : « Utiliser la PKI du DDI ». Deux actions de l'administrateur :
//  - faire confiance à une autorité émettrice du DDI : sa chaîne (celle que root publie) entre dans la liste de confiance d'EAP-TLS, son adresse de CRL est retenue
//    et la CRL est lue sur place (jamais de téléchargement) ; la tâche horaire la relit ensuite ;
//  - émettre le certificat du serveur RADIUS avec le profil « DDI-RADIUS-Server » : la clé est fabriquée ici, chiffrée au repos comme pour une demande ordinaire,
//    et n'est jamais vue par la PKI (elle ne reçoit que la demande de certificat).
// Ce fichier ne signe rien et ne parle pas à root directement : l'émission passe par le gestionnaire des certificats de la PKI (dépôt + attente de la réponse).
import { createPrivateKey } from 'node:crypto'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { encryptSecret } from '../utils/auth'
import { readCaFile, readPkiCas, caName, DN_VALUE_RE } from '../utils/pki-ca'
import { readPkiStatus } from '../utils/pki'
import { dnsList, ipList, newKeyAndCsr } from '../utils/pki-certs'
import { applyDdiTrust, syncDdiCrls, trustable } from '../utils/radius-ddi'
import { fillHashes, parseCert, pickServerCert, PkiError } from '../utils/radius-pki'
import type { PkiState } from '../utils/radius-pki'
import { loadPki, pushCrlsIfNeeded, savePki, withPki } from '../utils/radius-pki-store'
import { issueCert } from './pkicert'
import { checkServerCert, pkiView } from './radiuspki'

export const registered = true

async function guard<T>(fn: () => Promise<T>): Promise<T> {
  try { return await fn() }
  catch (e) {
    if (e instanceof PkiError) fail(e.code === 'ca_not_found' ? 404 : e.code.endsWith('unavailable') ? 503 : 400, `radius_pki_${e.code}`, undefined, e.data)
    if ((e as Error)?.message?.startsWith('openssl_')) fail(503, 'radius_pki_openssl')
    throw e
  }
}
/** Autorité émettrice du DDI choisie : elle doit exister, être active, gérée par le DDI et avoir un certificat publié. */
async function chosen(name: string) {
  const cas = (await readPkiCas())?.cas ?? []
  const ca = trustable(cas).find((c) => c.name === name)
  if (!ca) fail(404, 'not_found')
  return { ca, cas }
}
const pemOf = async (n: string, k: 'cert' | 'chain') => (await readCaFile(n, k))?.toString('utf8') ?? ''

// Ce que la PKI du DDI propose : les autorités émettrices utilisables, et si chacune est déjà dans la liste de confiance
route('GET', '/radius/pki/ddi', 'admin', async () => {
  const st = await readPkiStatus()
  const cas = (await readPkiCas())?.cas ?? []
  const s = await loadPki()
  const trusted = new Set(s.cas.map((c) => c.ddi).filter(Boolean))
  return {
    installed: !!st?.installed, ready: st?.state === 'healthy', hostname: st?.hostname ?? '',
    issuers: trustable(cas).map((c) => ({ name: c.name, dn: c.dn, notAfter: c.notAfter, signedBy: c.signedBy, crlUrl: c.crlUrl, hasCrl: c.files.crl, trusted: trusted.has(c.name) })),
  }
})

const trustBody = z.object({ ca: caName }).strict()
route('POST', '/radius/pki/ddi/trust', 'admin', async (c) => {
  const b = await c.body(trustBody)
  const { ca, cas } = await chosen(b.ca)
  const text = (await pemOf(ca.name, 'chain')) + (await pemOf(ca.name, 'cert'))
  if (!text.includes('BEGIN CERTIFICATE')) fail(404, 'not_found')
  return guard(() => withPki(async () => {
    const t = applyDdiTrust(await loadPki(), text, cas)
    const hashed = await fillHashes(t.state)
    if (hashed.cas.some((x) => !x.hash)) throw new PkiError('openssl_unavailable')
    const synced = await syncDdiCrls(hashed, cas)
    await savePki(synced.state)
    await audit(c, 'radius.pki.ddi_trust', 'radius', undefined, { ca: ca.name, added: t.added, skipped: t.skipped, names: t.names, crl_loaded: synced.changed, crl_failed: synced.failed, crl_missing: synced.missing })
    return { added: t.added, skipped: t.skipped, crl: { loaded: synced.changed, failed: synced.failed, missing: synced.missing }, view: pkiView(synced.state) }
  })).then(async (r) => ({ ...r, push: r.crl.loaded ? await pushCrlsIfNeeded().catch(() => 'pending' as const) : 'unchanged' as const }))
})

const serverBody = z.object({
  ca: caName, cn: z.string().trim().regex(DN_VALUE_RE), dns: dnsList, ip: ipList, alg: z.enum(['rsa2048', 'rsa3072', 'ecp256']).default('ecp256'),
}).strict().refine((b) => b.dns.length > 0, { path: ['dns'], message: 'san_required' })
route('POST', '/radius/pki/ddi/server', 'admin', async (c) => {
  const b = await c.body(serverBody)
  await chosen(b.ca)
  const { keyPem, csrPem } = await newKeyAndCsr(b.alg, b.cn)
  // émission par la PKI (dépôt de la demande de certificat, attente de root) : hors du verrou de l'état RADIUS, qui ne sert qu'à l'enregistrement
  const x = await issueCert(c, { ca: b.ca, profile: 'server', cn: b.cn, dns: b.dns, ip: b.ip, mail: [], upn: [] }, Buffer.from(csrPem, 'utf8'))
  return guard(() => withPki(async () => {
    const pem = pickServerCert(x.certPem, createPrivateKey(keyPem))
    const info = checkServerCert(pem)
    const s = await loadPki()
    const next: PkiState = { ...s, server: { pem, keyEnc: encryptSecret(keyPem) } }
    delete next.pending
    await savePki(next)
    await audit(c, 'radius.pki.ddi_server', 'radius', x.id, { ca: x.ca, serial: x.serial, subject: info.subject, notAfter: info.notAfter, fingerprint: parseCert(pem).info.fingerprint })
    return { serial: x.serial, view: pkiView(next) }
  }))
})
