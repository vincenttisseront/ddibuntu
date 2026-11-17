// Autorités de la PKI du DDI (0.14.1) : racine de laboratoire, émettrice signée par une racine du DDI ou par une racine hors ligne, import du certificat
// signé, CRL, remise à zéro d'une PKI vide. La console dépose des demandes minuscules et des fichiers PUBLICS (chaîne, certificat, CRL) ; root revalide
// tout et publie la liste des autorités avec leurs fichiers publics (utils/pki-ca.ts). Aucune clé privée n'existe côté console.
import { setResponseHeader } from 'h3'
import { audit, fail, route } from '../utils/router'
import { depositPkiRequest, pkiRequestPending, readPkiStatus } from '../utils/pki'
import type { PkiRequest } from '../utils/pki'
import {
  blobBytes, caName, CA_NAME_RE, dnOf, dropDeposit, EXTROOT_RE, FILES, importBody, issuingBody, putDeposit, readCaFile, readPkiCas, resetBody, rootBody, rootCrlBody,
} from '../utils/pki-ca'
import type { DepositKind, FileKey, PkiCa } from '../utils/pki-ca'
import { loadAd, publicationMap } from '../utils/pki-ad-store'

export const registered = true

/** La PKI doit tourner pour créer ou renouveler quoi que ce soit : root parle à EJBCA par sa ligne de commande. */
async function needHealthy() {
  const st = await readPkiStatus()
  if (!st?.installed) fail(409, 'pki_not_installed')
  if (st.state !== 'healthy') fail(409, 'pki_not_ready')
  return st
}
async function find(name: string): Promise<PkiCa | undefined> { return (await readPkiCas())?.cas.find((c) => c.name === name) }
async function send(c: Parameters<Parameters<typeof route>[3]>[0], req: PkiRequest, detail?: Record<string, unknown>) {
  const r = await depositPkiRequest(req)
  await audit(c, `pki.${req.action}`, 'pki_ca', 'name' in req ? req.name : undefined, detail)
  return { accepted: true, requestedAt: r.requestedAt }
}
/** Refus avant tout dépôt si une demande est déjà en cours (root les traite une à une). */
async function idle() { if (await pkiRequestPending()) fail(409, 'request_pending') }

route('GET', '/pki/cas', 'admin', async () => {
  const [pub, st, ad, pubs] = await Promise.all([readPkiCas(), readPkiStatus(), loadAd(), publicationMap()])
  const cas = (pub?.cas ?? []).map((x) => ({ ...x, publication: pubs[x.name] ?? null }))
  return {
    at: pub?.at ?? null, cas, adEnabled: ad.enabled,
    // racines dont la clé est dans la base du DDI : seules capables de signer une émettrice depuis la console
    signers: cas.filter((x) => x.kind === 'root' && x.state === 'active' && x.managed).map((x) => x.name),
    ready: st?.state === 'healthy', hostname: st?.hostname ?? '', port: st?.port ?? 8080,
  }
})

route('POST', '/pki/cas/root', 'admin', async (c) => {
  const b = await c.body(rootBody)
  await needHealthy(); await idle()
  const all = (await readPkiCas())?.cas ?? []
  if (all.some((x) => x.name.toLowerCase() === b.name.toLowerCase())) fail(409, 'pki_ca_exists')
  const out = await send(c, { action: 'ca_root', name: b.name, alg: b.alg, days: b.days, ...dnOf(b) }, { name: b.name, alg: b.alg, days: b.days, cn: b.cn })
  return out
})

route('POST', '/pki/cas/issuing', 'admin', async (c) => {
  const b = await c.body(issuingBody)
  await needHealthy(); await idle()
  const all = (await readPkiCas())?.cas ?? []
  if (all.some((x) => x.name.toLowerCase() === b.name.toLowerCase())) fail(409, 'pki_ca_exists')
  if (b.signedBy !== 'external') {
    const s = all.find((x) => x.name === b.signedBy)
    if (!s || s.kind !== 'root' || s.state !== 'active') fail(409, 'pki_signer_invalid')
  } else {
    const bytes = blobBytes(b.chain!, 'certs')
    if (!bytes) fail(400, 'pki_bad_file')
    await putDeposit(b.name, 'chain.pem', bytes)
  }
  try {
    return await send(c, { action: 'ca_issuing', name: b.name, alg: b.alg, days: b.days, signedBy: b.signedBy, ...dnOf(b) }, { name: b.name, alg: b.alg, days: b.days, cn: b.cn, signedBy: b.signedBy })
  } catch (e) { await dropDeposit(b.name, 'chain.pem'); throw e }
})

const NAME_PARAM = (v: string | undefined) => { const n = caName.safeParse(v); return n.success ? n.data : null }
async function waitingCa(name: string | undefined) {
  const n = NAME_PARAM(name); if (!n) fail(400, 'invalid_name')
  const ca = await find(n)
  if (!ca) fail(404, 'not_found')
  return ca
}

// Import du certificat que la racine hors ligne a signé : root vérifie qu'il correspond à la demande (même clé publique, même nom, CA:TRUE, signé par la chaîne)
route('POST', '/pki/cas/:name/import', 'admin', async (c) => {
  const ca = await waitingCa(c.params.name)
  const b = await c.body(importBody)
  await needHealthy(); await idle()
  if (ca.state !== 'waiting') fail(409, 'pki_ca_not_waiting')
  const bytes = blobBytes(b.certificate, 'certs'); if (!bytes) fail(400, 'pki_bad_file')
  await putDeposit(ca.name, 'cert.pem', bytes)
  try { return await send(c, { action: 'ca_import', name: ca.name }, { name: ca.name }) } catch (e) { await dropDeposit(ca.name, 'cert.pem'); throw e }
})

// Renouvellement immédiat de la CRL d'une autorité du DDI (le minuteur de root le fait de lui-même quand elle vieillit)
route('POST', '/pki/cas/:name/crl', 'admin', async (c) => {
  const ca = await waitingCa(c.params.name)
  await needHealthy(); await idle()
  if (ca.state !== 'active' || (ca.kind !== 'root' && ca.kind !== 'issuing')) fail(409, 'pki_ca_not_active')
  return send(c, { action: 'ca_crl', name: ca.name }, { name: ca.name })
})

// CRL (publique) de la racine HORS LIGNE, à republier avant son expiration : le DDI la sert avec les siennes, sur la même adresse que celle des certificats
route('POST', '/pki/cas/:name/rootcrl', 'admin', async (c) => {
  const name = c.params.name ?? ''
  if (!EXTROOT_RE.test(name)) fail(400, 'invalid_name')
  const ca = await find(name); if (!ca) fail(404, 'not_found')
  const b = await c.body(rootCrlBody)
  await needHealthy(); await idle()
  const bytes = blobBytes(b.crl, 'crl'); if (!bytes) fail(400, 'pki_bad_file')
  await putDeposit(name, 'crl', bytes)
  try { return await send(c, { action: 'ca_rootcrl', name }, { name }) } catch (e) { await dropDeposit(name, 'crl'); throw e }
})

// Téléchargements : seulement des fichiers publics (certificat, chaîne, demande de certificat à faire signer, CRL en DER)
route('GET', '/pki/cas/:name/:file', 'admin', async (c) => {
  const name = c.params.name ?? '', key = c.params.file as FileKey
  if (!CA_NAME_RE.test(name) || !(key in FILES)) fail(404, 'not_found')
  const data = await readCaFile(name, key)
  if (!data) fail(404, 'not_found')
  const f = FILES[key]
  setResponseHeader(c.event, 'Content-Type', f.type)
  setResponseHeader(c.event, 'Content-Disposition', `attachment; filename="${name}.${f.ext}"`)
  return data
})

// Remise à zéro d'une PKI qui ne contient aucune autorité avec clé (root le revérifie dans la base : jamais de destruction de clés). Permet de changer le nom
// public après une première installation « pour essayer », ou de repartir d'une base abandonnée.
route('POST', '/pki/reset', 'admin', async (c) => {
  const b = await c.body(resetBody)
  const st = await readPkiStatus()
  if (!st || (!st.dataPresent && !st.installed)) fail(409, 'pki_reset_nothing')
  if (!st.resetAllowed) fail(409, 'pki_reset_refused')
  const expected = (st.dataHostname || st.hostname || 'reset').toLowerCase()
  if (b.confirm !== expected) fail(400, 'pki_confirm_mismatch')
  await idle()
  return send(c, { action: 'reset' }, { hostname: st.dataHostname || st.hostname })
})
