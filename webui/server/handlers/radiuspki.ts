// Accès réseau — PKI du service RADIUS (0.13.2, itération 3) : autorités de confiance, certificat et clé du serveur, CRL, vérification à blanc d'un
// certificat client. La console valide pour guider l'administrateur ; root REVALIDE tout avant installation (ddibuntu-radius). Les clés et mots de
// passe ne sont jamais renvoyés ni journalisés ; la clé du serveur est chiffrée au repos et n'est déchiffrée que pour le dépôt vers root.
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { decryptSecret, encryptSecret } from '../utils/auth'
import { lookupAccount } from '../utils/radius-dir'
import { dirComplete, dirPassword, factoryFor, loadDir } from '../utils/radius-dir-store'
import {
  addCas, analyzeCas, asPem, applyCrl, checkClientCert, fillHashes, makeCsr, newKey, normalizeKey, normCrlUrl, parseCert, parseCrl, pickServerCert, PkiError, readiness, readPkcs12, refreshCrl, serverChain,
} from '../utils/radius-pki'
import type { PkiState } from '../utils/radius-pki'
import { loadPki, pushCrlsIfNeeded, savePki, withPki } from '../utils/radius-pki-store'

export const registered = true
const ID = /^[0-9a-f]{8}$/
const B64 = /^[A-Za-z0-9+/=\s]*$/

/** Erreur métier de la PKI → erreur d'API (code `radius_pki_<code>`, traduit par la console). */
async function guard<T>(fn: () => Promise<T>): Promise<T> {
  try { return await fn() }
  catch (e) {
    if (e instanceof PkiError) fail(e.code === 'ca_not_found' ? 404 : e.code.endsWith('unavailable') ? 503 : 400, `radius_pki_${e.code}`, undefined, e.data)
    if ((e as Error)?.message?.startsWith('openssl_')) fail(503, 'radius_pki_openssl')
    throw e
  }
}

/** Vue de l'état pour la console : jamais de clé, jamais le PEM d'une CRL. */
export function pkiView(s: PkiState) {
  const cas = analyzeCas(s)
  let server: any = null
  if (s.server) {
    const { info } = parseCert(s.server.pem), ch = serverChain(s)
    server = { ...info, chainOk: ch?.chainOk ?? false, pem: s.server.pem }
  }
  const p = s.pending
  return { checkCrl: s.checkCrl, cas, server, readiness: readiness(s),
    pending: p ? { cn: p.cn, sans: p.sans, keyType: p.keyType, createdAt: p.createdAt, csrPem: p.csrPem } : null }
}

route('GET', '/radius/pki', 'admin', async () => guard(async () => pkiView(await loadPki())))

route('PUT', '/radius/pki/options', 'admin', async (c) => {
  const b = await c.body(z.object({ checkCrl: z.boolean() }).strict())
  await withPki(async () => { const s = await loadPki(); await savePki({ ...s, checkCrl: b.checkCrl }) })
  await audit(c, 'radius.pki.options', 'radius', undefined, { checkCrl: b.checkCrl })
  return { ok: true }
})

// ---- Autorités de confiance ----
route('POST', '/radius/pki/cas', 'admin', async (c) => {
  const b = await c.body(z.object({ pem: z.string().max(200_000).optional(), dataBase64: z.string().max(700_000).regex(B64).optional(), name: z.string().trim().max(80).optional() }).strict())
  return guard(() => withPki(async () => {
    const r = addCas(await loadPki(), await asPem(b.pem, b.dataBase64), b.name)
    const next = await fillHashes(r.state)
    if (next.cas.some((x) => !x.hash)) throw new PkiError('openssl_unavailable')
    await savePki(next)
    await audit(c, 'radius.pki.ca_add', 'radius', undefined, { added: r.added.length, skipped: r.skipped, subjects: next.cas.filter((x) => r.added.includes(x.id)).map((x) => x.name) })
    return { added: r.added.length, skipped: r.skipped, view: pkiView(next) }
  }))
})
route('PUT', '/radius/pki/cas/:id', 'admin', async (c) => {
  const id = c.params.id!
  if (!ID.test(id)) fail(400, 'invalid_id')
  const b = await c.body(z.object({ name: z.string().trim().min(1).max(80).optional(), crlUrl: z.string().max(300).nullable().optional() }).strict())
  return guard(() => withPki(async () => {
    const s = await loadPki()
    if (!s.cas.some((x) => x.id === id)) throw new PkiError('ca_not_found')
    let url: string | null | undefined
    if (b.crlUrl !== undefined) { url = b.crlUrl === null || b.crlUrl === '' ? null : normCrlUrl(b.crlUrl); if (url === null && b.crlUrl) throw new PkiError('crl_url_invalid') }
    const next = { ...s, cas: s.cas.map((x) => {
      if (x.id !== id) return x
      const y = { ...x }
      if (b.name) y.name = b.name
      if (url !== undefined) { if (url) y.crlUrl = url; else delete y.crlUrl; delete y.crlError }
      return y
    }) }
    await savePki(next)
    await audit(c, 'radius.pki.ca_update', 'radius', id, { name: b.name ?? null, crlUrl: b.crlUrl === undefined ? undefined : url ?? null })
    return { ok: true }
  }))
})
route('DELETE', '/radius/pki/cas/:id', 'admin', async (c) => {
  const id = c.params.id!
  if (!ID.test(id)) fail(400, 'invalid_id')
  return guard(() => withPki(async () => {
    const s = await loadPki(), ca = s.cas.find((x) => x.id === id)
    if (!ca) throw new PkiError('ca_not_found')
    await savePki({ ...s, cas: s.cas.filter((x) => x.id !== id) })
    await audit(c, 'radius.pki.ca_delete', 'radius', id, { name: ca.name })
    return { ok: true }
  }))
})

// ---- CRL ----
route('POST', '/radius/pki/cas/:id/crl', 'admin', async (c) => {
  const id = c.params.id!
  if (!ID.test(id)) fail(400, 'invalid_id')
  const b = await c.body(z.object({ dataBase64: z.string().max(12 * 1024 * 1024).regex(B64) }).strict())
  return guard(() => withPki(async () => {
    const s = await loadPki()
    if (!s.cas.some((x) => x.id === id)) throw new PkiError('ca_not_found')
    const parsed = await parseCrl(Buffer.from(b.dataBase64, 'base64'), s)
    if (parsed.caId !== id) throw new PkiError('crl_wrong_issuer')
    const r = applyCrl(s, parsed, 'upload')
    await savePki(r.state)
    await audit(c, 'radius.pki.crl_upload', 'radius', id, { revoked: parsed.revoked, nextUpdate: parsed.nextUpdate, changed: r.changed })
    return { changed: r.changed, revoked: parsed.revoked, nextUpdate: parsed.nextUpdate }
  })).then(async (r) => ({ ...r, push: r.changed ? await pushCrlsIfNeeded().catch(() => 'pending' as const) : 'unchanged' as const }))
})
route('POST', '/radius/pki/cas/:id/crl/refresh', 'admin', async (c) => {
  const id = c.params.id!
  if (!ID.test(id)) fail(400, 'invalid_id')
  return guard(() => withPki(async () => {
    const s = await loadPki()
    if (!s.cas.some((x) => x.id === id)) throw new PkiError('ca_not_found')
    const r = await refreshCrl(s, id)
    await savePki(r.state)
    await audit(c, 'radius.pki.crl_refresh', 'radius', id, { ok: !r.error, changed: r.changed, error: r.error?.code ?? null })
    if (r.error) throw r.error
    const crl = r.state.cas.find((x) => x.id === id)!.crl!
    return { changed: r.changed, revoked: crl.revoked, nextUpdate: crl.nextUpdate }
  })).then(async (r) => ({ ...r, push: r.changed ? await pushCrlsIfNeeded().catch(() => 'pending' as const) : 'unchanged' as const }))
})

// ---- Certificat du serveur ----
const CSR = z.object({ cn: z.string().trim().min(1).max(64), sans: z.array(z.string().trim().min(1).max(253)).max(20), keyType: z.enum(['rsa2048', 'rsa3072', 'ec256']) }).strict()
route('POST', '/radius/pki/server/csr', 'admin', async (c) => {
  const b = await c.body(CSR)
  return guard(() => withPki(async () => {
    const key = await newKey(b.keyType)
    const csrPem = await makeCsr(key, b.cn, b.sans)
    const s = await loadPki()
    await savePki({ ...s, pending: { keyEnc: encryptSecret(key), csrPem, cn: b.cn, sans: b.sans, keyType: b.keyType, createdAt: Date.now() } })
    await audit(c, 'radius.pki.csr', 'radius', undefined, { cn: b.cn, sans: b.sans, keyType: b.keyType })
    return { csrPem }
  }))
})

/** Contrôles communs à un certificat serveur avant de l'accepter. */
function checkServerCert(pem: string) {
  const { info } = parseCert(pem)
  if (info.ca) throw new PkiError('server_is_ca')
  if (info.notAfter <= Date.now()) throw new PkiError('server_expired')
  if (info.ekus && !info.ekus.includes('1.3.6.1.5.5.7.3.1')) throw new PkiError('server_usage')
  return info
}
route('POST', '/radius/pki/server/cert', 'admin', async (c) => {
  const b = await c.body(z.object({ pem: z.string().max(200_000).optional(), dataBase64: z.string().max(700_000).regex(B64).optional() }).strict())
  return guard(() => withPki(async () => {
    const s = await loadPki()
    if (!s.pending) throw new PkiError('no_pending')
    const text = await asPem(b.pem, b.dataBase64)
    const { createPrivateKey } = await import('node:crypto')
    const key = createPrivateKey(decryptSecret(s.pending.keyEnc))
    const pem = pickServerCert(text, key)
    checkServerCert(pem)
    const next: PkiState = { ...s, server: { pem, keyEnc: s.pending.keyEnc } }
    delete next.pending
    await savePki(next)
    const info = parseCert(pem).info
    await audit(c, 'radius.pki.server_cert', 'radius', undefined, { subject: info.subject, notAfter: info.notAfter, fingerprint: info.fingerprint })
    return { view: pkiView(next) }
  }))
})
route('POST', '/radius/pki/server/import', 'admin', async (c) => {
  const b = await c.body(z.object({
    pem: z.string().max(200_000).optional(), certBase64: z.string().max(700_000).regex(B64).optional(), key: z.string().max(30_000).optional(), keyPassword: z.string().max(200).optional(),
    p12Base64: z.string().max(2_000_000).regex(B64).optional(), p12Password: z.string().max(200).optional(),
  }).strict())
  return guard(() => withPki(async () => {
    let certs: string, keyText: string, pass = b.keyPassword
    if (b.p12Base64) {
      const r = await readPkcs12(Buffer.from(b.p12Base64, 'base64'), b.p12Password ?? '')
      certs = r.certs; keyText = r.key; pass = undefined
    } else {
      if ((!b.pem && !b.certBase64) || !b.key) throw new PkiError('import_incomplete')
      certs = await asPem(b.pem, b.certBase64); keyText = b.key
    }
    const { pem: keyPem, key } = await normalizeKey(keyText, pass)
    const pem = pickServerCert(certs, key)
    const info = checkServerCert(pem)
    const s = await loadPki()
    const next: PkiState = { ...s, server: { pem, keyEnc: encryptSecret(keyPem) } }
    delete next.pending
    await savePki(next)
    await audit(c, 'radius.pki.server_import', 'radius', undefined, { subject: info.subject, notAfter: info.notAfter, fingerprint: info.fingerprint, via: b.p12Base64 ? 'pkcs12' : 'pem' })
    return { view: pkiView(next) }
  }))
})
route('DELETE', '/radius/pki/server', 'admin', async (c) => {
  await withPki(async () => { const s = await loadPki(); const n = { ...s }; delete n.server; await savePki(n) })
  await audit(c, 'radius.pki.server_delete', 'radius')
  return { ok: true }
})
route('DELETE', '/radius/pki/server/pending', 'admin', async (c) => {
  await withPki(async () => { const s = await loadPki(); const n = { ...s }; delete n.pending; await savePki(n) })
  await audit(c, 'radius.pki.csr_delete', 'radius')
  return { ok: true }
})

// ---- Vérification à blanc d'un certificat client ----
// Rien n'est déployé : la chaîne et la révocation sont jugées avec les autorités et CRL ENREGISTRÉES ; si l'annuaire est configuré, le compte est cherché
// (UPN → utilisateur, nom DNS → machine) pour montrer son état et ses groupes. Aucune connexion, aucun compte créé.
route('POST', '/radius/pki/check-client', 'admin', async (c) => {
  const b = await c.body(z.object({ pem: z.string().max(200_000).optional(), dataBase64: z.string().max(700_000).regex(B64).optional(), directory: z.boolean().optional() }).strict())
  return guard(async () => {
    const s = await loadPki()
    const r = await checkClientCert(s, await asPem(b.pem, b.dataBase64))
    let account: any = null
    if (b.directory) {
      const d = await loadDir()
      if (!dirComplete(d)) account = { checked: false, reason: 'radius_dir_incomplete' }
      else {
        const name = r.identity.upn ?? r.identity.dns[0] ?? null
        if (!name) account = { checked: false, reason: 'no_identity' }
        else {
          const kind = r.identity.upn ? 'user' : 'computer'
          const l = await lookupAccount(d, dirPassword(d), factoryFor(d), kind, name)
          account = l.ok ? { checked: true, kind, name, server: l.server, ...l.value } : { checked: false, reason: `radius_dir_${l.reason === 'service_bind' ? 'bind' : l.reason}` }
        }
      }
    }
    await audit(c, 'radius.pki.check_client', 'radius', undefined, { ok: r.ok, code: r.chain.code, revocation: r.revocation, serial: r.identity.serial, directory: !!b.directory })
    return { ...r, account }
  })
})
