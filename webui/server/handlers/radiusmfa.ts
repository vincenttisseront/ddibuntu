// Second facteur (0.17.0) — réglages du fournisseur MFA (administrateur) et test de joignabilité. Le fournisseur est générique : le premier type pris en charge est l'OAuth2
// « mot de passe » (point de jeton, champs configurables). Le secret client est chiffré et n'est jamais renvoyé ; seul « clientSecretSet » dit s'il existe.
// Le test n'envoie aucun compte réel : il tape à la porte du point de jeton avec des identifiants fictifs et lit comment le fournisseur répond.
import { request } from 'node:https'
import { audit, route } from '../utils/router'
import { loadMfa, MFA_KEY, mfaBody, mfaConfigured, mfaDigestPart, publicMfa, saveMfa, sealMfaSecret, mfaSecret } from '../utils/radius-mfa'
import type { MfaSettings } from '../utils/radius-mfa'
import { loadMfaInput } from '../utils/radius-mfa-store'

export const registered = true

route('GET', '/radius/mfa', 'admin', async () => ({ ...publicMfa(await loadMfa()), clients: (await loadMfaInput()).clients }))

route('PUT', '/radius/mfa', 'admin', async (c) => {
  const b = await c.body(mfaBody)
  const cur = await loadMfa()
  const { clientSecret, ...rest } = b
  // secret : absent = on garde l'actuel ; chaîne vide = client public (aucun secret) ; sinon nouveau secret, chiffré
  const clientSecretEnc = clientSecret === undefined || clientSecret === null ? cur.clientSecretEnc : sealMfaSecret(clientSecret)
  const next: MfaSettings = { ...rest, clientSecretEnc, caPem: rest.caPem.trim() ? rest.caPem.trim() + '\n' : '' }
  await saveMfa(next)
  await audit(c, 'radius_mfa', 'settings', MFA_KEY, { type: next.type, tokenUrl: next.tokenUrl, clientId: next.clientId, secretChanged: clientSecret !== undefined && clientSecret !== null,
    identity: next.identity, otpDigits: next.otpDigits, tlsVerify: next.tlsVerify, changed: JSON.stringify(mfaDigestPart(cur)) !== JSON.stringify(mfaDigestPart(next)) })
  return { ok: true }
})

export interface MfaProbe { ok: boolean; reason: 'reachable' | 'client_rejected' | 'not_found' | 'server_error' | 'tls' | 'timeout' | 'unreachable' | 'not_configured'; status?: number; ms: number }
/** Une requête de jeton avec des identifiants fictifs : ce qui compte, c'est que le fournisseur réponde (HTTPS valide) et reconnaisse ou non le client. */
export function probeMfa(m: MfaSettings): Promise<MfaProbe> {
  const t0 = Date.now()
  const done = (reason: MfaProbe['reason'], ok: boolean, status?: number): MfaProbe => ({ ok, reason, ...(status !== undefined ? { status } : {}), ms: Date.now() - t0 })
  if (!mfaConfigured(m)) return Promise.resolve(done('not_configured', false))
  const u = new URL(m.tokenUrl)
  const f = m.fields
  const body = new URLSearchParams({ grant_type: 'password', client_id: m.clientId, ...(mfaSecret(m) ? { client_secret: mfaSecret(m) } : {}), [f.identity]: 'ddi-probe', [f.password]: 'ddi-probe', [f.otp]: '0'.repeat(m.otpDigits) })
  for (const e of m.extra) body.set(e.name, e.value)
  const payload = body.toString()
  return new Promise((resolve) => {
    const req = request({ hostname: u.hostname, port: u.port || 443, path: u.pathname, method: 'POST', timeout: m.timeoutSec * 1000, rejectUnauthorized: m.tlsVerify, ...(m.caPem.trim() ? { ca: m.caPem } : {}),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(payload) } }, (res) => {
      const chunks: Buffer[] = []; let n = 0
      res.on('data', (d: Buffer) => { n += d.length; if (n < 8192) chunks.push(d) })
      res.on('end', () => {
        const st = res.statusCode ?? 0
        let err = ''
        try { err = String(JSON.parse(Buffer.concat(chunks).toString('utf8')).error ?? '') } catch { /* réponse non JSON */ }
        if (st === 404) return resolve(done('not_found', false, st))
        if (st >= 500) return resolve(done('server_error', false, st))   // un fournisseur qui répond par une erreur serveur n'est pas « joignable » au sens utile
        // un fournisseur qui ne reconnaît pas le client le dit : on le distingue d'un simple « utilisateur inconnu » (attendu ici)
        if (err === 'invalid_client' || err === 'unauthorized_client') return resolve(done('client_rejected', false, st))
        resolve(done('reachable', true, st))
      })
    })
    req.on('timeout', () => { req.destroy(); resolve(done('timeout', false)) })
    req.on('error', (e: NodeJS.ErrnoException) => resolve(done(/CERT|SELF_SIGNED|certificate|hostname|altnames/i.test(`${e.code ?? ''} ${e.message}`) ? 'tls' : 'unreachable', false)))
    req.end(payload)
  })
}

route('POST', '/radius/mfa/test', 'admin', async (c) => {
  const r = await probeMfa(await loadMfa())
  await audit(c, 'radius.mfa_test', 'radius', undefined, { ok: r.ok, reason: r.reason, status: r.status ?? null, ms: r.ms })
  return r
})
