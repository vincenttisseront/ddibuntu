// SSO OpenID Connect : configuration (administrateur), démarrage et retour de connexion.
// Tout l'état d'une tentative (state, nonce, vérificateur PKCE) tient dans un cookie chiffré de 10 minutes : sans base de données, donc utilisable sur tout nœud.
import { z } from 'zod'
import { getCookie, getQuery, getRequestURL, sendRedirect, setCookie, deleteCookie } from 'h3'
import { audit, fail, route, setSessionCookie } from '../utils/router'
import { getSetting, inRecovery, one, query, setSetting } from '../utils/db'
import { cfg } from '../utils/config'
import { trimTrailingSlashes } from '../utils/text'
import { createSession, decryptSecret, encryptSecret, safeEqual } from '../utils/auth'
import { sessionSettings } from '../utils/session-settings'
import { OIDC_DEFAULTS, discover, exchangeCode, fetchUserinfo, mapClaims, newPkce, randomToken, verifyIdToken, clearDiscoveryCache } from '../utils/oidc'
import type { OidcSettings } from '../utils/oidc'

export const registered = true
const CK = 'ddi_oidc', CK_PATH = '/api/auth/oidc'

const body = z.object({
  enabled: z.boolean(), issuer: z.string().trim().max(300), clientId: z.string().trim().max(200), clientSecret: z.string().max(500).optional(), clearSecret: z.boolean().optional(),
  publicUrl: z.string().trim().max(200).regex(/^(?:https?:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?)?$/, 'url'), scopes: z.string().trim().min(1).max(200).regex(/^[\w.:/ -]+$/), usernameClaim: z.string().trim().min(1).max(60), groupsClaim: z.string().trim().min(1).max(60),
  groupMap: z.array(z.object({ group: z.string().trim().min(1).max(300), role: z.enum(['admin', 'operator', 'viewer']), spaceIds: z.array(z.number().int().positive()).max(50).optional() })).max(50),
  defaultRole: z.enum(['operator', 'viewer']).nullable(), buttonLabel: z.string().trim().max(60),
})
const redirectBase = (s: OidcSettings, c: any) => trimTrailingSlashes(s.publicUrl || getRequestURL(c.event).origin)
const callbackUrl = (s: OidcSettings, c: any) => `${redirectBase(s, c)}/api/auth/oidc/callback`
const fin = (c: any, code: string) => sendRedirect(c.event, `/login?sso_error=${encodeURIComponent(code)}`, 302)

route('GET', '/sso/settings', 'admin', async (c) => {
  const { clientSecretEnc, ...s } = await getSetting<OidcSettings>('oidc', OIDC_DEFAULTS)
  return { ...OIDC_DEFAULTS, ...s, clientSecretSet: !!clientSecretEnc, callbackUrl: callbackUrl({ ...OIDC_DEFAULTS, ...s }, c) }
})
route('PUT', '/sso/settings', 'admin', async (c) => {
  const b = await c.body(body)
  if (b.enabled && (!b.issuer || !b.clientId)) fail(400, 'sso_incomplete')
  if (b.enabled && !/^https:\/\//.test(b.issuer) && process.env.DDI_OIDC_ALLOW_HTTP !== '1') fail(400, 'sso_https')
  if (b.enabled && !b.groupMap.length && !b.defaultRole) fail(400, 'sso_no_mapping')
  const cur = await getSetting<OidcSettings>('oidc', OIDC_DEFAULTS)
  const { clientSecret, clearSecret, ...rest } = b
  await setSetting('oidc', { ...cur, ...rest, clientSecretEnc: clientSecret ? encryptSecret(clientSecret) : clearSecret ? undefined : cur.clientSecretEnc })
  clearDiscoveryCache()
  await audit(c, 'sso_settings', 'settings', 'oidc', { enabled: b.enabled, issuer: b.issuer, secretChanged: !!clientSecret })
  return { ok: true }
})
route('POST', '/sso/test', 'admin', async () => {
  const s = await getSetting<OidcSettings>('oidc', OIDC_DEFAULTS)
  if (!s.issuer) fail(400, 'sso_incomplete')
  clearDiscoveryCache()
  try {
    const d = await discover(s.issuer)
    const j = await fetch(d.jwks_uri, { signal: AbortSignal.timeout(8000) }).then((r) => r.json()).catch(() => null) as any
    return { ok: true, issuer: d.issuer, authorization_endpoint: d.authorization_endpoint, token_endpoint: d.token_endpoint, userinfo: !!d.userinfo_endpoint, keys: Array.isArray(j?.keys) ? j.keys.length : 0 }
  } catch (e: any) { fail(400, 'sso_discovery', String(e?.message ?? e).slice(0, 200)) }
})

route('GET', '/auth/oidc/start', 'public', async (c) => {
  const s = await getSetting<OidcSettings>('oidc', OIDC_DEFAULTS)
  if (!s.enabled) return fin(c, 'disabled')
  let d; try { d = await discover(s.issuer) } catch { return fin(c, 'discovery') }
  const st = randomToken(), nonce = randomToken(), { verifier, challenge } = newPkce()
  setCookie(c.event, CK, encryptSecret(JSON.stringify({ st, nonce, verifier, exp: Date.now() + 600_000 })), { httpOnly: true, secure: cfg().cookieSecure, sameSite: 'lax', path: CK_PATH, maxAge: 600 })
  const u = new URL(d.authorization_endpoint)
  for (const [k, v] of Object.entries({ response_type: 'code', client_id: s.clientId, redirect_uri: callbackUrl(s, c), scope: s.scopes, state: st, nonce, code_challenge: challenge, code_challenge_method: 'S256' })) u.searchParams.set(k, v)
  return sendRedirect(c.event, u.toString(), 302)
})

route('GET', '/auth/oidc/callback', 'public', async (c) => {
  const s = await getSetting<OidcSettings>('oidc', OIDC_DEFAULTS)
  const q = getQuery(c.event)
  const raw = getCookie(c.event, CK); deleteCookie(c.event, CK, { path: CK_PATH })
  const bad = async (reason: string, extra: Record<string, unknown> = {}) => { await audit(c, 'login_failed', 'user', undefined, { sso: true, reason, ...extra }); return fin(c, reason) }
  if (!s.enabled) return fin(c, 'disabled')
  if (q.error) return bad('idp_error', { idp: String(q.error).slice(0, 60) })
  let ck: any; try { ck = JSON.parse(decryptSecret(raw ?? '')) } catch { return bad('state') }
  if (!ck || ck.exp < Date.now() || typeof q.state !== 'string' || !safeEqual(q.state, String(ck.st)) || typeof q.code !== 'string') return bad('state')
  let claims: Record<string, unknown>
  try {
    const d = await discover(s.issuer)
    const tok = await exchangeCode(d, { clientId: s.clientId, clientSecret: s.clientSecretEnc ? decryptSecret(s.clientSecretEnc) : '' }, { code: q.code, redirectUri: callbackUrl(s, c), verifier: ck.verifier })
    claims = await verifyIdToken(tok.id_token, d, s.clientId, ck.nonce)
    if (claims[s.groupsClaim] === undefined && tok.access_token) claims = { ...(await fetchUserinfo(d, tok.access_token).catch(() => ({}))), ...claims }   // groupes absents du jeton : userinfo
  } catch (e: any) { return bad('token', { detail: String(e?.code ?? e?.message ?? e).slice(0, 80) }) }
  const m = mapClaims(s, claims)
  if (!m.ok) return bad(m.reason)
  if (await inRecovery()) return bad('primary_only')            // un secondaire ne peut pas créer de compte ni de session : passer par l'adresse de service
  const ex = await one<any>('select id, source, disabled from users where lower(username) = lower($1)', [m.username])
  if (ex && ex.source !== 'oidc') return bad('conflict', { username: m.username })     // jamais de reprise d'un compte local ou AD portant le même nom
  if (ex?.disabled) return bad('disabled_user', { username: m.username })
  const r = await one<any>(
    `insert into users (username, display_name, role, source, space_ids, last_login) values ($1, $2, $3, 'oidc', $4, now())
     on conflict (lower(username)) do update set role = excluded.role, display_name = excluded.display_name, space_ids = excluded.space_ids, last_login = now() returning id`,
    [m.username, m.displayName, m.role, m.spaceIds])
  const ses = await createSession(r.id, c.ip, null)
  setSessionCookie(c.event, ses.token, ses.maxAge)
  await audit(c, 'login', 'user', r.id, { sso: 'oidc' })
  return sendRedirect(c.event, '/', 302)
})
