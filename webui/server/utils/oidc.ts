// SSO OpenID Connect (authorization code + PKCE S256) : découverte, échange du code, validation de l'id_token (signature JWKS, émetteur, audience, nonce, expiration)
// et correspondance « groupes de l'IdP → rôle (+ périmètre IPAM) ».
import { createHash, randomBytes } from 'node:crypto'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { delegatedSpaces } from './ad'
import type { Role } from './auth'
import { trimTrailingSlashes } from './text'

export interface OidcSettings {
  enabled: boolean; issuer: string; clientId: string; clientSecretEnc?: string; publicUrl: string
  scopes: string; usernameClaim: string; groupsClaim: string
  groupMap: Array<{ group: string; role: Role; spaceIds?: number[] }>
  defaultRole: Role | null; buttonLabel: string
}
export const OIDC_DEFAULTS: OidcSettings = {
  enabled: false, issuer: '', clientId: '', publicUrl: '', scopes: 'openid profile email', usernameClaim: 'preferred_username', groupsClaim: 'groups', groupMap: [], defaultRole: null, buttonLabel: '',
}
const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 }
const allowHttp = () => process.env.DDI_OIDC_ALLOW_HTTP === '1'    // tests uniquement : un IdP en clair n'a pas sa place en production

export const newPkce = () => { const verifier = randomBytes(32).toString('base64url'); return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') } }
export const randomToken = (n = 24) => randomBytes(n).toString('base64url')

export interface Discovery { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string; userinfo_endpoint?: string }
const dcache = new Map<string, { at: number; d: Discovery }>()
const okUrl = (u: unknown): u is string => { try { const x = new URL(String(u)); return x.protocol === 'https:' || (allowHttp() && x.protocol === 'http:') } catch { return false } }

export async function discover(issuer: string, fetcher: typeof fetch = fetch): Promise<Discovery> {
  const key = trimTrailingSlashes(issuer)
  const hit = dcache.get(key); if (hit && Date.now() - hit.at < 600_000) return hit.d
  if (!okUrl(key)) throw new Error('issuer_invalid')
  const r = await fetcher(`${key}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(8000), headers: { accept: 'application/json' } })
  if (!r.ok) throw new Error('discovery_failed')
  const d = await r.json() as Discovery
  if (trimTrailingSlashes(String(d.issuer ?? '')) !== key) throw new Error('issuer_mismatch')           // l'émetteur annoncé doit être celui demandé
  for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) if (!okUrl(d[k])) throw new Error('discovery_invalid')
  if (d.userinfo_endpoint !== undefined && !okUrl(d.userinfo_endpoint)) delete d.userinfo_endpoint
  dcache.set(key, { at: Date.now(), d }); return d
}
export const clearDiscoveryCache = () => dcache.clear()

const jwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>()
export async function verifyIdToken(idToken: string, d: Discovery, clientId: string, nonce: string): Promise<Record<string, unknown>> {
  let set = jwks.get(d.jwks_uri); if (!set) { set = createRemoteJWKSet(new URL(d.jwks_uri), { timeoutDuration: 8000, cooldownDuration: 30_000 }); jwks.set(d.jwks_uri, set) }
  const { payload } = await jwtVerify(idToken, set, { issuer: d.issuer, audience: clientId, algorithms: ['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'ES384'], clockTolerance: 60 })
  if (payload.nonce !== nonce) throw new Error('nonce_mismatch')
  return payload as Record<string, unknown>
}

export async function exchangeCode(d: Discovery, s: { clientId: string; clientSecret: string }, p: { code: string; redirectUri: string; verifier: string }): Promise<{ id_token: string; access_token?: string }> {
  const body = new URLSearchParams({ grant_type: 'authorization_code', code: p.code, redirect_uri: p.redirectUri, code_verifier: p.verifier, client_id: s.clientId })
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }
  if (s.clientSecret) headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(s.clientId)}:${encodeURIComponent(s.clientSecret)}`).toString('base64')}`
  const r = await fetch(d.token_endpoint, { method: 'POST', headers, body, signal: AbortSignal.timeout(10000) })
  if (!r.ok) throw new Error('token_exchange_failed')
  const j = await r.json() as any
  if (typeof j.id_token !== 'string') throw new Error('no_id_token')
  return j
}
export async function fetchUserinfo(d: Discovery, accessToken: string): Promise<Record<string, unknown>> {
  if (!d.userinfo_endpoint) return {}
  const r = await fetch(d.userinfo_endpoint, { headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' }, signal: AbortSignal.timeout(8000) })
  return r.ok ? await r.json() as Record<string, unknown> : {}
}

const asList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : typeof v === 'string' ? v.split(/[,\s]+/).filter(Boolean) : []) as string[]
export const claimGroups = (claims: Record<string, unknown>, claim: string): string[] => asList(claims[claim])

export type OidcMapped = { ok: true; username: string; displayName: string | null; role: Role; spaceIds: number[] | null } | { ok: false; reason: 'no_username' | 'no_group' }
export function mapClaims(s: Pick<OidcSettings, 'usernameClaim' | 'groupsClaim' | 'groupMap' | 'defaultRole'>, claims: Record<string, unknown>): OidcMapped {
  const raw = [claims[s.usernameClaim], claims.email, claims.sub].find((v) => typeof v === 'string' && v.trim())
  const username = typeof raw === 'string' ? raw.trim().replace(/[^A-Za-z0-9._@-]/g, '_').slice(0, 64) : ''
  if (!username) return { ok: false, reason: 'no_username' }
  const have = new Set(claimGroups(claims, s.groupsClaim).map((g) => g.toLowerCase()))
  const matched = s.groupMap.filter((m) => have.has(m.group.toLowerCase()))
  let role: Role | null = null
  for (const m of matched) if (!role || RANK[m.role] > RANK[role]) role = m.role
  let spaceIds: number[] | null = null
  if (role) spaceIds = delegatedSpaces(role, matched.filter((m) => m.role === role))
  else if (s.defaultRole) role = s.defaultRole
  if (!role) return { ok: false, reason: 'no_group' }
  const name = [claims.name, claims.preferred_username, claims.email].find((v) => typeof v === 'string' && v.trim())
  return { ok: true, username, displayName: typeof name === 'string' ? name.slice(0, 100) : null, role, spaceIds }
}
