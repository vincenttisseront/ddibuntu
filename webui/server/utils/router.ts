// Routeur d'API : un seul point d'entrée (server/api/[...slug].ts) qui centralise authentification,
// contrôle d'origine, CSRF, rôles, validation (zod), audit et assainissement des erreurs.
import { createError, deleteCookie, getCookie, getMethod, getQuery, getRequestHeader, getRequestIP, getRequestURL, readBody, setCookie, setResponseHeader } from 'h3'
import type { H3Event } from 'h3'
import type { ZodType } from 'zod'
import { cfg } from './config'
import { inRecovery, isSchemaReady, query } from './db'
import { ROLE_RANK, safeEqual, sessionFromToken } from './auth'
import { userFromApiToken } from './api-tokens'
import type { Role, SessionUser } from './auth'

export const COOKIE = 'ddi_session'
// Seules requêtes d'écriture admises sur un secondaire : ouvrir/fermer une session (jeton signé, rien n'est écrit en base ; voir utils/auth.ts)
const REPLICA_WRITABLE = new Set(['/auth/login', '/auth/login/mfa', '/auth/logout'])
export interface Ctx {
  event: H3Event
  params: Record<string, string>
  query: Record<string, any>
  user: SessionUser | null
  ip: string | null
  body<T>(schema: ZodType<T, any, any>): Promise<T>
}
type Handler = (c: Ctx) => Promise<unknown>
interface Entry { method: string; re: RegExp; keys: string[]; role: Role | 'public'; handler: Handler; path: string }
const table: Entry[] = []

export function route(method: string, path: string, role: Role | 'public', handler: Handler) {
  const keys: string[] = []
  const re = new RegExp('^' + path.replace(/:([a-z]+)/gi, (_m, k) => { keys.push(k); return '([^/]+)' }) + '/?$')
  table.push({ method, re, keys, role, handler, path })
}
export const routeCount = () => table.length
export const routeTable = () => table.map((e) => ({ method: e.method, path: e.path, role: e.role }))

export function fail(status: number, code: string, message?: string, data?: Record<string, unknown>): never {
  throw createError({ statusCode: status, statusMessage: code, message: message ?? code, data: { code, ...data } })
}
export function intParam(c: Ctx, key: string): number {
  const v = c.params[key]
  if (!v || !/^\d{1,9}$/.test(v)) fail(400, 'invalid_id')
  return Number(v)
}
export function qint(c: Ctx, key: string, def: number, min = 0, max = 1_000_000): number {
  const v = c.query[key]
  if (v === undefined || v === '') return def
  if (typeof v !== 'string' || !/^\d{1,9}$/.test(v)) fail(400, 'invalid_query')
  return Math.min(max, Math.max(min, Number(v)))
}
export function qstr(c: Ctx, key: string, max = 200): string | undefined {
  const v = c.query[key]
  if (v === undefined || v === '') return undefined
  if (typeof v !== 'string' || v.length > max || v.includes('\0')) fail(400, 'invalid_query')
  return v
}

export async function audit(c: Ctx, action: string, entity?: string, entityId?: string | number, detail?: unknown) {
  // secondaire (lecture seule) : la trace va au journal du service (le primaire garde le journal d'audit réparti)
  if (await inRecovery().catch(() => false)) { console.warn(`[audit-replica] ${action} ${entity ?? ''} ${entityId ?? ''} user=${c.user?.username ?? '-'} ip=${c.ip ?? '-'}`); return }
  await query('insert into audit_log (user_id, username, action, entity, entity_id, detail, ip) values ($1,$2,$3,$4,$5,$6::jsonb,$7)',
    [c.user?.id ?? null, c.user?.username ?? null, action, entity ?? null, entityId === undefined ? null : String(entityId),
     detail === undefined ? null : JSON.stringify(detail), c.ip])
}

const PG_MESSAGES: Record<string, [number, string]> = {
  '23505': [409, 'duplicate'], '23503': [409, 'in_use'], '23514': [400, 'constraint'], '23502': [400, 'missing_field'],
  '22P02': [400, 'invalid_input'], '22007': [400, 'invalid_input'], '22003': [400, 'invalid_input'], '22023': [400, 'invalid_input'],
  '25006': [503, 'replica'],
  '22021': [400, 'invalid_input'], '22P05': [400, 'invalid_input'], '22001': [400, 'invalid_input'], '22008': [400, 'invalid_input'],
}
const PG_RAISED = new Set(['ip_outside_subnet', 'pool_outside_subnet', 'pool_overlap'])

function sanitize(e: any): never {
  if (e?.statusCode) throw e
  const code: string | undefined = e?.code
  if (code === 'P0001' && PG_RAISED.has(e.message)) fail(400, e.message)
  if (code && PG_MESSAGES[code]) fail(...PG_MESSAGES[code]!)
  // le détail (peut contenir des valeurs) reste dans le journal serveur, jamais dans la réponse
  console.error('[api] erreur interne :', e?.code ?? '', e?.message ?? e)
  fail(500, 'internal')
}

function checkOrigin(event: H3Event) {
  const origin = getRequestHeader(event, 'origin')
  if (!origin) return
  let host: string
  try { host = new URL(origin).host } catch { fail(403, 'bad_origin') }
  const expected = getRequestHeader(event, 'host')
  if (host !== expected) fail(403, 'bad_origin')
}

export function validate<T>(schema: ZodType<T, any, any>, data: unknown): T {
  const r = schema.safeParse(data)
  if (!r.success) {
    const issues = r.error.issues.slice(0, 10).map((i) => ({ path: i.path.join('.'), message: i.message }))
    fail(400, 'validation', 'validation', { issues })
  }
  return r.data
}

export async function dispatch(event: H3Event): Promise<unknown> {
  const method = getMethod(event).toUpperCase()
  const path = getRequestURL(event).pathname.replace(/^\/api/, '') || '/'
  const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method)
  setResponseHeader(event, 'Cache-Control', 'no-store')
  try {
    let entry: Entry | undefined
    let params: Record<string, string> = {}
    for (const e of table) {
      if (e.method !== method) continue
      const m = e.re.exec(path)
      if (m) { entry = e; params = Object.fromEntries(e.keys.map((k, i) => [k, decodeURIComponent(m[i + 1]!)])); break }
    }
    if (!entry) {
      if (table.some((e) => e.re.test(path))) fail(405, 'method_not_allowed')
      fail(404, 'not_found')
    }
    if (!isSchemaReady() && !['/health', '/cluster/role'].includes(path)) fail(503, 'schema_pending')   // secondaire en attente des migrations du leader
    if (unsafe) {
      // nœud secondaire du cluster : aucune écriture (ni déploiement de fichiers) ; les modifications se font sur le leader / l'adresse de service
      if (!REPLICA_WRITABLE.has(path) && await inRecovery()) fail(503, 'replica')
      checkOrigin(event)
      const len = Number(getRequestHeader(event, 'content-length') ?? 0)
      if (len > cfg().maxBodyBytes) fail(413, 'too_large')
    }
    const ip = getRequestIP(event) ?? null
    let user: SessionUser | null = null
    const token = getCookie(event, COOKIE)
    if (token) user = await sessionFromToken(token)
    // jeton d'API : « Authorization: Bearer ddi_… » (sans cookie, donc sans CSRF) ; limité à viewer/operator, jamais aux routes d'administration
    const bearer = !user ? /^Bearer (ddi_[A-Za-z0-9_-]{20,80})$/.exec(getRequestHeader(event, 'authorization') ?? '')?.[1] : undefined
    if (bearer) {
      user = await userFromApiToken(bearer)
      if (!user) fail(401, 'invalid_token')
    }
    if (entry.role !== 'public') {
      if (!user) fail(401, 'unauthenticated')
      if (unsafe && user.source !== 'token') {
        const sent = getRequestHeader(event, 'x-csrf-token') ?? ''
        if (!safeEqual(sent, user.csrf)) fail(403, 'csrf')
      }
      if (user.source === 'token' && path.startsWith('/auth/') && path !== '/auth/me') fail(403, 'forbidden')   // mot de passe, sessions… : réservés aux comptes
      if (ROLE_RANK[user.role] < ROLE_RANK[entry.role]) fail(403, 'forbidden')
      // délégation : un opérateur restreint à des espaces IPAM n'écrit que dans l'IPAM (les routes /ipam/ vérifient l'espace elles-mêmes)
      if (unsafe && user.spaceIds && ROLE_RANK[entry.role] >= ROLE_RANK.operator && !path.startsWith('/ipam/')) fail(403, 'out_of_scope')
    }
    const ctx: Ctx = {
      event, params, user, ip,
      query: getQuery(event) as Record<string, any>,
      body: async (schema) => validate(schema, await readBody(event)),
    }
    return await entry.handler(ctx)
  } catch (e) {
    sanitize(e)
  }
}

export function setSessionCookie(event: H3Event, token: string, maxAge: number) {
  setCookie(event, COOKIE, token, { httpOnly: true, secure: cfg().cookieSecure, sameSite: 'lax', path: '/', maxAge })
}
export function clearSessionCookie(event: H3Event) {
  deleteCookie(event, COOKIE, { httpOnly: true, secure: cfg().cookieSecure, sameSite: 'lax', path: '/' })
}
