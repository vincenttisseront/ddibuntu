import { z } from 'zod'
import { audit, clearSessionCookie, fail, route, setSessionCookie, COOKIE } from '../utils/router'
import { one, query, tx, getSetting, isSchemaReady, inRecovery } from '../utils/db'
import { cfg } from '../utils/config'
import { createSession, destroySession, destroyUserSessions, dummyVerify, hashPassword, loginBlocked, passwordPolicyError, recordAttempt, safeEqual, verifyPassword, decryptSecret } from '../utils/auth'
import { AD_DEFAULTS, authenticateAd, defaultLdapFactory } from '../utils/ad'
import type { AdSettings } from '../utils/ad'
import { getCookie, getRequestHeader } from 'h3'

const username = z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9._@-]+$/)
const role = z.enum(['admin', 'operator', 'viewer'])

// Un secondaire dont la console vient d'être mise à jour attend que le leader applique les migrations : le processus est sain (la mise à jour en ligne
// ne doit pas faire de retour arrière), mais l'API répond « schema_pending » tant que le schéma n'est pas au niveau.
route('GET', '/health', 'public', async () => {
  if (isSchemaReady()) return { status: 'ok' }
  if (await inRecovery().catch(() => false)) return { status: 'waiting_leader' }
  fail(503, 'starting')
})

route('GET', '/auth/me', 'public', async (c) => (c.user ? { user: { id: c.user.id, username: c.user.username, role: c.user.role, source: c.user.source, displayName: c.user.displayName }, csrf: c.user.csrf } : { user: null }))

route('POST', '/auth/login', 'public', async (c) => {
  const b = await c.body(z.object({ username: z.string().min(1).max(256), password: z.string().min(1).max(512) }))
  if (await loginBlocked(b.username, c.ip)) fail(429, 'too_many_attempts')
  const u = await one<any>('select * from users where lower(username) = lower($1)', [b.username])
  let userId: number | null = null
  if (u && !u.disabled && u.source === 'local') {
    if (await verifyPassword(b.password, u.password_hash)) userId = u.id
  } else if (!u) {
    // compte inconnu localement : tentative Active Directory si activé
    const ad = await getSetting<AdSettings>('ad', AD_DEFAULTS)
    if (ad.enabled) {
      const res = await authenticateAd(b.username, b.password, ad, ad.bindPasswordEnc ? decryptSecret(ad.bindPasswordEnc) : '', defaultLdapFactory(ad))
      if (res.ok) {
        const r = await one<any>(
          `insert into users (username, display_name, role, source) values ($1, $2, $3, 'ad')
           on conflict (lower(username)) do update set role = excluded.role, display_name = excluded.display_name returning id`,
          [res.username, res.displayName, res.role])
        userId = r.id
      }
    } else await dummyVerify(b.password)
  } else if (u.source === 'ad' && !u.disabled) {
    const ad = await getSetting<AdSettings>('ad', AD_DEFAULTS)
    const res = await authenticateAd(b.username, b.password, ad, ad.bindPasswordEnc ? decryptSecret(ad.bindPasswordEnc) : '', defaultLdapFactory(ad))
    if (res.ok) { await query('update users set role = $2, display_name = $3 where id = $1', [u.id, res.role, res.displayName]); userId = u.id }
  } else await dummyVerify(b.password)
  await recordAttempt(b.username, c.ip, userId !== null)
  if (userId === null) { await audit(c, 'login_failed', 'user', undefined, { username: b.username.slice(0, 64) }); fail(401, 'bad_credentials') }
  await query('update users set last_login = now() where id = $1', [userId])
  const s = await createSession(userId, c.ip, getRequestHeader(c.event, 'user-agent') ?? null)
  setSessionCookie(c.event, s.token, s.maxAge)
  const me = await one<any>('select id, username, role, source, display_name from users where id = $1', [userId])
  c.user = { id: me.id, username: me.username, role: me.role, source: me.source, displayName: me.display_name, csrf: s.csrf, sessionId: 0 }
  await audit(c, 'login', 'user', userId)
  return { user: { id: me.id, username: me.username, role: me.role, source: me.source, displayName: me.display_name }, csrf: s.csrf }
})

route('POST', '/auth/logout', 'viewer', async (c) => {
  const t = getCookie(c.event, COOKIE)
  if (t) await destroySession(t)
  clearSessionCookie(c.event)
  await audit(c, 'logout', 'user', c.user!.id)
  return { ok: true }
})

route('POST', '/auth/password', 'viewer', async (c) => {
  const b = await c.body(z.object({ current: z.string().min(1).max(512), next: z.string().min(1).max(512) }))
  const u = await one<any>('select * from users where id = $1', [c.user!.id])
  if (!u || u.source !== 'local') fail(400, 'not_local_user')
  if (!(await verifyPassword(b.current, u.password_hash))) fail(403, 'bad_credentials')
  const pe = passwordPolicyError(b.next, u.username)
  if (pe) fail(400, pe)
  await query('update users set password_hash = $2 where id = $1', [u.id, await hashPassword(b.next)])
  await query('delete from sessions where user_id = $1 and id <> $2', [u.id, c.user!.sessionId])
  await audit(c, 'password_changed', 'user', u.id)
  return { ok: true }
})

// Première configuration : seulement tant qu'aucun utilisateur n'existe, et avec le jeton d'installation
route('POST', '/setup/admin', 'public', async (c) => {
  const b = await c.body(z.object({ token: z.string().min(1).max(200), username, password: z.string().min(1).max(512) }))
  const expected = cfg().setupToken
  if (!expected) fail(404, 'not_found')
  if (await loginBlocked('setup', c.ip)) fail(429, 'too_many_attempts')
  const n = await one<{ n: string }>('select count(*) n from users')
  if (Number(n?.n ?? 0) > 0) fail(409, 'already_configured')
  if (!safeEqual(b.token, expected)) { await recordAttempt('setup', c.ip, false); fail(403, 'bad_setup_token') }
  const pe = passwordPolicyError(b.password, b.username)
  if (pe) fail(400, pe)
  const r = await one<any>("insert into users (username, role, source, password_hash) values ($1, 'admin', 'local', $2) returning id", [b.username, await hashPassword(b.password)])
  c.user = { id: r.id, username: b.username, role: 'admin', source: 'local', displayName: null, csrf: '', sessionId: 0 }
  await audit(c, 'setup_admin', 'user', r.id)
  return { ok: true }
})

// ---- Utilisateurs (administrateur) ----
route('GET', '/users', 'admin', async () => ({ items: await query('select id, username, display_name, role, source, disabled, created_at, last_login from users order by lower(username)') }))
route('POST', '/users', 'admin', async (c) => {
  const b = await c.body(z.object({ username, display_name: z.string().max(100).optional(), role, password: z.string().min(1).max(512) }))
  const pe = passwordPolicyError(b.password, b.username)
  if (pe) fail(400, pe)
  const r = await one<any>("insert into users (username, display_name, role, source, password_hash) values ($1,$2,$3,'local',$4) returning id", [b.username, b.display_name ?? null, b.role, await hashPassword(b.password)])
  await audit(c, 'user_create', 'user', r.id, { username: b.username, role: b.role })
  return { id: r.id }
})
route('PUT', '/users/:id', 'admin', async (c) => {
  const id = Number(c.params.id)
  if (!Number.isInteger(id)) fail(400, 'invalid_id')
  const b = await c.body(z.object({ display_name: z.string().max(100).nullable().optional(), role: role.optional(), disabled: z.boolean().optional(), password: z.string().min(1).max(512).optional() }))
  await tx(async (cl) => {
    const u = (await cl.query('select * from users where id = $1 for update', [id])).rows[0]
    if (!u) fail(404, 'not_found')
    const demote = (b.role && b.role !== 'admin') || b.disabled === true
    if (u.role === 'admin' && demote) {
      const n = (await cl.query("select count(*) n from users where role = 'admin' and not disabled and id <> $1", [id])).rows[0].n
      if (Number(n) === 0) fail(409, 'last_admin')
    }
    if (b.password !== undefined) {
      if (u.source !== 'local') fail(400, 'not_local_user')
      const pe = passwordPolicyError(b.password, u.username)
      if (pe) fail(400, pe)
      await cl.query('update users set password_hash = $2 where id = $1', [id, await hashPassword(b.password)])
    }
    await cl.query('update users set display_name = coalesce($2, display_name), role = coalesce($3, role), disabled = coalesce($4, disabled) where id = $1', [id, b.display_name ?? null, b.role ?? null, b.disabled ?? null])
  })
  if (b.disabled || b.password !== undefined || b.role) await destroyUserSessions(id)
  await audit(c, 'user_update', 'user', id, { role: b.role, disabled: b.disabled, password: b.password !== undefined })
  return { ok: true }
})
route('DELETE', '/users/:id', 'admin', async (c) => {
  const id = Number(c.params.id)
  if (!Number.isInteger(id)) fail(400, 'invalid_id')
  if (id === c.user!.id) fail(409, 'self_delete')
  await tx(async (cl) => {
    const u = (await cl.query('select role from users where id = $1 for update', [id])).rows[0]
    if (!u) fail(404, 'not_found')
    if (u.role === 'admin') {
      const n = (await cl.query("select count(*) n from users where role = 'admin' and not disabled and id <> $1", [id])).rows[0].n
      if (Number(n) === 0) fail(409, 'last_admin')
    }
    await cl.query('delete from users where id = $1', [id])
  })
  await audit(c, 'user_delete', 'user', id)
  return { ok: true }
})

route('GET', '/audit', 'admin', async (c) => {
  const limit = Math.min(500, Number(c.query.limit ?? 100) || 100), offset = Number(c.query.offset ?? 0) || 0
  const q = typeof c.query.q === 'string' ? `%${c.query.q.slice(0, 80)}%` : '%'
  const items = await query(`select id, at, username, action, entity, entity_id, detail, host(ip) as ip from audit_log
    where (action ilike $1 or coalesce(username,'') ilike $1 or coalesce(entity,'') ilike $1) order by id desc limit $2 offset $3`, [q, limit, offset])
  return { items }
})

// Valeur exportée et lue par le point d'entrée : empêche l'élimination du module par l'optimiseur
export const registered = true
