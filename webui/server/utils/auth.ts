// Authentification : PBKDF2, sessions en base (jeton haché), CSRF, anti-force brute, chiffrement des secrets.
import { randomBytes, pbkdf2, timingSafeEqual, createHash, createCipheriv, createDecipheriv } from 'node:crypto'
import { promisify } from 'node:util'
import { cfg, requireSecret } from './config'
import { one, query } from './db'

const pbkdf2p = promisify(pbkdf2)
export const sha256hex = (s: string) => createHash('sha256').update(s).digest('hex')
export const newToken = (bytes = 32) => randomBytes(bytes).toString('base64url')

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b)
  return x.length === y.length && timingSafeEqual(x, y)
}

export async function hashPassword(pw: string): Promise<string> {
  const iter = cfg().pbkdf2Iterations
  const salt = randomBytes(16)
  const h = await pbkdf2p(pw, salt, iter, 32, 'sha256')
  return `pbkdf2$sha256$${iter}$${salt.toString('base64')}$${h.toString('base64')}`
}
export async function verifyPassword(pw: string, stored: string | null): Promise<boolean> {
  const parts = (stored ?? '').split('$')
  if (parts.length !== 5 || parts[0] !== 'pbkdf2' || parts[1] !== 'sha256') return false
  const iter = Number(parts[2])
  if (!Number.isInteger(iter) || iter < 1000 || iter > 5_000_000) return false
  const salt = Buffer.from(parts[3]!, 'base64'), want = Buffer.from(parts[4]!, 'base64')
  const got = await pbkdf2p(pw, salt, iter, want.length, 'sha256')
  return got.length === want.length && timingSafeEqual(got, want)
}
let dummyHash: Promise<string> | null = null
/** Travail équivalent pour un identifiant inconnu : le temps de réponse ne révèle pas son existence. */
export async function dummyVerify(pw: string): Promise<void> {
  dummyHash ??= hashPassword('dummy-password-for-timing')
  await verifyPassword(pw, await dummyHash)
}
export function passwordPolicyError(pw: string, username: string): string | null {
  if (pw.length < 12) return 'password_short'
  if (username && pw.toLowerCase().includes(username.toLowerCase())) return 'password_contains_username'
  return null
}

// ---- Chiffrement des secrets au repos (AES-256-GCM) ----
function aesKey(): Buffer { return createHash('sha256').update(requireSecret()).digest() }
export function encryptSecret(plain: string): string {
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', aesKey(), iv)
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()])
  return ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join(':')
}
export function decryptSecret(enc: string): string {
  const [v, iv, tag, ct] = enc.split(':')
  if (v !== 'v1' || !iv || !tag || !ct) throw new Error('secret illisible')
  const d = createDecipheriv('aes-256-gcm', aesKey(), Buffer.from(iv, 'base64'))
  d.setAuthTag(Buffer.from(tag, 'base64'))
  return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8')
}

// ---- Sessions ----
export type Role = 'viewer' | 'operator' | 'admin'
export const ROLE_RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 }
export interface SessionUser { id: number; username: string; role: Role; source: string; displayName: string | null; csrf: string; sessionId: number }

export async function createSession(userId: number, ip: string | null, ua: string | null) {
  const token = newToken(), csrf = newToken(24)
  const c = cfg()
  await query(
    `insert into sessions (token_hash, user_id, csrf_token, expires_at, ip, user_agent)
     values ($1, $2, $3, now() + make_interval(hours => $4), $5, $6)`,
    [sha256hex(token), userId, csrf, c.sessionHours, ip, ua?.slice(0, 300) ?? null])
  return { token, csrf, maxAge: c.sessionHours * 3600 }
}
export async function sessionFromToken(token: string): Promise<SessionUser | null> {
  const c = cfg()
  const r = await one<any>(
    `select s.id as sid, s.csrf_token, u.id, u.username, u.role, u.source, u.display_name
       from sessions s join users u on u.id = s.user_id
      where s.token_hash = $1 and s.expires_at > now()
        and s.last_seen > now() - make_interval(mins => $2) and not u.disabled`,
    [sha256hex(token), c.idleMinutes])
  if (!r) return null
  // meilleur effort : sur un nœud secondaire la base est en lecture seule (la session, répliquée, reste lisible)
  await query('update sessions set last_seen = now() where id = $1 and last_seen < now() - interval \'30 seconds\'', [r.sid]).catch((e: any) => { if (e?.code !== '25006') throw e })
  return { id: r.id, username: r.username, role: r.role, source: r.source, displayName: r.display_name, csrf: r.csrf_token, sessionId: Number(r.sid) }
}
export async function destroySession(token: string) { await query('delete from sessions where token_hash = $1', [sha256hex(token)]) }
export async function destroyUserSessions(userId: number) { await query('delete from sessions where user_id = $1', [userId]) }
export async function purgeSessions() { await query('delete from sessions where expires_at < now() or last_seen < now() - interval \'1 day\'') }

// ---- Anti-force brute : 5 échecs par identifiant ou 30 par adresse sur 15 minutes ----
export async function loginBlocked(username: string, ip: string | null): Promise<boolean> {
  const u = await one<{ n: string }>(`select count(*) n from login_attempts where lower(username) = lower($1) and not success and at > now() - interval '15 minutes'`, [username])
  if (Number(u?.n ?? 0) >= 5) return true
  if (ip) {
    const i = await one<{ n: string }>(`select count(*) n from login_attempts where ip = $1 and not success and at > now() - interval '15 minutes'`, [ip])
    if (Number(i?.n ?? 0) >= 30) return true
  }
  return false
}
export async function recordAttempt(username: string, ip: string | null, success: boolean) {
  await query('insert into login_attempts (username, ip, success) values ($1, $2, $3)', [username.slice(0, 100), ip, success])
  if (success) await query(`delete from login_attempts where lower(username) = lower($1) and not success`, [username])
}
