// Jetons d'API : « ddi_ » + 40 caractères aléatoires, montré UNE SEULE fois ; seule l'empreinte SHA-256 est stockée.
// Rôle viewer ou operator uniquement (jamais admin) : un jeton ne gère ni les comptes, ni les jetons, ni le cluster, ni les mises à jour.
import { randomBytes } from 'node:crypto'
import { query } from './db'
import { sha256hex } from './auth'
import type { SessionUser } from './auth'

export const TOKEN_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/
export const newApiToken = (): string => 'ddi_' + randomBytes(30).toString('base64url')   // 40 caractères après le préfixe
export const tokenHash = (t: string): string => sha256hex(t)

const lastTouch = new Map<number, number>()

/** Utilisateur « jeton » pour une requête, ou null (inconnu, révoqué, expiré). */
export async function userFromApiToken(token: string): Promise<SessionUser | null> {
  const r = (await query<any>('select id, name, role from api_tokens where token_hash = $1 and revoked_at is null and (expires_at is null or expires_at > now())', [tokenHash(token)]))[0]
  if (!r) return null
  const now = Date.now()
  if (now - (lastTouch.get(r.id) ?? 0) > 60_000) {   // « dernière utilisation » : au plus une écriture par minute ; ignorée sur un secondaire (lecture seule)
    lastTouch.set(r.id, now)
    query('update api_tokens set last_used_at = now() where id = $1', [r.id]).catch(() => {})
  }
  return { id: -r.id, username: `token:${r.name}`, role: r.role, source: 'token', displayName: null, csrf: '', sessionId: 0 }
}
