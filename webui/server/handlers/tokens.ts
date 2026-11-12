// Jetons d'API (administration) et description OpenAPI de l'API.
import { z } from 'zod'
import { audit, fail, intParam, route, routeTable } from '../utils/router'
import { one, query } from '../utils/db'
import { TOKEN_NAME_RE, newApiToken, tokenHash } from '../utils/api-tokens'
import { installedVersion } from '../utils/selfupdate'

export const registered = true

const Create = z.object({ name: z.string().regex(TOKEN_NAME_RE), role: z.enum(['viewer', 'operator']), expiresDays: z.number().int().min(1).max(3650).nullable() }).strict()

route('GET', '/tokens', 'admin', async () => ({
  items: await query('select id, name, prefix, role, created_by, created_at, expires_at, last_used_at, revoked_at, (revoked_at is null and (expires_at is null or expires_at > now())) as active from api_tokens order by id desc limit 200'),
}))
route('POST', '/tokens', 'admin', async (c) => {
  const b = await c.body(Create)
  if ((await one<any>('select 1 as x from api_tokens where lower(name) = lower($1) and revoked_at is null', [b.name]))) fail(409, 'token_exists')
  if ((await one<any>("select count(*)::int as n from api_tokens where revoked_at is null"))!.n >= 100) fail(409, 'too_many_tokens')
  const token = newApiToken()
  const r = (await query<any>("insert into api_tokens (name, prefix, token_hash, role, created_by, expires_at) values ($1, $2, $3, $4, $5, case when $6::int is null then null else now() + make_interval(days => $6::int) end) returning id, expires_at",
    [b.name, token.slice(0, 8), tokenHash(token), b.role, c.user!.username, b.expiresDays]))[0]
  await audit(c, 'token_create', 'api_token', r.id, { name: b.name, role: b.role, expiresDays: b.expiresDays })
  return { id: r.id, name: b.name, role: b.role, expires_at: r.expires_at, token }   // le seul affichage du secret
})
route('DELETE', '/tokens/:id', 'admin', async (c) => {
  const id = intParam(c, 'id')
  const r = await query<any>('update api_tokens set revoked_at = now() where id = $1 and revoked_at is null returning name', [id])
  if (!r.length) fail(404, 'not_found')
  await audit(c, 'token_revoke', 'api_token', id, { name: r[0].name })
  return { revoked: true }
})

// ---- OpenAPI 3.0, générée depuis la table des routes : chemins, méthodes, rôle minimal, paramètres de chemin.
const tagOf = (p: string) => p.split('/')[1] || 'root'
route('GET', '/openapi.json', 'viewer', async () => {
  const paths: Record<string, Record<string, unknown>> = {}
  for (const r of routeTable()) {
    const path = r.path.replace(/:([a-z]+)/gi, '{$1}')
    const params = [...r.path.matchAll(/:([a-z]+)/gi)].map((m) => ({ name: m[1]!, in: 'path', required: true, schema: { type: 'string' } }))
    const op = {
      summary: `${r.method} ${path}`, tags: [tagOf(r.path)], 'x-required-role': r.role,
      ...(params.length ? { parameters: params } : {}),
      ...(r.role === 'public' ? { security: [] } : {}),
      ...(['POST', 'PUT', 'PATCH'].includes(r.method) ? { requestBody: { required: false, content: { 'application/json': { schema: { type: 'object' } } } } } : {}),
      responses: { 200: { description: 'OK' }, 400: { description: 'Requête invalide' }, ...(r.role === 'public' ? {} : { 401: { description: 'Non authentifié' }, 403: { description: 'Rôle insuffisant' } }) },
    }
    ;(paths[path] ??= {})[r.method.toLowerCase()] = op
  }
  return {
    openapi: '3.0.3',
    info: { title: 'DDI-Buntu API', version: installedVersion() || '0', description: 'API de la console DDI-Buntu. Authentification : jeton d\'API (« Authorization: Bearer ddi_… », rôle viewer ou operator) ou session de la console. Les écritures ne sont acceptées que par le nœud principal du cluster.' },
    servers: [{ url: '/api' }],
    components: { securitySchemes: { bearer: { type: 'http', scheme: 'bearer', description: 'Jeton d\'API créé dans Système → API' } } },
    security: [{ bearer: [] }],
    paths,
  }
})
