// Accès réseau — annuaire Active Directory du service RADIUS (0.13.1, itération 2) : réglages de la liaison LDAPS en lecture seule (administrateur),
// test de liaison, recherche d'un compte (état + groupes imbriqués) et recherche de groupes. Aucune écriture dans l'annuaire ; le mot de passe de
// liaison est chiffré et jamais renvoyé. Les règles d'accès qui s'en serviront viennent aux itérations suivantes.
import { z } from 'zod'
import { audit, fail, qstr, route } from '../utils/router'
import { setSetting } from '../utils/db'
import { encryptSecret } from '../utils/auth'
import { DIR_KEY, findGroups, lookupAccount, testBind } from '../utils/radius-dir'
import type { DirSettings } from '../utils/radius-dir'
import { dirComplete, dirPassword, factoryFor, loadDir as load } from '../utils/radius-dir-store'

export const registered = true
const NAME = /^[\w.@\- $]{1,256}$/
const body = z.object({
  urls: z.array(z.string().regex(/^ldaps:\/\/[A-Za-z0-9._-]+(:\d{1,5})?$/, 'ldaps')).max(5),
  baseDn: z.string().trim().max(500), bindDn: z.string().trim().max(500),
  bindPassword: z.string().max(200).optional(), clearPassword: z.boolean().optional(),
  tlsRejectUnauthorized: z.boolean(),
  caPem: z.string().max(20000).regex(/^(?:-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----\s*)?$/).optional(),
}).strict()

/** Réglages complets exigés pour interroger l'annuaire (serveur, base, compte de liaison et son mot de passe). */
function ready(s: DirSettings): string {
  if (!dirComplete(s)) fail(400, 'radius_dir_incomplete')
  return dirPassword(s)
}
// raison d'échec → code d'erreur de l'API (traduit par la console)
const REASON: Record<string, string> = { service_bind: 'radius_dir_bind', tls: 'radius_dir_tls', unreachable: 'radius_dir_unreachable' }

route('GET', '/radius/directory', 'admin', async () => { const { bindPasswordEnc, ...s } = await load(); return { ...s, bindPasswordSet: !!bindPasswordEnc } })

route('PUT', '/radius/directory', 'admin', async (c) => {
  const b = await c.body(body)
  const cur = await load()
  const { bindPassword, clearPassword, ...rest } = b
  const next: DirSettings = { ...cur, ...rest, bindPasswordEnc: bindPassword ? encryptSecret(bindPassword) : clearPassword ? undefined : cur.bindPasswordEnc }
  if (!b.caPem) delete next.caPem
  await setSetting(DIR_KEY, next)
  await audit(c, 'radius_directory', 'settings', DIR_KEY, { servers: b.urls.length, passwordChanged: !!bindPassword, tlsRejectUnauthorized: b.tlsRejectUnauthorized })
  return { ok: true }
})

// Test : liaison de service sur chaque serveur déclaré (le résultat dit lequel répond, lequel refuse les identifiants, lequel a un certificat refusé).
route('POST', '/radius/directory/test', 'admin', async (c) => {
  const s = await load(), pw = ready(s)
  const r = await testBind(s, pw, factoryFor(s))
  await audit(c, 'radius.directory.test', 'radius', undefined, { ok: r.ok, servers: r.attempts.map((a) => ({ server: a.server, ok: a.ok })) })
  return r
})

// Recherche d'un compte : état (activé, verrouillé, expiré) et groupes directs et imbriqués. Lecture seule, sans connexion ni création de compte.
route('POST', '/radius/directory/lookup', 'admin', async (c) => {
  const b = await c.body(z.object({ kind: z.enum(['user', 'computer']), name: z.string().trim().regex(NAME) }).strict())
  const s = await load(), pw = ready(s)
  const r = await lookupAccount(s, pw, factoryFor(s), b.kind, b.name)
  await audit(c, 'radius.directory.lookup', 'radius', undefined, { kind: b.kind, name: b.name, found: r.ok ? r.value.found : null })
  if (!r.ok) fail(502, REASON[r.reason] ?? 'radius_dir_unreachable')
  return { server: r.server, ...r.value }
})

route('GET', '/radius/directory/groups', 'admin', async (c) => {
  const q = qstr(c, 'q', 100)?.trim()
  if (!q || q.length < 2 || !/^[\w.@\- $]+$/.test(q)) fail(400, 'invalid_query')
  const s = await load(), pw = ready(s)
  const r = await findGroups(s, pw, factoryFor(s), q)
  if (!r.ok) fail(502, REASON[r.reason] ?? 'radius_dir_unreachable')
  return { server: r.server, ...r.value }
})
