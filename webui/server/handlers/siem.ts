// Export des journaux vers un SIEM (administration) : destinations, formats, flux choisis, test d'envoi, envoi immédiat.
import { z } from 'zod'
import { audit, fail, intParam, route } from '../utils/router'
import { one, query } from '../utils/db'
import { encryptSecret } from '../utils/auth'
import { SIEM_FORMATS, SIEM_SOURCES } from '../utils/siem-format'
import { BATCH, currentCursors, deliver, runSiem, targetError, testEvent } from '../utils/siem'
import type { SiemTarget } from '../utils/siem'

export const registered = true

const Body = z.object({
  name: z.string().trim().min(1).max(60), enabled: z.boolean().default(true),
  protocol: z.enum(['udp', 'tcp', 'tls', 'https']),
  host: z.string().trim().max(253).regex(/^[A-Za-z0-9.:_-]*$/).default(''), port: z.number().int().min(1).max(65535).nullable().default(null), url: z.string().trim().max(500).default(''),
  format: z.enum(SIEM_FORMATS), framing: z.enum(['newline', 'octet']).default('newline'), facility: z.number().int().min(0).max(23).default(16),
  sources: z.array(z.enum(SIEM_SOURCES)).min(1).max(SIEM_SOURCES.length), tls_verify: z.boolean().default(true),
  auth_prefix: z.string().regex(/^[A-Za-z]{0,20}$/).default('Bearer'), secret: z.string().max(500).nullable().optional(),
}).strict()

const PUBLIC = 'id, name, enabled, protocol, host, port, url, format, framing, facility, sources, tls_verify, auth_prefix, (secret_enc is not null) as has_secret, sent, last_at, last_ok, last_error, created_at'

route('GET', '/siem/targets', 'admin', async () => ({
  items: await query(`select ${PUBLIC} from siem_targets order by name`),
  sources: SIEM_SOURCES, formats: SIEM_FORMATS, batch: BATCH,
}))

function check(b: z.infer<typeof Body>) {
  const bad = targetError({ protocol: b.protocol, host: b.host, port: b.port, url: b.url })
  if (bad) fail(422, bad)
  if (b.protocol === 'udp' && b.framing === 'octet') b.framing = 'newline'
}
const dupName = async (name: string, except = 0) => { if (await one<any>('select 1 as x from siem_targets where lower(name) = lower($1) and id <> $2', [name, except])) fail(409, 'siem_exists') }

route('POST', '/siem/targets', 'admin', async (c) => {
  const b = await c.body(Body)
  check(b); await dupName(b.name)
  if ((await one<any>('select count(*)::int as n from siem_targets'))!.n >= 10) fail(409, 'siem_too_many')
  const cursors = await currentCursors(b.sources)   // on part de « maintenant » : l'historique n'est pas renvoyé
  const r = await one<any>(`insert into siem_targets (name, enabled, protocol, host, port, url, format, framing, facility, sources, tls_verify, auth_prefix, secret_enc, cursors)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb) returning id`,
    [b.name, b.enabled, b.protocol, b.host, b.port, b.url, b.format, b.framing, b.facility, b.sources, b.tls_verify, b.auth_prefix, b.secret ? encryptSecret(b.secret) : null, JSON.stringify(cursors)])
  await audit(c, 'siem.create', 'siem_target', r.id, { name: b.name, protocol: b.protocol, format: b.format, sources: b.sources })
  return { id: r.id }
})

route('PUT', '/siem/targets/:id', 'admin', async (c) => {
  const id = intParam(c, 'id'), b = await c.body(Body)
  const old = await one<any>('select cursors, secret_enc from siem_targets where id = $1', [id])
  if (!old) fail(404, 'not_found')
  check(b); await dupName(b.name, id)
  // flux nouvellement choisis : départ « maintenant » ; flux retirés : curseur oublié (un retour ultérieur repart de « maintenant » aussi)
  const cursors: Record<string, number> = {}
  const fresh = await currentCursors(b.sources.filter((s) => old.cursors?.[s] === undefined))
  for (const s of b.sources) cursors[s] = old.cursors?.[s] ?? fresh[s] ?? 0
  const secret = b.secret === undefined ? old.secret_enc : b.secret ? encryptSecret(b.secret) : null   // absent = inchangé, vide = effacé
  await query(`update siem_targets set name=$2, enabled=$3, protocol=$4, host=$5, port=$6, url=$7, format=$8, framing=$9, facility=$10, sources=$11, tls_verify=$12, auth_prefix=$13, secret_enc=$14, cursors=$15::jsonb where id=$1`,
    [id, b.name, b.enabled, b.protocol, b.host, b.port, b.url, b.format, b.framing, b.facility, b.sources, b.tls_verify, b.auth_prefix, secret, JSON.stringify(cursors)])
  await audit(c, 'siem.update', 'siem_target', id, { name: b.name, protocol: b.protocol, format: b.format, sources: b.sources, enabled: b.enabled })
  return { id }
})

route('DELETE', '/siem/targets/:id', 'admin', async (c) => {
  const id = intParam(c, 'id')
  const r = await query<any>('delete from siem_targets where id = $1 returning name', [id])
  if (!r.length) fail(404, 'not_found')
  await audit(c, 'siem.delete', 'siem_target', id, { name: r[0].name })
  return { deleted: true }
})

// Envoie un événement de test (sans toucher aux curseurs) et rend le résultat tel quel.
route('POST', '/siem/targets/:id/test', 'admin', async (c) => {
  const id = intParam(c, 'id')
  const t = await one<SiemTarget>('select * from siem_targets where id = $1', [id])
  if (!t) fail(404, 'not_found')
  try { await deliver(t, [testEvent()]); await audit(c, 'siem.test', 'siem_target', id, { ok: true }); return { ok: true, detail: 'sent' } }
  catch (e: any) {
    const detail = String(e?.code ?? e?.message ?? 'error').replace(/[^A-Za-z0-9 _:.-]/g, '').slice(0, 120)
    await audit(c, 'siem.test', 'siem_target', id, { ok: false, detail })
    return { ok: false, detail }
  }
})

// Passage immédiat (le même que le minuteur) : utile pour vérifier sans attendre.
route('POST', '/siem/run', 'admin', async () => runSiem())
