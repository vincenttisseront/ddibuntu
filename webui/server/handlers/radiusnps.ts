// Accès réseau — import d'un NPS Windows (0.13.10, itération 5). L'administrateur dépose l'export `netsh nps export … exportPSK=YES` ; la console en tire un PLAN
// (clients → clients DDI-Buntu, stratégies réseau → règles d'accès) avec le sort de chaque élément (repris / adapté / non pris en charge) et la raison.
// L'aperçu n'écrit RIEN. La validation recalcule le plan, vérifie qu'il est identique à celui qui a été présenté (empreinte), puis écrit en UNE transaction.
// Rien n'est appliqué au service : les clients et règles créés attendent « Déployer » comme n'importe quel autre. Les règles ne sont actives que si l'administrateur le
// demande et seulement celles reprises sans réserve. Les secrets du fichier ne sont jamais renvoyés ni journalisés ; ceux qu'on génère ne sont montrés qu'une fois.
import { createHash } from 'node:crypto'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { query, tx } from '../utils/db'
import { genSecret, MAX_CLIENTS, sealSecret, USAGES } from '../utils/radius'
import { ruleBody } from '../utils/radius-rules'
import { NPS_MAX_BYTES, NpsParseError, parseNpsExport, planImport, sidsToResolve } from '../utils/radius-nps'
import type { GroupState, NpsExport, Plan, PlanCtx } from '../utils/radius-nps'
import { resolveGroupSids } from '../utils/radius-dir'
import { dirComplete, dirPassword, factoryFor, loadDir } from '../utils/radius-dir-store'
import { record } from './importer'

export const registered = true

const base = z.object({
  content: z.string().min(1).max(NPS_MAX_BYTES + 1000),
  filename: z.string().max(200).optional(),
  /** usage choisi par l'administrateur, par nom de client dans le NPS */
  usages: z.record(z.string().max(200), z.enum(USAGES)).default({}).refine((u) => Object.keys(u).length <= MAX_CLIENTS, 'usages'),
  /** éléments décochés : « c:<client> » ou « r:<stratégie> » */
  exclude: z.array(z.string().max(300)).max(5000).default([]),
  /** créer actives les règles reprises sans réserve (sinon toutes inactives) */
  activate: z.boolean().default(false),
}).strict()
const commitBody = base.extend({ digest: z.string().regex(/^[0-9a-f]{64}$/) }).strict()
type Body = z.output<typeof base>

interface Resolved { exp: NpsExport; groups: Map<string, GroupState>; directory: PlanCtx['directory'] }

/** Lecture du fichier et résolution des groupes dans l'annuaire (réseau : jamais sous verrou de base). */
async function resolve(content: string): Promise<Resolved> {
  let exp: NpsExport
  try { exp = parseNpsExport(content) } catch (e) { if (e instanceof NpsParseError) fail(400, `radius_${e.code}`); throw e }
  const sids = sidsToResolve(exp), groups = new Map<string, GroupState>()
  let directory: PlanCtx['directory'] = 'ok'
  if (sids.length) {
    const dir = await loadDir()
    if (!dirComplete(dir)) directory = 'missing'
    else {
      const r = await resolveGroupSids(dir, dirPassword(dir), factoryFor(dir), sids)
      if (!r.ok) directory = 'unreachable'
      else for (const [sid, v] of r.value) groups.set(sid, !v.found ? { state: 'notfound' } : v.usable ? { state: 'found', dn: v.dn, name: v.name } : { state: 'unusable', name: v.name })
    }
  }
  return { exp, groups, directory }
}

type Q = (t: string, p?: unknown[]) => Promise<{ rows: any[] }>
async function makePlan(r: Resolved, b: Body, q: Q): Promise<Plan> {
  const [cl, ru] = [(await q('select name, address::text as address from radius_clients')).rows, (await q('select name, comment from radius_rules')).rows]
  return planImport(r.exp, { existingClients: cl.map((c) => ({ name: String(c.name), address: String(c.address) })), existingRules: ru.map((x) => ({ name: String(x.name), comment: x.comment ?? null })),
    directory: r.directory, groups: r.groups, opts: { usages: b.usages, activate: b.activate, exclude: new Set(b.exclude) } })
}
/** Empreinte de ce que l'administrateur a vu (sans secret : le plan n'en contient pas). */
const digestOf = (p: Plan) => createHash('sha256').update(JSON.stringify([
  p.directory, p.clients.map((c) => [c.key, c.name, c.address, c.status, c.selected, c.usage, c.secret]),
  p.rules.map((x) => [x.key, x.name, x.status, x.selected, x.enabled, x.action, x.kind, x.groups, x.clients, x.usages, x.ssids, x.comment]),
])).digest('hex')

route('POST', '/radius/nps/preview', 'admin', async (c) => {
  const b = await c.body(base)
  const r = await resolve(b.content)
  const plan = await makePlan(r, b, (t, p) => query(t, p).then((rows) => ({ rows })))
  await audit(c, 'radius.nps.preview', 'radius', undefined, { filename: b.filename ?? null, clients: plan.totals.clients, rules: plan.totals.rules, directory: plan.directory })
  return { plan, digest: digestOf(plan), filename: b.filename ?? null }
})

route('POST', '/radius/nps/commit', 'admin', async (c) => {
  const b = await c.body(commitBody)
  const r = await resolve(b.content)
  const secrets = new Map(r.exp.clients.map((x) => [`c:${x.name}`, x.secret]))
  const out = await tx(async (cl) => {
    await cl.query('lock table radius_clients, radius_rules in share row exclusive mode')
    // le plan est refait SOUS VERROU, à partir de l'état réel : s'il diffère de celui qui a été présenté (clients ou règles modifiés entre-temps), on n'écrit rien
    const plan = await makePlan(r, b, (t, p) => cl.query(t, p) as Promise<{ rows: any[] }>)
    if (digestOf(plan) !== b.digest) fail(409, 'radius_nps_changed')
    const generated: Array<{ name: string; secret: string }> = []
    let clients = 0, clientsSkipped = 0, rules = 0, rulesSkipped = 0, active = 0
    for (const x of plan.clients) {
      if (!x.selected || x.status === 'skipped' || !x.address) continue
      const secret = x.secret === 'reused' ? secrets.get(x.key)! : genSecret()
      const ins = await cl.query('insert into radius_clients (name, address, usage, secret_enc, enabled, comment) values ($1,$2,$3,$4,true,$5) on conflict do nothing returning id',
        [x.name, x.address, x.usage, sealSecret(secret), `Import NPS : « ${x.original} »`.slice(0, 500)])
      if (!ins.rowCount) { clientsSkipped++; continue }
      clients++
      if (x.secret === 'generated') generated.push({ name: x.name, secret })
    }
    const rank = Number((await cl.query('select coalesce(max(rank), 0) as r from radius_rules')).rows[0].r)
    for (const x of plan.rules) {
      if (!x.selected || x.status === 'skipped') continue
      const v = ruleBody.safeParse({ name: x.name, enabled: x.enabled, action: x.action, kind: x.kind, groups: x.groups, clients: x.clients, usages: x.usages, ssids: x.ssids, reply: {}, comment: x.comment })
      if (!v.success) { rulesSkipped++; continue }
      await cl.query('insert into radius_rules (rank, name, enabled, action, conds, reply, comment) values ($1,$2,$3,$4,$5,$6,$7)',
        [rank + rules + 1, v.data.name, v.data.enabled, v.data.action, JSON.stringify(v.data.conds), JSON.stringify(v.data.reply), v.data.comment])
      rules++; if (v.data.enabled) active++
    }
    return { plan, generated, clients, clientsSkipped, rules, rulesSkipped, active }
  })
  const summary = { clients: out.clients, clientsSkipped: out.clientsSkipped, rules: out.rules, rulesSkipped: out.rulesSkipped, activeRules: out.active, generatedSecrets: out.generated.length, totals: out.plan.totals }
  await record(c, 'radius-nps', b.filename, summary)
  await audit(c, 'radius_nps_import', 'radius', undefined, { filename: b.filename ?? null, ...summary, generatedFor: out.generated.map((g) => g.name) })
  // les secrets générés ne sont montrés qu'ici : il faut les saisir sur les équipements concernés
  return { ...summary, generated: out.generated }
})
