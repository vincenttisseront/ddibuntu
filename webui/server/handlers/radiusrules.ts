// Accès réseau — règles d'accès du service RADIUS (0.13.3, itération 4). Liste ORDONNÉE (première correspondance), refus par défaut : une règle relie des
// conditions (type de compte, groupes AD imbriqués compris, clients, usages, SSID) à une décision (accepter avec VLAN / pool / durée / attributs, ou refuser).
// L'état du compte (désactivé, verrouillé, expiré) refuse AVANT les règles. La simulation évalue la liste enregistrée sur un vrai compte de l'annuaire, avec
// la même logique que celle que root génère (voir utils/radius-rules.ts) ; le déploiement se fait par « Déployer » (POST /radius/apply).
import { z } from 'zod'
import { audit, fail, intParam, route } from '../utils/router'
import { one, tx } from '../utils/db'
import { analyze, evaluate, ruleBody, RULES_MAX, ssidFromCalledStation, SSID_RE } from '../utils/radius-rules'
import { loadCompiled, getPushed, unknownClients } from '../utils/radius-rules-store'
import { authzDigest, authzProblems } from '../utils/radius-authz'
import { loadAuth } from '../utils/radius-auth'
import { loadMfaInput } from '../utils/radius-mfa-store'
import { dirPassword, factoryFor, loadDir } from '../utils/radius-dir-store'
import { lookupAccount } from '../utils/radius-dir'
import { readRadiusStatus } from '../utils/radius'
import { loadPki } from '../utils/radius-pki-store'
import { readiness } from '../utils/radius-pki'

export const registered = true
const REASON: Record<string, string> = { service_bind: 'radius_dir_bind', tls: 'radius_dir_tls', unreachable: 'radius_dir_unreachable' }
const detail = (b: z.output<typeof ruleBody>) => ({ name: b.name, action: b.action, enabled: b.enabled, kind: b.conds.kind, groups: b.conds.groups.length, clients: b.conds.clients.length, usages: b.conds.usages, ssids: b.conds.ssids.length, reply: Object.keys(b.reply) })
const insertArgs = (b: z.output<typeof ruleBody>) => [b.name, b.enabled, b.action, JSON.stringify(b.conds), JSON.stringify(b.reply), b.comment]

/** Vue complète pour la console : règles, avertissements, ce qui empêche de déployer, et si la liste enregistrée diffère de ce qui est déployé. */
async function view() {
  const { rows, clients, compiled } = await loadCompiled()
  const dir = await loadDir(), pki = await loadPki(), r = readiness(pki), st = await readRadiusStatus()
  const password = dir.bindPasswordEnc ? dirPassword(dir) : null, auth = await loadAuth(), mfa = await loadMfaInput()
  const problems = authzProblems({ rules: compiled, pkiEmpty: r.empty, pkiReady: r.ready, dir, password, ldapModule: st ? st.ldapModule : null, auth, mfa })
  const digest = authzDigest(compiled, dir, password, auth, mfa), pushed = await getPushed()
  const numOf = new Map(compiled.map((c) => [c.id, c.n]))
  const warnings = [...(compiled.length ? analyze(compiled) : []), ...unknownClients(rows, clients).filter((u) => numOf.has(u.id)).map((u) => ({ code: 'unknown_client' as const, rule: numOf.get(u.id)!, names: u.names }))]
  return { items: rows, numbers: Object.fromEntries(compiled.map((c) => [c.id, c.n])), warnings, problems, max: RULES_MAX, active: compiled.length,
    deployed: st?.authz ?? null, pending: digest !== (pushed ?? 'none'), unknown: unknownClients(rows, clients) }
}

route('GET', '/radius/rules', 'viewer', async () => view())

route('POST', '/radius/rules', 'admin', async (c) => {
  const b = await c.body(ruleBody)
  const id = await tx(async (cl) => {
    await cl.query('lock table radius_rules in share row exclusive mode')
    const n = (await cl.query('select count(*)::int as n, coalesce(max(rank), 0) as r from radius_rules')).rows[0]
    if (n.n >= RULES_MAX) fail(409, 'radius_rules_too_many')
    return (await cl.query('insert into radius_rules (rank, name, enabled, action, conds, reply, comment) values ($1,$2,$3,$4,$5,$6,$7) returning id', [n.r + 1, ...insertArgs(b)])).rows[0].id as number
  })
  await audit(c, 'radius_rule_create', 'radius_rule', id, detail(b))
  return { id }
})

route('PUT', '/radius/rules/:id', 'admin', async (c) => {
  const id = intParam(c, 'id'), b = await c.body(ruleBody)
  const r = await one<any>('update radius_rules set name=$2, enabled=$3, action=$4, conds=$5, reply=$6, comment=$7, updated_at=now() where id=$1 returning id', [id, ...insertArgs(b)])
  if (!r) fail(404, 'not_found')
  await audit(c, 'radius_rule_update', 'radius_rule', id, detail(b))
  return { ok: true }
})

route('DELETE', '/radius/rules/:id', 'admin', async (c) => {
  const id = intParam(c, 'id')
  const r = await one<any>('delete from radius_rules where id=$1 returning name', [id])
  if (!r) fail(404, 'not_found')
  await audit(c, 'radius_rule_delete', 'radius_rule', id, { name: r.name })
  return { ok: true }
})

// Nouvel ordre : la liste complète des identifiants (permutation exacte de l'existant, sinon 409 : quelqu'un d'autre a modifié la liste entre-temps).
route('PUT', '/radius/rules-order', 'admin', async (c) => {
  const b = await c.body(z.object({ ids: z.array(z.number().int().positive()).max(RULES_MAX) }).strict())
  await tx(async (cl) => {
    await cl.query('lock table radius_rules in share row exclusive mode')
    const cur = (await cl.query('select id from radius_rules')).rows.map((x) => Number(x.id)).sort((a, z2) => a - z2)
    const want = [...b.ids].sort((a, z2) => a - z2)
    if (cur.length !== want.length || cur.some((v, i) => v !== want[i])) fail(409, 'radius_rules_changed')
    for (const [i, id] of b.ids.entries()) await cl.query('update radius_rules set rank=$2, updated_at=now() where id=$1 and rank <> $2', [id, i + 1])
  })
  await audit(c, 'radius_rule_order', 'radius', undefined, { count: b.ids.length })
  return { ok: true }
})

// Simulation : compte réel de l'annuaire (état + groupes imbriqués) × règles ENREGISTRÉES (activées). Entrées strictes comme le moteur réel : un utilisateur
// est identifié par son UPN (« @ »), une machine par son nom DNS (« . ») — ce que porte le certificat.
route('POST', '/radius/rules/simulate', 'admin', async (c) => {
  const b = await c.body(z.object({
    kind: z.enum(['user', 'computer']), name: z.string().trim().min(3).max(256).regex(/^[\w.@\- $]+$/),
    clientId: z.number().int().positive().nullish(), ssid: z.string().regex(SSID_RE).nullish(), calledStationId: z.string().max(100).nullish(),
  }).strict())
  if (b.kind === 'user' ? !b.name.includes('@') : !b.name.includes('.')) fail(400, b.kind === 'user' ? 'radius_sim_upn' : 'radius_sim_dns')
  const { compiled } = await loadCompiled()
  const dir = await loadDir()
  if (!dir.urls.length || !dir.baseDn || !dir.bindDn || !dir.bindPasswordEnc) fail(400, 'radius_dir_incomplete')
  let client: { name: string; usage: any } | null = null
  if (b.clientId) {
    const row = await one<any>('select name, usage, enabled from radius_clients where id=$1', [b.clientId])
    if (!row) fail(404, 'not_found')
    // un client désactivé n'est pas dans le fichier de clients de root : ses requêtes sont ignorées, il n'y a rien à simuler
    if (row.enabled !== true) fail(409, 'radius_sim_client_disabled')
    client = { name: row.name, usage: row.usage }
  }
  const ssid = b.ssid ?? (b.calledStationId ? ssidFromCalledStation(b.calledStationId) : null)
  const lk = await lookupAccount(dir, dirPassword(dir), factoryFor(dir), b.kind, b.name)
  const identity = { kind: b.kind, name: b.name }
  const res = !lk.ok ? evaluate(compiled, { identity, directory: { status: 'unavailable' }, client, ssid })
    : evaluate(compiled, { identity, client, ssid, directory: lk.value.found ? { status: 'ok', found: true, state: lk.value.state, groups: lk.value.groups.map((g) => g.dn) } : { status: 'ok', found: false, ambiguous: lk.value.ambiguous } })
  await audit(c, 'radius.rules.simulate', 'radius', undefined, { kind: b.kind, name: b.name, decision: res.decision, code: res.code, rule: res.rule })
  return { ...res, server: lk.ok ? lk.server : null, directoryError: lk.ok ? null : (REASON[lk.reason] ?? 'radius_dir_unreachable'),
    account: lk.ok && lk.value.found ? { dn: lk.value.dn, displayName: lk.value.displayName, state: lk.value.state, groups: lk.value.groups, groupsTruncated: lk.value.groupsTruncated } : null }
})

