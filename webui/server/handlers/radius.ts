// Accès réseau — service RADIUS (0.13.0, itération 1) : clients (contrôleurs Wi-Fi, passerelles VPN, commutateurs) et état du service de CE nœud.
// Les secrets partagés sont chiffrés au repos et ne sont montrés qu'une fois (création, régénération). Le service lui-même est piloté par root
// (ddibuntu-radius) à partir d'une demande déposée par la console ; voir utils/radius.ts.
import { audit, fail, intParam, qint, qstr, route } from '../utils/router'
import { one, query, tx } from '../utils/db'
import { cfg } from '../utils/config'
import { clientBody, depositRadiusRequest, genSecret, MAX_CLIENTS, radiusRequestPending, readRadiusResult, readRadiusStatus, renderClientsConf, sealSecret, selftestSecret } from '../utils/radius'
import { radiusProbe } from '../utils/radius-proto'
import { buildDeposit, crlSetDigest, readiness } from '../utils/radius-pki'
import { loadPki, savePki, withPki } from '../utils/radius-pki-store'
import { decryptSecret } from '../utils/auth'
import { authzDigest, authzProblems, buildAuthzDeposit } from '../utils/radius-authz'
import { loadAuth } from '../utils/radius-auth'
import { getPushed, loadCompiled, setPushed } from '../utils/radius-rules-store'
import { dirPassword, loadDir } from '../utils/radius-dir-store'
import { readJournal, type JournalKind } from '../utils/radius-journal'
import { readClusterState } from '../utils/cluster'
import { depositBusy, notePending, reconcileNow, resultBeforeDeposit } from '../utils/radius-follow'

export const registered = true
const COLS = 'id, name, address::text as address, usage, enabled, comment, created_at, updated_at'

const pkiBrief = (p: Awaited<ReturnType<typeof loadPki>>) => { const r = readiness(p); return { configured: !r.empty, ready: r.ready, problems: r.problems.length } }

async function renameClientInRules(cl: { query: (t: string, p?: unknown[]) => Promise<{ rows: any[] }> }, from: string, to: string) {
  const rows = (await cl.query(`select id, conds from radius_rules where conds->'clients' ? $1`, [from])).rows
  for (const r of rows) {
    const clients = [...new Set((r.conds.clients as string[]).map((n) => (n === from ? to : n)))].sort()
    await cl.query('update radius_rules set conds = jsonb_set(conds, \'{clients}\', $2::jsonb), updated_at=now() where id=$1', [r.id, JSON.stringify(clients)])
  }
}

/** Résumé des règles pour l'onglet « Service » : combien d'actives, et si la liste enregistrée diffère de ce qui est déployé. */
async function rulesBrief() {
  const { compiled } = await loadCompiled(), dir = await loadDir()
  const digest = authzDigest(compiled, dir, dir.bindPasswordEnc ? dirPassword(dir) : null, await loadAuth())
  return { active: compiled.length, pending: digest !== ((await getPushed()) ?? 'none') }
}

/** Compteurs des dernières 24 h pour l'onglet « Service » (hors tests de la console). */
async function journalBrief() {
  const j = await readJournal({ limit: 1 })
  return { available: j.available, accept: j.counts.accept, reject: j.counts.reject, diag: j.counts.diag, truncated: j.truncated }
}

// RADIUS dans le cluster (0.15.0) : actif sur le leader seulement (derrière l'adresse virtuelle) ; sur un secondaire le service est volontairement arrêté.
async function clusterBrief() {
  const snap = await reconcileNow().catch(() => null)   // aussi hors cluster : le déploiement mémorisé suit la réponse de root, un nœud qui rejoindra un cluster l'aura déjà
  const st = await readClusterState()
  if (!st || st.nodeRole !== 'data') return null
  return { node: st.node, role: st.localRole, leader: st.leader, vip: st.vip ? { address: st.vip.address, held: st.vip.held } : null, deployed: !!snap?.deployed, follow: snap?.follow ?? null }
}
route('GET', '/radius', 'viewer', async () => {
  const n = await one<{ n: number; on: number }>('select count(*)::int as n, count(*) filter (where enabled)::int as on from radius_clients')
  return { auth: await loadAuth(), status: await readRadiusStatus(), result: await readRadiusResult(), requestPending: await radiusRequestPending(), pki: pkiBrief(await loadPki()), clients: n?.n ?? 0, enabledClients: n?.on ?? 0, max: MAX_CLIENTS, rules: await rulesBrief(), journal: await journalBrief(), cluster: await clusterBrief() }
})

// Journal des authentifications de CE nœud : acceptées, refusées (avec le certificat, la règle et la raison), et les diagnostics du démon
// (équipement inconnu, alerte TLS du poste). Filtres : résultat, texte libre (poste, MAC, équipement, certificat, raison), depuis N minutes.
route('GET', '/radius/events', 'viewer', async (c) => {
  const kind = qstr(c, 'kind', 10)
  if (kind !== undefined && !['accept', 'reject', 'diag'].includes(kind)) fail(400, 'invalid_query')
  const minutes = qint(c, 'minutes', 0, 0, 60 * 24 * 30)
  return readJournal({ kind: kind as JournalKind | undefined, q: qstr(c, 'q', 100), since: minutes ? Date.now() - minutes * 60_000 : undefined, limit: qint(c, 'limit', 200, 1, 1000), selftest: qstr(c, 'selftest', 1) === '1' })
})

route('GET', '/radius/clients', 'viewer', async () => ({ items: await query(`select ${COLS} from radius_clients order by name`) }))

route('POST', '/radius/clients', 'admin', async (c) => {
  const b = await c.body(clientBody)
  if (((await one<{ n: number }>('select count(*)::int as n from radius_clients'))?.n ?? 0) >= MAX_CLIENTS) fail(409, 'radius_too_many')
  const generated = !b.secret
  const secret = b.secret ?? genSecret()
  const r = await one<any>('insert into radius_clients (name, address, usage, secret_enc, enabled, comment) values ($1,$2,$3,$4,$5,$6) returning id',
    [b.name, b.address, b.usage, sealSecret(secret), b.enabled, b.comment])
  await audit(c, 'radius_client_create', 'radius_client', r.id, { name: b.name, address: b.address, usage: b.usage, generatedSecret: generated })
  // un secret généré n'est montré qu'ici : il faut le saisir sur l'équipement (un secret saisi par l'administrateur n'est jamais renvoyé)
  return { id: r.id, name: b.name, secret: generated ? secret : null }
})

route('PUT', '/radius/clients/:id', 'admin', async (c) => {
  const id = intParam(c, 'id'), b = await c.body(clientBody)
  const r = await tx(async (cl) => {
    const old = (await cl.query('select name from radius_clients where id=$1 for update', [id])).rows[0]
    if (!old) return null
    await cl.query(`update radius_clients set name=$2, address=$3, usage=$4, enabled=$5, comment=$6, secret_enc = coalesce($7, secret_enc), updated_at=now() where id=$1`,
      [id, b.name, b.address, b.usage, b.enabled, b.comment, b.secret ? sealSecret(b.secret) : null])
    // les règles d'accès désignent les clients par leur nom : un renommage doit les suivre, sinon la règle ne viserait plus ce client
    if (old.name !== b.name) await renameClientInRules(cl, old.name, b.name)
    return old
  })
  if (!r) fail(404, 'not_found')
  await audit(c, 'radius_client_update', 'radius_client', id, { name: b.name, address: b.address, usage: b.usage, enabled: b.enabled, secretChanged: !!b.secret })
  return { ok: true }
})

route('POST', '/radius/clients/:id/secret', 'admin', async (c) => {
  const id = intParam(c, 'id'), secret = genSecret()
  const r = await one<any>('update radius_clients set secret_enc=$2, updated_at=now() where id=$1 returning name', [id, sealSecret(secret)])
  if (!r) fail(404, 'not_found')
  await audit(c, 'radius_client_secret', 'radius_client', id, { name: r.name })
  return { secret }
})

route('DELETE', '/radius/clients/:id', 'admin', async (c) => {
  const id = intParam(c, 'id')
  const r = await one<any>('delete from radius_clients where id = $1 returning name', [id])
  if (!r) fail(404, 'not_found')
  await audit(c, 'radius_client_delete', 'radius_client', id, { name: r.name })
  return { ok: true }
})

async function deposit(c: Parameters<Parameters<typeof route>[3]>[0], req: Parameters<typeof depositRadiusRequest>[0], detail?: Record<string, unknown>) {
  if ((await radiusRequestPending()) || (await depositBusy())) fail(409, 'request_pending')
  const r = await depositRadiusRequest(req)
  await audit(c, `radius.${req.action}`, 'radius', undefined, detail)
  return { accepted: true, requestedAt: r.requestedAt }
}

// Déployer : (ré)écrit les clients actifs, contrôle la configuration, (re)démarre le service et ouvre le pare-feu à ces seuls réseaux.
// PKI vide → pas d'EAP ; PKI commencée mais incomplète → refus (on ne déploie jamais un EAP-TLS à moitié configuré) ; PKI prête → EAP-TLS activé.
route('POST', '/radius/apply', 'admin', async (c) => {
  const rows = await query<any>('select name, address::text as address, secret_enc, enabled from radius_clients order by name')
  const pki = await loadPki(), r = readiness(pki)
  if (!r.empty && !r.ready) fail(409, 'radius_pki_not_ready', undefined, { problems: r.problems })
  const dep = r.ready ? buildDeposit(pki, decryptSecret(pki.server!.keyEnc)) : undefined
  // règles d'accès : sans règle active, root déploie le refus par défaut ; avec des règles, EAP-TLS et l'annuaire doivent être prêts (sinon on ne déploie rien)
  const { compiled } = await loadCompiled(), dir = await loadDir(), st = await readRadiusStatus()
  const password = dir.bindPasswordEnc ? dirPassword(dir) : null, auth = await loadAuth()
  const problems = authzProblems({ rules: compiled, pkiEmpty: r.empty, pkiReady: r.ready, dir, password, ldapModule: st ? st.ldapModule : null, auth })
  if (problems.length) fail(409, 'radius_authz_not_ready', undefined, { problems })
  const authz = compiled.length && dep ? buildAuthzDeposit(compiled, dir, password!, auth) : undefined
  const req = { action: 'apply' as const, clients: renderClientsConf(rows), pki: dep, authz }
  const prev = await resultBeforeDeposit()
  const out = await deposit(c, req, { clients: rows.filter((x) => x.enabled).length, eap: !!dep, checkCrl: dep?.checkCrl ?? null, rules: compiled.length })
  await notePending('apply', out.requestedAt, prev, req)   // devient « le déploiement » quand root l'a accepté : c'est ce que rejouera le nouveau leader
  await setPushed(authzDigest(compiled, dir, password, auth))
  // les CRL déployées sont celles-ci : la tâche planifiée n'en renvoie une nouvelle (et ne redémarre le service) que si elles changent
  if (dep) await withPki(async () => { const s = await loadPki(); await savePki({ ...s, crlPushed: crlSetDigest(s) }) })
  return out
})
route('POST', '/radius/stop', 'admin', async (c) => {
  const prev = await resultBeforeDeposit()
  const out = await deposit(c, { action: 'stop' })
  await notePending('stop', out.requestedAt, prev)   // arrêt voulu : aucun nouveau leader ne redémarre le service
  return out
})

// Test d'Access-Request : requête PAP signée depuis le client d'essai local. « Refus » est la bonne réponse (aucune règle d'accès n'existe encore) ;
// « aucune réponse » = service arrêté, pas encore déployé, ou secret / client inconnus.
route('POST', '/radius/test', 'admin', async (c) => {
  const st = await readRadiusStatus()
  if (!st?.active) fail(409, 'radius_not_running')
  const r = await radiusProbe({ port: cfg().radiusPort, secret: selftestSecret() })
  await audit(c, 'radius.test', 'radius', undefined, { ok: r.ok, reply: r.reply ?? null, ms: r.ms, error: r.error ?? null })
  return r
})
