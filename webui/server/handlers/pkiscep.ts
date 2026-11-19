// SCEP de la PKI du DDI (0.14.8) : activation de l'alias, préenregistrement des équipements (un nom, un profil, des noms alternatifs et un défi à usage unique), nouveau défi
// pour un renouvellement, annulation. La console ne signe rien : elle dépose une demande minuscule (jamais le défi) et le défi dans un fichier SECRET que root lit une fois ;
// root revalide tout et parle à EJBCA (voir utils/pki-scep.ts). Le défi est rendu UNE seule fois, dans la réponse qui suit le succès de root.
import { setResponseHeader } from 'h3'
import { cfg } from '../utils/config'
import { audit, fail, route } from '../utils/router'
import type { Ctx } from '../utils/router'
import { depositPkiRequest, pkiRequestPending, readPkiResult, readPkiStatus } from '../utils/pki'
import type { PkiRequest } from '../utils/pki'
import { dropDeposit, putSecretDeposit, readPkiCas } from '../utils/pki-ca'
import { awaitRef, issueRequest, MAX_REQUEST_JSON, newIssueId, serialized } from '../utils/pki-certs'
import { awaitAction, CHALLENGE_LEN, newChallenge, readPkiScep, SCEP_ALIAS, scepCnParam, scepOfferBody } from '../utils/pki-scep'

export const registered = true

async function needHealthy() {
  const st = await readPkiStatus()
  if (!st?.installed) fail(409, 'pki_not_installed')
  if (st.state !== 'healthy') fail(409, 'pki_not_ready')
  return st
}
async function idle() { if (await pkiRequestPending()) fail(409, 'request_pending') }
const noStore = (c: Ctx) => setResponseHeader(c.event, 'Cache-Control', 'no-store')

route('GET', '/pki/scep', 'admin', async () => {
  const [st, scep, pub, pending] = await Promise.all([readPkiStatus(), readPkiScep(), readPkiCas(), pkiRequestPending()])
  // seules les émettrices actives du DDI délivrent des certificats finaux ; SCEP exige une clé RSA (le PKCS#7 de l'équipement est chiffré pour elle)
  const issuers = (pub?.cas ?? []).filter((x) => x.kind === 'issuing' && x.state === 'active' && x.managed)
    .map((x) => ({ name: x.name, dn: x.dn, keyAlg: x.keyAlg, keyBits: x.keyBits, rsa: x.keyAlg === 'RSA', sha256: x.sha256, certUrl: x.files.cert ? `/pki/cas/${x.name}/cert` : '' }))
  return {
    installed: !!st?.installed, state: st?.state ?? 'absent', ready: st?.state === 'healthy', hostname: st?.hostname ?? '', requestPending: pending,
    alias: SCEP_ALIAS, challengeLen: CHALLENGE_LEN, scep, issuers,
  }
})

/** Une demande SANS référence (activation, désactivation, annulation) : une à la fois, on attend le résultat de root puis on le rend. */
async function simple(c: Ctx, req: Extract<PkiRequest, { action: 'scep_enable' | 'scep_disable' | 'scep_cancel' }>, detail?: Record<string, unknown>) {
  return serialized(async () => {
    await idle()
    const startedAt = Math.floor(Date.now() / 1000), before = await readPkiResult()
    await depositPkiRequest(req)
    const out = await awaitAction(req.action, startedAt, pkiRequestPending, { timeoutMs: cfg().pkiIssueTimeoutMs, before })
    if (!out.ok) {
      await audit(c, `pki.${req.action}_failed`, 'pki_scep', 'cn' in req ? req.cn : undefined, { ...detail, code: out.code, message: out.message.slice(0, 200) })
      if (out.code === 'timeout') fail(504, 'pki_timeout')
      fail(422, 'pki_scep_refused', undefined, { detail: out.message })
    }
    await audit(c, `pki.${req.action}`, 'pki_scep', 'cn' in req ? req.cn : undefined, detail)
    return { ok: true, message: out.message }
  })
}

route('POST', '/pki/scep/enable', 'admin', async (c) => { await needHealthy(); return simple(c, { action: 'scep_enable' }) })
route('POST', '/pki/scep/disable', 'admin', async (c) => { await needHealthy(); return simple(c, { action: 'scep_disable' }) })

/**
 * Dépose le défi (fichier SECRET) puis la demande, attend root, rend le défi. Jamais le défi dans l'audit, dans une erreur ni dans la demande JSON.
 * Quel que soit le résultat, le dépôt est effacé ici aussi (root l'efface déjà) : un défi ne reste jamais sur le disque.
 */
async function withChallenge(c: Ctx, build: (id: string) => PkiRequest, detail: Record<string, unknown>, target: string) {
  return serialized(async () => {
    await idle()
    const id = newIssueId(), challenge = newChallenge()
    const req = build(id)
    if (JSON.stringify(req).length > MAX_REQUEST_JSON) fail(400, 'pki_request_too_large')
    const startedAt = Math.floor(Date.now() / 1000)
    await putSecretDeposit(id, 'scepw', Buffer.from(challenge, 'utf8'))
    try { await depositPkiRequest(req) } catch (e) { await dropDeposit(id, 'scepw'); throw e }
    const out = await awaitRef(id, startedAt, { timeoutMs: cfg().pkiIssueTimeoutMs })
    await dropDeposit(id, 'scepw')
    if (!out.ok) {
      await audit(c, `pki.${req.action}_failed`, 'pki_scep', target, { ...detail, code: out.code, message: out.message.slice(0, 200) })
      if (out.code === 'refused') fail(422, 'pki_scep_refused', undefined, { detail: out.message })
      if (out.code === 'timeout') fail(504, 'pki_timeout')
      fail(502, 'pki_issue_unknown')
    }
    await audit(c, `pki.${req.action}`, 'pki_scep', target, detail)
    noStore(c)
    return { id, cn: target, challenge, message: out.message }
  })
}

// Préenregistrement : root crée l'entité dans EJBCA (nom, profil, SAN, défi) ; l'équipement s'inscrit ensuite seul, une fois, avant la fin du délai
route('POST', '/pki/scep/offers', 'admin', async (c) => {
  const b = await c.body(scepOfferBody)
  await needHealthy()
  const [scep, pub] = await Promise.all([readPkiScep(), readPkiCas()])
  if (!scep?.enabled) fail(409, 'pki_scep_disabled')
  const ca = pub?.cas.find((x) => x.name === b.ca)
  if (!ca) fail(404, 'not_found')
  if (ca.kind !== 'issuing' || ca.state !== 'active' || !ca.managed) fail(409, 'pki_ca_not_issuing')
  if (ca.keyAlg !== 'RSA') fail(409, 'pki_scep_ca_not_rsa')
  if (scep.offers.some((o) => o.cn.toLowerCase() === b.cn.toLowerCase())) fail(409, 'pki_scep_name_taken')
  const detail = { ca: b.ca, profile: b.profile, cn: b.cn }
  const r = await withChallenge(c, (id) => ({ ...issueRequest(id, b), action: 'scep_offer' }) as PkiRequest, detail, b.cn)
  return { ...r, ca: b.ca, profile: b.profile, offerDays: scep.offerDays, url: scep.url }
})

// Nouveau défi pour un équipement déjà préenregistré (renouvellement, remplacement de la clé, inscription ratée) : l'entité repasse à « nouveau »
route('POST', '/pki/scep/offers/:cn/rearm', 'admin', async (c) => {
  const cn = c.params.cn ?? ''
  if (!scepCnParam(cn)) fail(400, 'invalid_id')
  await needHealthy()
  const scep = await readPkiScep()
  if (!scep?.enabled) fail(409, 'pki_scep_disabled')
  const o = scep.offers.find((x) => x.cn === cn)
  if (!o) fail(404, 'not_found')
  const r = await withChallenge(c, (id) => ({ action: 'scep_rearm', id, cn }), { ca: o.ca, profile: o.profile, previous: o.state }, cn)
  return { ...r, ca: o.ca, profile: o.profile, offerDays: scep.offerDays, url: scep.url }
})

// Annulation : l'entité préenregistrée disparaît d'EJBCA ; les certificats déjà émis restent valables (ils se révoquent dans l'onglet « Certificats »)
route('DELETE', '/pki/scep/offers/:cn', 'admin', async (c) => {
  const cn = c.params.cn ?? ''
  if (!scepCnParam(cn)) fail(400, 'invalid_id')
  await needHealthy()
  const o = (await readPkiScep())?.offers.find((x) => x.cn === cn)
  if (!o) fail(404, 'not_found')
  return simple(c, { action: 'scep_cancel', cn }, { ca: o.ca, profile: o.profile, state: o.state })
})
