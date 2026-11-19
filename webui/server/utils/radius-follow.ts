// RADIUS actif / passif (0.15.0) : orchestration côté console (la logique de décision est dans radius-snapshot.ts).
// Sur le leader du cluster, quand le service ne tourne pas alors qu'un déploiement a été accepté, la console rejoue ce déploiement : c'est ce qui fait reprendre
// RADIUS par le nouveau leader après une bascule (root, lui, arrête le service sur le secondaire : « ddibuntu-radius align »).
import { getSetting, inRecovery, setSetting } from './db'
import { readClusterState } from './cluster'
import { depositRadiusRequest, radiusRequestPending, readRadiusResult, readRadiusStatus } from './radius'
import { crlSetDigest, readiness } from './radius-pki'
import { loadPki, savePki, withPki } from './radius-pki-store'
import { EMPTY_SNAPSHOT, followDecision, openApply, parseSnapshot, reconcile, resultKey, SNAPSHOT_KEY, sealApply, snapshotBusy } from './radius-snapshot'
import type { ApplyRequest, SnapshotState } from './radius-snapshot'

let chain: Promise<unknown> = Promise.resolve()
/** Les lectures-modifications-écritures de l'état se font l'une après l'autre (une seule console par nœud ; la base n'est écrite que sur le leader). */
function exclusive<T>(fn: () => Promise<T>): Promise<T> {
  const r = chain.then(fn, fn)
  chain = r.catch(() => undefined)
  return r
}

export async function loadSnapshot(): Promise<SnapshotState> { return parseSnapshot(await getSetting<unknown>(SNAPSHOT_KEY, EMPTY_SNAPSHOT)) }
const save = (s: SnapshotState) => setSetting(SNAPSHOT_KEY, s)

/** Lit l'état en y appliquant la réponse de root ; l'écrit seulement si ce nœud a la base en écriture (un secondaire lit sans rien modifier). */
export function reconcileNow(now = Math.floor(Date.now() / 1000)): Promise<SnapshotState> {
  return exclusive(async () => {
    const before = await loadSnapshot()
    const after = reconcile(before, await readRadiusResult(), now)
    if (JSON.stringify(after) !== JSON.stringify(before) && !(await inRecovery())) await save(after)
    return after
  })
}

/** Appelé par « Déployer » / « Arrêter » juste après le dépôt : la demande ne devient « le déploiement » que quand root l'a acceptée (reconcile). */
export function notePending(kind: 'apply' | 'stop', requestedAt: number, prev: string, req?: ApplyRequest): Promise<void> {
  return exclusive(async () => {
    const s = await loadSnapshot()
    await save({ ...s, pending: { kind, ...(req ? { enc: sealApply(req) } : {}), at: requestedAt, auto: false, prev } })
  })
}

/** Valeur à passer à notePending : le dernier résultat de root, lu AVANT de déposer la demande. */
export async function resultBeforeDeposit(): Promise<string> { return resultKey(await readRadiusResult()) }

/** Une demande déposée attend encore sa réponse : un nouveau dépôt serait inattribuable. */
export async function depositBusy(now = Math.floor(Date.now() / 1000)): Promise<boolean> {
  try { return snapshotBusy(await reconcileNow(now), now) } catch { return false }
}

/** Une passe de la tâche planifiée. Retourne la raison de l'absence d'action, ou « applied ». */
export async function radiusFollowTick(now = Math.floor(Date.now() / 1000)): Promise<string> {
  const recovery = await inRecovery()
  if (recovery) return 'ce nœud n\'est pas le leader'
  const state = await reconcileNow(now)
  const d = followDecision({ cluster: await readClusterState(), recovery, state, status: await readRadiusStatus(), requestPending: await radiusRequestPending(), now })
  if (!d.act) return d.reason
  return exclusive(async () => {
    const s = await loadSnapshot()
    const req = openApply(s.deployed)
    if (!req) { await save({ ...s, follow: { at: now, ok: false, message: 'le dernier déploiement est illisible : redéployer depuis la console' } }); return 'instantané illisible' }
    // les CRL de l'instantané peuvent dater : on repart de celles que la console tient à jour
    let fresh: string | null = null
    if (req.pki) {
      const pki = await loadPki()
      if (readiness(pki).ready) {
        const crls: Record<string, string> = {}
        for (const c of pki.cas) if (c.crl) crls[`${c.id}.pem`] = c.crl.pem
        req.pki = { ...req.pki, crls }
        fresh = crlSetDigest(pki)
      }
    }
    const prev = await resultBeforeDeposit()
    const r = await depositRadiusRequest(req)
    if (fresh) await withPki(async () => { const p = await loadPki(); await savePki({ ...p, crlPushed: fresh! }) })
    await save({ ...s, pending: { kind: 'apply', enc: s.deployed!, at: r.requestedAt, auto: true, prev }, follow: { at: r.requestedAt, ok: null, message: '' } })
    console.log('[radius-follow] ce nœud est le leader et RADIUS ne tourne pas : dernier déploiement rejoué')
    return 'applied'
  })
}
