import { describe, expect, it } from 'vitest'
import { drillBusy, parseDrillCheck, parseDrillLive, parseDrillReport, parseDrills } from '../server/utils/drill'

const NOW = 1_800_000_000
const metrics = (over: Record<string, unknown> = {}) => ({ noPrimaryMs: 3003, resolutionMs: 507, promotionMs: 3450, demotionMs: 949, rejoinMs: 5450, catchUpMs: 2000, timeline: [2, 3], lagMaxBytes: 0, lsnContinuity: true, settleMs: 6175, ...over })
const phase = (name: string, from: string, to: string, over: Record<string, unknown> = {}) => ({
  name, from, to, cmdRc: 0, cmdMs: 3673, output: 'Successfully switched over', metrics: metrics(),
  verdicts: { noPrimary: 'ok', promotion: 'ok', rejoin: 'ok', catchUp: 'ok', timeline: 'ok', lsn: 'ok' },
  post: [{ id: 'leader', status: 'ok', detail: 'primaire : ' + to }, { id: 'quorum', status: 'ok', detail: 'quorum etcd : 3/3 voix saines (avant : 3)' }], ok: true, ...over })
const report = (over: Record<string, unknown> = {}) => ({
  v: 1, id: '20261111T163812Z', cluster: 'lab', node: 'n1', by: 'console', startedAt: NOW - 600, back: true, from: 'n1', to: 'n2',
  pre: { ok: true, checks: [{ id: 'topology', status: 'ok', detail: 'primaire : n1 ; 2 nœuds de données joignables' }, { id: 'kea', status: 'skip', detail: 'Kea ne répond pas' }], candidates: [{ name: 'n2', ok: true, lagBytes: 0, issues: [] }] },
  phases: [phase('switch', 'n1', 'n2'), phase('back', 'n2', 'n1')],
  events: [{ t: 396, kind: 'step', node: 'n1', detail: 'commande de bascule vers n2' }, { t: 1345, kind: 'leader', node: '-', detail: 'plus aucun primaire' }],
  resolutionMs: 507, outcome: 'success', finishedAt: NOW - 580, durationMs: 19503,
  thresholds: { noPrimaryMs: [15000, 30000], promotionMs: [30000, 60000], rejoinMs: [90000, 150000], catchUpLagBytes: 16384, maxLagBytes: 1048576 }, ...over })

describe('rapport de test de bascule', () => {
  it('relit un rapport complet tel que le produit root', () => {
    const r = parseDrillReport(report())!
    expect(r).toMatchObject({ id: '20261111T163812Z', by: 'console', from: 'n1', to: 'n2', back: true, outcome: 'success', durationMs: 19503 })
    expect(r.phases.map((p) => `${p.name}:${p.from}>${p.to}`)).toEqual(['switch:n1>n2', 'back:n2>n1'])
    expect(r.phases[0]!.metrics).toMatchObject({ noPrimaryMs: 3003, promotionMs: 3450, rejoinMs: 5450, catchUpMs: 2000, timeline: [2, 3], lsnContinuity: true })
    expect(r.phases[0]!.verdicts).toEqual({ noPrimary: 'ok', promotion: 'ok', rejoin: 'ok', catchUp: 'ok', timeline: 'ok', lsn: 'ok' })
    expect(r.pre.checks.map((c) => c.status)).toEqual(['ok', 'skip']); expect(r.events).toHaveLength(2)
    expect(r.thresholds.noPrimaryMs).toEqual([15000, 30000])
  })
  it('rapport refusé (pré-contrôles) : pas de phase, message conservé', () => {
    const r = parseDrillReport(report({ outcome: 'refused', phases: [], events: [], message: 'pré-contrôles non satisfaits', pre: { ok: false, checks: [{ id: 'lag', status: 'fail', detail: 'retard de 9 Mo' }], candidates: [] } }))!
    expect(r.outcome).toBe('refused'); expect(r.phases).toEqual([]); expect(r.pre.ok).toBe(false); expect(r.pre.checks[0]).toMatchObject({ id: 'lag', status: 'fail' })
  })
  it('refuse ce qui n’est pas un rapport v1 : version, identifiant, issue', () => {
    expect(parseDrillReport(null)).toBeNull(); expect(parseDrillReport('x')).toBeNull(); expect(parseDrillReport([])).toBeNull()
    expect(parseDrillReport(report({ v: 2 }))).toBeNull(); expect(parseDrillReport(report({ id: '../etc/passwd' }))).toBeNull()
    expect(parseDrillReport(report({ id: '20261111T163812Z/x' }))).toBeNull(); expect(parseDrillReport(report({ outcome: 'ok' }))).toBeNull()
  })
  it('valeurs hostiles ou hors bornes assainies, champs inconnus jamais recopiés', () => {
    const h = parseDrillReport(report({
      secret: 'topsecret', node: 'x'.repeat(500), by: '<img>', from: 'N 1', to: { a: 1 }, message: 'm'.repeat(1000), resolutionMs: -5, durationMs: 'long',
      phases: [phase('switch', 'n1', 'n2', { output: 'o'.repeat(1000), metrics: metrics({ noPrimaryMs: -1, promotionMs: 'vite', timeline: ['a'], lsnContinuity: 'oui', lagMaxBytes: 1e30 }), verdicts: { noPrimary: 'génial', lsn: 'warn' }, post: [{ id: '', status: 'ok', detail: 'sans id' }, { id: 'x', status: 'excellent', detail: 'd'.repeat(999) }], hack: 1 }),
        phase('autre', 'n1', 'n2'), phase('back', 'n2', 'N3'), phase('back', 'n2', 'n1'), phase('back', 'n2', 'n1')],
      events: [{ t: 'x', kind: 'k', node: 'n1', detail: 'sans temps' }, { t: 5, kind: 'k'.repeat(99), node: 'n'.repeat(99), detail: 'd'.repeat(999) }, ...Array.from({ length: 500 }, (_, i) => ({ t: i, kind: 'step', node: 'n1', detail: 'e' }))],
      thresholds: { noPrimaryMs: ['a', 1], promotionMs: [1, 2, 3], catchUpLagBytes: -1 },
    }))!
    expect(JSON.stringify(h)).not.toContain('topsecret'); expect(JSON.stringify(h)).not.toContain('hack')
    expect(h.node.length).toBe(63); expect(h.by).toBe('cli'); expect(h.from).toBeNull(); expect(h.to).toBeNull(); expect(h.message.length).toBe(300)
    expect(h.resolutionMs).toBe(0); expect(h.durationMs).toBe(0)
    expect(h.phases.map((x) => x.name)).toEqual(['switch'])   // seules les deux premières phases sont examinées ; une phase mal nommée est écartée
    expect(parseDrillReport(report({ phases: [phase('switch', 'n1', 'n2'), phase('back', 'n2', 'n1'), phase('back', 'n2', 'n1')] }))!.phases).toHaveLength(2)   // deux au plus
    const p = h.phases[0]!
    expect(p.output.length).toBe(200)
    expect(p.metrics).toMatchObject({ noPrimaryMs: null, promotionMs: null, timeline: [null, null], lsnContinuity: null, lagMaxBytes: null })
    expect(p.verdicts).toMatchObject({ noPrimary: 'fail', lsn: 'warn', rejoin: 'fail' })   // inconnu = écart, jamais « ok »
    expect(p.post.map((c) => c.status)).toEqual(['fail']); expect(p.post[0]!.detail.length).toBe(240)
    expect(h.events.length).toBeLessThanOrEqual(200); expect(h.events.every((e) => e.kind.length <= 16 && e.node.length <= 40 && e.detail.length <= 120)).toBe(true)
    expect(h.thresholds).toEqual({ noPrimaryMs: [15000, 30000], promotionMs: [30000, 60000], rejoinMs: [90000, 150000], catchUpLagBytes: 16384, maxLagBytes: 1048576 })
  })
})

describe('liste des rapports et test en cours', () => {
  const view = (over: Record<string, unknown> = {}) => JSON.stringify({ at: NOW - 10, active: null, reports: [report(), report({ id: '20261110T080000Z', outcome: 'failed' })], ...over })
  it('relit les rapports (les plus récents d’abord, tels que publiés) et ignore les entrées invalides', () => {
    const v = parseDrills(view(), NOW)!
    expect(v.reports.map((r) => r.id)).toEqual(['20261111T163812Z', '20261110T080000Z']); expect(v.active).toBeNull()
    const w = parseDrills(view({ reports: [report(), { v: 1, id: 'nimporte quoi' }, 'x', null, report({ id: '20261109T010101Z', outcome: 'warning' })] }), NOW)!
    expect(w.reports.map((r) => r.outcome)).toEqual(['success', 'warning'])
    expect(parseDrills(view({ reports: Array.from({ length: 40 }, (_, i) => report({ id: `2026010${i % 9 + 1}T000000Z` })) }), NOW)!.reports).toHaveLength(10)
  })
  it('fichier mal formé : ignoré', () => {
    expect(parseDrills('pas du json', NOW)).toBeNull(); expect(parseDrills('[]', NOW)).toBeNull(); expect(parseDrills('{"at":1}', NOW)).toBeNull(); expect(parseDrills('{"reports":[]}', NOW)).toBeNull()
  })
  it('marque « en cours » : valable 20 minutes, jamais d’un nœud ou d’un identifiant douteux', () => {
    const a = { id: '20261111T163812Z', node: 'n1', at: NOW - 30, phase: 'switch' }
    expect(parseDrills(view({ active: a }), NOW)!.active).toEqual(a)
    expect(parseDrills(view({ active: { ...a, at: NOW - 1300 } }), NOW)!.active).toBeNull()   // abandonnée (nœud mort en plein test)
    expect(parseDrills(view({ active: { ...a, at: NOW + 500 } }), NOW)!.active).toBeNull()    // horodatage dans le futur
    expect(parseDrills(view({ active: { ...a, node: 'N 1' } }), NOW)!.active).toBeNull()
    expect(parseDrills(view({ active: { ...a, id: 'x' } }), NOW)!.active).toBeNull()
    expect(parseDrills(view({ active: { ...a, phase: 'p'.repeat(99) } }), NOW)!.active!.phase.length).toBe(20)
  })
})

describe('pré-contrôles et avancement en direct', () => {
  const chk = (over: Record<string, unknown> = {}) => JSON.stringify({ ok: true, at: NOW - 5, leader: 'n1', candidate: 'n2', candidates: [{ name: 'n2', ok: true, lagBytes: 0, issues: [] }], checks: [{ id: 'topology', status: 'ok', detail: 'primaire : n1' }, { id: 'vip', status: 'skip', detail: 'pas de VIP' }], ...over })
  it('pré-contrôles : lus, âge calculé, statuts inconnus = écart', () => {
    const c = parseDrillCheck(chk(), NOW)!
    expect(c).toMatchObject({ ok: true, ageSeconds: 5, leader: 'n1', candidate: 'n2' }); expect(c.candidates[0]).toEqual({ name: 'n2', ok: true, lagBytes: 0, issues: [] })
    const h = parseDrillCheck(chk({ ok: 'oui', leader: 'N 1', candidate: 7, candidates: [{ name: 'x y', ok: true }, { name: 'n9', ok: true, issues: ['a'.repeat(999)] }], checks: [{ id: 'a', status: 'génial', detail: 'x' }, { status: 'ok' }] }), NOW)!
    expect(h.ok).toBe(false); expect(h.leader).toBeNull(); expect(h.candidate).toBeNull()
    expect(h.candidates.map((x) => x.name)).toEqual(['n9']); expect(h.candidates[0]!.issues[0]!.length).toBe(160)
    expect(h.checks).toEqual([{ id: 'a', status: 'fail', detail: 'x' }])
    expect(parseDrillCheck('x', NOW)).toBeNull(); expect(parseDrillCheck('{"ok":true}', NOW)).toBeNull()
  })
  const live = (over: Record<string, unknown> = {}) => JSON.stringify({ type: 'live', id: '20261111T163812Z', node: 'n1', phase: 'switch', startedAt: NOW - 20, at: NOW - 2, elapsedMs: 18000, steps: [{ t: 0, text: 'pré-contrôles' }, { t: 396, text: 'bascule n1 → n2' }], ...over })
  it('avancement : « en cours » tant que le dernier signe de vie a moins de 15 s', () => {
    const l = parseDrillLive(live(), NOW)!
    expect(l).toMatchObject({ id: '20261111T163812Z', node: 'n1', phase: 'switch', running: true, ageSeconds: 2 }); expect(l.steps).toHaveLength(2)
    expect(parseDrillLive(live({ at: NOW - 60 }), NOW)!.running).toBe(false)   // fichier resté après un arrêt brutal
    expect(parseDrillLive(live({ type: 'report' }), NOW)).toBeNull(); expect(parseDrillLive(live({ id: 'x' }), NOW)).toBeNull(); expect(parseDrillLive(live({ node: 'N' }), NOW)).toBeNull()
    expect(parseDrillLive(live({ steps: Array.from({ length: 50 }, (_, i) => ({ t: i, text: 't'.repeat(999) })) }), NOW)!.steps).toHaveLength(12)
    expect(parseDrillLive('', NOW)).toBeNull()
  })
  it('occupé = marque etcd valable OU avancement vivant', () => {
    const v = parseDrills(JSON.stringify({ at: NOW, active: { id: '20261111T163812Z', node: 'n1', at: NOW - 5, phase: 'back' }, reports: [] }), NOW)
    const idle = parseDrills(JSON.stringify({ at: NOW, active: null, reports: [] }), NOW)
    expect(drillBusy(v, null)).toBe(true); expect(drillBusy(idle, null)).toBe(false); expect(drillBusy(null, null)).toBe(false)
    expect(drillBusy(idle, parseDrillLive(live(), NOW))).toBe(true); expect(drillBusy(idle, parseDrillLive(live({ at: NOW - 99 }), NOW))).toBe(false)
  })
})
