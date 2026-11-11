// Test de bascule guidé (0.9.3) : rapports, pré-contrôles et avancement publiés par root (ddibuntu-cluster drill), lus ici en lecture seule.
// Les fichiers viennent d'un processus root mais transitent par des données de cluster : tout est relu champ par champ, borné, jamais copié tel quel.
import { promises as fs } from 'node:fs'
import { dirname, join } from 'node:path'
import { cfg } from './config'

export type DrillStatus = 'ok' | 'warn' | 'fail' | 'skip'
export interface DrillCheckItem { id: string; status: DrillStatus; detail: string }
export interface DrillCandidate { name: string; ok: boolean; lagBytes: number | null; issues: string[] }
export interface DrillCheck { ok: boolean; at: number; ageSeconds: number; leader: string | null; candidate: string | null; candidates: DrillCandidate[]; checks: DrillCheckItem[] }
export interface DrillMetrics {
  noPrimaryMs: number | null; resolutionMs: number | null; promotionMs: number | null; demotionMs: number | null; rejoinMs: number | null; catchUpMs: number | null
  timeline: [number | null, number | null]; lagMaxBytes: number | null; lsnContinuity: boolean | null; settleMs: number | null
}
export interface DrillPhase {
  name: 'switch' | 'back'; from: string; to: string; cmdRc: number | null; cmdMs: number | null; output: string
  metrics: DrillMetrics; verdicts: Record<string, DrillStatus>; post: DrillCheckItem[]; ok: boolean
}
export interface DrillEvent { t: number; kind: string; node: string; detail: string }
export type DrillOutcome = 'success' | 'warning' | 'failed' | 'refused'
export interface DrillReport {
  id: string; cluster: string; node: string; by: 'cli' | 'console'; startedAt: number; finishedAt: number; durationMs: number; back: boolean
  from: string | null; to: string | null; outcome: DrillOutcome; message: string; resolutionMs: number
  pre: { ok: boolean; checks: DrillCheckItem[]; candidates: DrillCandidate[] }
  phases: DrillPhase[]; events: DrillEvent[]
  thresholds: { noPrimaryMs: [number, number]; promotionMs: [number, number]; rejoinMs: [number, number]; catchUpLagBytes: number; maxLagBytes: number }
}
export interface DrillActive { id: string; node: string; at: number; phase: string }
export interface DrillsView { at: number; active: DrillActive | null; reports: DrillReport[] }
export interface DrillLive { id: string; node: string; phase: string; startedAt: number; at: number; elapsedMs: number; ageSeconds: number; running: boolean; steps: { t: number; text: string }[] }

export const DRILL_ID_RE = /^[0-9]{8}T[0-9]{6}Z$/
const NODE_RE = /^[a-z][a-z0-9-]{1,30}$/
const ACTIVE_TTL = 1200          // même durée que côté root : une marque plus vieille est abandonnée
const LIVE_FRESH = 15            // le moniteur émet un signe de vie toutes les 3 s
const MAX_FILE = 3 * 1024 * 1024

const rec = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {})
const str = (v: unknown, max = 128) => (typeof v === 'string' ? [...v].filter((c) => c >= ' ' && c !== '\x7f').join('').slice(0, max) : '')
const num = (v: unknown, lo = -1e15, hi = 1e15): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= lo && v <= hi ? v : null)
const nodeName = (v: unknown): string | null => (typeof v === 'string' && NODE_RE.test(v) ? v : null)
const status = (v: unknown, allowSkip: boolean): DrillStatus => (v === 'ok' || v === 'warn' || v === 'fail' || (allowSkip && v === 'skip') ? v : 'fail')
const ms = (v: unknown) => num(v, 0, 86_400_000)

function checkItems(v: unknown, allowSkip = true): DrillCheckItem[] {
  if (!Array.isArray(v)) return []
  return v.slice(0, 24).map((c) => { const o = rec(c); return { id: str(o.id, 24), status: status(o.status, allowSkip), detail: str(o.detail, 240) } }).filter((c) => c.id)
}
function candidates(v: unknown): DrillCandidate[] {
  if (!Array.isArray(v)) return []
  return v.slice(0, 16).flatMap((c) => {
    const o = rec(c), name = nodeName(o.name); if (!name) return []
    return [{ name, ok: o.ok === true, lagBytes: num(o.lagBytes, 0, 1e15), issues: Array.isArray(o.issues) ? o.issues.slice(0, 8).map((x) => str(x, 160)) : [] }]
  })
}

export function parseDrillCheck(raw: string, nowSec = Date.now() / 1000): DrillCheck | null {
  let j: unknown; try { j = JSON.parse(raw) } catch { return null }
  const o = rec(j); const at = num(o.at, 0, 1e11); if (at === null || !Array.isArray(o.checks)) return null
  return { ok: o.ok === true, at, ageSeconds: Math.max(0, Math.round(nowSec - at)), leader: nodeName(o.leader), candidate: nodeName(o.candidate), candidates: candidates(o.candidates), checks: checkItems(o.checks) }
}

function parseMetrics(v: unknown): DrillMetrics {
  const o = rec(v), tl = Array.isArray(o.timeline) ? o.timeline : []
  return {
    noPrimaryMs: ms(o.noPrimaryMs), resolutionMs: ms(o.resolutionMs), promotionMs: ms(o.promotionMs), demotionMs: ms(o.demotionMs), rejoinMs: ms(o.rejoinMs), catchUpMs: ms(o.catchUpMs),
    timeline: [num(tl[0], 0, 1e9), num(tl[1], 0, 1e9)], lagMaxBytes: num(o.lagMaxBytes, 0, 1e15), lsnContinuity: typeof o.lsnContinuity === 'boolean' ? o.lsnContinuity : null, settleMs: ms(o.settleMs),
  }
}
const VERDICT_KEYS = ['noPrimary', 'promotion', 'rejoin', 'catchUp', 'timeline', 'lsn']
function parsePhase(v: unknown): DrillPhase | null {
  const o = rec(v), from = nodeName(o.from), to = nodeName(o.to)
  if ((o.name !== 'switch' && o.name !== 'back') || !from || !to) return null
  const vv = rec(o.verdicts), verdicts: Record<string, DrillStatus> = {}
  for (const k of VERDICT_KEYS) verdicts[k] = status(vv[k], false)
  return { name: o.name, from, to, cmdRc: num(o.cmdRc, -1000, 1000), cmdMs: ms(o.cmdMs), output: str(o.output, 200), metrics: parseMetrics(o.metrics), verdicts, post: checkItems(o.post, false), ok: o.ok === true }
}
function parseEvents(v: unknown): DrillEvent[] {
  if (!Array.isArray(v)) return []
  return v.slice(0, 200).flatMap((e) => { const o = rec(e), t = ms(o.t); return t === null ? [] : [{ t, kind: str(o.kind, 16), node: str(o.node, 40), detail: str(o.detail, 120) }] })
}
function pair(v: unknown, d: [number, number]): [number, number] {
  return Array.isArray(v) && v.length === 2 && typeof v[0] === 'number' && typeof v[1] === 'number' && v[0] >= 0 && v[0] <= v[1] && v[1] <= 86_400_000 ? [v[0], v[1]] : d
}
export function parseDrillReport(j: unknown): DrillReport | null {
  const o = rec(j); const id = typeof o.id === 'string' && DRILL_ID_RE.test(o.id) ? o.id : null
  if (o.v !== 1 || !id) return null
  const outcome = o.outcome === 'success' || o.outcome === 'warning' || o.outcome === 'failed' || o.outcome === 'refused' ? o.outcome : null
  if (!outcome) return null
  const pre = rec(o.pre), th = rec(o.thresholds)
  return {
    id, cluster: str(o.cluster, 63), node: str(o.node, 63), by: o.by === 'console' ? 'console' : 'cli', startedAt: num(o.startedAt, 0, 1e11) ?? 0, finishedAt: num(o.finishedAt, 0, 1e11) ?? 0,
    durationMs: ms(o.durationMs) ?? 0, back: o.back === true, from: nodeName(o.from), to: nodeName(o.to), outcome, message: str(o.message, 300), resolutionMs: ms(o.resolutionMs) ?? 0,
    pre: { ok: pre.ok === true, checks: checkItems(pre.checks), candidates: candidates(pre.candidates) },
    phases: (Array.isArray(o.phases) ? o.phases.slice(0, 2) : []).map(parsePhase).filter((p): p is DrillPhase => p !== null),
    events: parseEvents(o.events),
    thresholds: {
      noPrimaryMs: pair(th.noPrimaryMs, [15000, 30000]), promotionMs: pair(th.promotionMs, [30000, 60000]), rejoinMs: pair(th.rejoinMs, [90000, 150000]),
      catchUpLagBytes: num(th.catchUpLagBytes, 0, 1e12) ?? 16384, maxLagBytes: num(th.maxLagBytes, 0, 1e12) ?? 1048576,
    },
  }
}

export function parseDrills(raw: string, nowSec = Date.now() / 1000): DrillsView | null {
  let j: unknown; try { j = JSON.parse(raw) } catch { return null }
  const o = rec(j); const at = num(o.at, 0, 1e11); if (at === null || !Array.isArray(o.reports)) return null
  const reports = o.reports.slice(0, 10).map(parseDrillReport).filter((r): r is DrillReport => r !== null)
  const a = rec(o.active), aat = num(a.at, 0, 1e11)
  const active: DrillActive | null = typeof a.id === 'string' && DRILL_ID_RE.test(a.id) && nodeName(a.node) && aat !== null && nowSec - aat >= 0 && nowSec - aat < ACTIVE_TTL
    ? { id: a.id, node: String(a.node), at: aat, phase: str(a.phase, 20) } : null
  return { at, active, reports }
}

export function parseDrillLive(raw: string, nowSec = Date.now() / 1000): DrillLive | null {
  let j: unknown; try { j = JSON.parse(raw) } catch { return null }
  const o = rec(j), at = num(o.at, 0, 1e11), id = typeof o.id === 'string' && DRILL_ID_RE.test(o.id) ? o.id : null, node = nodeName(o.node)
  if (o.type !== 'live' || at === null || !id || !node) return null
  const age = Math.max(0, Math.round(nowSec - at))
  return {
    id, node, phase: str(o.phase, 20), startedAt: num(o.startedAt, 0, 1e11) ?? 0, at, elapsedMs: ms(o.elapsedMs) ?? 0, ageSeconds: age, running: age <= LIVE_FRESH,
    steps: (Array.isArray(o.steps) ? o.steps.slice(-12) : []).flatMap((s) => { const x = rec(s), t = ms(x.t); return t === null ? [] : [{ t, text: str(x.text, 140) }] }),
  }
}

// ---- lecture des fichiers publiés (à côté de l'état du cluster)
async function readBounded(name: string): Promise<string | null> {
  try {
    const f = join(dirname(cfg().clusterStatusFile), name)
    const st = await fs.stat(f)
    if (!st.isFile() || st.size > MAX_FILE) return null
    return await fs.readFile(f, 'utf8')
  } catch { return null }
}
export async function readDrills(): Promise<DrillsView | null> { const r = await readBounded('cluster-drills.json'); return r === null ? null : parseDrills(r) }
export async function readDrillCheck(): Promise<DrillCheck | null> { const r = await readBounded('cluster-drill-check.json'); return r === null ? null : parseDrillCheck(r) }
export async function readDrillLive(): Promise<DrillLive | null> { const r = await readBounded('cluster-drill-live.json'); return r === null ? null : parseDrillLive(r) }

// Un test est « en cours » si root en a posé la marque (etcd, valable 20 min) ou si son avancement donne encore signe de vie.
export function drillBusy(view: DrillsView | null, live: DrillLive | null): boolean { return !!view?.active || !!live?.running }
