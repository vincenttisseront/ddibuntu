// Plan de bascule (0.12.6) : check-list ordonnée. Les points « auto » se déduisent de l'état de la console, les autres se cochent à la main.
export const CUTOVER_ITEMS = [
  { id: 'ttl', auto: false }, { id: 'verify', auto: true }, { id: 'leases', auto: true }, { id: 'relay', auto: false },
  { id: 'stop_windows', auto: false }, { id: 'promote', auto: true }, { id: 'clients_dns', auto: false },
] as const
export type CutoverId = (typeof CUTOVER_ITEMS)[number]['id']
export const LEASE_FRESH_MS = 30 * 60_000

export interface CutoverCtx { reviewDone: boolean; leasePushAt: string | null; secondaryLeft: number; now: number }
export interface CutoverItem { id: CutoverId; auto: boolean; done: boolean }

export const parseCutover = (raw: unknown): { started: { at: string; by: string | null; snapshotId: number } | null; manual: Record<string, boolean>; finishedAt: string | null } => {
  const o = (raw && typeof raw === 'object' ? raw : {}) as any
  const s = o.started && typeof o.started === 'object' && Number.isInteger(o.started.snapshotId) ? o.started : null
  const manual: Record<string, boolean> = {}
  for (const i of CUTOVER_ITEMS) manual[i.id] = o.manual?.[i.id] === true
  return { started: s ? { at: String(s.at ?? ''), by: s.by ?? null, snapshotId: s.snapshotId } : null, manual, finishedAt: typeof o.finishedAt === 'string' ? o.finishedAt : null }
}

export function cutoverItems(manual: Record<string, boolean>, ctx: CutoverCtx): CutoverItem[] {
  const auto: Record<string, boolean> = {
    verify: ctx.reviewDone,
    leases: !!ctx.leasePushAt && ctx.now - Date.parse(ctx.leasePushAt) <= LEASE_FRESH_MS,
    promote: ctx.secondaryLeft === 0,
  }
  return CUTOVER_ITEMS.map((i) => ({ id: i.id, auto: i.auto, done: i.auto ? !!auto[i.id] : manual[i.id] === true }))
}
