// 0.9.35 — découverte planifiée (échéance, validation) et règles d'hygiène de l'IPAM.
import { describe, expect, it } from 'vitest'
import { DEFAULT_SCHEDULE, ScheduleBody, isDue } from '../server/utils/discovery-schedule'
import { DEFAULT_THRESHOLDS, evaluate } from '../server/utils/alert-rules'
import type { Snapshot } from '../server/utils/alert-rules'

const last = (at: number) => ({ at, ok: true, scanned: 1, alive: 1, known: 1, unknown: 0, macChanged: 0 })
describe('échéance de la découverte planifiée', () => {
  const on = { ...DEFAULT_SCHEDULE, enabled: true, intervalHours: 24 }
  it('désactivée : jamais', () => expect(isDue(DEFAULT_SCHEDULE, null, 1e9)).toBe(false))
  it('jamais exécutée : due', () => expect(isDue(on, null, 1e9)).toBe(true))
  it('pas avant l\'intervalle', () => { expect(isDue(on, last(1e9 - 3600), 1e9)).toBe(false); expect(isDue(on, last(1e9 - 86400), 1e9)).toBe(true) })
})
describe('validation du réglage', () => {
  const ok = { enabled: true, intervalHours: 6, subnetIds: [1], methods: { tcp: false, icmp: true, arp: true, reverse: true, leases: true } }
  it('accepte un réglage valide', () => expect(ScheduleBody.safeParse(ok).success).toBe(true))
  it('refuse intervalle hors bornes, champ inconnu, trop de réseaux', () => {
    expect(ScheduleBody.safeParse({ ...ok, intervalHours: 0 }).success).toBe(false)
    expect(ScheduleBody.safeParse({ ...ok, intervalHours: 169 }).success).toBe(false)
    expect(ScheduleBody.safeParse({ ...ok, x: 1 }).success).toBe(false)
    expect(ScheduleBody.safeParse({ ...ok, subnetIds: Array.from({ length: 51 }, (_, i) => i + 1) }).success).toBe(false)
  })
})
describe('règles d\'hygiène', () => {
  const base = (hy?: Snapshot['hygiene']): Snapshot => ({ now: 1e9, cluster: null, localHealth: null, backup: null, backupResult: null, subnets: [], hygiene: hy })
  const keys = (s: Snapshot) => evaluate(s, DEFAULT_THRESHOLDS, { leader: null, leaderChangedAt: null }).findings.map((f) => f.rule).sort()
  it('non évalué (secondaire) : rien', () => expect(keys(base())).toEqual([]))
  it('fantômes : information ; rien à 0', () => {
    expect(keys(base({ ghosts: 3, ghostDays: 30, scanAt: null, unknown: 0, macChanged: 0 }))).toEqual(['ipam.ghosts'])
    expect(keys(base({ ghosts: 0, ghostDays: 30, scanAt: null, unknown: 0, macChanged: 0 }))).toEqual([])
  })
  it('inconnus et MAC changée : seulement si le dernier passage est récent (7 jours)', () => {
    expect(keys(base({ ghosts: 0, ghostDays: 30, scanAt: 1e9 - 100, unknown: 2, macChanged: 1 }))).toEqual(['ipam.mac_changed', 'ipam.unknown_hosts'])
    expect(keys(base({ ghosts: 0, ghostDays: 30, scanAt: 1e9 - 8 * 86400, unknown: 2, macChanged: 1 }))).toEqual([])
  })
})
