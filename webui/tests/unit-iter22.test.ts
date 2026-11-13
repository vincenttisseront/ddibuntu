import { describe, expect, it } from 'vitest'
import { leaseLabel, parseLeaseDns, planLeaseDns } from '../server/utils/lease-dns'

describe('synchronisation bail → DNS (fonctions pures)', () => {
  it('nom relatif à la zone', () => {
    expect(leaseLabel('PC-Alice', 'corp.test')).toBe('pc-alice')
    expect(leaseLabel('pc-alice.corp.test.', 'corp.test')).toBe('pc-alice')
    expect(leaseLabel('pc-alice.autre.domaine', 'corp.test')).toBe('pc-alice')   // domaine étranger : premier label
    expect(leaseLabel('-bad', 'corp.test')).toBeNull()
    expect(leaseLabel('a_b', 'corp.test')).toBeNull()
    expect(leaseLabel('', 'corp.test')).toBeNull()
    expect(leaseLabel(null, 'corp.test')).toBeNull()
    expect(leaseLabel('x'.repeat(64), 'corp.test')).toBeNull()
  })
  it('réglage : désactivé sauf true explicite', () => {
    expect(parseLeaseDns(null)).toEqual({ enabled: false }); expect(parseLeaseDns({ enabled: 'true' })).toEqual({ enabled: false }); expect(parseLeaseDns({ enabled: true })).toEqual({ enabled: true })
  })
  it('plan : ajouts et retraits, insensible à la casse, idempotent', () => {
    const a = { zone_id: 1, name: 'pc', type: 'A' as const, rdata: '10.0.0.5' }, p = { zone_id: 2, name: '5.0.0', type: 'PTR' as const, rdata: 'pc.corp.test.' }
    expect(planLeaseDns([a, p], [])).toEqual({ add: [a, p], del: [] })
    expect(planLeaseDns([a, p], [{ ...a, id: 1 }, { ...p, id: 2 }])).toEqual({ add: [], del: [] })
    const old = { zone_id: 1, name: 'PC', type: 'A' as const, rdata: '10.0.0.9', id: 7 }
    expect(planLeaseDns([a], [old])).toEqual({ add: [a], del: [old] })
    expect(planLeaseDns([], [{ ...a, id: 1 }]).del).toHaveLength(1)
  })
})
