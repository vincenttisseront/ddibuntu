import { describe, expect, it } from 'vitest'
import { planLeases } from '../server/utils/lease-import'

const SC = [{ id: 7, cidr: '10.90.0.0/24', leaseTime: 3600 }]
const NOW = new Date('2026-11-13T10:00:00Z')
const CSV = `"IPAddress","ClientId","HostName","AddressState","ExpiryUtc"
"10.90.0.20","aa-bb-cc-00-00-20","PC-Alice.corp.local","Active","2026-11-14T10:00:00"
"10.90.0.21","aa-bb-cc-00-00-21","","Active","2026-11-14T10:00:00"
"10.90.0.22","aa-bb-cc-00-00-22","vieux","Active","2026-11-12T10:00:00"
"10.90.0.23","aa-bb-cc-00-00-23","res","ActiveReservation","2026-11-14T10:00:00"
"10.99.0.1","aa-bb-cc-00-00-24","ailleurs","Active","2026-11-14T10:00:00"
"pas-une-ip","aa-bb-cc-00-00-25","x","Active","2026-11-14T10:00:00"
"10.90.0.26","zz","x","Active","2026-11-14T10:00:00"
"10.90.0.20","aa-bb-cc-00-00-20","doublon","Active","2026-11-14T10:00:00"`

describe('reprise des baux Windows', () => {
  it('classe chaque ligne ; nom court en minuscules ; expiration lue en UTC', () => {
    const p = planLeases(CSV, SC, NOW)
    expect(p.total).toBe(8)
    expect(p.import.map((l) => [l.ip, l.mac, l.hostname, l.scopeId, l.lifetime])).toEqual([['10.90.0.20', 'aa:bb:cc:00:00:20', 'pc-alice', 7, 3600], ['10.90.0.21', 'aa:bb:cc:00:00:21', null, 7, 3600]])
    expect(p.import[0]!.expire.toISOString()).toBe('2026-11-14T10:00:00.000Z'); expect(p.import[0]!.n).toBe(10 * 2 ** 24 + 90 * 2 ** 16 + 20)
    expect(p.skipped).toEqual({ invalid: 3, not_active: 1, expired: 1, no_scope: 1 })
  })
  it('CSV sans les bonnes colonnes ou vide : erreur, rien à importer', () => {
    expect(planLeases('a,b\n1,2', SC, NOW)).toMatchObject({ errors: ['leases_csv_invalid'], import: [] })
    expect(planLeases('', SC, NOW).errors).toEqual(['leases_csv_invalid'])
  })
})
