import { describe, expect, it } from 'vitest'
import { compareDhcp, compareDns, normAnswer } from '../server/utils/migration-verify'

const win = (o: any = {}) => ({ warnings: [], scopes: [{ cidr: '10.0.0.0/24', name: 'a', leaseTime: 3600, enabled: true, pools: [{ start: '10.0.0.10', end: '10.0.0.50' }], options: { routers: ['10.0.0.1'] }, reservations: [{ mac: 'AA:BB:CC:00:00:01', ip: '10.0.0.5', hostname: 'h', description: null }], exclusions: [], ...o }] })
const db = (o: any = {}) => ({ cidr: '10.0.0.0/24', lease_time: 3600, enabled: true, options: { routers: ['10.0.0.1'] }, pools: [{ start: '10.0.0.10', end: '10.0.0.50' }], reservations: [{ mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.5', hostname: 'h' }], ...o })

describe('vérification avant bascule', () => {
  it('DHCP identique : aucun écart (casse et séparateurs des MAC ignorés)', () => { expect(compareDhcp(win(), [db()])).toEqual([]) })
  it('DHCP : chaque écart est nommé', () => {
    const kinds = (w: any, d: any[]) => compareDhcp(win(w), d).map((f) => f.kind).sort()
    expect(kinds({}, [])).toEqual(['scope_missing'])
    expect(kinds({}, [db(), db({ cidr: '10.1.0.0/24' })])).toEqual(['scope_extra'])
    expect(kinds({ leaseTime: 60, enabled: false }, [db()])).toEqual(['lease_differs', 'state_differs'])
    expect(kinds({}, [db({ pools: [{ start: '10.0.0.10', end: '10.0.0.60' }] })])).toEqual(['pool_extra', 'pool_missing'])
    expect(kinds({}, [db({ reservations: [{ mac: 'aa:bb:cc:00:00:01', ip: '10.0.0.6', hostname: 'h' }] })])).toEqual(['reservation_differs'])
    expect(kinds({}, [db({ reservations: [{ mac: 'aa:bb:cc:00:00:09', ip: '10.0.0.6', hostname: null }] })])).toEqual(['reservation_extra', 'reservation_missing'])
    expect(kinds({ options: { routers: ['10.0.0.2'] } }, [db()])).toEqual(['option_differs'])
  })
  it('DNS : normalisation (casse, point final, doublons, ordre) et écarts, serveur muet compris', async () => {
    expect(normAnswer(['B.', 'a', 'A', ''])).toEqual(['a', 'b'])
    const run = async (s: string, n: string) => (n === 'x' ? ['1.1.1.1', '2.2.2.2'] : n === 'y' ? (s === 'w' ? ['1.1.1.1'] : ['2.2.2.2']) : s === 'w' ? null : [])
    const out = await compareDns([{ name: 'x', type: 'A' }, { name: 'y', type: 'A' }, { name: 'z', type: 'A' }], 'w', 'd', run)
    expect(out.checked).toBe(3); expect(out.diffs.map((d) => d.name)).toEqual(['y', 'z']); expect(out.diffs[1]).toMatchObject({ windows: null, ddi: [] })
  })
})

import { cutoverItems, parseCutover } from '../server/utils/cutover'
import { PS_CUTOVER_ROLLBACK, PS_CUTOVER_STOP, PS_CUTOVER_TTL } from '../app/utils/migration-scripts'
describe('plan de bascule (logique)', () => {
  const now = Date.parse('2026-11-13T12:00:00Z')
  it('points automatiques déduits ; baux périmés ou zones encore secondaires = pas fait', () => {
    const f = (o: any) => Object.fromEntries(cutoverItems({ ttl: true }, { reviewDone: true, leasePushAt: '2026-11-13T11:50:00Z', secondaryLeft: 0, now, ...o }).map((i) => [i.id, i.done]))
    expect(f({})).toMatchObject({ ttl: true, verify: true, leases: true, promote: true, relay: false })
    expect(f({ leasePushAt: '2026-11-13T11:00:00Z' }).leases).toBe(false); expect(f({ leasePushAt: null }).leases).toBe(false)
    expect(f({ secondaryLeft: 2 }).promote).toBe(false); expect(f({ reviewDone: false }).verify).toBe(false)
  })
  it('lecture tolérante de l\'état enregistré', () => {
    expect(parseCutover(null)).toMatchObject({ started: null, finishedAt: null }); expect(parseCutover({ started: { snapshotId: 'x' } }).started).toBeNull()
    expect(parseCutover({ started: { snapshotId: 4, at: 'a' }, manual: { ttl: true, zzz: true } }).manual).toMatchObject({ ttl: true, relay: false })
  })
  it('scripts de bascule : jamais de secret, et seuls ceux-ci modifient Windows', () => {
    expect(PS_CUTOVER_STOP).toContain('InActive'); expect(PS_CUTOVER_ROLLBACK).toContain('-State Active'); expect(PS_CUTOVER_TTL).toContain('Set-DnsServerResourceRecord')
    for (const s of [PS_CUTOVER_STOP, PS_CUTOVER_ROLLBACK, PS_CUTOVER_TTL]) expect(s).not.toMatch(/ddi_[A-Za-z0-9_-]{20,}|password|jeton/i)
  })
})

import { joinTxt } from '../server/utils/migration-verify'
describe('TXT : découpage en chaînes différent mais contenu identique', () => {
  it('joinTxt concatène les chaînes adjacentes, pas les guillemets échappés', () => {
    expect(joinTxt('"v=dkim1; k=rsa; " "p=abc" "def"')).toBe('"v=dkim1; k=rsa; p=abcdef"')
    expect(joinTxt('"a\\" \\"b"')).toBe('"a\\" \\"b"')
  })
  it('compareDns : pas d\'écart si seul le découpage diffère ; écart si le contenu diffère', async () => {
    const run = async (s: string, _n: string, t: string) => (t === 'TXT' ? (s === 'w' ? ['"v=1; " "p=abcdef"'] : ['"v=1; p=abc" "def"']) : ['1.2.3.4'])
    expect((await compareDns([{ name: 'x.t', type: 'TXT' }], 'w', 'd', run)).diffs).toEqual([])
    const run2 = async (s: string) => [s === 'w' ? '"v=1; p=abcdef"' : '"v=1; p=abcXYZ"']
    expect((await compareDns([{ name: 'x.t', type: 'TXT' }], 'w', 'd', run2)).diffs.length).toBe(1)
  })
})
