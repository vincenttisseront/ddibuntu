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
