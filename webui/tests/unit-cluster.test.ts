import { describe, expect, it } from 'vitest'
import { parseClusterState, switchoverCandidates } from '../server/utils/cluster'

const NOW = 1_800_000_000
const base = {
  cluster: 'lab', node: 'n1', role: 'data', local_role: 'leader', at: NOW - 30, bind: 'primary',
  etcd: { healthy: true, members: 3 },
  peers: [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }],
  patroni: { members: [{ name: 'n1', role: 'leader', state: 'running', host: '10.9.0.1', timeline: 3 }, { name: 'n2', role: 'replica', state: 'streaming', lag: 2048, timeline: 3 }] },
  kea: { running: true, ha: true, mode: 'load-balancing', local: { state: 'load-balancing' }, partner: { state: 'load-balancing' } },
  vip: { address: '192.0.2.10/24', iface: 'ens192', held: true },
}

describe('état du cluster publié par root', () => {
  it('lit l’état, trouve le leader et signale le retard', () => {
    const s = parseClusterState(JSON.stringify(base), NOW)!
    expect(s.leader).toBe('n1'); expect(s.localRole).toBe('leader'); expect(s.stale).toBe(false); expect(s.ageSeconds).toBe(30)
    expect(s.nodes.map((n) => n.name)).toEqual(['n1', 'n2', 'n3']); expect(s.nodes[1]).toMatchObject({ patroniRole: 'replica', state: 'streaming', lagBytes: 2048 })
    expect(s.nodes[2]).not.toHaveProperty('state')   // l’arbitre n’a pas de base
    expect(s.vip).toEqual({ address: '192.0.2.10/24', iface: 'ens192', held: true }); expect(s.bind).toBe('primary')
  })
  it('périmé au-delà de 3 minutes', () => { expect(parseClusterState(JSON.stringify({ ...base, at: NOW - 400 }), NOW)!.stale).toBe(true) })
  it('fichier mal formé ou hostile : ignoré, champs inconnus et valeurs hors bornes écartés', () => {
    expect(parseClusterState('pas du json', NOW)).toBeNull(); expect(parseClusterState('[]', NOW)).toBeNull(); expect(parseClusterState('{"x":1}', NOW)).toBeNull()
    const s = parseClusterState(JSON.stringify({ ...base, local_role: '<script>', bind: 'x', secret: 'topsecret', peers: [{ name: 'n'.repeat(500), ip: 5, role: {} }], vip: { address: 7 } }), NOW)!
    expect(s.localRole).toBe('unknown'); expect(s.bind).toBeNull(); expect(s.vip).toBeNull(); expect(JSON.stringify(s)).not.toContain('topsecret')
    expect(s.nodes[0]!.name.length).toBeLessThanOrEqual(63)
  })
  it('candidats à la bascule : seulement un secondaire de données en bonne santé, état frais, quorum présent', () => {
    expect(switchoverCandidates(parseClusterState(JSON.stringify(base), NOW)!)).toEqual(['n2'])
    expect(switchoverCandidates(parseClusterState(JSON.stringify({ ...base, at: NOW - 999 }), NOW)!)).toEqual([])            // périmé
    expect(switchoverCandidates(parseClusterState(JSON.stringify({ ...base, etcd: { healthy: false, members: 1 } }), NOW)!)).toEqual([])   // pas de quorum
    const bad = { ...base, patroni: { members: [{ name: 'n1', role: 'leader', state: 'running' }, { name: 'n2', role: 'replica', state: 'starting' }] } }
    expect(switchoverCandidates(parseClusterState(JSON.stringify(bad), NOW)!)).toEqual([])
    expect(switchoverCandidates(null)).toEqual([])
  })
})
