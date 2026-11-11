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

// ---- 0.9.2 : réglages communs, certificats, nouvelles actions
import { actionRefusal, parsePki, parseSettings } from '../server/utils/cluster'
const member = (name: string, over: Record<string, unknown> = {}) => ({ name, ip: '10.9.0.' + name.slice(1), role: name === 'n3' ? 'witness' : 'data', reachable: true, healthy: true, learner: false, isLeader: false, version: '3.4.30', raftIndex: 5, raftTerm: 2, dbSize: 1024, latencyMs: 2, ...over })
const quorum = (over: Record<string, unknown> = {}) => ({ voters: 3, needed: 2, healthy: 3, hasQuorum: true, tolerance: 1, leader: 'n1', members: [member('n1'), member('n2'), member('n3')], unknownToEtcd: [], ...over })
const settings = { published: { rev: 3, vip: '192.0.2.10/24', vrid: 77, iface: 'ens18', net: '10.9.0.0/24' }, applied: { rev: 3, vip: '192.0.2.10/24', vrid: 77, iface: 'ens18', net: '10.9.0.0/24' } }
const pki = { node: { notAfter: NOW + 400 * 86400, daysLeft: 400, serial: 'AB12' }, ca: { notAfter: NOW + 3000 * 86400, daysLeft: 3000 }, renewDays: 60, pending: false }
const mk = (over: Record<string, unknown> = {}) => parseClusterState(JSON.stringify({ ...base, node: 'n2', local_role: 'replica', etcd: { healthy: true, members: 3, quorum: quorum() }, settings, pki, ...over }), NOW)!

describe('réglages communs et certificat dans l’état publié', () => {
  it('lit les réglages publiés/appliqués et le certificat', () => {
    const s = mk()
    expect(s.settings).toEqual(settings); expect(s.pki).toEqual(pki)
  })
  it('absents (ancien nœud) : null, jamais d’erreur', () => {
    const s = parseClusterState(JSON.stringify(base), NOW)!
    expect(s.settings).toBeNull(); expect(s.pki).toBeNull()
  })
  it('valeurs hostiles ou hors bornes écartées', () => {
    expect(parseSettings({ applied: { rev: -1, vrid: 999, vip: 'x'.repeat(500), iface: 7, net: {} }, published: 'oups' })).toEqual({ published: null, applied: { rev: 0, vip: 'x'.repeat(18), vrid: 51, iface: null, net: null } })
    expect(parseSettings(null)).toBeNull(); expect(parseSettings({ published: { rev: 1 } })).toBeNull()
    expect(parsePki({ node: { notAfter: 'x', daysLeft: 1e12, serial: 'z'.repeat(300) }, ca: { notAfter: 1, daysLeft: -5 }, renewDays: -3, pending: 'oui' })).toEqual({ node: { notAfter: 0, daysLeft: 36500, serial: 'z'.repeat(64) }, ca: { notAfter: 1, daysLeft: -5 }, renewDays: 60, pending: false })
    expect(parsePki(null)).toBeNull(); expect(parsePki({ node: {} })).toBeNull()
  })
})

describe('refus préalables des nouvelles actions (root revérifie tout)', () => {
  const R = (a: any, over: Record<string, unknown> = {}) => actionRefusal(mk(over), a)
  it('adresse virtuelle : confirmation = nom du cluster, quorum, adresse d’un nœud interdite', () => {
    const a = { action: 'set-vip', vip: '192.0.2.50/24', iface: 'ens18', confirm: 'lab' }
    expect(R(a)).toBeNull()
    expect(R({ ...a, confirm: 'autre' })).toBe('confirm_mismatch')
    expect(R({ ...a, vip: '10.9.0.3/24' })).toBe('vip_is_node')
    expect(R(a, { etcd: { healthy: false, members: 3, quorum: quorum({ hasQuorum: false, healthy: 1 }) } })).toBe('quorum_required')
    expect(R(a, { at: NOW - 900 })).toBe('quorum_required')
    expect(R(a, { role: 'witness' })).toBe('action_data_node_only')
    expect(actionRefusal(null, a as any)).toBe('not_clustered')
  })
  it('retrait de l’adresse virtuelle et interface : exigent une adresse en place', () => {
    expect(R({ action: 'clear-vip', confirm: 'lab' })).toBeNull()
    expect(R({ action: 'clear-vip', confirm: 'lab' }, { vip: null })).toBe('no_vip')
    expect(R({ action: 'clear-vip', confirm: 'x' })).toBe('confirm_mismatch')
    expect(R({ action: 'vip-iface', iface: 'eth1' })).toBeNull()
    expect(R({ action: 'vip-iface', iface: 'eth1' }, { vip: null })).toBe('no_vip')
  })
  it('réseau dédié : doit contenir tous les nœuds', () => {
    expect(R({ action: 'set-net', net: '10.9.0.0/16', confirm: 'lab' })).toBeNull()
    expect(R({ action: 'set-net', net: '10.9.0.0/30', confirm: 'lab' })).toBeNull()                    // .0 à .3 : les trois nœuds y sont
    expect(R({ action: 'set-net', net: '10.9.0.0/31', confirm: 'lab' })).toBe('nodes_outside_net')   // n2 et n3 sortiraient du réseau
    expect(R({ action: 'set-net', net: '10.8.0.0/16', confirm: 'lab' })).toBe('nodes_outside_net')
    expect(R({ action: 'set-net', net: '10.9.0.0/16', confirm: 'x' })).toBe('confirm_mismatch')
  })
  it('renouvellement : refusé tant qu’une demande est en cours', () => {
    expect(R({ action: 'renew-cert' })).toBeNull()
    expect(R({ action: 'renew-cert' }, { pki: { ...pki, pending: true } })).toBe('renew_pending')
  })
  it('changement d’adresse : confirmation, adresse libre dans le réseau, jamais sur le primaire, quorum avec marge', () => {
    const a = { action: 'change-ip', ip: '10.9.0.20', confirm: 'n2' }
    expect(R(a)).toBeNull()
    expect(R({ ...a, confirm: 'n1' })).toBe('confirm_mismatch')
    expect(R({ ...a, ip: '10.9.0.2' })).toBe('same_ip')
    expect(R({ ...a, ip: '10.9.0.1' })).toBe('node_ip_taken')
    expect(R({ ...a, ip: '10.8.0.20' })).toBe('ip_outside_net')
    expect(R(a, { local_role: 'leader' })).toBe('is_leader')
    expect(R(a, { etcd: { healthy: true, members: 3, quorum: quorum({ healthy: 2, members: [member('n1'), member('n2'), member('n3', { healthy: false, reachable: false })] }) } })).toBe('quorum_margin_required')
    expect(R(a, { etcd: { healthy: false, members: 3, quorum: quorum({ hasQuorum: false, healthy: 1 }) } })).toBe('quorum_required')
  })
})
