import { describe, expect, it } from 'vitest'
import { analyzeHealth, ptrToIp, type HealthData } from '../server/utils/dns-health'

const z = (id: number, name: string, view_id: number | null = null) => ({ id, name, type: 'primary', view_id, disabled: false })
const r = (id: number, zone_id: number, name: string, type: string, rdata: string, extra: Record<string, unknown> = {}) => ({ id, zone_id, name, type, rdata, disabled: false, source: 'manual', protected: false, ...extra })
const base = (): HealthData => ({
  zones: [z(1, 'lab.test'), z(2, '2.0.10.in-addr.arpa')],
  records: [r(1, 1, 'web', 'A', '10.0.2.5'), r(2, 2, '5', 'PTR', 'web.lab.test.')],
  addresses: [{ subnet_id: 1, ip: '10.0.2.5', hostname: 'web', zone_id: 1 }],
  subnets: [{ id: 1, cidr: '10.0.2.0/24' }],
})

describe('contrôle de cohérence DNS ↔ IPAM', () => {
  it('ptrToIp', () => { expect(ptrToIp('5.2.0.10.in-addr.arpa')).toBe('10.0.2.5'); expect(ptrToIp('x.2.0.10.in-addr.arpa')).toBeNull(); expect(ptrToIp('1.0.0.0.ip6.arpa')).toBeNull() })
  it('données cohérentes : aucun constat, score 100', () => { const o = analyzeHealth(base()); expect(o.findings).toEqual([]); expect(o.score).toBe(100) })
  it('PTR orphelin', () => {
    const d = base(); d.records.push(r(3, 2, '9', 'PTR', 'ghost.lab.test.'))
    const o = analyzeHealth(d); expect(o.findings.map((f) => f.key)).toEqual(['orphan_ptr:3']); expect(o.score).toBeLessThan(100)
  })
  it('A sans PTR, A sans fiche IPAM', () => {
    const d = base(); d.records.push(r(3, 1, 'db', 'A', '10.0.2.7'))
    expect(analyzeHealth(d).findings.map((f) => f.kind).sort()).toEqual(['a_no_ipam', 'a_no_ptr'])
  })
  it('IP nommée non publiée ; sans zone = non corrigeable', () => {
    const d = base(); d.addresses.push({ subnet_id: 1, ip: '10.0.2.8', hostname: 'app', zone_id: 1 }, { subnet_id: 1, ip: '10.0.2.9', hostname: 'nozone', zone_id: null })
    const f = analyzeHealth(d).findings.filter((x) => x.kind === 'ip_no_name')
    expect(f.map((x) => [x.name, x.fixable])).toEqual([['10.0.2.8 (app)', true], ['10.0.2.9 (nozone)', false]])
  })
  it('CNAME pendant : seulement si la cible est dans une zone gérée', () => {
    const d = base(); d.records.push(r(3, 1, 'alias', 'CNAME', 'nope'), r(4, 1, 'ext', 'CNAME', 'www.example.org.'), r(5, 1, 'ok', 'CNAME', 'web'))
    expect(analyzeHealth(d).findings.map((f) => f.key)).toEqual(['dangling_cname:3'])
  })
  it('enregistrements dynamiques, désactivés et zones désactivées ignorés ; protégés non corrigeables', () => {
    const d = base(); d.records.push(r(3, 2, '9', 'PTR', 'ghost.lab.test.', { source: 'dhcp' }), r(4, 2, '8', 'PTR', 'x.lab.test.', { disabled: true }), r(5, 2, '7', 'PTR', 'y.lab.test.', { protected: true }))
    const f = analyzeHealth(d).findings; expect(f.map((x) => [x.key, x.fixable])).toEqual([['orphan_ptr:5', false]])
  })
  it('vues : un PTR ne valide pas un A d’une autre vue', () => {
    const d = base(); d.zones.push(z(3, 'lab.test', 7), z(4, '2.0.10.in-addr.arpa', 7)); d.records.push(r(3, 3, 'web', 'A', '10.0.2.5'))
    expect(analyzeHealth(d).findings.map((f) => f.key)).toContain('a_no_ptr:3')
  })
})
