// Unitaires du cockpit (sans base) : fusion requête + réécriture RPZ, anonymisation, analyse du journal.
import { describe, expect, it } from 'vitest'
import { maskClient, mergeEvents } from '../server/utils/ingest'
import { parseBindLog } from '../server/utils/querylog'

const L = (t: string, client: string, body: string) => `2026-11-10T08:00:${t}.000Z client @0x7f ${client}#5000 (x): ${body}`
describe('cockpit : analyse du journal', () => {
  it('type de requête extrait et normalisé ; ligne sans rapport ignorée', () => {
    const e = parseBindLog([L('00', '10.0.0.5', 'query: Exemple.COM IN aaaa + (10.0.0.1)'), 'bruit', L('01', '10.0.0.5', 'query: a.test IN TXT +E (10.0.0.1)')].join('\n'))
    expect(e.map((x) => [x.domain, x.qtype])).toEqual([['exemple.com', 'AAAA'], ['a.test', 'TXT']])
  })
  it('requête + réécriture RPZ = UNE ligne bloquée ; sans réécriture = autorisée', () => {
    const rows = mergeEvents(parseBindLog([
      L('00', '10.0.0.5', 'query: ads.example.net IN A + (10.0.0.1)'), L('00', '10.0.0.5', 'rpz QNAME NXDOMAIN rewrite ads.example.net/A/IN via ads.example.net.rpz.local'),
      L('01', '10.0.0.6', 'query: ok.example.net IN A + (10.0.0.1)'),
    ].join('\n')))
    expect(rows.map((r) => [r.client, r.domain, r.qtype, r.status])).toEqual([['10.0.0.5', 'ads.example.net', 'A', 'blocked'], ['10.0.0.6', 'ok.example.net', 'A', 'allowed']])
  })
  it('liste blanche (PASSTHRU) : autorisée avec la raison « whitelist »', () => {
    const rows = mergeEvents(parseBindLog([L('00', '10.0.0.5', 'query: pub.example.net IN A + (x)'), L('00', '10.0.0.5', 'rpz QNAME PASSTHRU rewrite pub.example.net/A/IN via pub.example.net.rpz.local')].join('\n')))
    expect(rows).toHaveLength(1); expect(rows[0]).toMatchObject({ status: 'allowed', reason: 'whitelist' })
  })
  it('deux clients, même domaine : chaque réécriture se rattache à SON client', () => {
    const rows = mergeEvents(parseBindLog([L('00', '10.0.0.5', 'query: t.example.net IN A +'), L('00', '10.0.0.6', 'query: t.example.net IN A +'), L('00', '10.0.0.6', 'rpz QNAME NXDOMAIN rewrite t.example.net/A/IN via z')].join('\n')))
    expect(rows.map((r) => [r.client, r.status])).toEqual([['10.0.0.5', 'allowed'], ['10.0.0.6', 'blocked']])
  })
  it('réécriture sans requête vue (journal tronqué) : conservée quand même ; trop ancienne pour une requête : ligne séparée', () => {
    expect(mergeEvents(parseBindLog(L('00', '10.0.0.5', 'rpz QNAME NXDOMAIN rewrite seul.example.net/A/IN via z')))).toHaveLength(1)
    const rows = mergeEvents(parseBindLog([L('00', '10.0.0.5', 'query: d.example.net IN A +'), L('30', '10.0.0.5', 'rpz QNAME NXDOMAIN rewrite d.example.net/A/IN via z')].join('\n')))
    expect(rows.map((r) => r.status).sort()).toEqual(['allowed', 'blocked'])
  })
  it('anonymisation : dernier octet IPv4 et fin des adresses IPv6 masqués', () => {
    expect(maskClient('192.168.14.77')).toBe('192.168.14.0'); expect(maskClient('2001:db8:1:2:aaaa:bbbb:cccc:dddd')).toBe('2001:db8:1:2::'); expect(maskClient('::1')).toBe('::1')
  })
})
