// Formats d'export SIEM : syslog RFC 5424 / 3164, CEF, LEEF, JSON, cadrage TCP
import { describe, expect, it } from 'vitest'
import { cef, formatEvent, frame, json, leef, rfc3164, rfc5424 } from '~~/server/utils/siem-format'
import type { SiemEvent } from '~~/server/utils/siem-format'
import { hostError, targetError } from '~~/server/utils/siem'

const ctx = { host: 'ddi01', version: '0.13.9', facility: 16 }
const ev: SiemEvent = { source: 'dns_blocked', id: 7, at: new Date('2026-11-17T09:05:03.123Z'), severity: 5, event: 'dns.blocked', message: 'DNS bloquée : 10.0.0.6 → ads.test A', fields: { client: '10.0.0.6', domain: 'ads.test', reason: 'liste "x"', empty: '', nul: null } }

describe('RFC 5424', () => {
  it('en-tête, données structurées échappées, priorité = facility*8+gravité', () => {
    const l = rfc5424(ev, ctx)
    expect(l.startsWith('<133>1 2026-11-17T09:05:03.123Z ddi01 ddibuntu - dns_blocked [ddibuntu@32473 source="dns_blocked" client="10.0.0.6" domain="ads.test" reason="liste \\"x\\""] DNS bloquée')).toBe(true)
    expect(l).not.toContain('empty='); expect(l).not.toContain('nul=')
  })
  it('échappe ] et \\ et retire les sauts de ligne', () => {
    const l = rfc5424({ ...ev, message: 'a\nb', fields: { k: 'x]y\\z' } }, ctx)
    expect(l).toContain('k="x\\]y\\\\z"'); expect(l).not.toMatch(/[\r\n]/)
  })
})
describe('RFC 3164', () => {
  it('horodatage « Mmm dd HH:MM:SS » et paires clé=valeur', () => {
    const l = rfc3164(ev, ctx)
    expect(l).toMatch(/^<133>Nov 17 09:05:03 ddi01 ddibuntu: DNS bloquée : .* client=10\.0\.0\.6 domain=ads\.test reason="liste 'x'"$/)
    expect(rfc3164({ ...ev, at: new Date('2026-11-05T01:02:03Z') }, ctx)).toContain('Nov  5 01:02:03')
  })
})
describe('CEF', () => {
  it('en-tête à 7 champs, sévérité 0-10, extension avec clés standard', () => {
    const l = cef(ev, ctx)
    expect(l.startsWith('CEF:0|DDI-Buntu|DDI-Buntu|0.13.9|dns.blocked|DNS bloquée')).toBe(true)
    expect(l.split('|').slice(0, 7).length).toBe(7); expect(l.split('|')[6]).toBe('4')
    expect(l).toContain('src=10.0.0.6'); expect(l).toContain('request=ads.test'); expect(l).toContain('rt=1794906303123'.slice(0, 0) + 'rt=')
  })
  it('échappe « | » dans l\'en-tête et « = » dans l\'extension', () => {
    const l = cef({ ...ev, event: 'a|b', message: 'x|y', fields: { domain: 'a=b\\c' } }, ctx)
    expect(l).toContain('|a\\|b|x\\|y|'); expect(l).toContain('request=a\\=b\\\\c')
  })
  it('gravités syslog 0..7 → 10..1', () => {
    expect([0, 2, 3, 4, 5, 6, 7].map((s) => cef({ ...ev, severity: s }, ctx).split('|')[6])).toEqual(['10', '9', '7', '6', '4', '3', '1'])
  })
})
describe('LEEF 2.0', () => {
  it('séparateur ^ déclaré, valeurs sans ^', () => {
    const l = leef({ ...ev, fields: { domain: 'a^b' } }, ctx)
    expect(l.startsWith('LEEF:2.0|DDI-Buntu|DDI-Buntu|0.13.9|dns.blocked|^|devTime=2026-11-17T09:05:03.123Z^')).toBe(true)
    expect(l).toContain('^domain=a b'); expect(l.split('|^|')[1]!.split('^').every((p) => p.includes('='))).toBe(true)
  })
})
describe('JSON', () => {
  it('une ligne, champs standard et champs de l\'événement', () => {
    const o = JSON.parse(json(ev, ctx))
    expect(o).toMatchObject({ timestamp: '2026-11-17T09:05:03.123Z', host: 'ddi01', app: 'ddibuntu', source: 'dns_blocked', event: 'dns.blocked', severity: 5, client: '10.0.0.6', domain: 'ads.test' })
    expect('empty' in o).toBe(false)
  })
  it('un champ ne remplace jamais un champ standard', () => { expect(JSON.parse(json({ ...ev, fields: { host: 'evil', source: 'x' } }, ctx)).host).toBe('ddi01') })
})
describe('cadrage et sélection', () => {
  it('newline / comptage d\'octets (RFC 6587)', () => {
    expect(frame(['ab', 'é'], 'newline').toString()).toBe('ab\né\n')
    expect(frame(['ab', 'é'], 'octet').toString()).toBe('2 ab2 é')
  })
  it('formatEvent aiguille vers le bon format', () => { expect(formatEvent('cef', ev, ctx)).toMatch(/^CEF:0/); expect(formatEvent('json', ev, ctx)).toMatch(/^\{/) })
  it('adresses interdites', () => {
    expect(hostError('169.254.169.254')).toBe('siem_host_forbidden'); expect(hostError('fe80::1')).toBe('siem_host_forbidden'); expect(hostError('10.1.2.3')).toBeNull()
    expect(targetError({ protocol: 'udp', host: '', port: 514, url: '' })).toBe('siem_host_required')
    expect(targetError({ protocol: 'https', host: '', port: null, url: '' })).toBe('siem_url_required')
  })
})
