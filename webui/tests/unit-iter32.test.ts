import { describe, expect, it } from 'vitest'
import { formatError, formatName } from '../server/utils/naming'

const ctx = { ip: '10.1.2.7', vlan: 20, site: 'Paris Nord' }
describe('génération de noms', () => {
  it('jetons : octets, remplissage, VLAN, site, IP', () => {
    expect(formatName('srv-{o4:3}', ctx)).toBe('srv-007'); expect(formatName('v{vlan}-{o3}-{o4}', ctx)).toBe('v20-2-7'); expect(formatName('{site}-{o4}', ctx)).toBe('paris-nord-7')
    expect(formatName('h-{ip}', ctx)).toBe('h-10-1-2-7'); expect(formatName('SRV-{o4:2}', ctx)).toBe('srv-07')
  })
  it('jeton sans valeur ou résultat invalide : pas de nom', () => {
    expect(formatName('{site}-{o4}', { ...ctx, site: null })).toBeNull(); expect(formatName('v{vlan}', { ...ctx, vlan: null })).toBeNull()
    expect(formatName('-{o4}', ctx)).toBeNull(); expect(formatName('a'.repeat(70), ctx)).toBeNull()
  })
  it('validation du format', () => {
    expect(formatError('srv-{o4:3}')).toBeNull(); expect(formatError('')).toBe('format_length'); expect(formatError('a b')).toBe('format_chars')
    expect(formatError('x-{foo}')).toBe('format_token'); expect(formatError('x-{o4')).toBe('format_token'); expect(formatError('x'.repeat(101))).toBe('format_length')
  })
})
