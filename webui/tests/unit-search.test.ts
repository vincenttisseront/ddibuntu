import { describe, expect, it } from 'vitest'
import { interpret } from '../server/handlers/search'

describe('interprétation de la saisie de recherche', () => {
  it('adresse IPv4 et IPv6 normalisées', () => {
    expect(interpret('10.0.0.5')).toMatchObject({ ip: '10.0.0.5', cidr: null })
    expect(interpret('2001:DB8:0:0:0:0:0:1').ip).toBe('2001:db8::1')
  })
  it('CIDR : bits hôte normalisés, jamais pris pour une IP', () => {
    expect(interpret('10.0.0.77/24')).toMatchObject({ ip: null, cidr: '10.0.0.0/24' })
    expect(interpret('10.0.0.0/33')).toMatchObject({ ip: null, cidr: null })
  })
  it('MAC : fragment avec séparateur ou adresse complète, jamais un nombre court', () => {
    expect(interpret('AA:bb:cc').mac).toBe('aabbcc')
    expect(interpret('aabbccddeeff').mac).toBe('aabbccddeeff')
    expect(interpret('aa-bb-cc-dd').mac).toBe('aabbccdd')
    expect(interpret('2024').mac).toBeNull()
    expect(interpret('srv-app').mac).toBeNull()
  })
  it('texte libre : ni IP, ni CIDR, ni MAC', () => {
    expect(interpret('paris')).toEqual({ ip: null, cidr: null, mac: null })
    expect(interpret("'; drop table users;--")).toEqual({ ip: null, cidr: null, mac: null })
  })
})
