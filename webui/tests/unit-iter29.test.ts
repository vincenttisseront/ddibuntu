import { describe, expect, it } from 'vitest'
import { checkLocator, gssTemplate, LOCATOR_SRV, validRealm } from '../server/utils/ad-post'
import { PS_RETIRE } from '../app/utils/migration-scripts'

describe('après la migration', () => {
  const all = LOCATOR_SRV.map((name) => ({ name, rdata: '0 100 389 dc1.corp.test.' }))
  const hosts = new Set(['dc1.corp.test'])
  it('SRV complets et résolus : aucun écart', () => { expect(checkLocator('corp.test', all, hosts)).toMatchObject({ findings: [], present: 8, expected: 8 }) })
  it('absent, cible inconnue, données invalides ; cible relative résolue dans la zone', () => {
    const srv = all.filter((r) => r.name !== '_gc._tcp').map((r) => r.name === '_ldap._tcp' ? { ...r, rdata: '0 100 389 dc9.corp.test.' } : r.name === '_kpasswd._tcp' ? { ...r, rdata: 'oups' } : r.name === '_kerberos._tcp' ? { ...r, rdata: '0 100 88 dc1' } : r)
    const f = checkLocator('corp.test', srv, hosts).findings
    expect(f.map((x) => `${x.name}:${x.kind}`).sort()).toEqual(['_gc._tcp:missing', '_kpasswd._tcp:bad_rdata', '_ldap._tcp:target_unresolved'])
  })
  it('gabarit GSS-TSIG : domaine en majuscules, noms validés, aucun secret', () => {
    const g = gssTemplate('Corp.Test', 'corp.test'); expect(g).toContain('grant CORP.TEST ms-self'); expect(g).toContain('zone "corp.test"'); expect(g).not.toMatch(/password|secret/i)
    expect(validRealm('corp.test')).toBe(true); for (const b of ['corp', 'a b.c', 'x.y;rm', '"bad.test"', '-a.b']) expect(validRealm(b)).toBe(false)
  })
  it('script de retrait : la désinstallation reste commentée', () => {
    expect(PS_RETIRE).toMatch(/^# Uninstall-WindowsFeature/m); expect(PS_RETIRE).not.toMatch(/^Uninstall-/m)
  })
})
