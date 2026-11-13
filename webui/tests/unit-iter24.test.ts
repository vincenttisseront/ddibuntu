import { describe, expect, it } from 'vitest'
import { MIGRATION_STEPS, parseMigration } from '../server/handlers/migration'
import { PS_DHCP, PS_DNS, PS_INVENTORY, PS_LEASES, PS_PUSH } from '../app/utils/migration-scripts'

describe('migration Windows : état et scripts', () => {
  it('état : réglage absent ou corrompu = rien de fait ; seul « true » compte', () => {
    expect(Object.values(parseMigration(null)).every((v) => v === false)).toBe(true)
    expect(parseMigration({ done: { dhcp: 'oui', dns: true, bidon: true } })).toMatchObject({ dhcp: false, dns: true })
    expect(Object.keys(parseMigration({ done: { x: true } }))).toEqual([...MIGRATION_STEPS])
  })
  it('scripts : lecture seule (aucune commande de modification) et fichiers attendus par les imports', () => {
    for (const s of [PS_INVENTORY, PS_DHCP, PS_DNS, PS_LEASES, PS_PUSH]) expect(s).not.toMatch(/\b(Set|Add|Remove|New-DhcpServer|Restart|Stop|Uninstall)-/i)
    expect(PS_DHCP).toContain('Export-DhcpServer'); expect(PS_DNS).toContain('/ZoneExport'); expect(PS_INVENTORY).toContain('Get-DhcpServerv4Failover')
  })
  it('envoi planifié : jeton jamais fourni, rafraîchissement demandé', () => {
    expect(PS_PUSH).toContain('COLLER-LE-JETON-ICI'); expect(PS_PUSH).not.toMatch(/ddi_[A-Za-z0-9_-]{20,}/)
    expect(PS_PUSH).toContain('refresh = $true'); expect(PS_PUSH).toContain('/api/migration/leases/commit')
  })
})

import { PS_CUTOVER_TTL as TTLS } from '../app/utils/migration-scripts'
describe('scripts Windows : modules absents', () => {
  it('chaque script qui a besoin du module DNS ou DHCP le vérifie avant et explique quoi faire', () => {
    for (const s of [PS_INVENTORY, PS_DNS, TTLS]) expect(s).toMatch(/Get-Command Get-DnsServerZone/)
    expect(PS_INVENTORY).toMatch(/Get-Command Get-DhcpServerv4Scope/); expect(PS_INVENTORY).toContain('RSAT')
    expect(PS_INVENTORY).not.toMatch(/\b(Set|Add|Remove|Restart|Stop|Uninstall)-/i)
  })
})
