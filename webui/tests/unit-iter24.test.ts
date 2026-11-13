import { describe, expect, it } from 'vitest'
import { MIGRATION_STEPS, parseMigration } from '../server/handlers/migration'
import { PS_DHCP, PS_DNS, PS_INVENTORY } from '../app/utils/migration-scripts'

describe('migration Windows : état et scripts', () => {
  it('état : réglage absent ou corrompu = rien de fait ; seul « true » compte', () => {
    expect(Object.values(parseMigration(null)).every((v) => v === false)).toBe(true)
    expect(parseMigration({ done: { dhcp: 'oui', dns: true, bidon: true } })).toMatchObject({ dhcp: false, dns: true })
    expect(Object.keys(parseMigration({ done: { x: true } }))).toEqual([...MIGRATION_STEPS])
  })
  it('scripts : lecture seule (aucune commande de modification) et fichiers attendus par les imports', () => {
    for (const s of [PS_INVENTORY, PS_DHCP, PS_DNS]) expect(s).not.toMatch(/\b(Set|Add|Remove|New-DhcpServer|Restart|Stop|Uninstall)-/i)
    expect(PS_DHCP).toContain('Export-DhcpServer'); expect(PS_DNS).toContain('/ZoneExport'); expect(PS_INVENTORY).toContain('Get-DhcpServerv4Failover')
  })
})
