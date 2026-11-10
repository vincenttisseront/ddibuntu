// Unitaires : informations système du tableau de bord (valeurs bornées, pas d'exception si le volume est illisible).
import { describe, expect, it } from 'vitest'
import { hostInfo, percent } from '../server/utils/hostinfo'

describe('tableau de bord : état de l\'hôte', () => {
  it('pourcentage : arrondi à 0,1 ; total nul = 0', () => { expect(percent(1, 3)).toBe(33.3); expect(percent(5, 0)).toBe(0) })
  it('hostInfo renvoie des valeurs cohérentes', async () => {
    process.env.DDI_GENERATED_DIR = '/nonexistent-dir-for-test'
    const h = await hostInfo()
    expect(h.hostname.length).toBeGreaterThan(0); expect(h.uptimeSeconds).toBeGreaterThanOrEqual(0)
    expect(h.memPercent).toBeGreaterThanOrEqual(0); expect(h.memPercent).toBeLessThanOrEqual(100)
    expect(h.cpus).toBeGreaterThanOrEqual(1); expect(h.diskPercent).toBeNull()
    process.env.DDI_GENERATED_DIR = '/tmp'
    const h2 = await hostInfo(); expect(h2.diskPercent).not.toBeNull(); expect(h2.diskPercent!).toBeLessThanOrEqual(100)
    delete process.env.DDI_GENERATED_DIR
  })
})
