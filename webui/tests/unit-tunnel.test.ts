import { describe, expect, it } from 'vitest'
import { labelEntropy, scoreTunnel, shannon } from '../server/handlers/tunnel'

describe('entropie', () => {
  it('Shannon : constante nulle, deux symboles équiprobables 1 bit', () => {
    expect(shannon('')).toBe(0)
    expect(shannon('aaaa')).toBe(0)
    expect(shannon('abab')).toBeCloseTo(1, 5)
  })
  it('étiquettes courtes ignorées, longues aléatoires nettement plus élevées que des mots', () => {
    expect(labelEntropy(['www', 'mail', 'api'])).toBeNull()
    const words = labelEntropy(['accountsgoogle', 'updateservice', 'downloadcenter'])!
    const rand = labelEntropy(['x7k2q9v4m1z8b3n5c6d0f2ghjk4lp', 'q1w2e3r4t5y6u7i8o9p0asdfghjklz'])!
    expect(rand).toBeGreaterThan(words)
    expect(rand).toBeGreaterThan(3.6)
  })
})
describe('score', () => {
  const base = { subs: 0, avgLen: 5, maxLabel: 8, rareShare: 0, entropy: null }
  it('trafic ordinaire : score nul', () => { expect(scoreTunnel(base)).toEqual({ score: 0, severity: 'low', reasons: [] }) })
  it('beaucoup de sous-noms seuls ne suffisent pas à une gravité élevée', () => {
    const v = scoreTunnel({ ...base, subs: 500 })
    expect(v.score).toBe(3); expect(v.severity).toBe('low')
  })
  it('profil de tunnel : gravité élevée avec tous les indices', () => {
    const v = scoreTunnel({ subs: 300, avgLen: 55, maxLabel: 60, rareShare: 0.9, entropy: 4.2 })
    expect(v.severity).toBe('high')
    expect(v.reasons).toEqual(['many_subdomains', 'long_names', 'long_label', 'high_entropy', 'rare_types'])
  })
  it('profil intermédiaire : gravité moyenne', () => {
    expect(scoreTunnel({ subs: 50, avgLen: 22, maxLabel: 20, rareShare: 0, entropy: 3.4 }).severity).toBe('medium')
  })
})
