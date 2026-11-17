// 0.13.5 — labels IPAM : normalisation et validation
import { describe, expect, it } from 'vitest'
import { labelsS, LABEL_RE, normLabel } from '~~/server/utils/labels'

describe('labels', () => {
  it('normalise : minuscules, espaces simples, sans doublon', () => {
    expect(normLabel('  Env:Prod  ')).toBe('env:prod')
    expect(normLabel('Site  Paris')).toBe('site paris')
    expect(labelsS.parse(['Env:Prod', ' env:prod', 'DMZ', ''])).toEqual(['env:prod', 'dmz'])
  })
  it('refuse les caractères hors liste et les noms trop longs', () => {
    for (const bad of ['a;b', 'a,b', '<x>', '-debut', 'x'.repeat(41)]) expect(LABEL_RE.test(normLabel(bad)), bad).toBe(false)
    for (const ok of ['env:prod', 'role/web', 'été', 'site paris', 'a.b_c-d', 'user@x+1']) expect(LABEL_RE.test(normLabel(ok)), ok).toBe(true)
    expect(() => labelsS.parse(['ok', 'a;b'])).toThrow()
    expect(() => labelsS.parse(Array.from({ length: 21 }, (_, i) => `l${i}`))).toThrow()
  })
})
