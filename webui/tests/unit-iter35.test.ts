// 0.13.5 — labels IPAM : normalisation et validation
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
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

describe('retour visuel pendant les chargements (0.13.8)', () => {
  const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8')
  it('le tableau de bord ne bloque plus la navigation', () => {
    const s = read('app/pages/index.vue')
    expect(s).not.toMatch(/await useFetch<any>\('\/api\/dashboard'\)/)
    expect(s).toContain('lazy: true')
    expect(s).toContain('dash-loading')
  })
  it("l'indicateur global suit aussi les changements de page", () => {
    expect(read('app/components/BusyIndicator.vue')).toContain('useLoadingIndicator')
  })
  it('les tableaux sont compacts globalement', () => {
    expect(read('app/assets/css/main.css')).toMatch(/table:not\(\.sr-only\) :is\(th, td\)/)
  })
})

import { deriveNameFormat } from '../app/utils/nameformat'
describe('format de nom généré déduit de la règle', () => {
  it('convertit les jokers', () => {
    expect(deriveNameFormat('srv-###')).toBe('srv-{o4:3}')
    expect(deriveNameFormat('vmdmz-*')).toBe('vmdmz-{o4:3}')
    expect(deriveNameFormat('pc-??')).toBe('pc-{o4:2}')
    expect(deriveNameFormat('  ')).toBe('')
  })
})
