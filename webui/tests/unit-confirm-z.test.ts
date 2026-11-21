// 0.21.1 — la boîte de confirmation doit passer devant toute fenêtre déjà ouverte (liste des alias, formulaires) : à même niveau d'empilement,
// c'est l'ordre d'insertion dans la page qui décide, et la confirmation (montée une fois pour l'application) se retrouvait dessous.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

describe('boîte de confirmation', () => {
  it('a un niveau d\'empilement supérieur à celui des fenêtres (z-50 par défaut)', () => {
    const src = readFileSync(join(__dirname, '../app/components/ConfirmDialog.vue'), 'utf8')
    expect(src).toMatch(/overlay:\s*'z-\[(\d+)\]'/); expect(src).toMatch(/content:\s*'z-\[(\d+)\]'/)
    for (const m of src.matchAll(/z-\[(\d+)\]/g)) expect(Number(m[1])).toBeGreaterThan(50)
  })
})
