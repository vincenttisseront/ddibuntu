// 0.12.25 — un item de USelect/USelectMenu ne peut pas avoir une valeur '' (Reka UI : « SelectItem must have a value prop that is not an empty string »)
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

function walk(d: string): string[] { return readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : p.endsWith('.vue') ? [p] : [] }) }
describe('sélecteurs', () => {
  it("aucun item de sélecteur avec une valeur vide", () => {
    const bad = walk(join(__dirname, '..', 'app')).filter((f) => /value:\s*(''|"")/.test(readFileSync(f, 'utf8')))
    expect(bad).toEqual([])
  })
})
