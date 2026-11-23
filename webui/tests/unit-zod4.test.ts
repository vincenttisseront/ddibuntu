// zod 4 : `.partial()` applique désormais les `.default()` aux champs absents. Les routes de mise à jour partielle passent par
// patchOf(), qui retire ces valeurs par défaut : modifier le nom d'hôte d'une adresse ne doit pas remettre son statut à « used ».
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import { patchOf, validate } from '../server/utils/router'

const addr = z.object({ ip: z.string(), status: z.enum(['used', 'reserved', 'gateway']).default('used'), hostname: z.string().optional(), tags: z.array(z.string()).default([]) }).strict()

describe('mises à jour partielles (zod 4)', () => {
  it('un champ absent reste absent, même s\'il a une valeur par défaut', () => {
    expect(validate(patchOf(addr.omit({ ip: true })), { hostname: 'srv1' })).toEqual({ hostname: 'srv1' })
  })
  it('un champ fourni est validé comme avant', () => {
    expect(validate(patchOf(addr), { status: 'reserved' })).toEqual({ status: 'reserved' })
    expect(() => validate(patchOf(addr), { status: 'inconnu' })).toThrow()
  })
  it('le mode strict est conservé', () => {
    expect(() => validate(patchOf(addr), { champ: 1 })).toThrow()
  })
  it('la création garde ses valeurs par défaut', () => {
    expect(validate(addr, { ip: '10.0.0.1' })).toEqual({ ip: '10.0.0.1', status: 'used', tags: [] })
  })
  it('aucune route ne combine encore .partial() et un schéma à valeurs par défaut sans patchOf', () => {
    const dir = join(__dirname, '../server/handlers')
    for (const f of readdirSync(dir).filter((n) => n.endsWith('.ts'))) expect(readFileSync(join(dir, f), 'utf8'), f).not.toMatch(/\.partial\(\)/)
  })
})
