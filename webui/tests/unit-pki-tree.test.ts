// 0.14.13 — arbre des autorités : rattachement au signeur (racine du DDI, racine hors ligne), ordre, profondeur, aucune autorité perdue ni dupliquée, boucles sans effet.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { parentName, pkiTreeRows } from '../app/utils/pkiTree'

const ca = (name: string, kind: string, signedBy?: string, extRoot?: string) => ({ name, kind, signedBy, extRoot })
const names = (rows: ReturnType<typeof pkiTreeRows>) => rows.map((r) => `${r.depth}:${r.ca.name}`)

describe('pkiTreeRows', () => {
  it('place les émettrices sous la racine du DDI qui les signe', () => {
    const rows = pkiTreeRows([ca('Iss-B', 'issuing', 'Root'), ca('Root', 'root', 'self'), ca('Iss-A', 'issuing', 'Root')])
    expect(names(rows)).toEqual(['0:Root', '1:Iss-A', '1:Iss-B'])
    expect(rows[1]!.last).toBe(false); expect(rows[2]!.last).toBe(true)
  })
  it('rattache une émettrice signée hors ligne à sa racine externe, et garde les racines hors ligne en tête', () => {
    const rows = pkiTreeRows([ca('Iss', 'issuing', 'external', 'ExtRoot-1'), ca('Lab', 'root', 'self'), ca('ExtRoot-1', 'extroot')])
    expect(names(rows)).toEqual(['0:Lab', '0:ExtRoot-1', '1:Iss'])
  })
  it('une émettrice dont le signeur est inconnu reste une tête d\'arbre', () => {
    expect(names(pkiTreeRows([ca('Iss', 'issuing', 'Disparue'), ca('Iss2', 'issuing', 'external')]))).toEqual(['0:Iss', '0:Iss2'])
  })
  it('descend sur plusieurs niveaux et marque les guides', () => {
    const rows = pkiTreeRows([ca('R', 'root', 'self'), ca('I1', 'issuing', 'R'), ca('I2', 'issuing', 'I1'), ca('I3', 'issuing', 'R')])
    expect(names(rows)).toEqual(['0:R', '1:I1', '2:I2', '1:I3'])
    expect(rows[2]!.guides).toEqual([false, true]) // R est seule en tête (pas de trait) ; I1 a une sœur à venir (I3) : trait tracé à sa colonne
  })
  it('ne perd ni ne duplique aucune autorité, même avec une boucle de signatures', () => {
    const rows = pkiTreeRows([ca('A', 'issuing', 'B'), ca('B', 'issuing', 'A'), ca('C', 'issuing', 'C')])
    expect(rows.map((r) => r.ca.name).sort()).toEqual(['A', 'B', 'C'])
  })
  it('liste vide', () => { expect(pkiTreeRows([])).toEqual([]) })
  it('parentName ignore l\'auto-signature et le signeur absent', () => {
    const n = new Set(['R'])
    expect(parentName(ca('R', 'root', 'self'), n)).toBeNull()
    expect(parentName(ca('X', 'issuing', 'R'), n)).toBe('R')
    expect(parentName(ca('X', 'issuing', 'Z'), n)).toBeNull()
    expect(parentName(ca('E', 'extroot', 'R'), n)).toBeNull()
  })
})

describe('PkiCas.vue', () => {
  const vue = readFileSync(resolve(__dirname, '../app/components/PkiCas.vue'), 'utf8')
  it('affiche l\'arbre et le détail de l\'autorité choisie, sans carte par autorité', () => {
    expect(vue).toContain('data-test="pki-ca-tree"'); expect(vue).toContain('pki-ca-node-'); expect(vue).toContain('pkiTreeRows')
    expect(vue).not.toContain('v-for="c in ordered"')
  })
  it('les textes existent en français et en anglais', () => {
    for (const l of ['fr', 'en']) {
      const i = readFileSync(resolve(__dirname, `../app/i18n/${l}.ts`), 'utf8')
      expect(i).toContain('"pki.ca.tree"'); expect(i).toContain('"pki.ca.has_warning"')
    }
  })
})
