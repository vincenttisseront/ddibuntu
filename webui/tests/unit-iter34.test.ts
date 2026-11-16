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
  it("pas d'appel refresh() via une référence de composant (« refresh is not a function » en production) : refreshNuxtData()", () => {
    const bad = walk(join(__dirname, '..', 'app')).filter((f) => /\.value\?\.refresh\(\)/.test(readFileSync(f, 'utf8')))
    expect(bad).toEqual([])
  })
})

import { parseBlocklist } from '~~/server/utils/blocklist'
describe('listes de blocage', () => {
  it('un fichier hosts déclaré « domains » donne les vrais domaines, pas les adresses IP', () => {
    const txt = '# Title\n127.0.0.1 localhost\n255.255.255.255 broadcasthost\n0.0.0.0 ads.example.com\n0.0.0.0 track.example.org # c\n'
    expect(parseBlocklist(txt, 'domains').domains).toEqual(['ads.example.com', 'track.example.org'])
    expect(parseBlocklist(txt, 'hosts').domains).toEqual(['ads.example.com', 'track.example.org'])
    expect(parseBlocklist('0.0.0.0\n1.2.3.4\nplain.example.com\n', 'domains').domains).toEqual(['plain.example.com'])
  })
})

describe('listes adblock', () => {
  it('un fichier adblock déclaré « domains » ou « hosts » est reconnu (lignes ||domaine^)', () => {
    const txt = '! Title: x\n[Adblock Plus]\n||ads.example.com^\n||track.example.org^\n@@||ok.example.com^\n'
    for (const f of ['adblock', 'domains', 'hosts'] as const) expect(parseBlocklist(txt, f).domains).toEqual(['ads.example.com', 'track.example.org'])
  })
})
