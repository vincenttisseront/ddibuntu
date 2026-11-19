// Défaut vu en 0.14.18 : un commentaire « // » ajouté au milieu d'une ligne de déclarations (« const a = ref(), b = ref() ») mettait « b » en commentaire ;
// le composant plantait au rendu (« minutes is not defined », erreur 500 sur l'onglet Journal). Le build ne le voit pas : on contrôle les sources.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const walk = (d: string): string[] => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : p.endsWith('.vue') ? [p] : [] })

describe('composants Vue', () => {
  it('aucun commentaire « // » ne met en commentaire une déclaration de la même ligne', () => {
    const bad: string[] = []
    for (const f of walk(join(__dirname, '..', 'app'))) {
      readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
        const c = line.indexOf(' // ')
        if (c > 0 && /\b[A-Za-z_]\w* = (ref|computed|reactive|shallowRef|useState)\b/.test(line.slice(c))) bad.push(`${f.split('/app/')[1]}:${i + 1}`)
      })
    }
    expect(bad).toEqual([])
  })
  it('la règle voit bien le défaut d\'origine', () => {
    const line = "const kind = ref('all')   // pas de valeur vide, minutes = ref(1440), q = ref('')"
    const c = line.indexOf(' // ')
    expect(/\b[A-Za-z_]\w* = (ref|computed|reactive)\b/.test(line.slice(c))).toBe(true)
  })
})
