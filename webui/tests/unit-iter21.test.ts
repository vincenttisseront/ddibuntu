import { describe, expect, it } from 'vitest'
import { aliasProblem, chainLength, cnameTarget, collectAliases, fqdnOf, zoneForName } from '../server/utils/aliases'
import type { AliasRec } from '../server/utils/aliases'

let n = 0
const cn = (name: string, rdata: string, zone = 'example.org', view: number | null = null, o: Partial<AliasRec> = {}): AliasRec =>
  ({ id: ++n, zoneId: 1, zone, view, name, rdata, ttl: null, comment: null, disabled: false, protected: false, ...o })

describe('alias : noms et cibles', () => {
  it('nom complet et cible, relatifs ou absolus', () => {
    expect(fqdnOf('www', 'Example.ORG')).toBe('www.example.org'); expect(fqdnOf('@', 'example.org')).toBe('example.org')
    expect(cnameTarget('srv.example.org.', 'x.net')).toBe('srv.example.org'); expect(cnameTarget('srv', 'example.org')).toBe('srv.example.org')
    expect(cnameTarget('@', 'example.org')).toBe('example.org'); expect(cnameTarget('.', 'example.org')).toBeNull()
  })
})
describe('alias : collecte', () => {
  it('alias direct, relatif ou absolu, et alias d’alias avec leur profondeur', () => {
    const c = [cn('www', 'srv'), cn('api', 'srv.example.org.'), cn('front', 'www.example.org.'), cn('autre', 'ailleurs.example.org.')]
    const r = collectAliases(['srv.example.org'], null, c)
    expect(r.map((a) => [a.fqdn, a.depth]).sort()).toEqual([['api.example.org', 1], ['front.example.org', 2], ['www.example.org', 1]])
  })
  it('alias dans une autre zone et respect de la vue DNS', () => {
    const c = [cn('shop', 'srv.example.org.', 'autre.net'), cn('shop', 'srv.example.org.', 'autre.net', 7)]
    expect(collectAliases(['srv.example.org'], null, c).map((a) => a.fqdn)).toEqual(['shop.autre.net'])
    expect(collectAliases(['srv.example.org'], 7, c).length).toBe(1)
    expect(collectAliases(['srv.example.org'], 9, c)).toEqual([])
  })
  it('boucle sans fin et chaîne trop longue : terminent', () => {
    const loop = [cn('a', 'b'), cn('b', 'a')]
    expect(collectAliases(['a.example.org'], null, loop).length).toBe(2)
    const long = Array.from({ length: 20 }, (_, i) => cn(`h${i + 1}`, `h${i}`)); expect(collectAliases(['h0.example.org'], null, long).length).toBe(8)
  })
})
describe('alias : contrôles de création', () => {
  const c = [cn('www', 'srv'), cn('front', 'www')]
  it('refuse soi-même, boucle et chaîne trop longue ; accepte le reste', () => {
    expect(aliasProblem('srv.example.org', 'srv.example.org', null, c)).toBe('cname_self')
    expect(aliasProblem('front.example.org', 'front.example.org', null, c)).toBe('cname_self')
    expect(aliasProblem('srv.example.org', 'front.example.org', null, c)).toBe('cname_loop')     // srv → front → www → srv
    expect(aliasProblem('neuf.example.org', 'front.example.org', null, c)).toBeNull()
    const long = Array.from({ length: 8 }, (_, i) => cn(`h${i + 1}`, `h${i}`))
    expect(aliasProblem('fin.example.org', 'h8.example.org', null, long)).toBe('cname_chain_too_long')
    expect(aliasProblem('fin.example.org', 'h3.example.org', null, long)).toBeNull()
  })
  it('modification d’un alias existant : son propre enregistrement ne compte pas', () => {
    const www = c[0]!
    expect(aliasProblem('www.example.org', 'srv.example.org', null, c, www.id)).toBeNull()
    expect(aliasProblem('www.example.org', 'front.example.org', null, c, www.id)).toBe('cname_loop')
  })
  it('longueur de chaîne', () => { expect(chainLength('front.example.org', null, c)).toBe(2); expect(chainLength('srv.example.org', null, c)).toBe(0); expect(chainLength('a.example.org', null, [cn('a', 'b'), cn('b', 'a')])).toBe(-1) })
})
describe('alias : zone d’un nom saisi', () => {
  const z = [{ name: 'example.org', view: null }, { name: 'dev.example.org', view: null }, { name: 'autre.net', view: null }, { name: 'example.org', view: 3 }]
  it('suffixe le plus long, dans la vue seulement', () => {
    expect(zoneForName('www.dev.example.org.', null, z)?.name).toBe('dev.example.org')
    expect(zoneForName('WWW.example.org', null, z)?.name).toBe('example.org')
    expect(zoneForName('www.example.org', 3, z)?.view).toBe(3)
    expect(zoneForName('www.inconnu.fr', null, z)).toBeNull(); expect(zoneForName('xexample.org', null, z)).toBeNull()
  })
})
