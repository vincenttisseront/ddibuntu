import { describe, expect, it } from 'vitest'
import { covers, normNets, splitNets } from '../server/utils/firewall'

describe('pare-feu : réseaux d\'administration', () => {
  it('normalise : CIDR, adresse seule, IPv6, doublons ; refuse /0 et le reste', () => {
    expect(normNets(['192.168.1.0/24', '10.20.0.15', '10.20.0.15/32', '2001:db8::1', ' '])).toEqual(['192.168.1.0/24', '10.20.0.15/32', '2001:db8::1/128'])
    expect(normNets(['10.0.0.5/24'])).toEqual(['10.0.0.0/24'])
    for (const bad of ['0.0.0.0/0', '::/0', 'x', '10.0.0.0/33', '10.0.0.1; rm']) expect(normNets([bad])).toBeNull()
  })
  it('covers : le poste d\'administration est-il couvert ?', () => {
    expect(covers(['10.20.0.0/24'], '10.20.0.7')).toBe(true)
    expect(covers(['10.20.0.0/24'], '::ffff:10.20.0.7')).toBe(true)
    expect(covers(['10.20.0.0/24'], '10.21.0.7')).toBe(false)
    expect(covers(['2001:db8::/32'], '10.20.0.7')).toBe(false)
    expect(covers([], '10.20.0.7')).toBe(false); expect(covers(['10.0.0.0/8'], null)).toBe(false)
  })
  it('splitNets accepte virgules, espaces, retours à la ligne', () => { expect(splitNets('a, b\nc;d')).toEqual(['a', 'b', 'c', 'd']) })
})

import { checkHints, validateFiles } from '../server/utils/render'
describe('diagnostic des NS sans adresse', () => {
  it('extrait les noms (dédoublonnés) de la sortie de named-checkzone', () => {
    const out = "zone a.b/IN: NS 'x.a.b' has no address records (A or AAAA)\nzone a.b/IN: NS 'x.a.b' has no address records (A or AAAA)\nzone a.b/IN: NS 'y.a.b' has no address records (A or AAAA)\nzone a.b/IN: not loaded due to errors."
    expect(checkHints(out)).toEqual([{ code: 'ns_no_address', names: ['x.a.b', 'y.a.b'] }]); expect(checkHints('zone a.b/IN: loaded serial 1\nOK')).toEqual([])
  })
  it('validateFiles joint le diagnostic au résultat refusé', async () => {
    const zone = { path: 'zones/db.ex.test', kind: 'zone' as const, content: '$ORIGIN ex.test.\n$TTL 300\n@ IN SOA ns1.ex.test. h.ex.test. ( 1 900 600 86400 300 )\n@ IN NS ns1.ex.test.\n@ IN NS stale.ex.test.\nns1 IN A 192.0.2.1\n' }
    const r = (await validateFiles([zone]))[0]!
    if (r.ok === null) return   // named-checkzone absent
    expect(r.ok).toBe(false); expect(r.hints).toEqual([{ code: 'ns_no_address', names: ['stale.ex.test'] }])
  })
})

import { ktpassCommand } from '../app/utils/ktpass'
describe('commande ktpass de l\'aide Kerberos', () => {
  it('pré-remplie avec le domaine et le nom de la console ; une seule ligne ; compte de service et mot de passe aléatoire', () => {
    const c = ktpassCommand('AR-SYSTEMS.FR', 'DDI-02.ar-systems.fr')
    expect(c).toBe('ktpass -princ DNS/ddi-02.ar-systems.fr@AR-SYSTEMS.FR -mapuser AR-SYSTEMS\\svc-ddi-dns -pass +rndpass -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -out dns.keytab')
    expect(c).not.toContain('\n'); expect(c).not.toContain('^'); expect(c).not.toMatch(/\$ /)
  })
  it('adresse IP ou nom court dans la barre d\'adresse : nom d\'exemple dans le domaine ; domaine inconnu ou invalide : exemple', () => {
    expect(ktpassCommand('ar-systems.fr', '10.0.31.150')).toContain('DNS/ddi1.ar-systems.fr@AR-SYSTEMS.FR')
    expect(ktpassCommand('ar-systems.fr', 'ddi')).toContain('DNS/ddi1.ar-systems.fr@AR-SYSTEMS.FR')
    expect(ktpassCommand('', '')).toContain('@CORP.LOCAL'); expect(ktpassCommand('x; calc', 'h')).toContain('@CORP.LOCAL')
  })
  it('le principal produit est accepté par l\'installation du keytab (DNS/<nom>@DOMAINE)', () => {
    expect(/DNS\/[A-Za-z0-9][A-Za-z0-9.-]{0,200}@AR-SYSTEMS\.FR/.test(ktpassCommand('AR-SYSTEMS.FR', 'ddi.ar-systems.fr'))).toBe(true)
  })
})
