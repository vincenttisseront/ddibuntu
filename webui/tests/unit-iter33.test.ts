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

import { ktpassCommand, ktNames, ktAccountScript, ktutilSteps } from '../app/utils/ktpass'
describe('commande ktpass de l\'aide Kerberos', () => {
  it('pré-remplie avec le domaine et le nom de la console ; une seule ligne ; compte de service et mot de passe aléatoire', () => {
    const c = ktpassCommand('EXAMPLE.LOCAL', 'DDI-02.example.local')
    expect(c).toBe('ktpass -princ DNS/ddi-02.example.local@EXAMPLE.LOCAL -mapuser EXAMPLE\\svc_ddi_dns -pass +rndpass -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -out dns.keytab')
    expect(c).not.toContain('\n'); expect(c).not.toContain('^'); expect(c).not.toMatch(/\$ /)
  })
  it('adresse IP ou nom court dans la barre d\'adresse : nom d\'exemple dans le domaine ; domaine inconnu ou invalide : exemple', () => {
    expect(ktpassCommand('example.local', '192.0.2.150')).toContain('DNS/ddi1.example.local@EXAMPLE.LOCAL')
    expect(ktpassCommand('example.local', 'ddi')).toContain('DNS/ddi1.example.local@EXAMPLE.LOCAL')
    expect(ktpassCommand('', '')).toContain('@CORP.LOCAL'); expect(ktpassCommand('x; calc', 'h')).toContain('@CORP.LOCAL')
  })
  it('le principal produit est accepté par l\'installation du keytab (DNS/<nom>@DOMAINE)', () => {
    expect(/DNS\/[A-Za-z0-9][A-Za-z0-9.-]{0,200}@EXAMPLE\.LOCAL/.test(ktpassCommand('EXAMPLE.LOCAL', 'ddi.example.local'))).toBe(true)
  })
})

describe('aide Kerberos : méthode ktutil et champs modifiables', () => {
  it('nom du compte, NetBIOS et kvno sont pris en compte ; toute valeur invalide retombe sur un exemple sûr', () => {
    expect(ktpassCommand('EXAMPLE.LOCAL', 'ddi.example.local', { account: 'svc_x', netbios: 'exmpl' })).toContain('-mapuser EXMPL\\svc_x ')
    expect(ktNames('example.local', 'ddi.example.local', { account: 'a b; calc', netbios: 'x y', kvno: '2; rm' })).toMatchObject({ account: 'svc_ddi_dns', netbios: 'EXAMPLE', kvno: '2' })
    expect(ktNames('a-very-long-domain-name.example.com', 'h.example.com').netbios.length).toBeLessThanOrEqual(15)
  })
  it('étape PowerShell : compte dédié, SPN, kvno ; jamais de mot de passe en clair ni de réinitialisation', () => {
    const c = ktAccountScript('EXAMPLE.LOCAL', 'ddi.example.local', { account: 'svc_ddi_dns' })
    expect(c).toContain('New-ADUser -Name svc_ddi_dns')
    expect(c).toContain('setspn -S DNS/ddi.example.local svc_ddi_dns')
    expect(c).toContain('msDS-KeyVersionNumber')
    expect(c).toContain('-KerberosEncryptionType AES256')
    expect(c).not.toMatch(/Set-ADAccountPassword|-Reset/)
  })
  it('ktutil : principal, kvno, AES256 et salt AD (royaume + nom du compte, casse exacte) ; aucun secret dans la commande', () => {
    const k = ktutilSteps('example.local', 'DDI.example.local', { account: 'svc_ddi_dns', kvno: '3' })
    expect(k).toContain('addent -password -p DNS/ddi.example.local@EXAMPLE.LOCAL -k 3 -e aes256-cts-hmac-sha1-96 -s EXAMPLE.LOCALsvc_ddi_dns')
    expect(k).toContain('wkt dns.keytab'); expect(k).toContain('klist -ket dns.keytab'); expect(k).not.toMatch(/\$pw|-pass /)
  })
})
