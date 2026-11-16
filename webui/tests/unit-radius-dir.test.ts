// Annuaire AD du service RADIUS (0.13.1) : décodage de l'état d'un compte, filtres échappés, classement des erreurs, bascule entre serveurs,
// groupes imbriqués, ambiguïté, troncature. Faux LDAP : les cas qu'un annuaire réel produit mal (500+ groupes, homonymes, serveur de secours) ;
// le comportement contre un vrai Samba AD est vérifié par e2e-iter39.
import { describe, expect, it } from 'vitest'
import { escapeFilter } from '../server/utils/ad'
import type { LdapLike } from '../server/utils/ad'
import { accountFilter, classify, decodeAccount, filetimeToMs, findGroups, groupSearchFilter, IN_CHAIN, lookupAccount, MAX_FOUND_GROUPS, MAX_GROUPS, testBind, withService } from '../server/utils/radius-dir'
import type { DirSettings } from '../server/utils/radius-dir'

const S: DirSettings = { urls: ['ldaps://dc1.lab.test', 'ldaps://dc2.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc@lab.test', tlsRejectUnauthorized: true }
type Search = (base: string, o: { filter: string; sizeLimit?: number; attributes: string[] }) => any[]
interface Node { bindErr?: Error; search?: Search }
function fake(nodes: Record<string, Node>) {
  const log: string[] = []
  const factory = (url: string): LdapLike => ({
    async bind(dn: string, pw: string) { log.push(`bind ${url} ${dn} ${pw ? 'pw' : 'nopw'}`); const e = nodes[url]?.bindErr; if (e) throw e },
    async search(base, o) { log.push(`search ${url} ${base} ${o.filter}`); return { searchEntries: nodes[url]?.search?.(base, o) ?? [] } },
    async unbind() { log.push(`unbind ${url}`) },
  })
  return { factory, log }
}
const credErr = Object.assign(new Error('80090308: LdapErr: DSID-0C09044E, data 52e, v4563'), { name: 'InvalidCredentialsError', code: 49 })
const tlsErr = Object.assign(new Error('unable to verify the first certificate'), { code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' })
const downErr = Object.assign(new Error('connect ECONNREFUSED 10.0.0.1:636'), { code: 'ECONNREFUSED' })

describe('filetimeToMs', () => {
  it('« jamais » (0, valeur maximale), illisible, valeur réelle', () => {
    expect(filetimeToMs('0')).toBeNull(); expect(filetimeToMs('9223372036854775807')).toBeNull(); expect(filetimeToMs('')).toBeNull()
    expect(filetimeToMs('pas un nombre')).toBeNull(); expect(filetimeToMs(undefined)).toBeNull(); expect(filetimeToMs('-5')).toBeNull(); expect(filetimeToMs('1'.repeat(25))).toBeNull()
    expect(filetimeToMs('132000000000000000')).toBe(1555526400000)   // 2019-04-17T18:40:00Z, contrôlé sur un vrai AD
    expect(filetimeToMs(['132000000000000000'])).toBe(1555526400000)
  })
})

describe('decodeAccount', () => {
  const now = Date.parse('2026-11-16T12:00:00Z')
  it('compte actif : utilisable', () => expect(decodeAccount({ userAccountControl: '512', accountExpires: '9223372036854775807', 'msDS-User-Account-Control-Computed': '0' }, now)).toMatchObject({ enabled: true, locked: false, expired: false, usable: true, reasons: [] }))
  it('désactivé (bit 0x2), y compris machine 4098', () => {
    expect(decodeAccount({ userAccountControl: '514' }, now)).toMatchObject({ enabled: false, usable: false, reasons: ['disabled'] })
    expect(decodeAccount({ userAccountControl: '4098' }, now).reasons).toEqual(['disabled'])
    expect(decodeAccount({ userAccountControl: '4096' }, now).usable).toBe(true)
  })
  it('verrouillé : l\'attribut calculé prime sur le drapeau de userAccountControl', () => {
    expect(decodeAccount({ userAccountControl: '512', 'msDS-User-Account-Control-Computed': '16' }, now).reasons).toEqual(['locked'])
    expect(decodeAccount({ userAccountControl: String(512 | 16), 'msDS-User-Account-Control-Computed': '0' }, now).locked).toBe(false)   // verrouillage échu
    expect(decodeAccount({ userAccountControl: String(512 | 16) }, now).locked).toBe(true)   // pas d'attribut calculé : repli sur le drapeau
  })
  it('expiré : date passée ; une date future ne bloque pas', () => {
    const past = decodeAccount({ userAccountControl: '512', accountExpires: '132000000000000000' }, now)
    expect(past).toMatchObject({ expired: true, usable: false, reasons: ['expired'], expiresAt: 1555526400000 })
    const fut = String((BigInt(now) + 86400000n + 11644473600000n) * 10000n)
    expect(decodeAccount({ userAccountControl: '512', accountExpires: fut }, now)).toMatchObject({ expired: false, usable: true })
  })
  it('cumul des motifs ; userAccountControl absent ou illisible = compte inutilisable (jamais « actif » par défaut)', () => {
    expect(decodeAccount({ userAccountControl: '514', 'msDS-User-Account-Control-Computed': '16', accountExpires: '132000000000000000' }, now).reasons).toEqual(['disabled', 'locked', 'expired'])
    expect(decodeAccount({}, now)).toMatchObject({ enabled: false, usable: false, reasons: ['unreadable'] })
    expect(decodeAccount({ userAccountControl: 'x' }, now)).toMatchObject({ usable: false, reasons: ['unreadable'] })
    expect(decodeAccount({ userAccountControl: '' , accountExpires: '132000000000000000' }, now).reasons).toEqual(['unreadable', 'expired'])
  })
})

describe('filtres', () => {
  it('utilisateur : UPN si « @ », sinon sAMAccountName ; machine : nom DNS si « . », sinon nom SAM avec « $ »', () => {
    expect(accountFilter('user', 'alice')).toContain('(sAMAccountName=alice)')
    expect(accountFilter('user', 'alice@lab.test')).toContain('(userPrincipalName=alice@lab.test)')
    expect(accountFilter('user', ' alice ')).toContain('(sAMAccountName=alice)')
    expect(accountFilter('computer', 'pc001.lab.test')).toContain('(dNSHostName=pc001.lab.test)')
    expect(accountFilter('computer', 'PC001')).toContain('(sAMAccountName=PC001$)')
    expect(accountFilter('computer', 'PC001$')).toContain('(sAMAccountName=PC001$)')
    expect(accountFilter('user', 'x')).toContain('(!(objectClass=computer))')
  })
  it('injection : *, parenthèses, antislash et NUL sont échappés, la structure du filtre ne change pas', () => {
    const builders: Array<[string, (v: string) => string]> = [['utilisateur', (v) => accountFilter('user', v)], ['machine (nom DNS)', (v) => accountFilter('computer', `${v}.x`)], ['machine (SAM)', (v) => accountFilter('computer', v)], ['groupe', (v) => groupSearchFilter(v)]]
    const count = (f: string, c: string) => [...f].filter((x) => x === c).length
    for (const [name, build] of builders) {
      const calm = build('abc')
      for (const evil of ['a*)(objectClass=*', '*)(|(uid=*', 'a\\29', 'a\0b', '*', ')(']) {
        const f = build(evil)
        expect(count(f, '('), `${name} : ${evil}`).toBe(count(calm, '('))   // la valeur n'a ouvert aucune parenthèse
        expect(count(f, ')'), `${name} : ${evil}`).toBe(count(calm, ')'))   // … ni n'en a fermé
        expect(f.includes('\0'), name).toBe(false)
        expect(f, `${name} : ${evil}`).toContain(escapeFilter(name.startsWith('machine (nom') ? `${evil}.x` : evil))   // la valeur figure dans le filtre sous sa forme échappée
      }
    }
  })
})

describe('classify', () => {
  it('identifiants refusés, certificat refusé, injoignable', () => {
    expect(classify(credErr)).toBe('service_bind'); expect(classify({ message: 'invalid credentials' })).toBe('service_bind')
    expect(classify(tlsErr)).toBe('tls'); expect(classify({ code: 'DEPTH_ZERO_SELF_SIGNED_CERT' })).toBe('tls'); expect(classify({ message: 'Hostname/IP does not match certificate\'s altnames' })).toBe('tls')
    expect(classify(downErr)).toBe('unreachable'); expect(classify(new Error('timeout'))).toBe('unreachable'); expect(classify(undefined)).toBe('unreachable')
  })
})

describe('withService', () => {
  it('mot de passe vide : refusé sans AUCUNE connexion (une liaison sans mot de passe réussirait « anonymement »)', async () => {
    const { factory, log } = fake({ [S.urls[0]!]: {} })
    const r = await withService(S, '', factory, async () => 1)
    expect(r).toMatchObject({ ok: false, reason: 'service_bind' }); expect(log).toEqual([])
  })
  it('bascule sur le serveur suivant si le premier est injoignable ; la liaison est toujours refermée', async () => {
    const { factory, log } = fake({ [S.urls[0]!]: { bindErr: downErr }, [S.urls[1]!]: {} })
    const r = await withService(S, 'pw', factory, async () => 'ok')
    expect(r).toMatchObject({ ok: true, server: S.urls[1], value: 'ok' })
    expect(log).toEqual([`bind ${S.urls[0]} svc@lab.test pw`, `unbind ${S.urls[0]}`, `bind ${S.urls[1]} svc@lab.test pw`, `unbind ${S.urls[1]}`])
  })
  it('échec de recherche : serveur suivant ; refus d\'identifiants prioritaire dans le diagnostic final', async () => {
    const boom = () => { throw downErr }
    const a = fake({ [S.urls[0]!]: { search: boom }, [S.urls[1]!]: { search: boom } })
    expect(await withService(S, 'pw', a.factory, (c) => c.search('x', { scope: 'sub', filter: '(a=b)', attributes: [] }))).toMatchObject({ ok: false, reason: 'unreachable' })
    const b = fake({ [S.urls[0]!]: { bindErr: downErr }, [S.urls[1]!]: { bindErr: credErr } })
    expect(await withService(S, 'pw', b.factory, async () => 1)).toMatchObject({ ok: false, reason: 'service_bind' })
    const c = fake({ [S.urls[0]!]: { bindErr: tlsErr }, [S.urls[1]!]: { bindErr: downErr } })
    expect(await withService(S, 'pw', c.factory, async () => 1)).toMatchObject({ ok: false, reason: 'tls' })
  })
  it('aucun serveur déclaré', async () => expect(await withService({ ...S, urls: [] }, 'pw', fake({}).factory, async () => 1)).toMatchObject({ ok: false, reason: 'unreachable' }))
})

describe('testBind', () => {
  it('un résultat par serveur, sans recherche ; mot de passe vide = refus sans connexion', async () => {
    const { factory, log } = fake({ [S.urls[0]!]: { bindErr: credErr }, [S.urls[1]!]: {} })
    const r = await testBind(S, 'pw', factory)
    expect(r).toEqual({ ok: true, attempts: [{ server: S.urls[0], ok: false, reason: 'service_bind' }, { server: S.urls[1], ok: true }] })
    expect(log.some((l) => l.startsWith('search'))).toBe(false)
    const none = fake({ [S.urls[0]!]: {} }); const e = await testBind(S, '', none.factory)
    expect(e.ok).toBe(false); expect(none.log.some((l) => l.startsWith('bind'))).toBe(false)
  })
})

const user = (extra: Record<string, unknown> = {}) => ({ dn: 'CN=alice Test,CN=Users,DC=lab,DC=test', sAMAccountName: 'alice', userPrincipalName: 'alice@lab.test', displayName: 'Alice Test', userAccountControl: '512', accountExpires: '9223372036854775807', memberOf: ['CN=grp-vpn,CN=Users,DC=lab,DC=test'], ...extra })
const grp = (n: string) => ({ dn: `CN=${n},CN=Users,DC=lab,DC=test`, cn: n })

describe('lookupAccount', () => {
  it('compte + groupes directs et imbriqués : directs d\'abord, puis par nom ; règle de chaîne sur le DN exact', async () => {
    const seen: string[] = []
    const { factory } = fake({ [S.urls[0]!]: { search: (base, o) => {
      seen.push(o.filter)
      if (o.filter.includes(`:${IN_CHAIN}:=`)) return [grp('grp-wifi'), grp('grp-vpn'), grp('grp-tout-acces')]
      return [user()]
    } } })
    const r = await lookupAccount(S, 'pw', factory, 'user', 'alice')
    expect(r.ok).toBe(true)
    const v = (r as any).value
    expect(v).toMatchObject({ found: true, kind: 'user', sam: 'alice', upn: 'alice@lab.test', dnsHostName: null, displayName: 'Alice Test', groupsTruncated: false, state: { usable: true } })
    expect(v.groups.map((g: any) => `${g.name}${g.direct ? '*' : ''}`)).toEqual(['grp-vpn*', 'grp-tout-acces', 'grp-wifi'])
    expect(seen[1]).toBe(`(&(objectCategory=group)(member:${IN_CHAIN}:=CN=alice Test\\2cCN=Users\\2cDC=lab\\2cDC=test))`.replace(/\\2c/g, ','))   // le DN n'a ni *, ni parenthèses, ni antislash à échapper
  })
  it('DN contenant des caractères spéciaux : échappé dans la règle de chaîne', async () => {
    const seen: string[] = []
    const { factory } = fake({ [S.urls[0]!]: { search: (_b, o) => { seen.push(o.filter); return o.filter.includes(IN_CHAIN) ? [] : [user({ dn: 'CN=Dupont (admin)*,OU=A,DC=lab,DC=test' })] } } })
    await lookupAccount(S, 'pw', factory, 'user', 'dupont')
    expect(seen[1]).toContain('CN=Dupont \\28admin\\29\\2a,OU=A,DC=lab,DC=test')
  })
  it('introuvable ; deux comptes homonymes = ambigu (on ne choisit jamais)', async () => {
    expect(await lookupAccount(S, 'pw', fake({ [S.urls[0]!]: { search: () => [] } }).factory, 'user', 'x')).toMatchObject({ ok: true, value: { found: false, ambiguous: false } })
    expect(await lookupAccount(S, 'pw', fake({ [S.urls[0]!]: { search: () => [user(), user({ dn: 'CN=autre' })] } }).factory, 'user', 'x')).toMatchObject({ ok: true, value: { found: false, ambiguous: true } })
  })
  it('machine : nom DNS et état', async () => {
    const pc = { dn: 'CN=PC001,CN=Computers,DC=lab,DC=test', sAMAccountName: 'PC001$', dNSHostName: 'pc001.lab.test', userAccountControl: '4098' }
    const r: any = await lookupAccount(S, 'pw', fake({ [S.urls[0]!]: { search: (_b, o) => (o.filter.includes(IN_CHAIN) ? [] : [pc]) } }).factory, 'computer', 'pc001.lab.test')
    expect(r.value).toMatchObject({ found: true, kind: 'computer', sam: 'PC001$', dnsHostName: 'pc001.lab.test', upn: null, state: { usable: false, reasons: ['disabled'] } })
  })
  it('plus de 500 groupes : liste tronquée et signalée', async () => {
    const many = Array.from({ length: MAX_GROUPS + 1 }, (_, i) => grp(`g${String(i).padStart(4, '0')}`))
    const r: any = await lookupAccount(S, 'pw', fake({ [S.urls[0]!]: { search: (_b, o) => (o.filter.includes(IN_CHAIN) ? many : [user()]) } }).factory, 'user', 'alice')
    expect(r.value.groups).toHaveLength(MAX_GROUPS); expect(r.value.groupsTruncated).toBe(true)
  })
  it('annuaire injoignable ou identifiants refusés : échec motivé, sans résultat partiel', async () => {
    expect(await lookupAccount(S, 'pw', fake({ [S.urls[0]!]: { bindErr: credErr }, [S.urls[1]!]: { bindErr: credErr } }).factory, 'user', 'a')).toMatchObject({ ok: false, reason: 'service_bind' })
  })
})

describe('findGroups', () => {
  it('triés par nom, avec description ; au plus 50 et la troncature est signalée', async () => {
    const r: any = await findGroups(S, 'pw', fake({ [S.urls[0]!]: { search: () => [{ dn: 'CN=b,DC=x', cn: 'b', description: 'Bé' }, { dn: 'CN=a,DC=x', cn: 'a' }] } }).factory, 'wifi')
    expect(r.value).toEqual({ groups: [{ dn: 'CN=a,DC=x', name: 'a', description: '', usable: true }, { dn: 'CN=b,DC=x', name: 'b', description: 'Bé', usable: true }], truncated: false })
    // un DN à échappement hexadécimal (Samba écrit « = » et « ; » ainsi) n'est pas comparable côté FreeRADIUS : signalé, non utilisable
    const hex: any = await findGroups(S, 'pw', fake({ [S.urls[0]!]: { search: () => [{ dn: 'CN=T a\\3Db,DC=x', cn: 'T a=b' }, { dn: 'CN=T a\\,b,DC=x', cn: 'T a,b' }] } }).factory, 'T')
    expect(hex.value.groups.map((g: any) => [g.name, g.usable])).toEqual([['T a,b', true], ['T a=b', false]])
    const many = Array.from({ length: MAX_FOUND_GROUPS + 1 }, (_, i) => ({ dn: `CN=g${i},DC=x`, cn: `g${String(i).padStart(3, '0')}` }))
    const t: any = await findGroups(S, 'pw', fake({ [S.urls[0]!]: { search: () => many } }).factory, 'g')
    expect(t.value.groups).toHaveLength(MAX_FOUND_GROUPS); expect(t.value.truncated).toBe(true)
  })
})
