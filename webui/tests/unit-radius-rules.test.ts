// Règles d'accès RADIUS (0.13.3) : validation, compilation, évaluation (première correspondance, refus par défaut), analyse de la liste.
// Le jeu de cas tests/radius-rules-cases.json est PARTAGÉ avec tests/b30-radius-rules-live.sh, qui joue les mêmes cas sur un vrai FreeRADIUS + Samba AD :
// ce que dit ce fichier (moteur de la console, utilisé par la simulation) et ce que décide root doivent rester identiques.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { analyze, compileRules, evaluate, GROUP_DN_RE, replyAttrs, rowToRule, ruleBody, rulesJson, ssidFromCalledStation, VENDOR_ATTRS } from '../server/utils/radius-rules'
import type { CompiledRule, Directory, EvalInput, RuleRow } from '../server/utils/radius-rules'
import type { AccountState } from '../server/utils/radius-dir'
import { authzDigest, authzProblems, buildAuthzDeposit } from '../server/utils/radius-authz'
import type { DirSettings } from '../server/utils/radius-dir'

const FX = JSON.parse(readFileSync(new URL('../../tests/radius-rules-cases.json', import.meta.url), 'utf8'))
const state = (s: string): AccountState => ({
  enabled: s !== 'disabled', locked: s === 'locked', expired: s === 'expired', expiresAt: null, usable: s === 'ok',
  reasons: s === 'ok' ? [] : [s as 'disabled' | 'locked' | 'expired'],
})
function rowsOf(): RuleRow[] {
  return FX.rules.map((r: any, i: number) => { const b = ruleBody.parse(r); return rowToRule({ id: 100 + i, rank: i + 1, name: b.name, enabled: b.enabled, action: b.action, conds: b.conds, reply: b.reply, comment: b.comment }) })
}
const compiled = () => compileRules(rowsOf(), FX.clients)
function input(who: string, client: string | null, ssid: string | null): EvalInput {
  const acc = FX.accounts[who]
  const c = client ? FX.clients.find((x: any) => x.name === client) : null
  const directory: Directory = !acc ? { status: 'ok', found: false, ambiguous: false } : { status: 'ok', found: true, state: state(acc.state), groups: acc.groups }
  return { identity: { kind: who.includes('@') ? 'user' : 'computer', name: who }, directory, client: c ? { name: c.name, usage: c.usage } : null, ssid }
}

describe('jeu de cas partagé avec FreeRADIUS (b30)', () => {
  for (const k of FX.cases) {
    it(k.id, () => {
      const d = evaluate(compiled(), input(k.who, k.client, k.ssid))
      expect(d.decision).toBe(k.expect.decision)
      expect(d.code).toBe(k.expect.code)
      if (k.expect.rule) expect(d.rule).toBe(k.expect.rule)
      const get = (n: string) => d.reply.find((a) => a.name === n)?.value
      if (k.expect.vlan) expect(get('Tunnel-Private-Group-Id')).toBe(String(k.expect.vlan)); else expect(get('Tunnel-Private-Group-Id')).toBeUndefined()
      if (k.expect.pool) expect(get('Framed-Pool')).toBe(k.expect.pool); else expect(get('Framed-Pool')).toBeUndefined()
      if (k.expect.timeout) expect(get('Session-Timeout')).toBe(String(k.expect.timeout))
      if (k.expect.filter) expect(get('Filter-Id')).toBe(k.expect.filter)
      for (const [n, v] of Object.entries(k.expect.attrs ?? {})) expect(get(n)).toBe(v)
      if (d.decision === 'reject') expect(d.reply).toEqual([])
    })
  }
  it('numérotation : les règles désactivées ne comptent pas, le client disparu garde son numéro mais ne s\'applique jamais', () => {
    const c = compiled()
    expect(c.map((r) => r.n)).toEqual([1, 2, 3, 4, 5, 6, 7])
    expect(c.at(-1)!.name).toBe('Client disparu'); expect(c.at(-1)!.nas).toEqual([])
    expect(c.find((r) => r.name === 'Regle desactivee')).toBeUndefined()
  })
})

describe('compilation', () => {
  const row = (o: Partial<RuleRow> & { conds?: Partial<RuleRow['conds']> }): RuleRow => rowToRule({ id: 1, rank: 1, name: 'r', enabled: true, action: 'accept', reply: {}, comment: null, ...o, conds: { kind: null, groups: [], clients: [], usages: [], ssids: [], ...(o.conds ?? {}) } })
  const cl = [{ name: 'a', usage: 'wifi' as const, enabled: true }, { name: 'b', usage: 'vpn' as const, enabled: true }, { name: 'c', usage: 'wifi' as const, enabled: false }]
  it('sans condition client ni usage : tous les clients (nas = null)', () => expect(compileRules([row({})], cl)[0]!.nas).toBeNull())
  it('clients et usages se cumulent (l\'un OU l\'autre), clients désactivés exclus', () => {
    expect(compileRules([row({ conds: { usages: ['wifi'] } as any })], cl)[0]!.nas).toEqual(['a'])
    expect(compileRules([row({ conds: { usages: ['wifi'], clients: ['b'] } as any })], cl)[0]!.nas).toEqual(['a', 'b'])
    expect(compileRules([row({ conds: { clients: ['c'] } as any })], cl)[0]!.nas).toEqual([])
  })
  it('le rang décide de l\'ordre, puis l\'identifiant', () => {
    const r = compileRules([row({ id: 3, rank: 2, name: 'z' }), row({ id: 2, rank: 2, name: 'y' }), row({ id: 9, rank: 1, name: 'x' })], cl)
    expect(r.map((x) => x.name)).toEqual(['x', 'y', 'z']); expect(r.map((x) => x.n)).toEqual([1, 2, 3])
  })
  it('le fichier de référence tests/radius-rules-compiled.json (celui que rejoue b30 sur FreeRADIUS) est exactement ce que la console dépose pour ce jeu de règles', () => {
    expect(rulesJson(compiled())).toBe(readFileSync(new URL('../../tests/radius-rules-compiled.json', import.meta.url), 'utf8'))
  })
  it('rules.json ne contient que des données (pas d\'identifiant interne)', () => {
    const j = JSON.parse(rulesJson(compiled()))
    expect(Object.keys(j)).toEqual(['rules']); expect(Object.keys(j.rules[0]).sort()).toEqual(['action', 'groups', 'kind', 'name', 'nas', 'reply', 'ssids'])
  })
})

describe('évaluation : ordre et cas limites', () => {
  const R = (o: Partial<CompiledRule>): CompiledRule => ({ n: 1, id: 1, name: 'r', action: 'accept', kind: null, groups: [], nas: null, ssids: [], reply: {}, ...o })
  const ok = (groups: string[] = []): Directory => ({ status: 'ok', found: true, state: state('ok'), groups })
  const base = (d: Directory): EvalInput => ({ identity: { kind: 'user', name: 'a@x.y' }, directory: d, client: { name: 'a', usage: 'wifi' }, ssid: null })
  it('première correspondance : un refus placé avant l\'acceptation l\'emporte, et inversement', () => {
    const g = 'CN=g,DC=x,DC=y'
    expect(evaluate([R({ n: 1, action: 'reject', groups: [g] }), R({ n: 2 })], base(ok([g]))).code).toBe('rule_reject')
    expect(evaluate([R({ n: 1 }), R({ n: 2, action: 'reject', groups: [g] })], base(ok([g]))).code).toBe('rule_accept')
  })
  it('refus par défaut : liste vide, ou aucune règle ne correspond (la trace dit pourquoi)', () => {
    expect(evaluate([], base(ok())).code).toBe('default_reject')
    const d = evaluate([R({ groups: ['CN=g,DC=x,DC=y'] })], base(ok(['CN=h,DC=x,DC=y'])))
    expect(d.code).toBe('default_reject'); expect(d.trace[0]!.conds[0]).toMatchObject({ type: 'groups', ok: false, got: [] })
  })
  it('un groupe : l\'un quelconque des groupes de la règle suffit (OU), toutes les conditions de la règle sont requises (ET)', () => {
    const a = 'CN=a,DC=x', b = 'CN=b,DC=x'
    expect(evaluate([R({ groups: [a, b] })], base(ok([b]))).code).toBe('rule_accept')
    expect(evaluate([R({ groups: [a], kind: 'computer' })], base(ok([a]))).code).toBe('default_reject')
    expect(evaluate([R({ groups: [a], ssids: ['S'] })], base(ok([a]))).code).toBe('default_reject')
  })
  it('les DN de groupe se comparent à l\'identique (casse comprise), comme FreeRADIUS', () => {
    expect(evaluate([R({ groups: ['CN=Grp,DC=x'] })], base(ok(['CN=grp,DC=x']))).code).toBe('default_reject')
  })
  it('SSID : sensible à la casse ; sans SSID connu, une règle qui en exige un ne correspond pas', () => {
    const r = [R({ ssids: ['Corp'] })]
    expect(evaluate(r, { ...base(ok()), ssid: 'Corp' }).code).toBe('rule_accept')
    expect(evaluate(r, { ...base(ok()), ssid: 'corp' }).code).toBe('default_reject')
    expect(evaluate(r, base(ok())).code).toBe('default_reject')
  })
  it('client absent : une règle limitée à des clients ne correspond pas, une règle sans restriction oui', () => {
    expect(evaluate([R({ nas: ['a'] })], { ...base(ok()), client: null }).code).toBe('default_reject')
    expect(evaluate([R({})], { ...base(ok()), client: null }).code).toBe('rule_accept')
  })
  it('la règle « jamais » (nas = []) est tracée comme telle', () => {
    const d = evaluate([R({ nas: [] })], base(ok()))
    expect(d.code).toBe('default_reject'); expect(d.trace[0]).toMatchObject({ matched: false, never: true })
  })
  it('étapes avant les règles : identité, annuaire, compte (aucune règle ne peut les outrepasser)', () => {
    const accept = [R({})]
    expect(evaluate(accept, { ...base(ok()), identity: null })).toMatchObject({ stage: 'identity', code: 'no_identity' })
    expect(evaluate(accept, base({ status: 'unavailable' }))).toMatchObject({ stage: 'directory', code: 'directory_unavailable' })
    expect(evaluate(accept, base({ status: 'ok', found: false, ambiguous: true }))).toMatchObject({ code: 'account_ambiguous' })
    expect(evaluate(accept, base({ status: 'ok', found: false, ambiguous: false }))).toMatchObject({ code: 'account_not_found' })
    for (const [s, c] of [['disabled', 'account_disabled'], ['locked', 'account_locked'], ['expired', 'account_expired']] as const)
      expect(evaluate(accept, base({ status: 'ok', found: true, state: state(s), groups: [] }))).toMatchObject({ stage: 'account', code: c, trace: [] })
    expect(evaluate(accept, base({ status: 'ok', found: true, state: { ...state('ok'), usable: false, reasons: ['unreadable'] }, groups: [] })).code).toBe('account_unreadable')
  })
  it('compte désactivé ET verrouillé : la première raison, dans l\'ordre de la console (désactivé avant verrouillé avant expiré)', () => {
    const s: AccountState = { enabled: false, locked: true, expired: true, expiresAt: 1, usable: false, reasons: ['disabled', 'locked', 'expired'] }
    expect(evaluate([R({})], base({ status: 'ok', found: true, state: s, groups: [] })).code).toBe('account_disabled')
  })
  it('attributs de réponse : VLAN (3 attributs), pool, durée, Filter-Id, attributs constructeur, dans cet ordre', () => {
    expect(replyAttrs({ vlan: 10, pool: 'p', sessionTimeout: 60, filterId: 'f', attrs: [{ name: 'Aruba-User-Role', value: 'x' }] }).map((a) => a.name))
      .toEqual(['Tunnel-Type', 'Tunnel-Medium-Type', 'Tunnel-Private-Group-Id', 'Framed-Pool', 'Session-Timeout', 'Filter-Id', 'Aruba-User-Role'])
    expect(replyAttrs({})).toEqual([])
  })
})

describe('SSID du Called-Station-Id', () => {
  it.each([
    ['AA-BB-CC-DD-EE-FF:Corp Wifi', 'Corp Wifi'], ['aa:bb:cc:dd:ee:ff:Corp', 'Corp'], ['aabb.ccdd.eeff:Invités', 'Invités'], ['AABBCCDDEEFF:x:y', 'x:y'],
    ['AA-BB-CC-DD-EE-FF', null], ['AA-BB-CC-DD-EE-FF:', null], ['pas une adresse:Corp', null], ['', null],
  ])('%s → %s', (csid, ssid) => expect(ssidFromCalledStation(csid)).toBe(ssid))
})

describe('validation d\'une règle (ruleBody)', () => {
  const ok = { name: 'R', action: 'accept' }
  it('valeurs par défaut et normalisation', () => {
    const b = ruleBody.parse({ ...ok, usages: ['wifi', 'vpn', 'wifi'], clients: ['b', 'a', 'a'], groups: [{ dn: 'CN=g,DC=x,DC=y', name: '' }] })
    expect(b.enabled).toBe(true); expect(b.conds).toMatchObject({ kind: null, clients: ['a', 'b'], usages: ['vpn', 'wifi'], ssids: [] })
    expect(b.conds.groups[0]!.name).toBe('g'); expect(b.reply).toEqual({})
  })
  it('refus : champs inconnus, nom vide, action inconnue, bornes de VLAN et de durée', () => {
    for (const bad of [{ ...ok, x: 1 }, { ...ok, name: ' ' }, { ...ok, action: 'maybe' }, { ...ok, reply: { vlan: 0 } }, { ...ok, reply: { vlan: 4095 } }, { ...ok, reply: { sessionTimeout: 59 } }, { ...ok, reply: { sessionTimeout: 2592001 } }, { ...ok, reply: { vlan: 1.5 } }])
      expect(ruleBody.safeParse(bad).success, JSON.stringify(bad)).toBe(false)
    for (const good of [{ ...ok, reply: { vlan: 1 } }, { ...ok, reply: { vlan: 4094 } }, { ...ok, reply: { sessionTimeout: 60 } }]) expect(ruleBody.safeParse(good).success).toBe(true)
  })
  it('un refus ne porte aucune réponse', () => { expect(ruleBody.safeParse({ ...ok, action: 'reject', reply: { vlan: 5 } }).success).toBe(false); expect(ruleBody.safeParse({ ...ok, action: 'reject' }).success).toBe(true) })
  it('attributs constructeur : liste blanche, forme de la valeur, pas de doublon', () => {
    expect(Object.keys(VENDOR_ATTRS)).toContain('Aruba-User-Role')
    expect(ruleBody.safeParse({ ...ok, reply: { attrs: [{ name: 'Service-Type', value: 'x' }] } }).success).toBe(false)
    expect(ruleBody.safeParse({ ...ok, reply: { attrs: [{ name: 'Aruba-User-Role', value: 'a"b' }] } }).success).toBe(false)
    expect(ruleBody.safeParse({ ...ok, reply: { attrs: [{ name: 'Aruba-User-Role', value: 'a' }, { name: 'Aruba-User-Role', value: 'b' }] } }).success).toBe(false)
  })
  it('SSID, pool, Filter-Id, nom de client : caractères admis seulement', () => {
    for (const bad of [{ ssids: ["a'b"] }, { ssids: ['a'.repeat(33)] }, { ssids: ['a"b'] }, { reply: { pool: 'a b' } }, { reply: { filterId: "x'y" } }, { reply: { filterId: 'x\\y' } }, { clients: ['Majuscule'] }, { clients: ['a b'] }])
      expect(ruleBody.safeParse({ ...ok, ...bad }).success, JSON.stringify(bad)).toBe(false)
  })
  it('DN de groupe : échappements RFC 4514 admis, injection refusée', () => {
    for (const good of ['CN=g,CN=Users,DC=lab,DC=test', "CN=Réseau\\, Wi-Fi d'essai,CN=Users,DC=lab,DC=test", 'CN=back\\\\slash,DC=x', 'CN=a\\,b,DC=x', 'CN=a\\#b\\+c\\<d\\>,DC=x']) expect(GROUP_DN_RE.test(good), good).toBe(true)
    for (const bad of ['CN=g"x,DC=x', 'CN=${x},DC=x', 'CN=%{x},DC=x', 'CN=g`x,DC=x', 'CN=g\\q,DC=x', 'CN=g\\', 'CN=g\nx', 'a=', 'CN=g}x,DC=x', 'x'.repeat(513), 'CN=a\\3Db,DC=x', 'CN=a\\3Bb,DC=x', 'CN=a\\2Cb,DC=x']) expect(GROUP_DN_RE.test(bad), JSON.stringify(bad)).toBe(false)
    expect(ruleBody.safeParse({ ...ok, groups: [{ dn: 'sans-egal-aaa', name: '' }] }).success).toBe(false)
  })
  it('le motif des DN de groupe est identique dans la console, l\'interface et le script root', () => {
    const src = GROUP_DN_RE.source
    const ui = readFileSync(new URL('../app/components/RadiusRules.vue', import.meta.url), 'utf8')
    expect(ui, 'RadiusRules.vue : DN_OK').toContain(`const DN_OK = /${src}/`)
    const root = readFileSync(new URL('../../src/rootfs/usr/local/sbin/ddibuntu-radius', import.meta.url), 'utf8')
    const m = /GDN = re\.compile\(r"(.*)"\)/.exec(root)
    expect(m, 'ddibuntu-radius : GDN').not.toBeNull()
    // Python n'a pas « \/ » ; les guillemets sont échappés dans la chaîne brute du script root
    const norm = (x: string) => x.replace(/\\"/g, '"').replace(/^\^|\$$/g, '')
    expect(norm(m![1]!)).toBe(norm(src))
  })
  it('groupe en double (casse ignorée) refusé ; plafonds', () => {
    expect(ruleBody.safeParse({ ...ok, groups: [{ dn: 'CN=g,DC=x', name: '' }, { dn: 'cn=G,dc=x', name: '' }] }).success).toBe(false)
    expect(ruleBody.safeParse({ ...ok, groups: Array.from({ length: 31 }, (_, i) => ({ dn: `CN=g${i},DC=x`, name: '' })) }).success).toBe(false)
    expect(ruleBody.safeParse({ ...ok, ssids: Array.from({ length: 21 }, (_, i) => `s${i}`) }).success).toBe(false)
  })
})

describe('analyse de la liste', () => {
  const R = (n: number, o: Partial<CompiledRule> = {}): CompiledRule => ({ n, id: n, name: `r${n}`, action: 'accept', kind: null, groups: [], nas: null, ssids: [], reply: {}, ...o })
  it('aucune règle d\'acceptation', () => { expect(analyze([])).toEqual([{ code: 'no_accept' }]); expect(analyze([R(1, { action: 'reject', groups: ['g'] })]).map((w) => w.code)).toEqual(['no_accept']) })
  it('acceptation sans aucune condition', () => expect(analyze([R(1)])).toEqual([{ code: 'catch_all_accept', rule: 1 }]))
  it('règle masquée par une règle plus large placée avant', () => {
    expect(analyze([R(1, { groups: ['g'] }), R(2, { groups: ['g'], ssids: ['s'] })])).toContainEqual({ code: 'shadowed', rule: 2, by: 1 })
    expect(analyze([R(1, { groups: ['g', 'h'] }), R(2, { groups: ['h'], action: 'reject' })])).toContainEqual({ code: 'shadowed', rule: 2, by: 1 })
    expect(analyze([R(1), R(2, { groups: ['g'] })])).toContainEqual({ code: 'shadowed', rule: 2, by: 1 })
  })
  it('pas de faux positif : conditions croisées, règle plus étroite en tête, règle « jamais »', () => {
    expect(analyze([R(1, { groups: ['g'] }), R(2, { groups: ['h'] })]).filter((w) => w.code === 'shadowed')).toEqual([])
    expect(analyze([R(1, { groups: ['g'], ssids: ['s'] }), R(2, { groups: ['g'] })]).filter((w) => w.code === 'shadowed')).toEqual([])
    expect(analyze([R(1, { groups: ['g'], kind: 'user' }), R(2, { groups: ['g'] })]).filter((w) => w.code === 'shadowed')).toEqual([])
    expect(analyze([R(1, { nas: [], groups: ['g'] }), R(2, { groups: ['g'] })]).filter((w) => w.code === 'shadowed')).toEqual([])
    expect(analyze([R(1, { nas: ['a'] }), R(2, { nas: ['a', 'b'] })]).filter((w) => w.code === 'shadowed')).toEqual([])
  })
  it('règle sans client correspondant', () => expect(analyze([R(1, { groups: ['g'] }), R(2, { nas: [], groups: ['h'] })])).toContainEqual({ code: 'empty_nas', rule: 2 }))
})

describe('dépôt vers root', () => {
  const dir: DirSettings = { urls: ['ldaps://dc1.lab.test'], baseDn: 'DC=lab,DC=test', bindDn: 'svc@lab.test', tlsRejectUnauthorized: true, bindPasswordEnc: 'x' }
  const rules = compiled()
  const p = (o: Partial<Parameters<typeof authzProblems>[0]> = {}) => authzProblems({ rules, pkiEmpty: false, pkiReady: true, dir, password: 'pw', ldapModule: true, ...o })
  it('prêt', () => expect(p()).toEqual([]))
  it('sans règle active, rien n\'est exigé (refus par défaut déployé tel quel)', () => expect(p({ rules: [], pkiEmpty: true, pkiReady: false, password: null })).toEqual([]))
  it('EAP-TLS, annuaire, module LDAP : chaque manque est signalé', () => {
    expect(p({ pkiEmpty: true, pkiReady: false })).toContain('eap_required'); expect(p({ pkiReady: false })).toContain('eap_required')
    expect(p({ password: null })).toEqual(['directory_incomplete']); expect(p({ dir: { ...dir, urls: [] } })).toEqual(['directory_incomplete'])
    expect(p({ ldapModule: false })).toEqual(['ldap_module_missing']); expect(p({ ldapModule: null })).toEqual([])
  })
  it('réglages que root refuserait : URL non LDAPS, base illisible, mot de passe avec expansion ou saut de ligne', () => {
    expect(p({ dir: { ...dir, urls: ['ldap://dc1.lab.test'] } })).toEqual(['directory_settings'])
    expect(p({ dir: { ...dir, baseDn: 'DC=a"b' } })).toEqual(['directory_settings'])
    for (const pw of ['a${HOME}b', 'a$ENV{X}', 'a$(id)', 'a\nb', 'x'.repeat(201)]) expect(p({ password: pw }), pw).toEqual(['directory_chars'])
    expect(p({ password: 'a$b\\c"d' })).toEqual([])
  })
  it('le dépôt contient les règles, les réglages et l\'autorité LDAPS ; l\'empreinte change avec le moindre réglage', () => {
    const d = buildAuthzDeposit(rules, { ...dir, caPem: '-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----' }, 'pw')
    expect(JSON.parse(d.ldap)).toEqual({ urls: dir.urls, baseDn: dir.baseDn, bindDn: dir.bindDn, bindPassword: 'pw', tlsRejectUnauthorized: true }); expect(d.caPem).toContain('BEGIN CERTIFICATE'); expect(JSON.parse(d.rules).rules).toHaveLength(7)
    expect(buildAuthzDeposit(rules, dir, 'pw').caPem).toBeUndefined()
  })
  it('empreinte : « none » sans règle, jamais le mot de passe, sensible à chaque élément', () => {
    process.env.DDI_SECRET_KEY ??= 'k'.repeat(48)
    expect(authzDigest([], dir, 'pw')).toBe('none')
    const a = authzDigest(rules, dir, 'pw')
    expect(a).toMatch(/^[0-9a-f]{64}$/); expect(a).not.toContain('pw')
    expect(authzDigest(rules, dir, 'pw2')).not.toBe(a); expect(authzDigest(rules, { ...dir, baseDn: 'DC=x' }, 'pw')).not.toBe(a); expect(authzDigest(rules.slice(1), dir, 'pw')).not.toBe(a)
    expect(authzDigest(rules, dir, 'pw')).toBe(a)
  })
})
