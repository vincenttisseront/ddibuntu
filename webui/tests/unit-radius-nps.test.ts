// Import d'un NPS Windows (0.13.4) : lecture de l'export, motifs réduits à des jokers, adresses et noms de clients, plan d'import (statuts, notes, sûreté).
// L'export de référence est SYNTHÉTIQUE (tests/radius-nps-export.xml) : sa structure est celle lue par l'outil d'audit AD-NPS sur de vrais exports.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { classifySid, extractSids, globAlternatives, globMatch, normClientName, NpsParseError, npsAddress, parseCondition, parseNpsExport, planImport, sidsToResolve } from '../server/utils/radius-nps'
import type { GroupState, PlanCtx } from '../server/utils/radius-nps'
import { ruleBody } from '../server/utils/radius-rules'
import { clientBody } from '../server/utils/radius'
import { resolveGroupSids, sidBase } from '../server/utils/radius-dir'
import type { DirSettings, Factory } from '../server/utils/radius-dir'

const XML = readFileSync(new URL('../../tests/radius-nps-export.xml', import.meta.url), 'utf8')
const D = 'S-1-5-21-111-222-333'
const GROUPS = new Map<string, GroupState>([
  [`${D}-1106`, { state: 'found', dn: 'CN=GG-Admins-Reseau,OU=Groupes,DC=lab,DC=test', name: 'GG-Admins-Reseau' }],
  [`${D}-1107`, { state: 'found', dn: 'CN=GG-Wifi-Users,OU=Groupes,DC=lab,DC=test', name: 'GG-Wifi-Users' }],
  [`${D}-1108`, { state: 'notfound' }],
  [`${D}-1109`, { state: 'unusable', name: 'Invités=temp' }],
])
const ctx = (over: Partial<PlanCtx> = {}, opts: Partial<PlanCtx['opts']> = {}): PlanCtx => ({ existingClients: [], existingRules: [], directory: 'ok', groups: GROUPS, opts: { usages: {}, activate: false, exclude: new Set(), ...opts }, ...over })
const plan = (c: PlanCtx = ctx()) => planImport(parseNpsExport(XML), c)
const codes = (x: { notes: Array<{ code: string }> }) => x.notes.map((n) => n.code)

describe('lecture de l\'export NPS', () => {
  const exp = parseNpsExport(XML)
  it('clients : uniquement ceux du conteneur Clients (pas les groupes de serveurs RADIUS distants)', () => {
    expect(exp.clientsContainer).toBe(true)
    expect(exp.clients.map((c) => c.name)).toEqual(['AP Étage 1', 'wlc-1', 'VPN-FW', 'Switch Core', 'ap9', 'Too Wide', 'wlc-1-bis', 'ddi-selftest'])
    expect(exp.clients.find((c) => c.name === 'Switch Core')!.secret).toBeNull()
    expect(exp.clients.some((c) => c.address === '10.99.0.1')).toBe(false)
  })
  it('stratégies : réseau et demande de connexion distinguées, profil retrouvé par msNPAction, méthodes EAP lues', () => {
    expect(exp.policies.filter((p) => p.connection).map((p) => p.name)).toEqual(['Use Windows authentication for all users'])
    const net = exp.policies.filter((p) => !p.connection)
    expect(net.map((p) => p.name)).toEqual(['Admins réseau', 'Wi-Fi utilisateurs', 'Tous les utilisateurs', 'Refus invités', 'VPN legacy', 'Heures bureau', 'Ancienne', 'VLAN invités'])
    const by = (n: string) => net.find((p) => p.name === n)!
    expect(by('Admins réseau')).toMatchObject({ order: 1, enabled: true, grant: true, eapTypes: [13], profileFound: true, otherAttrs: [] })
    expect(by('Admins réseau').conditions).toHaveLength(2)
    expect(by('Wi-Fi utilisateurs').eapTypes).toEqual([25])
    expect(by('Refus invités').grant).toBe(false)
    expect(by('VPN legacy')).toMatchObject({ eapTypes: [], authTypes: [4] })
    expect(by('Ancienne').enabled).toBe(false)
    expect(by('VLAN invités').otherAttrs).toEqual(['msRADIUSTunnelPvtGroupID'])
  })
  it('refuse ce qui n\'est pas un export NPS exploitable', () => {
    const err = (s: string) => { try { parseNpsExport(s); return null } catch (e) { return e instanceof NpsParseError ? e.code : 'autre' } }
    expect(err('')).toBe('nps_empty')
    expect(err('<a><b></a>')).toBe('nps_xml')
    expect(err('<?xml version="1.0"?><Root><x/></Root>')).toBe('nps_not_nps')
    expect(err('<!DOCTYPE r [<!ENTITY a "b">]><Root/>')).toBe('nps_doctype')
    expect(err('x'.repeat(8_000_001))).toBe('nps_too_big')
  })
  it('un fichier précédé d\'une marque d\'ordre des octets est lu', () => { expect(parseNpsExport('﻿' + XML).clients).toHaveLength(8) })
  it('SID à résoudre : groupes ordinaires seulement (ni « Tout le monde », ni groupes principaux), sans doublon', () => {
    expect(sidsToResolve(exp)).toEqual([`${D}-1106`, `${D}-1107`, `${D}-1108`, `${D}-1109`])
  })
})

describe('conditions et motifs', () => {
  it('fonction et argument', () => {
    expect(parseCondition('NTGROUPS("S-1-5-21-1-2-3-1105")')).toEqual({ fn: 'NTGROUPS', arg: 'S-1-5-21-1-2-3-1105' })
    expect(parseCondition('MATCH("NAS-Port-Type=^19$")')).toEqual({ fn: 'MATCH', arg: 'NAS-Port-Type=^19$' })
    expect(parseCondition('n\'importe quoi')).toBeNull()
  })
  it('SID : tous, séparateur quelconque, sans doublon', () => {
    expect(extractSids('NTGROUPS("S-1-5-21-1-2-3-1105;S-1-5-32-544 S-1-5-21-1-2-3-1105")')).toEqual(['S-1-5-21-1-2-3-1105', 'S-1-5-32-544'])
  })
  it('classement des SID', () => {
    expect(classifySid('S-1-1-0')).toEqual({ t: 'everyone' })
    expect(classifySid('S-1-5-11')).toEqual({ t: 'everyone' })
    expect(classifySid(`${D}-513`)).toEqual({ t: 'primary', kind: 'user' })
    expect(classifySid(`${D}-515`)).toEqual({ t: 'primary', kind: 'computer' })
    expect(classifySid(`${D}-512`)).toEqual({ t: 'group' })
    expect(classifySid('S-1-5-32-544')).toEqual({ t: 'group' })
  })
  it('motifs : littéraux et jokers seulement, ancrage respecté', () => {
    expect(globAlternatives('^19$')).toEqual(['19'])
    expect(globAlternatives('^15$|^19$')).toEqual(['15', '19'])
    expect(globAlternatives('^AP-.*')).toEqual(['AP-*'])
    expect(globAlternatives('AP1')).toEqual(['*AP1*'])
    expect(globAlternatives('^.*:Corp\\.WiFi$')).toEqual(['*:Corp.WiFi'])
    // tout le reste est refusé : classes, quantificateurs, groupes, point seul, échappements alphanumériques (\d, \w…)
    for (const bad of ['^AP[0-9]$', '^(a|b)$', '^a+$', '^a.c$', '^\\d+$', '^a?$', '', '^a{2}$', '|']) expect(globAlternatives(bad), bad).toBeNull()
  })
  it('motif volumineux ou pathologique : refusé sans calcul coûteux', () => {
    expect(globAlternatives('a'.repeat(501))).toBeNull()
    expect(globAlternatives(Array(201).fill('a').join('|'))).toBeNull()
    const t0 = Date.now()
    expect(globMatch('*a*a*a*a*a*a*a*a*b', 'a'.repeat(5000))).toBe(false)
    expect(Date.now() - t0).toBeLessThan(1000)
  })
  it('comparaison de jokers insensible à la casse', () => {
    expect(globMatch('ap-*', 'AP-Etage-1')).toBe(true)
    expect(globMatch('wlc-1', 'WLC-1')).toBe(true)
    expect(globMatch('wlc-1', 'wlc-10')).toBe(false)
    expect(globMatch('*:corpwifi', 'AA-BB-CC-DD-EE-FF:CorpWiFi')).toBe(true)
    expect(globMatch('*', '')).toBe(true)
  })
})

describe('clients : noms et adresses', () => {
  it('nom Ipnoria : minuscules, tirets, une lettre au début, 41 caractères, jamais le nom réservé', () => {
    expect(normClientName('AP Étage 1')).toBe('ap-etage-1')
    expect(normClientName('  __Wi_Fi__ ')).toBe('wi-fi')
    expect(normClientName('10.0.0.1')).toBe('nas-10-0-0-1')
    expect(normClientName('!!!')).toBe('nas')
    expect(normClientName('ddi-selftest')).toBe('nas-ddi-selftest')
    expect(normClientName('x'.repeat(80))).toHaveLength(41)
    for (const n of ['AP Étage 1', 'a'.repeat(90), '9lives', 'é']) expect(normClientName(n)).toMatch(/^[a-z][a-z0-9-]{0,40}$/)
  })
  it('adresses', () => {
    expect(npsAddress('10.20.0.11')).toEqual({ ok: true, address: '10.20.0.11/32' })
    expect(npsAddress('10.10.0.0/24')).toEqual({ ok: true, address: '10.10.0.0/24' })
    expect(npsAddress('10.10.0.0/255.255.255.0')).toEqual({ ok: true, address: '10.10.0.0/24' })
    expect(npsAddress('2001:db8::1')).toMatchObject({ ok: true })
    expect(npsAddress('ap9.corp.local')).toEqual({ ok: false, problem: 'address_dns' })
    expect(npsAddress('10.0.0.0/8')).toEqual({ ok: false, problem: 'address_range' })
    expect(npsAddress('127.0.0.1')).toEqual({ ok: false, problem: 'address_range' })
    expect(npsAddress('10.0.0.0/255.0.255.0')).toEqual({ ok: false, problem: 'address_invalid' })
    expect(npsAddress('')).toEqual({ ok: false, problem: 'address_invalid' })
    expect(npsAddress('300.1.1.1')).toEqual({ ok: false, problem: 'address_invalid' })
  })
})

describe('plan d\'import : clients', () => {
  const p = plan()
  const c = (orig: string) => p.clients.find((x) => x.original === orig)!
  it('statuts et notes', () => {
    expect(c('AP Étage 1')).toMatchObject({ status: 'adapted', name: 'ap-etage-1', address: '10.20.0.11/32', secret: 'reused', selected: true })
    expect(codes(c('AP Étage 1'))).toEqual(['renamed'])
    expect(c('wlc-1')).toMatchObject({ status: 'imported', name: 'wlc-1', secret: 'reused' })
    expect(c('VPN-FW')).toMatchObject({ status: 'adapted', name: 'vpn-fw', secret: 'generated' })
    expect(codes(c('VPN-FW'))).toContain('secret_weak')
    expect(codes(c('Switch Core'))).toEqual(['renamed', 'secret_absent'])
    expect(c('Switch Core').address).toBe('10.10.0.0/24')
    expect(c('ap9')).toMatchObject({ status: 'skipped', selected: false }); expect(codes(c('ap9'))).toEqual(['address_dns'])
    expect(codes(c('Too Wide'))).toEqual(['address_range'])
    expect(codes(c('wlc-1-bis'))).toEqual(['address_dup'])
    expect(c('ddi-selftest')).toMatchObject({ status: 'adapted', name: 'nas-ddi-selftest' })
  })
  it('aucun secret dans le plan', () => {
    const json = JSON.stringify(p)
    for (const s of ['Zk3mPq8vTn5wRb7yHc2LdX9a', 'Hq7nVd4sKf2jXm9tBw6pLz3R', 'partage', 'NeDoitJamais']) expect(json).not.toContain(s)
  })
  it('rien n\'est écrasé : client ou adresse déjà présents', () => {
    const q = plan(ctx({ existingClients: [{ name: 'wlc-1', address: '10.20.0.2/32' }, { name: 'ap-etage-1', address: '10.99.9.9/32' }, { name: 'manuel', address: '10.30.0.1/32' }] }))
    const g = (o: string) => q.clients.find((x) => x.original === o)!
    expect(codes(g('wlc-1'))).toEqual(['exists'])
    expect(g('wlc-1').status).toBe('skipped')
    expect(g('AP Étage 1')).toMatchObject({ status: 'adapted', name: 'ap-etage-1-2' })   // même nom, autre adresse : suffixe
    expect(codes(g('VPN-FW'))).toEqual(['address_taken'])
    expect(codes(g('wlc-1-bis'))).toEqual(['address_taken'])   // l'adresse appartient à « wlc-1 », pas à lui
  })
  it('usage choisi par l\'administrateur, exclusion d\'un client, plafond', () => {
    const q = plan(ctx({}, { usages: { 'wlc-1': 'wifi', 'VPN-FW': 'vpn' }, exclude: new Set(['c:Switch Core']) }))
    expect(q.clients.find((x) => x.original === 'wlc-1')!.usage).toBe('wifi')
    expect(q.clients.find((x) => x.original === 'AP Étage 1')!.usage).toBe('other')
    expect(q.clients.find((x) => x.original === 'Switch Core')!.selected).toBe(false)
    const full = plan(ctx({ existingClients: Array.from({ length: 1999 }, (_, i) => ({ name: `x${i}`, address: `10.${1 + (i >> 8)}.${i & 255}.1/32` })) }))
    expect(full.clients.filter((x) => x.status !== 'skipped')).toHaveLength(1)
    expect(full.clients.filter((x) => codes(x).includes('limit')).length).toBeGreaterThan(0)
  })
  it('un client du plan est accepté tel quel par la validation de la console', () => {
    for (const x of p.clients.filter((y) => y.status !== 'skipped')) expect(clientBody.safeParse({ name: x.name, address: x.address, usage: x.usage, secret: null, enabled: true }).success, x.name).toBe(true)
  })
})

describe('plan d\'import : règles', () => {
  const p = plan()
  const r = (n: string) => p.rules.find((x) => x.name === n)!
  it('ordre de la stratégie NPS conservé ; demandes de connexion comptées mais jamais reprises', () => {
    expect(p.rules.map((x) => x.name)).toEqual(['Admins réseau', 'Wi-Fi utilisateurs', 'Tous les utilisateurs', 'Refus invités', 'VPN legacy', 'Heures bureau', 'Ancienne', 'VLAN invités'])
    expect(p.connectionPolicies).toBe(1)
  })
  it('reprise sans réserve : groupe résolu + client + EAP-TLS + accès accordé', () => {
    expect(r('Admins réseau')).toMatchObject({ status: 'imported', action: 'accept', kind: null, clients: ['wlc-1'], usages: [], ssids: [], enabled: false, selected: true })
    expect(r('Admins réseau').groups).toEqual([{ dn: 'CN=GG-Admins-Reseau,OU=Groupes,DC=lab,DC=test', name: 'GG-Admins-Reseau' }])
    expect(r('Admins réseau').comment).toMatch(/^Import NPS · ordre 1$/)
  })
  it('PEAP converti en EAP-TLS, type de port, groupe perdu, SSID : adapté, jamais actif', () => {
    const w = r('Wi-Fi utilisateurs')
    expect(w.status).toBe('adapted')
    expect(w).toMatchObject({ kind: 'user', usages: ['wifi'], ssids: ['CorpWiFi'], enabled: false })
    expect(w.groups.map((g) => g.name)).toEqual(['GG-Wifi-Users'])
    expect(codes(w)).toEqual(expect.arrayContaining(['group_notfound', 'groups_partial', 'auth_converted', 'port_type']))
    expect(w.comment).toMatch(/à revoir/)
  })
  it('groupe principal « Utilisateurs du domaine » : approché par le type de compte, à revoir', () => {
    expect(r('Tous les utilisateurs')).toMatchObject({ status: 'adapted', kind: 'user', groups: [] })
    expect(codes(r('Tous les utilisateurs'))).toContain('group_primary')
  })
  it('groupe inutilisable (échappement hexadécimal) ou introuvable : rien à reprendre, non pris en charge', () => {
    expect(r('Refus invités')).toMatchObject({ status: 'skipped', selected: false, action: 'reject' })
    expect(codes(r('Refus invités'))).toEqual(['group_unusable'])
  })
  it('authentification sans EAP : non pris en charge (EAP-TLS seulement)', () => {
    expect(r('VPN legacy').status).toBe('skipped'); expect(codes(r('VPN legacy'))).toEqual(['auth_none'])
  })
  it('condition sans équivalent (heure) : adaptée, signalée, jamais active', () => {
    expect(r('Heures bureau')).toMatchObject({ status: 'adapted', enabled: false })
    expect(r('Heures bureau').notes).toContainEqual({ code: 'cond_dropped', params: { type: 'TIMEOFDAY' } })
  })
  it('attributs de profil non repris (VLAN…) : adaptée, avec leur nom', () => {
    expect(r('VLAN invités').status).toBe('adapted')
    expect(r('VLAN invités').notes).toContainEqual({ code: 'attrs_lost', params: { names: 'msRADIUSTunnelPvtGroupID' } })
  })
  it('stratégie désactivée dans le NPS : reprise mais jamais active', () => {
    const q = plan(ctx({}, { activate: true }))
    expect(q.rules.find((x) => x.name === 'Ancienne')).toMatchObject({ status: 'imported', npsEnabled: false, enabled: false })
    expect(codes(q.rules.find((x) => x.name === 'Ancienne')!)).toContain('disabled_in_nps')
  })
  it('« activer » : seules les règles reprises sans réserve sont actives', () => {
    const q = plan(ctx({}, { activate: true }))
    expect(q.rules.filter((x) => x.enabled).map((x) => x.name)).toEqual(['Admins réseau'])
    expect(plan().rules.some((x) => x.enabled)).toBe(false)
  })
  it('annuaire indisponible : les règles à groupes ne sont pas reprises, avec la raison', () => {
    const q = plan(ctx({ directory: 'missing', groups: new Map() }))
    expect(q.directory).toBe('missing')
    const a = q.rules.find((x) => x.name === 'Admins réseau')!
    expect(a.status).toBe('skipped'); expect(a.notes[0]).toMatchObject({ code: 'group_directory', params: { why: 'missing' } })
    expect(q.rules.find((x) => x.name === 'Tous les utilisateurs')!.status).toBe('adapted')   // groupe principal : pas besoin de l'annuaire
  })
  it('client cité par une règle : nom Ipnoria, ou règle non reprise s\'il n\'est pas repris', () => {
    const q = plan(ctx({}, { exclude: new Set(['c:wlc-1']) }))
    const a = q.rules.find((x) => x.name === 'Admins réseau')!
    expect(a.status).toBe('skipped'); expect(codes(a)).toEqual(['clients_not_imported'])
    // jamais « aucun client » = « tous les clients » : une règle sans client résolu n'est pas créée
    expect(q.rules.filter((x) => x.status !== 'skipped').every((x) => x.name !== 'Admins réseau')).toBe(true)
  })
  it('« Tout le monde » : plus large que la stratégie d\'origine ? non, équivalent, mais signalé', () => {
    const xml = XML.replace(`NTGROUPS("S-1-5-21-111-222-333-513")`, 'NTGROUPS("S-1-1-0")')
    const q = planImport(parseNpsExport(xml), ctx())
    const t = q.rules.find((x) => x.name === 'Tous les utilisateurs')!
    expect(t).toMatchObject({ status: 'adapted', kind: null, groups: [] }); expect(codes(t)).toContain('group_everyone')
  })
  it('règle déjà importée (même nom, commentaire d\'import) : non reprise ; règle saisie à la main de même nom : reprise', () => {
    const done = plan(ctx({ existingRules: [{ name: 'Admins réseau', comment: 'Import NPS · ordre 1' }] }))
    expect(codes(done.rules.find((x) => x.name === 'Admins réseau')!)).toEqual(['rule_exists'])
    const manual = plan(ctx({ existingRules: [{ name: 'Admins réseau', comment: null }] }))
    expect(manual.rules.find((x) => x.name === 'Admins réseau')!.status).toBe('imported')
  })
  it('chaque règle prévue est acceptée telle quelle par la validation des règles', () => {
    for (const x of p.rules.filter((y) => y.status !== 'skipped')) {
      const parsed = ruleBody.safeParse({ name: x.name, enabled: x.enabled, action: x.action, kind: x.kind, groups: x.groups, clients: x.clients, usages: x.usages, ssids: x.ssids, reply: {}, comment: x.comment })
      expect(parsed.success, x.name + ' ' + JSON.stringify((parsed as any).error?.issues)).toBe(true)
    }
  })
  it('totaux', () => {
    expect(p.totals.rules).toEqual({ imported: 2, adapted: 4, skipped: 2 })
    expect(p.totals.clients).toEqual({ imported: 1, adapted: 4, skipped: 3 })
  })
})

describe('résolution des groupes par SID', () => {
  const DIR: DirSettings = { urls: ['ldaps://dc'], baseDn: 'DC=lab,DC=test', bindDn: 'svc@lab.test', tlsRejectUnauthorized: true }
  it('base de recherche : SID valide seulement (rien d\'autre n\'entre dans le DN)', () => {
    expect(sidBase('S-1-5-21-1-2-3-1105')).toBe('<SID=S-1-5-21-1-2-3-1105>')
    expect(sidBase('S-1-5-32-544')).toBe('<SID=S-1-5-32-544>')
    for (const bad of ['', 'S-1-5', 'S-2-5-21-1-2-3', 'S-1-5-21-1-2-3>,CN=x', 'S-1-5-21-1-2-3 ', '<SID=S-1-5-21-1-2-3>', 'S-1-5-21-a-b-c', 'S-1-5-' + '1-'.repeat(20) + '1']) expect(sidBase(bad), bad).toBeNull()
  })
  const fake = (handler: (base: string) => any): Factory => () => ({ bind: async () => ({}), unbind: async () => ({}), search: async (base: string) => { const r = handler(base); if (r instanceof Error) throw r; return { searchEntries: r } } })
  it('trouvé, introuvable (NoSuchObject), inutilisable (échappement hexadécimal) ; une panne n\'est pas un « introuvable »', async () => {
    const noSuch = Object.assign(new Error('Base-DN not found Code: 0x20'), { name: 'NoSuchObjectError' })
    const f = fake((base) => base.includes('-1106') ? [{ dn: 'CN=GG,OU=g,DC=lab,DC=test', cn: 'GG' }] : base.includes('-1109') ? [{ dn: 'CN=a\\3Db,DC=lab,DC=test', cn: 'a=b' }] : base.includes('-1110') ? [] : noSuch)
    const r = await resolveGroupSids(DIR, 'pw', f, ['S-1-5-21-1-2-3-1106', 'S-1-5-21-1-2-3-1109', 'S-1-5-21-1-2-3-1110', 'S-1-5-21-1-2-3-1111', 'pas-un-sid'])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.get('S-1-5-21-1-2-3-1106')).toEqual({ found: true, dn: 'CN=GG,OU=g,DC=lab,DC=test', name: 'GG', usable: true })
    expect(r.value.get('S-1-5-21-1-2-3-1109')).toMatchObject({ found: true, usable: false })
    expect(r.value.get('S-1-5-21-1-2-3-1110')).toEqual({ found: false })
    expect(r.value.get('S-1-5-21-1-2-3-1111')).toEqual({ found: false })
    expect(r.value.get('pas-un-sid')).toEqual({ found: false })
    const down = await resolveGroupSids(DIR, 'pw', fake(() => new Error('connect ECONNRESET')), ['S-1-5-21-1-2-3-1106'])
    expect(down.ok).toBe(false)
    expect((await resolveGroupSids(DIR, '', f, ['S-1-5-21-1-2-3-1106'])).ok).toBe(false)   // mot de passe vide : jamais de liaison anonyme
  })
})
