// Journal des authentifications RADIUS (0.14.18) : décodage des valeurs de %{escape:}, analyse d'une ligne « v1 » (18 champs), classement des motifs,
// lecture des lignes utiles du journal technique de FreeRADIUS, lecture en fin de fichier avec filtres et compteurs. Le format écrit par ddibuntu-radius
// est vérifié contre un vrai FreeRADIUS par tests/b28..b30 ; ici, côté console, avec des lignes du même format.
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { classify, decodeVal, parseAuthLine, parseTechLine, readJournal } from '../server/utils/radius-journal'

process.env.DDI_TEST_MODE = '1'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-rj-'))
process.env.DDI_RADIUS_AUTHLOG_DIR = TMP
afterAll(() => rmSync(TMP, { recursive: true, force: true }))

const F = ['v1', '1700000000', 'accept', 'PC001.lab.test', 'wifi-hq', '10.0.0.5', 'aa-bb-cc-dd-ee-ff', 'AA-BB-CC-00-11-22:Corp', 'ap-hq', '/CN=3Dpc001', '/CN=3DLab Issuing CA', '1001', '271119151329Z', '', 'pc001.lab.test', 'computer:pc001.lab.test', 'regle 2 : Postes', '']
const line = (o: Record<number, string> = {}) => F.map((v, i) => o[i] ?? v).join('|')

describe('décodage des valeurs', () => {
  it('« =XX » devient l\'octet (UTF-8), le reste est inchangé', () => {
    expect(decodeVal('/CN=3Dalice')).toBe('/CN=alice')
    expect(decodeVal('a=7Cb=22c=27d')).toBe('a|b"c\'d')
    expect(decodeVal('=C3=A9t=C3=A9')).toBe('été')
    expect(decodeVal('=3D41')).toBe('=41')   // un « = » d'origine est codé : jamais pris pour un octet
    expect(decodeVal('plain')).toBe('plain')
  })
  it('neutralise les caractères de contrôle et borne la longueur', () => {
    expect(decodeVal('a=0Ab=0Dc=00d')).toBe('a·b·c·d')
    expect(decodeVal('x'.repeat(1000)).length).toBe(300)
    expect(decodeVal('=ZZ=3')).toBe('=ZZ=3')   // séquence invalide laissée telle quelle
  })
})

describe('classement des motifs', () => {
  it.each([
    ['eap_tls: (TLS) OpenSSL says error 23 : certificate revoked', 'revoked'],
    ['OpenSSL says error 10 : certificate has expired', 'cert_expired'],
    ['OpenSSL says error 20 : unable to get local issuer certificate', 'unknown_ca'],
    ['OpenSSL says error 26 : unsuitable certificate purpose', 'purpose'],
    ['ddibuntu : certificat sans identite (ni UPN ni nom DNS)', 'no_identity'],
    ['ddibuntu : compte introuvable dans l\'annuaire', 'account_missing'],
    ['ddibuntu : compte desactive', 'account_disabled'], ['ddibuntu : compte verrouille', 'account_locked'], ['ddibuntu : compte expire', 'account_expired'],
    ['ddibuntu : annuaire indisponible ou compte ambigu', 'directory_down'],
    ['ddibuntu : regle 3 : refus', 'rule_deny'], ['ddibuntu : aucune regle ne correspond (refus par defaut)', 'no_rule'],
    ['ddibuntu : certificat valide, aucune regle d\'acces (refus par defaut)', 'no_rule'],
    ['eap: No mutually acceptable types found', 'eap_method'],
    ['ddibuntu : identifiant non pris en charge', 'identity_unsupported'], ['ddibuntu : domaine inconnu', 'domain_unknown'], ['ddibuntu : nom NetBIOS du domaine non configure', 'netbios_missing'],
    ['mschap: ERROR: NT_STATUS_WRONG_PASSWORD', 'bad_password'], ['ldap: Bind as user failed', 'bad_password'], ['Peer NAK received', 'eap_method'],
    ['unknown CA', 'unknown_ca'], ['certificate unknown', 'cert_refused'], ['handshake failure', 'no_cert'],
    ['', 'unknown'], ['quelque chose d\'inattendu', 'other'],
  ])('« %s » → %s', (reason, why) => { expect(classify(reason)).toBe(why) })
})

describe('ligne du journal d\'authentifications', () => {
  it('une acceptation complète', () => {
    const e = parseAuthLine(line())!
    expect(e).toMatchObject({ at: 1700000000_000, kind: 'accept', user: 'PC001.lab.test', client: 'wifi-hq', nas: '10.0.0.5', mac: 'aa-bb-cc-dd-ee-ff', subject: '/CN=pc001', issuer: '/CN=Lab Issuing CA', serial: '1001',
      dns: 'pc001.lab.test', identity: 'computer:pc001.lab.test', decision: 'regle 2 : Postes', why: 'ok', selftest: false })
    expect(e.called).toBe('AA-BB-CC-00-11-22:Corp')
  })
  it('un refus : motif classé, test de la console reconnu', () => {
    const e = parseAuthLine(line({ 2: 'reject', 4: 'ddi-selftest', 16: '', 17: 'ddibuntu : compte desactive' }))!
    expect([e.kind, e.why, e.selftest]).toEqual(['reject', 'account_disabled', true])
  })
  it('valeurs piégées : « | », guillemets et retours à la ligne ne cassent pas la ligne', () => {
    const e = parseAuthLine(line({ 3: 'a=7Cb=22c=0Ad<script>=3C', 6: 'aa=7Cbb' }))!
    expect(e.user).toBe('a|b"c·d<script><')
    expect(e.mac).toBe('aa|bb')
  })
  it.each([
    ['nombre de champs', 'v1|1|accept|x'], ['version', line({ 0: 'v2' })], ['résultat', line({ 2: 'maybe' })], ['heure', line({ 1: 'abc' })], ['heure nulle', line({ 1: '0' })], ['vide', ''],
  ])('refuse : %s', (_n, l) => { expect(parseAuthLine(l)).toBeNull() })
})

describe('journal technique de FreeRADIUS', () => {
  it('équipement inconnu', () => {
    const e = parseTechLine('Thu Nov 19 15:41:25 2026 : Error: Ignoring request to auth address * port 1812 bound to server default from unknown client 192.168.16.77 port 40001 proto udp')!
    expect([e.kind, e.why, e.nas]).toEqual(['diag', 'unknown_client', '192.168.16.77'])
    expect(e.at).toBe(new Date('Thu Nov 19 15:41:25 2026').getTime())
  })
  it('alerte TLS envoyée par le poste (lue), pas celle du serveur (écrite)', () => {
    const r = parseTechLine('Thu Nov 19 15:41:25 2026 : ERROR: (7) eap_tls: TLS Alert read:fatal:unknown CA')!
    expect([r.kind, r.why, r.reason]).toEqual(['diag', 'unknown_ca', 'unknown CA'])
    expect(parseTechLine('Thu Nov 19 15:41:25 2026 : ERROR: (7) eap_tls: TLS Alert write:fatal:handshake failure')).toBeNull()
    expect(parseTechLine('Thu Nov 19 15:41:25 2026 : ERROR: (7) tls: TLS Alert read:fatal:decrypt error')!.why).toBe('tls_alert')
  })
  it('lignes réelles de FreeRADIUS 3.2.5 (capturées par b29)', () => {
    const r = parseTechLine('Thu Nov 19 16:27:19 2026 : ERROR: (4) eap_tls: ERROR: (TLS) TLS - Alert read:fatal:unknown CA')!
    expect([r.kind, r.why, r.reason]).toEqual(['diag', 'unknown_ca', 'unknown CA'])
    expect(parseTechLine('Thu Nov 19 16:26:53 2026 : ERROR: (51) eap_tls: ERROR: (TLS) TLS - Alert write:fatal:unknown CA')).toBeNull()
    expect(parseTechLine('Thu Nov 19 16:27:19 2026 : Auth: (4) Login incorrect (eap_tls: (TLS) TLS - Alert read:fatal:unknown CA): [test@lab.test] (from client ddi-selftest port 0 cli 02-00-00-00-00-01)')).toBeNull()
  })
  it('les autres lignes sont ignorées', () => {
    expect(parseTechLine('Thu Nov 19 15:41:25 2026 : Auth: (7) Login incorrect (x): [bob] (from client y port 0)')).toBeNull()
    expect(parseTechLine('texte quelconque')).toBeNull()
  })
})

describe('lecture du fichier', () => {
  const now = 1_800_000_000_000, s = (min: number) => String(Math.floor((now - min * 60_000) / 1000))
  beforeAll(() => {
    mkdirSync(TMP, { recursive: true })
    writeFileSync(join(TMP, 'radius-auth.log'), [
      'ligne sans rapport', line({ 1: s(2000), 3: 'trop-ancien' }),                                                      // hors des 24 h
      line({ 1: s(120), 3: 'alice@lab.test', 15: 'user:alice@lab.test', 16: 'regle 1 : Employes' }),
      line({ 1: s(60), 2: 'reject', 3: 'bob', 17: 'eap_tls: (TLS) OpenSSL says error 23 : certificate revoked' }),
      line({ 1: s(30), 2: 'reject', 3: 'pc002', 6: 'de-ad-be-ef-00-01', 17: 'ddibuntu : compte desactive' }),
      line({ 1: s(20), 2: 'reject', 3: 'pc003', 17: 'ddibuntu : compte desactive' }),
      line({ 1: s(10), 2: 'reject', 3: 'test', 4: 'ddi-selftest', 17: 'ddibuntu : aucune regle ne correspond' }),
      'v1|cassee',
    ].join('\n') + '\n')
    writeFileSync(join(TMP, 'radius.log'), 'Thu Nov 19 15:41:25 2026 : Error: Ignoring request to auth address * port 1812 bound to server default from unknown client 10.9.9.9 port 1 proto udp\n')
  })
  it('compteurs sur 24 h hors tests de la console ; motifs du plus fréquent au plus rare', async () => {
    const r = await readJournal({ limit: 50 }, now)
    expect(r.available).toBe(true)
    expect(r.counts).toMatchObject({ accept: 1, reject: 3 })
    expect(r.reasons[0]).toEqual({ why: 'account_disabled', n: 2 })
    expect(r.events.map((e) => e.user).filter(Boolean)).not.toContain('test')   // le test de la console est masqué par défaut
  })
  it('événements du plus récent au plus ancien ; limite, filtres résultat, texte, période, tests', async () => {
    const all = (await readJournal({ limit: 50 }, now)).events.filter((e) => e.kind !== 'diag')
    expect(all.map((e) => e.user)).toEqual(['pc003', 'pc002', 'bob', 'alice@lab.test', 'trop-ancien'])
    expect((await readJournal({ limit: 2 }, now)).events).toHaveLength(2)
    expect((await readJournal({ kind: 'accept', limit: 50 }, now)).events.map((e) => e.user)).toEqual(['alice@lab.test', 'trop-ancien'])
    expect((await readJournal({ q: 'DE-AD-BE', limit: 50 }, now)).events.map((e) => e.user)).toEqual(['pc002'])
    expect((await readJournal({ q: 'revoked', limit: 50 }, now)).events.map((e) => e.user)).toEqual(['bob'])
    expect((await readJournal({ since: now - 45 * 60_000, limit: 50 }, now)).events.map((e) => e.user)).toEqual(['pc003', 'pc002'])
    expect((await readJournal({ selftest: true, q: 'ddi-selftest', limit: 50 }, now)).events.map((e) => e.user)).toEqual(['test'])
    expect((await readJournal({ kind: 'diag', limit: 50 }, now)).events.map((e) => e.nas)).toEqual(['10.9.9.9'])
  })
  it('une ligne ajoutée est vue au passage suivant (le cache suit le fichier)', async () => {
    appendFileSync(join(TMP, 'radius-auth.log'), line({ 1: s(1), 3: 'nouveau' }) + '\n')
    expect((await readJournal({ limit: 1 }, now)).events[0]!.user).toBe('nouveau')
  })
})

describe('fichier absent ou trop long', () => {
  it('absent : indisponible, aucun événement', async () => {
    const empty = mkdtempSync(join(tmpdir(), 'ddi-rj0-')); const keep = process.env.DDI_RADIUS_AUTHLOG_DIR
    try { process.env.DDI_RADIUS_AUTHLOG_DIR = empty; const r = await readJournal({ limit: 10 }); expect([r.available, r.events.length, r.truncated]).toEqual([false, 0, false]) }
    finally { process.env.DDI_RADIUS_AUTHLOG_DIR = keep; rmSync(empty, { recursive: true, force: true }) }
  })
  it('plus long que la fenêtre : seule la fin est lue, sans ligne coupée', async () => {
    const big = mkdtempSync(join(tmpdir(), 'ddi-rj1-')); const keep = process.env.DDI_RADIUS_AUTHLOG_DIR, keepMax = process.env.DDI_RADIUS_AUTHLOG_MAX_BYTES
    try {
      process.env.DDI_RADIUS_AUTHLOG_DIR = big; process.env.DDI_RADIUS_AUTHLOG_MAX_BYTES = '10000'
      const secs = Math.floor(Date.now() / 1000)
      writeFileSync(join(big, 'radius-auth.log'), Array.from({ length: 200 }, (_, i) => line({ 1: String(secs - 200 + i), 3: `u${i}` })).join('\n') + '\n')
      const r = await readJournal({ limit: 1000 })
      expect(r.truncated).toBe(true)
      expect(r.events.length).toBeGreaterThan(10); expect(r.events.length).toBeLessThan(200)
      expect(r.events[0]!.user).toBe('u199')
      expect(r.events.every((e) => /^u\d+$/.test(e.user))).toBe(true)   // aucune ligne coupée n'a été prise pour un événement
    } finally { process.env.DDI_RADIUS_AUTHLOG_DIR = keep; if (keepMax === undefined) delete process.env.DDI_RADIUS_AUTHLOG_MAX_BYTES; else process.env.DDI_RADIUS_AUTHLOG_MAX_BYTES = keepMax; rmSync(big, { recursive: true, force: true }) }
  })
})
