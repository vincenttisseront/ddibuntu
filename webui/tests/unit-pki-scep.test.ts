// 0.14.8 — SCEP de la PKI : lecture bornée de l'état publié par root (pki-scep.json), validation du préenregistrement (les MÊMES règles que root : test différentiel avec
// pki-helper.py), défi à usage unique, attente du résultat de root pour les demandes sans référence.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-pki-scep-'))
const FILE = join(TMP, 'pki-scep.json')
process.env.DDI_PKI_SCEP = FILE; process.env.DDI_PKI_STATUS = join(TMP, 'status.json'); process.env.DDI_PKI_RESULT = join(TMP, 'result.json'); process.env.DDI_GENERATED_DIR = TMP
process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'
const ROOT = resolve(__dirname, '../..')
const HELPER = join(ROOT, 'src/rootfs/usr/local/lib/ddibuntu/pki-helper.py')
let scep: typeof import('../server/utils/pki-scep')
beforeAll(async () => { scep = await import('../server/utils/pki-scep') })
afterEach(() => { rmSync(FILE, { force: true }); rmSync(join(TMP, 'result.json'), { force: true }); rmSync(join(TMP, '.pki-request'), { force: true }) })

const NOW = 1_800_000_000
const offer = (over: Record<string, unknown> = {}) => ({ cn: 'sw-core-1', state: 'waiting', status: 10, ca: 'Lab-SubRSA', profile: 'network', dn: 'CN=sw-core-1,O=Lab,C=FR', san: 'dNSName=sw-core-1.lab.test',
  createdAt: NOW - 100, modifiedAt: NOW - 100, expiresAt: NOW + 86400, cert: null, ...over })
const doc = (over: Record<string, unknown> = {}) => ({ at: NOW, enabled: true, alias: 'ddibuntu', path: '/x', port: 8080, url: 'http://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe', offerDays: 7, offers: [offer()], ...over })

describe('lecture de pki-scep.json', () => {
  it('lit un état complet', () => {
    const r = scep.parsePkiScep(doc({ offers: [offer(), offer({ cn: 'sw-2', state: 'issued', status: 40, expiresAt: null, cert: { serial: '1234ABCD', notAfter: '2027-01-01T00:00:00Z', revoked: false, sha1: 'a'.repeat(40) } })] }))!
    expect(r.enabled).toBe(true); expect(r.url).toContain('/scep/ddibuntu/pkiclient.exe'); expect(r.offers).toHaveLength(2); expect(r.offerDays).toBe(7)
    expect(r.offers[0]!.state).toBe('waiting'); expect(r.offers[0]!.expiresAt).toBe(NOW + 86400); expect(r.offers[1]!.cert).toEqual({ serial: '1234ABCD', notAfter: '2027-01-01T00:00:00Z', revoked: false, sha1: 'a'.repeat(40) })
  })
  it.each([null, 'texte', 12, [], {}, { at: 'x' }])('refuse un document illisible : %j', (v) => { expect(scep.parsePkiScep(v)).toBeNull() })
  it('l\'alias et le chemin sont ceux du DDI, jamais ceux du fichier', () => {
    const r = scep.parsePkiScep(doc({ alias: '../../etc', path: '/evil' }))!
    expect(r.alias).toBe('ddibuntu'); expect(r.path).toBe('/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe')
  })
  it('n\'accepte que l\'adresse exacte donnée par root', () => {
    for (const u of ['https://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe', 'http://evil.test:8080/ejbca/publicweb/apply/scep/other/pkiclient.exe',
      'http://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe?x=1', 'javascript:alert(1)', 'http://pki.lab.test/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe',
      'http://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe\nX: y', 'http://a b:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe']) {
      expect(scep.parsePkiScep(doc({ url: u }))!.url, u).toBe('')
    }
    expect(scep.parsePkiScep(doc({ url: 'http://pki.lab.test:8080/ejbca/publicweb/apply/scep/ddibuntu/pkiclient.exe' }))!.url).toContain('pki.lab.test:8080')
  })
  it('écarte les équipements au nom invalide ou réservé au format et borne la liste', () => {
    const many = Array.from({ length: 2100 }, (_v, i) => offer({ cn: `sw-${i}` }))
    const r = scep.parsePkiScep(doc({ offers: [offer({ cn: 'a b' }), offer({ cn: 'x;y' }), offer({ cn: '../x' }), offer({ cn: '' }), offer({ cn: 5 }), 'x', null, ...many] }))!
    expect(r.offers.length).toBeLessThanOrEqual(2000); expect(r.offers.every((o) => scep.SCEP_CN_RE.test(o.cn))).toBe(true)
  })
  it('état, profil et empreinte inconnus : valeurs sûres', () => {
    const r = scep.parsePkiScep(doc({ offers: [offer({ state: 'exploded', profile: 'EVIL', cert: { serial: 'zz', notAfter: 'x', revoked: 1, sha1: 'pas-une-empreinte' } }),
      offer({ cn: 'b', cert: { serial: 'AB12', notAfter: '2027-01-01T00:00:00Z', revoked: true, sha1: 'pas-une-empreinte' } })] }))!
    expect(r.offers[0]!.state).toBe('other'); expect(r.offers[0]!.profile).toBe(''); expect(r.offers[0]!.cert).toBeNull()
    expect(r.offers[1]!.cert).toEqual({ serial: 'AB12', notAfter: '2027-01-01T00:00:00Z', revoked: true, sha1: '' })
  })
  it('caractères de contrôle retirés des textes ; nombres entiers seulement', () => {
    const r = scep.parsePkiScep(doc({ port: 99999, offerDays: 9999, offers: [offer({ dn: 'CN=a\u0001\u001b[31m', san: 'x\ny', expiresAt: 2.5, createdAt: 'x' })] }))!
    expect(r.port).toBe(8080); expect(r.offerDays).toBe(365); expect(r.offers[0]!.dn).not.toMatch(/[\x00-\x1f]/); expect(r.offers[0]!.san).toBe('x y'); expect(r.offers[0]!.expiresAt).toBeNull(); expect(r.offers[0]!.createdAt).toBe(0)
  })
  it('lit le fichier publié ; fichier absent, illisible ou trop gros : null', async () => {
    expect(await scep.readPkiScep()).toBeNull()
    writeFileSync(FILE, JSON.stringify(doc())); expect((await scep.readPkiScep())?.offers).toHaveLength(1)
    writeFileSync(FILE, '{pas du json'); expect(await scep.readPkiScep()).toBeNull()
    writeFileSync(FILE, ' '.repeat(2_100_000)); expect(await scep.readPkiScep()).toBeNull()
  })
})

describe('défi à usage unique', () => {
  it('24 caractères sans ambiguïté, acceptés par root', () => {
    const seen = new Set<string>()
    for (let i = 0; i < 200; i++) {
      const c = scep.newChallenge()
      expect(c).toMatch(/^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{24}$/)
      seen.add(c)
    }
    expect(seen.size).toBe(200)
    const r = spawnSync('python3', ['-I', HELPER, 'scep-pw', (() => { const p = join(TMP, 'pw'); writeFileSync(p, scep.newChallenge(), { mode: 0o600 }); return p })()], { encoding: 'utf8' })
    expect(r.status).toBe(0); expect(r.stdout.trim()).toMatch(/^[A-Z2-9]{24}$/)
  })
  it('chaque position tire sur tout l\'alphabet (pas de biais grossier)', () => {
    const count: Record<string, number> = {}
    for (let i = 0; i < 4000; i++) for (const ch of scep.newChallenge()) count[ch] = (count[ch] ?? 0) + 1
    expect(Object.keys(count)).toHaveLength(32)
    const total = 4000 * 24, expected = total / 32
    for (const [ch, n] of Object.entries(count)) expect(Math.abs(n - expected) / expected, ch).toBeLessThan(0.1)
  })
})

describe('préenregistrement : mêmes règles que root (test différentiel)', () => {
  const root = (json: unknown) => spawnSync('python3', ['-I', HELPER, 'parse-request'], { input: JSON.stringify(json), encoding: 'utf8' })
  const base = { ca: 'Lab-SubRSA', profile: 'network', cn: 'sw-core-1.lab.test', dns: ['sw-core-1.lab.test'] }
  const both = (over: Record<string, unknown>, expectOk: boolean, why: string) => {
    const body = { ...base, ...over }
    const p = scep.scepOfferBody.safeParse(body)
    const r = root({ action: 'scep_offer', id: '0123456789abcdef', ...p.success ? p.data : body })
    expect(p.success, `console : ${why}`).toBe(expectOk)
    expect(r.status === 0 && r.stdout.length > 0, `root : ${why}`).toBe(expectOk)
  }
  it('accepté partout', () => {
    both({}, true, 'cas nominal'); both({ cn: 'a' }, true, 'nom d\'un caractère'); both({ cn: 'A1.b_c-d' }, true, 'ponctuation permise'); both({ cn: 'a'.repeat(63) }, true, '63 caractères')
    both({ profile: 'machine', dns: ['pc01.lab.test'], cn: 'pc01' }, true, 'profil machine'); both({ profile: 'server', dns: ['radius.lab.test'], ip: ['10.1.2.3'], cn: 'radius' }, true, 'profil serveur')
    both({ profile: 'user', dns: [], mail: ['j.dupont@lab.test'], upn: ['jdupont@lab.test'], cn: 'jdupont' }, true, 'profil utilisateur')
    both({ o: 'Laboratoire', ou: 'Réseau', c: 'FR' }, true, 'composants du nom distinctif')
  })
  it.each([
    ['nom avec une espace', { cn: 'Jean Dupont' }], ['nom avec une virgule', { cn: 'x,O=Evil' }], ['nom avec un signe égal', { cn: 'a=b' }], ['nom vide', { cn: '' }], ['nom commençant par un point', { cn: '.sw1' }],
    ['nom commençant par un tiret', { cn: '-sw1' }], ['nom de 64 caractères', { cn: 'a'.repeat(64) }], ['nom superadmin', { cn: 'superadmin' }], ['nom ejbca en majuscules', { cn: 'EJBCA' }],
    ['nom réservé aux entités d\'émission', { cn: 'ddi-0123456789abcdef' }], ['nom réservé, majuscules', { cn: 'DDI-x' }], ['nom avec saut de ligne', { cn: 'sw\n1' }], ['nom avec barre oblique', { cn: 'a/b' }],
    ['nom accentué', { cn: 'équipement' }], ['autorité avec une barre', { ca: 'a/b' }], ['autorité ManagementCA', { ca: 'ManagementCA' }], ['profil inconnu', { profile: 'EMPTY' }],
    ['réseau sans SAN', { dns: [], ip: [] }], ['SAN injectant un autre SAN', { dns: ['a.lab.test,dNSName=evil.test'] }], ['profil machine avec une adresse IP', { profile: 'machine', ip: ['10.1.2.3'] }],
    ['IP invalide', { ip: ['10.1.2.300'] }], ['pays invalide', { c: 'france' }],
  ])('refusé partout : %s', (why, over) => { both(over as Record<string, unknown>, false, why) })
  it('champ inconnu : la console le refuse (corps strict), root l\'ignore sans jamais le recopier', () => {
    expect(scep.scepOfferBody.safeParse({ ...base, x: 1 }).success).toBe(false)
    const r = root({ action: 'scep_offer', id: '0123456789abcdef', ...base, x: 'ignoré' })
    expect(r.status).toBe(0); expect(r.stdout).not.toContain('ignoré'); expect(r.stdout).toContain('cn\tsw-core-1.lab.test')
  })
  it('la console refuse le nom avant d\'envoyer quoi que ce soit ; root refuse aussi la demande JSON correspondante', () => {
    expect(scep.scepCnOk('sw1')).toBe(true); expect(scep.scepCnOk('superadmin')).toBe(false); expect(scep.scepCnOk('DDI-x')).toBe(false); expect(scep.scepCnOk('a b')).toBe(false)
    const r = root({ action: 'scep_offer', id: '0123456789abcdef', ca: 'Lab-SubRSA', profile: 'network', cn: 'superadmin', dns: ['a.lab.test'] })
    expect(r.stdout.trim()).toBe('')
  })
  it('rearm et cancel : mêmes noms refusés des deux côtés', () => {
    for (const cn of ['sw1', 'sw-1.lab.test', 'superadmin', 'ejbca', 'ddi-aaaaaaaaaaaaaaaa', 'a b', 'x;y', '../x', '', 'a'.repeat(64)]) {
      const ok = scep.scepCnParam(cn)
      const a = root({ action: 'scep_rearm', id: '0123456789abcdef', cn }), b = root({ action: 'scep_cancel', cn })
      expect(a.status === 0 && a.stdout.length > 0, `rearm ${cn}`).toBe(ok); expect(b.status === 0 && b.stdout.length > 0, `cancel ${cn}`).toBe(ok)
    }
  })
  it('la demande JSON ne porte jamais de défi et reste sous 4 Ko, même avec tous les noms alternatifs', async () => {
    const certs = await import('../server/utils/pki-certs')
    const p = scep.scepOfferBody.parse({ ca: 'Lab-SubRSA', profile: 'server', cn: 'radius-1', o: 'x'.repeat(60), ou: 'y'.repeat(60), c: 'FR',
      dns: Array.from({ length: 8 }, (_v, i) => `${'a'.repeat(50)}${i}.lab.test`), ip: ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'] })
    const req = { ...certs.issueRequest('0123456789abcdef', p), action: 'scep_offer' }
    expect(JSON.stringify(req).length).toBeLessThan(certs.MAX_REQUEST_JSON)
    expect(JSON.stringify(req)).not.toMatch(/challenge|password|scepw/i)
    expect(root(req).status).toBe(0)
  })
  it('corps strict : un défi, un mot de passe ou un identifiant fournis par le client sont refusés', () => {
    for (const x of [{ challenge: 'ABCDEFGHJKLMNPQRSTUVWXYZ' }, { password: 'x'.repeat(20) }, { id: '0123456789abcdef' }, { action: 'scep_offer' }]) expect(scep.scepOfferBody.safeParse({ ...base, ...x }).success).toBe(false)
  })
})

describe('attente du résultat de root (demandes sans référence)', () => {
  const wr = (o: Record<string, unknown>) => writeFileSync(join(TMP, 'result.json'), JSON.stringify(o))
  const never = async () => false
  it('rend le résultat de la même action publié après le dépôt', async () => {
    wr({ at: NOW, action: 'scep_enable', ok: true, message: 'SCEP activé' })
    expect(await scep.awaitAction('scep_enable', NOW, never, { timeoutMs: 1000, pollMs: 10 })).toEqual({ ok: true, message: 'SCEP activé' })
    wr({ at: NOW, action: 'scep_cancel', ok: false, message: 'inconnu' })
    expect(await scep.awaitAction('scep_cancel', NOW, never, { timeoutMs: 1000, pollMs: 10 })).toEqual({ ok: false, code: 'refused', message: 'inconnu' })
  })
  it('ignore le résultat d\'une autre action et celui d\'avant le dépôt', async () => {
    wr({ at: NOW, action: 'cert_issue', ok: true, message: 'x' })
    expect((await scep.awaitAction('scep_enable', NOW, never, { timeoutMs: 150, pollMs: 10 })).ok).toBe(false)
    wr({ at: NOW - 5, action: 'scep_enable', ok: true, message: 'ancien' })
    expect(await scep.awaitAction('scep_enable', NOW, never, { timeoutMs: 150, pollMs: 10 })).toEqual({ ok: false, code: 'timeout', message: 'timeout' })
  })
  it('n\'accepte le résultat qu\'une fois la demande consommée par root', async () => {
    wr({ at: NOW, action: 'scep_disable', ok: true, message: 'fait' })
    let pending = true
    setTimeout(() => { pending = false }, 120)
    const t0 = Date.now()
    const r = await scep.awaitAction('scep_disable', NOW, async () => pending, { timeoutMs: 2000, pollMs: 10 })
    expect(r).toEqual({ ok: true, message: 'fait' }); expect(Date.now() - t0).toBeGreaterThanOrEqual(100)
  })
  it('un résultat identique à celui d\'avant le dépôt, de la même seconde, n\'est pas celui de cette demande', async () => {
    const old = { at: NOW, action: 'scep_cancel', ok: true, message: '« a » annulé' }
    wr(old)
    expect(await scep.awaitAction('scep_cancel', NOW, never, { timeoutMs: 120, pollMs: 10, before: old })).toEqual({ ok: false, code: 'timeout', message: 'timeout' })
    setTimeout(() => wr({ ...old, message: '« b » annulé' }), 60)
    expect(await scep.awaitAction('scep_cancel', NOW, never, { timeoutMs: 1000, pollMs: 10, before: old })).toEqual({ ok: true, message: '« b » annulé' })
    wr({ ...old, at: NOW + 1 })
    expect((await scep.awaitAction('scep_cancel', NOW, never, { timeoutMs: 1000, pollMs: 10, before: old })).ok).toBe(true)
  })
  it('délai dépassé : timeout', async () => {
    expect(await scep.awaitAction('scep_enable', NOW, never, { timeoutMs: 100, pollMs: 10 })).toEqual({ ok: false, code: 'timeout', message: 'timeout' })
  })
})
