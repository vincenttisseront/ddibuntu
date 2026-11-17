// 0.14.1 — autorités de la PKI : validation des demandes de la console (la même que celle de root, vérifiée par un test différentiel), fichiers remis
// (certificat, chaîne, CRL), dépôts pour root, lecture de la liste et des fichiers publics que root publie.
import { spawnSync } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-pkica-unit-'))
const CAS = join(TMP, 'pki-cas.json'), CADIR = join(TMP, 'pki-ca')
Object.assign(process.env, { DDI_PKI_STATUS: join(TMP, 'status.json'), DDI_PKI_RESULT: join(TMP, 'result.json'), DDI_PKI_CAS: CAS, DDI_PKI_CA_DIR: CADIR, DDI_GENERATED_DIR: TMP,
  DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij' })
const ROOT = resolve(__dirname, '../..')
const HELPER = join(ROOT, 'src/rootfs/usr/local/lib/ddibuntu/pki-helper.py')
let ca: typeof import('../server/utils/pki-ca')
let pki: typeof import('../server/utils/pki')
beforeAll(async () => { ca = await import('../server/utils/pki-ca'); pki = await import('../server/utils/pki') })

const rootAccepts = (body: unknown) => { const r = spawnSync('python3', [HELPER, 'parse-request'], { input: JSON.stringify(body), encoding: 'utf8' }); return r.status === 0 && r.stdout.length > 0 }
const rootLines = (body: unknown) => spawnSync('python3', [HELPER, 'parse-request'], { input: JSON.stringify(body), encoding: 'utf8' }).stdout.trim().split('\n')
const good = { name: 'Lab-Root', alg: 'rsa3072', days: 3650, cn: 'Lab Root CA', o: 'Laboratoire', ou: '', c: 'FR' }

describe('racine : corps de la demande', () => {
  it('accepte une demande valide', () => { expect(ca.rootBody.safeParse(good).success).toBe(true) })
  it('refuse un champ inconnu (corps strict)', () => { expect(ca.rootBody.safeParse({ ...good, extra: 1 }).success).toBe(false) })
  it.each([
    ['nom vide', { name: '' }], ['nom avec espace', { name: 'a b' }], ['nom ManagementCA', { name: 'ManagementCA' }], ['nom ExtRoot-…', { name: 'ExtRoot-0a1b2c3d' }],
    ['nom remontant l\'arborescence', { name: '../x' }], ['nom de 49 caractères', { name: 'a'.repeat(49) }], ['algorithme inconnu', { alg: 'des' }],
    ['durée trop courte', { days: 364 }], ['durée trop longue', { days: 7306 }], ['durée en texte', { days: '3650' }], ['durée décimale', { days: 3650.5 }],
    ['CN absent', { cn: undefined }], ['CN avec virgule', { cn: 'X,O=pirate' }], ['CN avec plus', { cn: 'X+Y' }], ['CN avec égal', { cn: 'X=1' }], ['CN avec barre oblique', { cn: 'X/Y' }],
    ['CN avec point-virgule', { cn: 'X;Y' }], ['CN avec guillemet', { cn: 'X"Y' }], ['CN avec retour à la ligne', { cn: 'X\nY' }], ['CN de 65 caractères', { cn: 'a'.repeat(65) }],
    ['pays de trois lettres', { c: 'FRA' }], ['pays en minuscules', { c: 'fr' }], ['O avec virgule', { o: 'A,B' }],
  ])('refuse : %s', (_n, patch) => { expect(ca.rootBody.safeParse({ ...good, ...patch }).success).toBe(false) })
  it('les valeurs facultatives vides sont ignorées dans ce que root reçoit', () => {
    expect(ca.dnOf({ cn: 'X', o: '', ou: '', c: '' })).toEqual({ cn: 'X' })
    expect(ca.dnOf({ cn: 'X', o: 'Lab', ou: 'Pôle', c: 'FR' })).toEqual({ cn: 'X', o: 'Lab', ou: 'Pôle', c: 'FR' })
  })
})

describe('émettrice : corps de la demande', () => {
  const issuing = { name: 'Lab-Sub', alg: 'ecp256', days: 1825, cn: 'Lab Sub', signedBy: 'Lab-Root' }
  it('signée par une racine du DDI : pas de chaîne', () => { expect(ca.issuingBody.safeParse(issuing).success).toBe(true) })
  it('signée par une racine du DDI : une chaîne en trop est refusée', () => { expect(ca.issuingBody.safeParse({ ...issuing, chain: { pem: '-----BEGIN CERTIFICATE-----' } }).success).toBe(false) })
  it('externe : la chaîne est obligatoire, « external » est la valeur par défaut', () => {
    expect(ca.issuingBody.safeParse({ ...issuing, signedBy: 'external' }).success).toBe(false)
    expect(ca.issuingBody.safeParse({ ...issuing, signedBy: undefined, chain: { pem: 'x' } }).success).toBe(true)
  })
  it('durée de l\'émettrice plafonnée à 10 ans', () => { expect(ca.issuingBody.safeParse({ ...issuing, days: 3651 }).success).toBe(false); expect(ca.issuingBody.safeParse({ ...issuing, days: 3650 }).success).toBe(true) })
  it.each(['../x', 'ManagementCA', 'ExtRoot-0a1b2c3d', 'a b', ''])('signeur invalide « %s » refusé', (signedBy) => { expect(ca.issuingBody.safeParse({ ...issuing, signedBy }).success).toBe(false) })
})

describe('fichiers remis', () => {
  it('le fichier est du PEM ou du DER, jamais les deux ni aucun', () => {
    expect(ca.blob.safeParse({ pem: 'x' }).success).toBe(true); expect(ca.blob.safeParse({ der: 'MIIB' }).success).toBe(true)
    expect(ca.blob.safeParse({}).success).toBe(false); expect(ca.blob.safeParse({ pem: 'x', der: 'MIIB' }).success).toBe(false); expect(ca.blob.safeParse({ der: 'pas du base64 !' }).success).toBe(false)
  })
  it('certificat : PEM avec l\'étiquette attendue, DER qui commence par une SEQUENCE', () => {
    const pem = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'
    expect(ca.blobBytes({ pem }, 'certs')?.toString()).toBe(pem)
    expect(ca.blobBytes({ pem: pem.replace(/\n/g, '\r\n') }, 'certs')?.toString()).toBe(pem)
    expect(ca.blobBytes({ pem: 'rien' }, 'certs')).toBeNull()
    expect(ca.blobBytes({ pem }, 'crl')).toBeNull()
    expect(ca.blobBytes({ der: Buffer.from([0x30, 0x82, 0x01, 0x00]).toString('base64') }, 'certs')).not.toBeNull()
    expect(ca.blobBytes({ der: Buffer.from([0x41, 0x42]).toString('base64') }, 'certs')).toBeNull()
  })
  it('CRL : PEM « X509 CRL »', () => {
    expect(ca.blobBytes({ pem: '-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n' }, 'crl')).not.toBeNull()
    expect(ca.blobBytes({ pem: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n' }, 'crl')).toBeNull()
  })
  it('plus de 16 Ko : refusé', () => {
    expect(ca.blobBytes({ pem: '-----BEGIN CERTIFICATE-----\n' + 'A'.repeat(17000) }, 'certs')).toBeNull()
    expect(ca.blobBytes({ der: Buffer.concat([Buffer.from([0x30]), Buffer.alloc(17000)]).toString('base64') }, 'certs')).toBeNull()
  })
})

describe('console et root disent la même chose', () => {
  const names = ['Lab-Root', 'a', 'A1.b_c-d', '0abc', 'x'.repeat(48), 'x'.repeat(49), '-abc', '.abc', 'a b', 'a/b', 'a\\b', 'é', 'ManagementCA', 'ExtRoot-0a1b2c3d', 'ExtRoot-zz', '', 'a\nb', 'a;b']
  it.each(names)('nom « %s »', (name) => {
    const c = ca.rootBody.safeParse({ ...good, name }); const r = rootAccepts({ action: 'ca_root', ...good, ou: undefined, name })
    if (c.success) expect(rootAccepts({ action: 'ca_root', ...good, ou: undefined, name: c.data.name }), 'ce que la console envoie').toBe(true)   // jamais plus permissive que root
    if (r) expect(c.success, 'root accepte, la console devrait aussi').toBe(true)
  })
  const cns = ['Lab Root CA', 'X', 'Émettrice n°1', 'a'.repeat(64), 'a'.repeat(65), ' X', 'X ', 'a,b', 'a+b', 'a=b', 'a\\b', 'a"b', 'a<b', 'a>b', 'a;b', 'a#b', 'a/b', 'a\tb', 'a\u0000b', 'a  b', '']
  it.each(cns)('CN « %s »', (cn) => {
    const c = ca.rootBody.safeParse({ ...good, cn }); const r = rootAccepts({ action: 'ca_root', ...good, ou: undefined, cn })
    if (c.success) expect(rootAccepts({ action: 'ca_root', ...good, ou: undefined, cn: c.data.cn }), 'ce que la console envoie').toBe(true)   // la console retire les espaces de bord
    if (r) expect(c.success, 'root accepte, la console devrait aussi').toBe(true)
  })
  it.each([[364, false], [365, true], [7305, true], [7306, false]])('durée racine %i', (days, ok) => {
    expect(ca.rootBody.safeParse({ ...good, days }).success).toBe(ok); expect(rootAccepts({ action: 'ca_root', ...good, ou: undefined, days })).toBe(ok)
  })
  it.each([[3650, true], [3651, false]])('durée émettrice %i', (days, ok) => {
    const b = { ...good, days, signedBy: 'Lab-Root' }
    expect(ca.issuingBody.safeParse(b).success).toBe(ok); expect(rootAccepts({ action: 'ca_issuing', ...b, ou: undefined })).toBe(ok)
  })
  it('ce que la console envoie est exactement ce que root lit', () => {
    const b = ca.rootBody.parse({ ...good, ou: 'Pôle' })
    const lines = rootLines({ action: 'ca_root', name: b.name, alg: b.alg, days: b.days, ...ca.dnOf(b) })
    expect(lines).toEqual(['action\tca_root', 'name\tLab-Root', 'alg\trsa3072', 'days\t3650', 'dn\tCN=Lab Root CA,OU=Pôle,O=Laboratoire,C=FR'])
  })
  it.each(['ExtRoot-0a1b2c3d', 'ExtRoot-0A1B2C3D', 'ExtRoot-0a1b2c3', 'ExtRoot-0a1b2c3d4', 'Lab-Root'])('nom de racine externe « %s »', (name) => {
    expect(ca.EXTROOT_RE.test(name)).toBe(rootAccepts({ action: 'ca_rootcrl', name }))
  })
})

describe('dépôts pour root', () => {
  it('écrit en 0640 dans pki-in, sous le nom attendu par root', async () => {
    await ca.putDeposit('Lab-Ext', 'chain.pem', Buffer.from('chaîne'))
    const f = join(TMP, 'pki-in', 'Lab-Ext.chain.pem')
    expect(readFileSync(f, 'utf8')).toBe('chaîne'); expect((statSync(f).mode & 0o777).toString(8)).toBe('640')
    expect((statSync(join(TMP, 'pki-in')).mode & 0o777).toString(8)).toBe('750')
  })
  it('remplace un ancien dépôt et ne suit jamais un lien symbolique', async () => {
    const f = join(TMP, 'pki-in', 'Lab-Link.cert.pem'), target = join(TMP, 'cible.txt')
    writeFileSync(target, 'intact'); symlinkSync(target, f)
    await ca.putDeposit('Lab-Link', 'cert.pem', Buffer.from('nouveau'))
    expect(readFileSync(target, 'utf8')).toBe('intact')
    expect(lstatSync(f).isSymbolicLink()).toBe(false); expect(readFileSync(f, 'utf8')).toBe('nouveau')
    expect(() => readlinkSync(f)).toThrow()
  })
  it('refuse un nom qui sortirait du dossier', async () => {
    await expect(ca.putDeposit('../evil', 'crl', Buffer.from('x'))).rejects.toThrow()
    await expect(ca.putDeposit('a/b', 'crl', Buffer.from('x'))).rejects.toThrow()
    expect(existsSync(join(TMP, 'evil.crl'))).toBe(false)
  })
  it('retire un dépôt', async () => {
    await ca.putDeposit('Lab-Del', 'crl', Buffer.from('x')); await ca.dropDeposit('Lab-Del', 'crl')
    expect(existsSync(join(TMP, 'pki-in', 'Lab-Del.crl'))).toBe(false)
    await ca.dropDeposit('Lab-Del', 'crl')   // déjà absent : sans erreur
  })
})

describe('liste des autorités publiée par root', () => {
  const item = (o: Record<string, unknown> = {}) => ({ name: 'Lab-Root', kind: 'root', state: 'active', status: 1, dn: 'CN=Lab Root CA', issuer: 'CN=Lab Root CA', selfSigned: true, serial: 'ab', notBefore: '2026-01-01T00:00:00Z',
    notAfter: '2036-01-01T00:00:00Z', keyAlg: 'RSA', keyBits: 3072, curve: '', sigAlg: 'sha256WithRSAEncryption', pathLen: null, sha256: 'a'.repeat(64), signedBy: 'self', alg: 'rsa3072',
    createdAt: 1700000000, extRoot: null, crlUrl: 'http://pki.lab.test:8080/x', certUrl: 'http://pki.lab.test:8080/y', crl: { number: 2, thisUpdate: '2026-11-17T09:00:00Z', nextUpdate: '2026-11-24T09:00:00Z', bytes: 500 },
    files: { cert: true, chain: false, csr: false, crl: true }, ...o })
  it('absente ou illisible : null', async () => {
    expect(await ca.readPkiCas()).toBeNull()
    writeFileSync(CAS, 'pas du json'); expect(await ca.readPkiCas()).toBeNull()
    writeFileSync(CAS, JSON.stringify({ cas: [] })); expect(await ca.readPkiCas()).toBeNull()
    writeFileSync(CAS, JSON.stringify({ at: 1, cas: 'x' })); expect(await ca.readPkiCas()).toBeNull()
  })
  it('lit une liste complète', async () => {
    writeFileSync(CAS, JSON.stringify({ at: 1700000000, ok: true, cas: [item(), item({ name: 'Lab-Wait', kind: 'issuing', state: 'waiting', extRoot: 'ExtRoot-0a1b2c3d', files: { cert: false, chain: true, csr: true, crl: false }, crl: undefined })] }))
    const r = (await ca.readPkiCas())!
    expect(r.cas).toHaveLength(2)
    expect(r.cas[0]).toMatchObject({ name: 'Lab-Root', kind: 'root', state: 'active', selfSigned: true, keyBits: 3072, managed: true, crl: { number: 2, bytes: 500 }, extRoot: '' })
    expect(r.cas[1]).toMatchObject({ state: 'waiting', extRoot: 'ExtRoot-0a1b2c3d', crl: null, files: { csr: true, cert: false } })
  })
  it('assainit : types, longueurs, valeurs inconnues, noms que le DDI ne gère pas', async () => {
    writeFileSync(CAS, JSON.stringify({ at: 1, cas: [item({ name: 'x'.repeat(200), kind: 'n-importe-quoi', state: 'bizarre', dn: 'd'.repeat(900), sha256: 'pas-un-hash', pathLen: 'x', extRoot: '../../etc', crlUrl: 'u'.repeat(3000), files: 5 }),
      item({ name: 'a b' }), item({ name: 'ManagementCA' }), { kind: 'root' }, 'texte', null] }))
    const r = (await ca.readPkiCas())!
    expect(r.cas).toHaveLength(3)
    const [a, b, c] = r.cas as [any, any, any]
    expect(a.name.length).toBe(80); expect(a.kind).toBe('unknown'); expect(a.state).toBe('other'); expect(a.dn.length).toBe(512); expect(a.sha256).toBe(''); expect(a.pathLen).toBeNull()
    expect(a.extRoot).toBe(''); expect(a.crlUrl.length).toBe(1024); expect(a.files).toEqual({ cert: false, chain: false, csr: false, crl: false }); expect(a.managed).toBe(false)
    expect(b.managed).toBe(false)   // « a b » : listée, mais aucune action possible
    expect(c.managed).toBe(false)   // ManagementCA : jamais gérée par le DDI
  })
  it('plafonne à 200 autorités', async () => {
    writeFileSync(CAS, JSON.stringify({ at: 1, cas: Array.from({ length: 300 }, (_v, i) => item({ name: `CA-${i}` })) }))
    expect((await ca.readPkiCas())!.cas).toHaveLength(200)
  })
})

describe('fichiers publics d\'une autorité', () => {
  it('lit un fichier ordinaire', async () => {
    mkdirSync(join(CADIR, 'Lab-Root'), { recursive: true }); writeFileSync(join(CADIR, 'Lab-Root', 'cert.pem'), 'PEM')
    expect((await ca.readCaFile('Lab-Root', 'cert'))?.toString()).toBe('PEM')
    expect(await ca.readCaFile('Lab-Root', 'chain')).toBeNull()
  })
  it('refuse un lien symbolique, un fichier trop gros, un nom ou un type invalide', async () => {
    writeFileSync(join(TMP, 'secret.txt'), 'secret'); symlinkSync(join(TMP, 'secret.txt'), join(CADIR, 'Lab-Root', 'chain.pem'))
    expect(await ca.readCaFile('Lab-Root', 'chain')).toBeNull()
    writeFileSync(join(CADIR, 'Lab-Root', 'crl.der'), Buffer.alloc(70000)); expect(await ca.readCaFile('Lab-Root', 'crl')).toBeNull()
    expect(await ca.readCaFile('../Lab-Root', 'cert')).toBeNull(); expect(await ca.readCaFile('Lab Root', 'cert')).toBeNull()
    expect(await ca.readCaFile('Lab-Root', 'key' as any)).toBeNull(); expect(await ca.readCaFile('Lab-Root', '../cert' as any)).toBeNull()
  })
  it('ne publie jamais de clé : seuls certificat, chaîne, demande et CRL existent', () => {
    expect(Object.values(ca.FILES).map((f) => f.file).sort()).toEqual(['cert.pem', 'chain.pem', 'crl.der', 'csr.pem'])
  })
})

describe('état publié : champs de 0.14.1', () => {
  it('données conservées, secrets, nombre d\'autorités, remise à zéro', async () => {
    writeFileSync(process.env.DDI_PKI_STATUS!, JSON.stringify({ at: 1, state: 'absent', dataPresent: true, secretsPresent: false, dataHostname: 'pki.lab.test', casCount: 2, resetAllowed: false }))
    expect(await pki.readPkiStatus()).toMatchObject({ dataPresent: true, secretsPresent: false, dataHostname: 'pki.lab.test', casCount: 2, resetAllowed: false })
    writeFileSync(process.env.DDI_PKI_STATUS!, JSON.stringify({ at: 1, casCount: -3, resetAllowed: 'oui', dataHostname: 'h'.repeat(400) }))
    expect(await pki.readPkiStatus()).toMatchObject({ dataPresent: false, secretsPresent: false, casCount: null, resetAllowed: false })
    expect((await pki.readPkiStatus())!.dataHostname.length).toBe(253)
  })
})
