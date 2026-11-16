// PKI RADIUS EAP-TLS (0.13.2), côté console : séparation des PEM, liste de confiance (ordre d'ajout libre), chaîne du serveur, disponibilité du déploiement,
// CRL (PEM / DER, émettrice, signature, péremption, retour en arrière), vérification d'un certificat client, CSR, clés (chiffrées, faibles), PKCS#12,
// adresses de CRL, téléchargement borné. Tout est fabriqué avec le vrai binaire openssl (tests/lib-pki.sh) : aucune donnée simulée pour les certificats.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  addCas, analyzeCas, applyCrl, asPem, buildDeposit, checkClientCert, crlSetDigest, fetchCrl, fillHashes, makeCsr, newKey, normalizeKey, normCrlUrl, parseCert, parseCrl, pickServerCert,
  PkiError, readiness, readPkcs12, refreshCrl, serverChain, splitCerts,
} from '../server/utils/radius-pki'
import type { PkiState } from '../server/utils/radius-pki'
import { createPrivateKey } from 'node:crypto'

const ROOT = resolve(__dirname, '../..'), D = mkdtempSync(join(tmpdir(), 'ddi-pki-'))
const sh = (script: string) => execFileSync('bash', ['-c', `set -e; source ${ROOT}/tests/lib-pki.sh; cd ${D}; ${script}`], { encoding: 'utf8' })
const rd = (f: string) => readFileSync(join(D, f), 'utf8')
const rdb = (f: string) => readFileSync(join(D, f))
const err = async (p: Promise<unknown> | (() => unknown), code: string) => { try { await (typeof p === 'function' ? p() : p) } catch (e) { expect((e as PkiError).code).toBe(code); return }; throw new Error(`pas d'erreur (attendu : ${code})`) }
const dateOf = (days: number) => new Date(Date.now() + days * 86400_000).toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z').replace('T', '')

let base: PkiState, full: PkiState

beforeAll(async () => {
  sh(`
    pki_root R "Lab Root"; pki_inter I R "Lab Issuing CA"; pki_root X "Foreign Root"; pki_root Y "Lab Issuing CA"   # Y : homonyme de I, autre clé
    pki_issue I srv "radius.lab.test" server "DNS:radius.lab.test"
    pki_issue I alice "alice" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:alice@lab.test,email:alice@lab.test"
    pki_issue I bob "bob" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:bob@lab.test"
    pki_issue I pc "pc01.lab.test" client "DNS:pc01.lab.test"
    pki_issue I carl "carl" clientbad "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:carl@lab.test"
    pki_issue I dave "dave" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:dave@lab.test" 20200101000000Z 20210101000000Z
    pki_issue X frank "frank" client "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:frank@lab.test"
    pki_issue I badsrv "client-only" client
    pki_issue R direct "direct" client
    pki_crl I crl-ok.pem 7
    pki_revoke I bob.pem; pki_crl I crl-bob.pem 7
    openssl crl -in crl-bob.pem -outform DER -out crl-bob.der
    pki_crl I crl-expired.pem expire
    pki_issue Y rogue "rogue" client; pki_crl Y crl-rogue.pem 7        # CRL signée par le faux « Lab Issuing CA »
    pki_crl R crl-root.pem 30; pki_crl X crl-foreign.pem 7
    # deux CRL de l'autorité émettrice à des dates différentes (retour en arrière)
    openssl ca -batch -config I/openssl.cnf -gencrl -crlexts crl_ext -crl_lastupdate ${dateOf(-2)} -crl_nextupdate ${dateOf(5)} -out crl-old.pem 2>/dev/null
    openssl ca -batch -config I/openssl.cnf -gencrl -crlexts crl_ext -crl_lastupdate ${dateOf(-1)} -crl_nextupdate ${dateOf(6)} -out crl-new.pem 2>/dev/null
    openssl ca -batch -config I/openssl.cnf -gencrl -crlexts crl_ext -crl_lastupdate ${dateOf(1)} -crl_nextupdate ${dateOf(8)} -out crl-future.pem 2>/dev/null
    # autorité intermédiaire déjà expirée
    openssl req -new -newkey rsa:2048 -nodes -keyout old.key -out old.csr -subj "/CN=Old CA" 2>/dev/null
    openssl ca -batch -config R/openssl.cnf -extensions v3_inter -in old.csr -out old.pem -startdate 20200101000000Z -enddate 20210101000000Z -notext 2>/dev/null
    # clés
    openssl genrsa -out k1024.key 1024 2>/dev/null; openssl genpkey -algorithm ed25519 -out ed.key; openssl ecparam -name prime256v1 -genkey -noout -out ec.key
    openssl pkey -in srv.key -aes256 -passout pass:secret-1 -out srv-enc.key
    openssl pkcs12 -export -in srv.pem -inkey srv.key -certfile I/ca.pem -passout pass:p12-pass -out srv.p12 2>/dev/null
    openssl x509 -in I/ca.pem -outform DER -out inter.der
    openssl crl2pkcs7 -nocrl -certfile I/ca.pem -certfile R/ca.pem -out chain.p7b; openssl crl2pkcs7 -nocrl -certfile I/ca.pem -certfile R/ca.pem -outform DER -out chain-der.p7b
    openssl pkcs12 -export -in alice.pem -inkey alice.key -passout pass:p12-pass -out alice.p12 2>/dev/null
  `)
  let s: PkiState = { checkCrl: true, cas: [] }
  s = (await fillHashes(addCas(s, rd('I/ca.pem') + rd('R/ca.pem')).state))
  base = s
  const withCrl = applyCrl(base, await parseCrl(rdb('crl-bob.pem'), base), 'upload').state
  const withBoth = applyCrl(withCrl, await parseCrl(rdb('crl-root.pem'), withCrl), 'upload').state
  full = { ...withBoth, server: { pem: rd('srv.pem'), keyEnc: 'x' } }
}, 120000)
afterAll(() => rmSync(D, { recursive: true, force: true }))

describe('splitCerts', () => {
  it('un ou plusieurs certificats, fins de ligne Windows normalisées', () => {
    expect(splitCerts(rd('srv.pem'))).toHaveLength(1)
    expect(splitCerts(rd('I/ca.pem') + '\n\n' + rd('R/ca.pem'))).toHaveLength(2)
    expect(splitCerts(rd('srv.pem').replace(/\n/g, '\r\n'))[0]).not.toContain('\r')
  })
  it('refuse une clé privée, du texte, rien, un certificat tronqué', () => {
    expect(() => splitCerts(rd('srv.pem') + rd('srv.key'))).toThrow(/pem_has_private_key/)
    expect(() => splitCerts(rd('srv.key'))).toThrow(/pem_no_certificate/)
    expect(() => splitCerts('')).toThrow(/pem_no_certificate/)
    expect(() => splitCerts('bonjour')).toThrow(/pem_no_certificate/)
    expect(() => splitCerts(rd('srv.pem') + 'du texte en plus')).toThrow(/pem_unexpected_content/)
    expect(() => splitCerts(rd('srv.pem').slice(0, 300))).toThrow(/pem_no_certificate/)
  })
})

describe('fichiers de certificats (asPem)', () => {
  const b64 = (f: string) => rdb(f).toString('base64')
  it('texte PEM tel quel ; fichier PEM, DER (.cer d\'AD CS), PKCS#7 PEM et DER (.p7b avec chaîne)', async () => {
    expect(await asPem(rd('R/ca.pem'))).toBe(rd('R/ca.pem'))
    expect(splitCerts(await asPem(undefined, b64('R/ca.pem')))).toHaveLength(1)
    const der = splitCerts(await asPem(undefined, b64('inter.der')))
    expect(der).toEqual(splitCerts(rd('I/ca.pem')))
    expect(splitCerts(await asPem(undefined, b64('chain.p7b')))).toHaveLength(2)
    expect(splitCerts(await asPem(undefined, b64('chain-der.p7b')))).toHaveLength(2)
  })
  it('rien, fichier vide, fichier quelconque : refusés', async () => {
    await err(asPem(), 'pem_no_certificate'); await err(asPem('  '), 'pem_no_certificate')
    await err(asPem(undefined, Buffer.from('bonjour').toString('base64')), 'pem_invalid')
    await err(asPem(undefined, Buffer.from([0x30, 0x82, 0x01]).toString('base64')), 'pem_invalid')
  })
})

describe('liste de confiance', () => {
  it('intermédiaire ajoutée AVANT la racine : chaîne incomplète jusqu\'à l\'ajout de la racine ; racine, émettrice et expirée détectées', async () => {
    const a = await fillHashes(addCas({ checkCrl: true, cas: [] }, rd('I/ca.pem')).state)
    expect(analyzeCas(a).map((c) => [c.root, c.chainOk, c.issuing])).toEqual([[false, false, true]])
    const b = await fillHashes(addCas(a, rd('R/ca.pem')).state)
    const v = analyzeCas(b)
    expect(v.map((c) => [c.name, c.root, c.chainOk, c.issuing])).toEqual([['Lab Issuing CA', false, true, true], ['Lab Root', true, true, false]])
    expect(v.every((c) => /^[0-9a-f]{8}$/.test(c.hash))).toBe(true)
  })
  it('doublon ignoré, certificat feuille refusé, autorité expirée refusée, plafond respecté', async () => {
    const r = addCas(base, rd('I/ca.pem'))
    expect([r.added.length, r.skipped, r.state.cas.length]).toEqual([0, 1, 2])
    expect(() => addCas(base, rd('srv.pem'))).toThrow(/ca_not_a_ca/)
    expect(() => addCas(base, rd('old.pem'))).toThrow(/ca_expired/)
    let s: PkiState = { checkCrl: true, cas: [] }
    for (let i = 0; i < 20; i++) { sh(`pki_root Z${i} "Racine ${i}"`); s = addCas(s, rd(`Z${i}/ca.pem`)).state }
    expect(() => addCas(s, rd('X/ca.pem'))).toThrow(/ca_too_many/)
  })
  it('nom donné à une seule autorité, sinon le CN', () => {
    expect(addCas({ checkCrl: true, cas: [] }, rd('R/ca.pem'), 'Racine interne').state.cas[0]!.name).toBe('Racine interne')
    expect(addCas({ checkCrl: true, cas: [] }, rd('R/ca.pem')).state.cas[0]!.name).toBe('Lab Root')
  })
  it('chaîne du serveur : certificat + intermédiaires, jamais la racine ; incomplète sans la racine', () => {
    const ch = serverChain(full)!
    expect(ch.chainOk).toBe(true)
    expect(splitCerts(ch.pem).map((p) => parseCert(p).info.subject)).toEqual([expect.stringContaining('radius.lab.test'), expect.stringContaining('Lab Issuing CA')])
    const noRoot = { ...full, cas: full.cas.filter((c) => !analyzeCas(full).find((v) => v.id === c.id)!.root) }
    expect(serverChain(noRoot)!.chainOk).toBe(false)
    expect(serverChain({ checkCrl: true, cas: [] })).toBeNull()
  })
})

describe('disponibilité du déploiement', () => {
  const codes = (r: ReturnType<typeof readiness>) => r.problems.map((p) => p.code).sort()
  it('vide : ni prêt, ni en erreur (pas d\'EAP)', () => { expect(readiness({ checkCrl: true, cas: [] })).toMatchObject({ empty: true, ready: false, problems: [] }) })
  it('complet : prêt', () => { expect(readiness(full)).toMatchObject({ ready: true, empty: false, problems: [] }) })
  it('sans serveur, sans racine, sans CRL, CRL périmée, CRL absente de l\'émettrice seulement', async () => {
    expect(codes(readiness(base))).toEqual(['crl_missing', 'no_server'])
    expect(codes(readiness({ ...base, checkCrl: false }))).toEqual(['no_server'])
    const only = await fillHashes(addCas({ checkCrl: false, cas: [] }, rd('I/ca.pem')).state)
    expect(codes(readiness({ ...only, server: full.server }))).toEqual(['ca_chain', 'no_root', 'server_chain'])
    expect(codes(readiness({ ...full, cas: full.cas.map((c) => c.crl ? { ...c, crl: { ...c.crl, nextUpdate: Date.now() - 1000 } } : c) }))).toEqual(['crl_expired'])   // émettrice périmée ; la racine n'a pas besoin de CRL
    const rootOnlyCrl = { ...full, cas: full.cas.map((c) => c.name === 'Lab Issuing CA' ? { ...c, crl: undefined } : c) }
    expect(codes(readiness(rootOnlyCrl))).toEqual(['crl_missing'])
  })
  it('serveur : mauvais usage, expiré, expire bientôt ; avertissement CRL < 24 h', async () => {
    const bad = { ...full, server: { pem: rd('badsrv.pem'), keyEnc: 'x' } }
    expect(codes(readiness(bad))).toContain('server_usage')
    const soon = { ...full, cas: full.cas.map((c) => c.crl ? { ...c, crl: { ...c.crl, nextUpdate: Date.now() + 3600_000 } } : c) }
    expect(readiness(soon)).toMatchObject({ ready: true }); expect(readiness(soon).warnings.map((w) => w.code)).toContain('crl_expiring')
    expect(codes(readiness(full, Date.now() + 2000 * 86400_000))).toEqual(expect.arrayContaining(['ca_expired', 'server_expired']))
  })
})

describe('CRL', () => {
  it('PEM et DER donnent la même CRL ; révoqués comptés ; rattachée à la bonne autorité', async () => {
    const a = await parseCrl(rdb('crl-bob.pem'), base), b = await parseCrl(rdb('crl-bob.der'), base)
    expect(a).toMatchObject({ revoked: 1 }); expect(b.sha256).toBe(a.sha256)
    expect(base.cas.find((c) => c.id === a.caId)!.name).toBe('Lab Issuing CA')
    expect((await parseCrl(rdb('crl-ok.pem'), base)).revoked).toBe(0)
    const rc = await parseCrl(rdb('crl-root.pem'), base)
    expect(base.cas.find((c) => c.id === rc.caId)!.name).toBe('Lab Root')
  })
  it('refuse : émettrice inconnue, signature fausse (homonyme), périmée, illisible, vide, trop grosse', async () => {
    await err(parseCrl(rdb('crl-foreign.pem'), base), 'crl_unknown_issuer')
    await err(parseCrl(rdb('crl-rogue.pem'), base), 'crl_bad_signature')
    await err(parseCrl(rdb('crl-expired.pem'), base), 'crl_expired')
    await err(parseCrl(rdb('crl-future.pem'), base), 'crl_not_yet_valid')
    await err(parseCrl(Buffer.from('pas une CRL'), base), 'crl_invalid')
    await err(parseCrl(Buffer.alloc(0), base), 'crl_size')
    await err(parseCrl(Buffer.alloc(9 * 1024 * 1024), base), 'crl_size')
  })
  it('retour en arrière refusé ; même CRL = inchangée ; nouvelle CRL = changement ; empreinte d\'ensemble', async () => {
    const nw = await parseCrl(rdb('crl-new.pem'), base), old = await parseCrl(rdb('crl-old.pem'), base)
    const s1 = applyCrl(base, nw, 'upload'); expect(s1.changed).toBe(true)
    expect(() => applyCrl(s1.state, old, 'upload')).toThrow(/crl_older/)
    expect(applyCrl(s1.state, nw, 'url').changed).toBe(false)
    expect(crlSetDigest(s1.state)).not.toBe(crlSetDigest(base)); expect(crlSetDigest(s1.state)).toBe(crlSetDigest(applyCrl(s1.state, nw, 'url').state))
  })
  it('adresses : http(s) seulement, sans identifiants, sans bouclage ni lien local', () => {
    for (const u of ['http://pki.lab.test/crl/ca.crl', 'https://pki.lab.test:8443/ca.crl?x=1', 'http://10.0.0.5/ca.crl']) expect(normCrlUrl(u), u).toBe(u)
    for (const u of ['ftp://pki/ca.crl', 'ldap://dc1/CN=x', 'http://user:pw@pki/ca.crl', 'http://localhost/ca.crl', 'http://127.0.0.1/ca.crl', 'http://169.254.169.254/x', 'http://0.0.0.0/x', 'http://pki/ca crl', 'http://' + 'a'.repeat(300), 'javascript:alert(1)', 'http:///x', '']) expect(normCrlUrl(u), u).toBeNull()
  })
  it('téléchargement : statut, redirection refusée, taille bornée, contenu', async () => {
    const mk = (status: number, body: Uint8Array | string, headers: Record<string, string> = {}) => (async () => new Response(body, { status, headers })) as unknown as typeof fetch
    await err(fetchCrl('http://x/ca.crl', mk(404, 'non')), 'crl_fetch_status')
    await err(fetchCrl('http://x/ca.crl', mk(302, '', { location: 'http://evil/' })), 'crl_fetch_status')
    await err(fetchCrl('http://x/ca.crl', (async () => { throw new Error('boom') }) as any), 'crl_fetch_failed')
    await err(fetchCrl('http://x/ca.crl', mk(200, new Uint8Array(9 * 1024 * 1024))), 'crl_size')
    expect((await fetchCrl('http://x/ca.crl', mk(200, rdb('crl-bob.pem')))).equals(rdb('crl-bob.pem'))).toBe(true)
  })
  it('actualisation : enregistre la CRL, mémorise l\'échec, refuse la CRL d\'une autre autorité', async () => {
    const id = (n: string) => base.cas.find((c) => c.name === n)!.id
    const withUrl = { ...base, cas: base.cas.map((c) => ({ ...c, crlUrl: 'http://pki.lab.test/x.crl' })) }
    const ok = await refreshCrl(withUrl, id('Lab Issuing CA'), (async () => new Response(rdb('crl-bob.pem'), { status: 200 })) as any)
    expect([ok.error, ok.changed]).toEqual([undefined, true]); expect(ok.state.cas.find((c) => c.name === 'Lab Issuing CA')!.crl!.revoked).toBe(1)
    const ko = await refreshCrl(withUrl, id('Lab Issuing CA'), (async () => new Response('x', { status: 500 })) as any)
    expect(ko.error?.code).toBe('crl_fetch_status'); expect(ko.state.cas.find((c) => c.name === 'Lab Issuing CA')!.crlError).toMatchObject({ code: 'crl_fetch_status' })
    const wrong = await refreshCrl(withUrl, id('Lab Issuing CA'), (async () => new Response(rdb('crl-root.pem'), { status: 200 })) as any)
    expect(wrong.error?.code).toBe('crl_wrong_issuer')
    expect((await refreshCrl(base, id('Lab Root'))).error?.code).toBe('crl_no_url')
    expect((await refreshCrl({ ...base, cas: base.cas.map((c) => ({ ...c, crlUrl: 'http://localhost/x' })) }, id('Lab Root'))).error?.code).toBe('crl_url_invalid')
  })
})

describe('vérification d\'un certificat client', () => {
  it('valide : chaîne acceptée, identité (UPN, e-mail), usage, aucune révocation', async () => {
    const r = await checkClientCert(full, rd('alice.pem'))
    expect(r).toMatchObject({ ok: true, revocation: 'good', chain: { ok: true, code: null }, identity: { upn: 'alice@lab.test', email: ['alice@lab.test'], clientAuth: true } })
    expect((await checkClientCert(full, rd('pc.pem'))).identity).toMatchObject({ upn: null, dns: ['pc01.lab.test'] })
    expect((await checkClientCert(full, rd('direct.pem'))).ok).toBe(true)   // émis directement par la racine
  })
  it('chaîne fournie dans le fichier (intermédiaire collée après la feuille)', async () => {
    const r = await checkClientCert({ ...full, checkCrl: false, cas: full.cas.filter((c) => c.name === 'Lab Root') }, rd('alice.pem') + rd('I/ca.pem'))
    expect(r.ok).toBe(true)
  })
  it('révoqué, expiré, hors liste de confiance, mauvais usage : refus avec le bon motif', async () => {
    expect(await checkClientCert(full, rd('bob.pem'))).toMatchObject({ ok: false, revocation: 'revoked', chain: { code: 'revoked' } })
    expect(await checkClientCert(full, rd('dave.pem'))).toMatchObject({ ok: false, chain: { code: 'expired' } })
    expect(await checkClientCert(full, rd('frank.pem'))).toMatchObject({ ok: false, chain: { code: 'untrusted' } })
    expect(await checkClientCert(full, rd('carl.pem'))).toMatchObject({ ok: false, chain: { code: 'usage' } })
  })
  it('CRL absente ou périmée = refus (comme le service) ; sans vérification de révocation = accepté', async () => {
    expect(await checkClientCert(base, rd('alice.pem'))).toMatchObject({ ok: false, revocation: 'crl_missing' })
    const exp = { ...full, cas: full.cas.map((c) => c.crl ? { ...c, crl: { ...c.crl, pem: rd('crl-expired.pem') } } : c) }
    expect(await checkClientCert(exp, rd('alice.pem'))).toMatchObject({ ok: false, revocation: 'crl_expired' })
    expect(await checkClientCert({ ...base, checkCrl: false }, rd('bob.pem'))).toMatchObject({ ok: true, revocation: 'skipped' })
  })
  it('liste de confiance vide : tout est hors liste ; entrée invalide refusée', async () => {
    expect((await checkClientCert({ checkCrl: false, cas: [] }, rd('alice.pem'))).chain.code).toBe('untrusted')
    await err(checkClientCert(full, rd('alice.key')), 'pem_no_certificate')
  })
})

describe('certificat du serveur : CSR, clés, PKCS#12', () => {
  it('CSR : CN, noms DNS, usage serveur ; clé RSA 2048 / 3072 / EC générées', async () => {
    const key = await newKey('rsa2048'); expect(key).toContain('BEGIN PRIVATE KEY')
    const csr = await makeCsr(key, 'radius.lab.test', ['radius', 'radius2.lab.test'])
    writeFileSync(join(D, 'x.csr'), csr)
    const t = sh('openssl req -in x.csr -noout -text -verify 2>&1')
    expect(t).toContain('verify OK'); expect(t).toContain('CN = radius.lab.test'); expect(t).toMatch(/DNS:radius.lab.test, DNS:radius, DNS:radius2.lab.test/); expect(t).toContain('TLS Web Server Authentication')
    expect(createPrivateKey(await newKey('ec256')).asymmetricKeyType).toBe('ec')
    expect((createPrivateKey(await newKey('rsa3072')).asymmetricKeyDetails as any).modulusLength).toBe(3072)
  }, 60000)
  it('CSR : noms invalides (injection de champs, caractères) refusés', async () => {
    const key = await newKey('ec256')
    for (const [cn, sans] of [['a,O=evil', []], ['a/CN=b', []], ['', []], ['ok', ['bad name']], ['ok', ['a,DNS:b']], ['ok', ['x'.repeat(300)]], ['ok', Array.from({ length: 21 }, (_, i) => `h${i}.lab.test`)]] as Array<[string, string[]]>)
      await err(makeCsr(key, cn, sans), 'csr_invalid_name')
  })
  it('clé : PEM clair accepté ; chiffrée → mot de passe exigé / faux / bon ; RSA 1024, Ed25519, plusieurs clés, texte refusés ; EC acceptée', async () => {
    expect((await normalizeKey(rd('srv.key'))).pem).toContain('BEGIN PRIVATE KEY')
    await err(normalizeKey(rd('srv-enc.key')), 'key_needs_password')
    await err(normalizeKey(rd('srv-enc.key'), 'faux'), 'key_bad_password')
    expect((await normalizeKey(rd('srv-enc.key'), 'secret-1')).pem).toContain('BEGIN PRIVATE KEY')
    await err(normalizeKey(rd('k1024.key')), 'key_weak')
    await err(normalizeKey(rd('ed.key')), 'key_type')
    await err(normalizeKey(rd('srv.key') + rd('alice.key')), 'key_invalid')
    await err(normalizeKey('bonjour'), 'key_invalid')
    await err(normalizeKey(rd('srv.pem')), 'key_invalid')
    expect((await normalizeKey(rd('ec.key'))).key.asymmetricKeyType).toBe('ec')
  })
  it('certificat choisi par sa clé ; clé d\'un autre certificat refusée', async () => {
    const { key } = await normalizeKey(rd('srv.key'))
    expect(pickServerCert(rd('I/ca.pem') + rd('srv.pem'), key)).toBe(splitCerts(rd('srv.pem'))[0])
    expect(() => pickServerCert(rd('alice.pem'), key)).toThrow(/server_key_mismatch/)
  })
  it('PKCS#12 : certificat + chaîne + clé ; mauvais mot de passe ; fichier invalide ; sans clé', async () => {
    const r = await readPkcs12(rdb('srv.p12'), 'p12-pass')
    expect(splitCerts(r.certs)).toHaveLength(2); expect(r.key).toContain('PRIVATE KEY')
    const { key } = await normalizeKey(r.key); expect(pickServerCert(r.certs, key)).toBeTruthy()
    await err(readPkcs12(rdb('srv.p12'), 'faux'), 'p12_bad_password')
    await err(readPkcs12(Buffer.from('pas un p12'), 'x'), 'p12_invalid')
    await err(readPkcs12(Buffer.alloc(0), 'x'), 'p12_size')
  })
})

describe('dépôt pour root', () => {
  it('contenu : liste de confiance, chaîne du serveur (sans racine), clé, CRL par autorité', async () => {
    const d = buildDeposit(full, rd('srv.key'))
    expect(splitCerts(d.ca)).toHaveLength(2); expect(splitCerts(d.server)).toHaveLength(2); expect(d.key).toContain('PRIVATE KEY')
    expect(Object.keys(d.crls).sort()).toEqual(full.cas.filter((c) => c.crl).map((c) => `${c.id}.pem`).sort()); expect(d.checkCrl).toBe(true)
    expect(() => buildDeposit({ ...full, cas: full.cas.filter((c) => c.name !== 'Lab Root') }, 'k')).toThrow(/server_chain/)
  })
})
