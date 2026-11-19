// 0.14.14 — noms proposés par défaut dans les formulaires de la PKI : domaine du DDI, premier numéro libre, nom lu dans une vraie demande de certificat (openssl),
// et branchement dans les trois écrans (certificats, autorités, SCEP) avec les textes dans les deux langues.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { csrCommonName, domainOf, freeNumber, suggestCaNames, suggestCertName, suggestImportName, suggestSans } from '../app/utils/pkiNames'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-names-'))
afterAll(() => rmSync(TMP, { recursive: true, force: true }))
const csr = (subj: string, extra: string[] = [], form: 'PEM' | 'DER' = 'PEM') => {
  const r = spawnSync('openssl', ['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(TMP, 'k.pem'), '-subj', subj, '-outform', form, ...extra], { encoding: form === 'PEM' ? 'utf8' : 'buffer' as any })
  expect(r.status).toBe(0)
  return r.stdout as any
}
const read = (rel: string) => readFileSync(resolve(__dirname, rel), 'utf8')

describe('domainOf', () => {
  it.each([['pki.lab.test', 'lab.test'], ['PKI.Lab.Test.', 'lab.test'], ['pki.corp', 'corp'], ['pki', ''], ['', ''], [undefined, ''], ['a b.c', ''], ['.lab', '']])('« %s » → « %s »', (h, d) => { expect(domainOf(h as any)).toBe(d) })
})
describe('numéros libres', () => {
  it('premier numéro non pris, casse ignorée', () => { expect(freeNumber((n) => `a-${n}`, ['A-1', 'a-2', 'b-3'])).toBe(3) })
  it('borné', () => { expect(freeNumber(() => 'x', ['x'])).toBe(999) })
})
describe('suggestCertName', () => {
  it('serveur : nom complet avec le domaine, numéroté sur deux chiffres', () => { expect(suggestCertName('serveur', 'lab.test', true, [])).toBe('serveur-01.lab.test') })
  it('saute les noms déjà émis', () => { expect(suggestCertName('poste', 'lab.test', true, ['poste-01.lab.test', 'POSTE-02.lab.test'])).toBe('poste-03.lab.test') })
  it('utilisateur : sans domaine', () => { expect(suggestCertName('utilisateur', 'lab.test', false, [])).toBe('utilisateur-01') })
  it('pas de domaine connu : nom court', () => { expect(suggestCertName('serveur', '', true, [])).toBe('serveur-01') })
  it('jamais plus de 63 caractères', () => { expect(suggestCertName('x'.repeat(80), 'lab.test', true, []).length).toBeLessThanOrEqual(63) })
})
describe('suggestSans', () => {
  it('un nom complet devient le nom DNS (en minuscules)', () => { expect(suggestSans('server', 'DC01.Lab.Test', 'lab.test')).toEqual({ dns: 'dc01.lab.test', upn: '' }) })
  it('un nom court n\'est pas un nom DNS', () => { expect(suggestSans('machine', 'poste-01', 'lab.test')).toEqual({ dns: '', upn: '' }) })
  it('un nom invalide en DNS ne donne rien', () => { expect(suggestSans('network', 'a b.c', 'lab.test').dns).toBe(''); expect(suggestSans('network', 'a..b', 'lab.test').dns).toBe('') })
  it('utilisateur : identifiant UPN nom@domaine, pas de nom DNS', () => {
    expect(suggestSans('user', 'utilisateur-01', 'lab.test')).toEqual({ dns: '', upn: 'utilisateur-01@lab.test' })
    expect(suggestSans('user', 'Élodie Martin', 'lab.test').upn).toBe(''); expect(suggestSans('user', 'a@b', 'lab.test').upn).toBe(''); expect(suggestSans('user', 'x', '').upn).toBe('')
  })
})
describe('autorités', () => {
  it('émettrice et racine : nom et CN cohérents, premier numéro libre', () => {
    expect(suggestCaNames('issuing', [])).toEqual({ name: 'DDI-Issuing-1', cn: 'DDI Issuing CA 1' })
    expect(suggestCaNames('issuing', ['DDI-Issuing-1', 'DDI-Issuing-2'])).toEqual({ name: 'DDI-Issuing-3', cn: 'DDI Issuing CA 3' })
    expect(suggestCaNames('root', ['DDI-Issuing-1'])).toEqual({ name: 'DDI-Root-1', cn: 'DDI Root CA 1' })
  })
  it('autorité reprise', () => { expect(suggestImportName(['Imported-CA-1'])).toBe('Imported-CA-2') })
  it('les noms proposés respectent les règles de root (48 caractères, jetons autorisés)', () => {
    const { name } = suggestCaNames('issuing', []); expect(name).toMatch(/^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/)
  })
})
describe('csrCommonName (vraie demande openssl)', () => {
  it('PEM', () => { expect(csrCommonName(csr('/CN=dc01.lab.test/O=Lab/C=FR'))).toBe('dc01.lab.test') })
  it('DER (fichier choisi)', () => { expect(csrCommonName(new Uint8Array(csr('/CN=dc02.lab.test', [], 'DER')))).toBe('dc02.lab.test') })
  it('nom UTF-8', () => { expect(csrCommonName(csr('/CN=Élodie Martin/O=Lab', ['-utf8']))).toBe('Élodie Martin') })
  it('prend le nom du sujet, pas celui d\'un nom alternatif', () => { expect(csrCommonName(csr('/CN=dc01.lab.test', ['-addext', 'subjectAltName=DNS:autre.lab.test']))).toBe('dc01.lab.test') })
  it('sans CN : rien', () => { expect(csrCommonName(csr('/O=Lab/C=FR'))).toBeNull() })
  it('texte quelconque, PEM tronqué, vide : rien', () => {
    expect(csrCommonName('pas une demande')).toBeNull(); expect(csrCommonName('-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----')).toBeNull()
    expect(csrCommonName('')).toBeNull(); expect(csrCommonName(new Uint8Array())).toBeNull()
  })
  it('nom contenant un séparateur de nom distinctif : écarté', () => { expect(csrCommonName(csr('/CN=a\\,b'))).toBeNull() })
})
describe('branchement dans les écrans', () => {
  it('certificats : proposition qui suit le profil et la demande tant que le champ n\'est pas modifié', () => {
    const v = read('../app/components/PkiCerts.vue')
    for (const k of ['suggestCertName', 'suggestSans', 'csrCommonName', 'refreshCn', 'refreshSans', 'cnAuto', 'dnsAuto', "watch(() => iss.profile"]) expect(v).toContain(k)
  })
  it('SCEP et autorités', () => {
    expect(read('../app/components/PkiScep.vue')).toContain('suggestCertName'); const c = read('../app/components/PkiCas.vue')
    expect(c).toContain('suggestCaNames'); expect(c).toContain('suggestImportName')
  })
  it.each(['fr', 'en'])('textes %s', (l) => {
    const i = read(`../app/i18n/${l}.ts`)
    for (const k of ['server', 'machine', 'user', 'network', 'other']) expect(i).toContain(`"pki.name.${k}"`)
  })
})
