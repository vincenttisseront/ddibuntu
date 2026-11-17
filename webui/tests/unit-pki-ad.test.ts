// 0.14.2 — publication des autorités de la PKI dans l'Active Directory : emplacements, publication / rapprochement / retrait sur un annuaire en mémoire
// (erreurs injectées : droits, conteneur absent, conflit, écriture qui ne tient pas), vérification des droits sans écrire, délégation à faire, script de repli.
// L'annuaire réel (Samba AD) est essayé par e2e-iter46.test.ts.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  accountInfo, backoffSeconds, checkCa, checkContainers, CONFIG_NC_RE, containerDn, containerFor, delegation, fallbackScript, objectDn, pemToDer, PLACEHOLDER, publishCa, rootDse,
  sha256Hex, sidToString, withdrawCa, classifyWrite,
} from '../server/utils/pki-ad'
import type { PkiLdap } from '../server/utils/pki-ad'

const NC = 'CN=Configuration,DC=lab,DC=test'
const T = mkdtempSync(join(tmpdir(), 'ddi-ad-'))
let pemA = '', pemB = '', derA: Buffer, derB: Buffer
beforeAll(() => {
  const mk = (cn: string, f: string) => { execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(T, f + '.key'), '-out', join(T, f + '.pem'), '-subj', `/CN=${cn}`, '-days', '30', '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: 'ignore' }); return readFileSync(join(T, f + '.pem'), 'utf8') }
  pemA = mk('Racine A', 'a'); pemB = mk('Racine B', 'b'); derA = pemToDer(pemA)!; derB = pemToDer(pemB)!
})
afterAll(() => rmSync(T, { recursive: true, force: true }))

const lerr = (name: string, code: number, msg = name) => Object.assign(new Error(msg), { name, code })
/** Annuaire en mémoire : conteneurs, objets « certificationAuthority », erreurs injectables, et — comme ldapts — valeur unique rendue seule, binaire en Buffer. */
class FakeDir implements PkiLdap {
  objects = new Map<string, { cn: string; certs: Buffer[]; extra: Record<string, unknown> }>()
  containers = new Set([containerDn(NC, 'roots'), containerDn(NC, 'aia')])
  canCreate = new Set([containerDn(NC, 'roots'), containerDn(NC, 'aia')])
  fail: Partial<Record<'add' | 'replace' | 'del' | 'search', any>> = {}
  corrupt = false; keepOnDelete = false; log: string[] = []
  async bind() { return {} }
  async unbind() { return {} }
  async search(base: string, o: { attributes: string[] }) {
    if (this.fail.search) throw this.fail.search
    if (base === '') return { searchEntries: [{ dn: '', configurationNamingContext: NC, defaultNamingContext: 'DC=lab,DC=test', dnsHostName: 'dc1.lab.test' }] }
    if (this.containers.has(base)) return { searchEntries: [{ dn: base, ...(this.canCreate.has(base) ? { allowedChildClassesEffective: ['account', 'certificationAuthority', 'user'] } : {}) }] }
    const ob = this.objects.get(base)
    if (!ob) throw lerr('NoSuchObjectError', 32)
    const v = ob.certs.length === 1 ? ob.certs[0]! : ob.certs
    return { searchEntries: [{ dn: base, ...(o.attributes.includes('cACertificate') ? { cACertificate: v } : {}), ...ob.extra }] }
  }
  private parentOk(dn: string) { return this.containers.has(dn.slice(dn.indexOf(',') + 1)) }
  async add(dn: string, e: Record<string, unknown>) {
    this.log.push('add ' + dn)
    if (this.fail.add) throw this.fail.add
    if (!this.parentOk(dn)) throw lerr('NoSuchObjectError', 32)
    if (this.objects.has(dn)) throw lerr('AlreadyExistsError', 68)
    this.objects.set(dn, { cn: String(e.cn), certs: this.corrupt ? [derB] : (e.cACertificate as Buffer[]), extra: { objectClass: e.objectClass, certificateRevocationList: e.certificateRevocationList, authorityRevocationList: e.authorityRevocationList } })
  }
  async replaceBinary(dn: string, _a: string, v: Buffer) {
    this.log.push('replace ' + dn)
    if (this.fail.replace) throw this.fail.replace
    const o = this.objects.get(dn); if (!o) throw lerr('NoSuchObjectError', 32)
    o.certs = this.corrupt ? [derB] : [v]
  }
  async del(dn: string) {
    this.log.push('del ' + dn)
    if (this.fail.del) throw this.fail.del
    if (!this.objects.has(dn)) throw lerr('NoSuchObjectError', 32)
    if (!this.keepOnDelete) this.objects.delete(dn)
  }
}
const dnA = objectDn(NC, 'roots', 'Lab-Root'), dnI = objectDn(NC, 'aia', 'Lab-Sub')

describe('emplacements', () => {
  it('racines et racines hors ligne dans « Certification Authorities », émettrices dans « AIA », le reste nulle part', () => {
    expect(containerFor('root')).toBe('roots'); expect(containerFor('extroot')).toBe('roots'); expect(containerFor('issuing')).toBe('aia')
    expect(containerFor('unknown')).toBeNull(); expect(containerFor('')).toBeNull()
    expect(containerDn(NC, 'roots')).toBe('CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=test')
    expect(objectDn(NC, 'aia', 'ExtRoot-0a1b2c3d')).toBe('CN=ExtRoot-0a1b2c3d,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=test')
  })
  it('la partition Configuration annoncée par un serveur est validée avant tout usage', () => {
    for (const ok of ['CN=Configuration,DC=lab,DC=test', 'CN=Configuration,DC=corp,DC=example,DC=com', 'cn=configuration,dc=a-b,dc=c']) expect(CONFIG_NC_RE.test(ok), ok).toBe(true)
    for (const bad of ['', 'CN=Configuration', 'CN=Configuration,OU=x,DC=a', 'CN=Configuration,DC=a,CN=Evil', 'CN=Configuration,DC=lab,DC=test,', 'DC=lab,DC=test', 'CN=Configuration,DC=a\\,b', 'CN=Configuration,DC=-a', 'CN=Configuration,DC=lab,DC=test\nx']) expect(CONFIG_NC_RE.test(bad), JSON.stringify(bad)).toBe(false)
  })
  it('PEM → DER : seul un vrai certificat passe', () => {
    expect(derA.length).toBeGreaterThan(300); expect(sha256Hex(derA)).toMatch(/^[0-9a-f]{64}$/); expect(sha256Hex(derA)).not.toBe(sha256Hex(derB))
    for (const bad of ['', 'pas un certificat', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n', Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])]) expect(pemToDer(bad)).toBeNull()
    expect(pemToDer(Buffer.from(pemA))!.equals(derA)).toBe(true)
  })
})

describe('RootDSE et droits sur les conteneurs', () => {
  it('lit la partition Configuration, le domaine et le contrôleur', async () => {
    expect(await rootDse(new FakeDir())).toEqual({ configNc: NC, defaultNc: 'DC=lab,DC=test', host: 'dc1.lab.test' })
  })
  it('refuse un RootDSE sans partition Configuration valable', async () => {
    const d = new FakeDir(); d.search = async () => ({ searchEntries: [{ dn: '', configurationNamingContext: 'CN=Configuration,OU=pirate' }] })
    expect(await rootDse(d)).toEqual({ error: 'config_nc' })
    d.search = async () => ({ searchEntries: [] }); expect(await rootDse(d)).toEqual({ error: 'config_nc' })
  })
  it('droit de création lu sans écrire : délégué, non délégué, conteneur absent', async () => {
    const d = new FakeDir()
    expect((await checkContainers(d, NC)).map((c) => [c.container, c.exists, c.canCreate])).toEqual([['roots', true, true], ['aia', true, true]])
    d.canCreate.delete(containerDn(NC, 'aia'))
    expect((await checkContainers(d, NC)).map((c) => [c.container, c.exists, c.canCreate])).toEqual([['roots', true, true], ['aia', true, false]])
    d.containers.delete(containerDn(NC, 'roots'))
    expect((await checkContainers(d, NC)).map((c) => [c.container, c.exists, c.canCreate])).toEqual([['roots', false, false], ['aia', true, false]])
    expect(d.log).toEqual([])   // aucune écriture
  })
  it('une panne autre que « objet absent » remonte', async () => {
    const d = new FakeDir(); d.fail.search = lerr('Error', -1, 'connect ECONNREFUSED')
    await expect(checkContainers(d, NC)).rejects.toThrow('ECONNREFUSED')
  })
})

describe('publication', () => {
  it('crée l\'objet avec les quatre attributs du schéma et relit l\'empreinte', async () => {
    const d = new FakeDir()
    const r = await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false })
    expect(r).toEqual({ ok: true, action: 'added', sha: sha256Hex(derA) })
    const o = d.objects.get(dnA)!
    expect(o.cn).toBe('Lab-Root'); expect(o.certs).toEqual([derA]); expect(o.extra.objectClass).toEqual(['top', 'certificationAuthority'])
    expect(o.extra.certificateRevocationList).toEqual([PLACEHOLDER]); expect(o.extra.authorityRevocationList).toEqual([PLACEHOLDER])
  })
  it('rejouer ne change rien (idempotent, aucune écriture)', async () => {
    const d = new FakeDir(); await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false }); d.log = []
    expect(await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: true })).toEqual({ ok: true, action: 'unchanged', sha: sha256Hex(derA) })
    expect(d.log).toEqual([])
  })
  it('un certificat qui change (renouvellement) remplace le nôtre ; jamais celui d\'un autre', async () => {
    const d = new FakeDir(); await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false })
    expect(await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derB, owned: true })).toEqual({ ok: true, action: 'replaced', sha: sha256Hex(derB) })
    expect(d.objects.get(dnA)!.certs).toEqual([derB])
    const e = new FakeDir(); e.objects.set(dnI, { cn: 'Lab-Sub', certs: [derB], extra: {} })   // objet déjà là, pas publié par nous
    expect(await publishCa(e, { dn: dnI, name: 'Lab-Sub', der: derA, owned: false })).toEqual({ ok: false, reason: 'conflict' })
    expect(e.objects.get(dnI)!.certs).toEqual([derB]); expect(e.log).toEqual([])   // intact, rien écrit
  })
  it('un objet déjà là qui porte notre certificat est reconnu sans y toucher, même avec d\'autres certificats', async () => {
    const d = new FakeDir(); d.objects.set(dnA, { cn: 'Lab-Root', certs: [derA, derB], extra: {} })
    expect(await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false })).toMatchObject({ ok: true, action: 'unchanged' })
    expect(d.log).toEqual([])
  })
  it('une écriture qui ne tient pas est un échec visible (empreinte relue ≠ attendue)', async () => {
    const d = new FakeDir(); d.corrupt = true
    expect(await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false })).toEqual({ ok: false, reason: 'mismatch' })
    d.corrupt = false; d.objects.get(dnA)!.certs = [derB]; d.corrupt = true
    expect(await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: true })).toEqual({ ok: false, reason: 'mismatch' })
  })
  it('chaque erreur de l\'annuaire dit ce qu\'il faut corriger', async () => {
    const cases: Array<[string, any]> = [['denied', lerr('InsufficientAccessError', 50)], ['conflict', lerr('AlreadyExistsError', 68)], ['schema', lerr('ObjectClassViolationError', 65)], ['bind', lerr('InvalidCredentialsError', 49)], ['unreachable', lerr('Error', -1, 'connect ECONNREFUSED 10.0.0.19:636')]]
    for (const [reason, err] of cases) {
      const d = new FakeDir(); d.fail.add = err
      expect(await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false }), reason).toEqual({ ok: false, reason })
    }
    const d = new FakeDir(); d.containers.delete(containerDn(NC, 'roots'))
    expect(await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false })).toEqual({ ok: false, reason: 'no_container' })
    const e = new FakeDir(); e.objects.set(dnA, { cn: 'x', certs: [derB], extra: {} }); e.fail.replace = lerr('InsufficientAccessError', 50)
    expect(await publishCa(e, { dn: dnA, name: 'Lab-Root', der: derA, owned: true })).toEqual({ ok: false, reason: 'denied' })
  })
  it('la valeur binaire rendue en chaîne (texte valide) est comprise comme des octets', async () => {
    const d = new FakeDir(); const txt = Buffer.from('abc', 'utf8')
    d.objects.set(dnA, { cn: 'x', certs: [], extra: {} }); d.search = async () => ({ searchEntries: [{ dn: dnA, cACertificate: 'abc' }] })
    expect(await checkCa(d, dnA, sha256Hex(txt))).toEqual({ ok: true, state: 'ok' })
  })
})

describe('rapprochement', () => {
  it('ok, absent, différent, erreur', async () => {
    const d = new FakeDir(); await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false })
    expect(await checkCa(d, dnA, sha256Hex(derA))).toEqual({ ok: true, state: 'ok' })
    expect(await checkCa(d, dnA, sha256Hex(derB))).toEqual({ ok: true, state: 'different' })
    expect(await checkCa(d, dnI, sha256Hex(derA))).toEqual({ ok: true, state: 'missing' })
    d.fail.search = lerr('InsufficientAccessError', 50); expect(await checkCa(d, dnA, sha256Hex(derA))).toEqual({ ok: false, reason: 'denied' })
  })
})

describe('retrait', () => {
  it('seulement ce qui est à nous, puis vérifié', async () => {
    const d = new FakeDir(); await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false })
    expect(await withdrawCa(d, { dn: dnA, sha: sha256Hex(derA), owned: true })).toEqual({ ok: true, action: 'deleted' }); expect(d.objects.has(dnA)).toBe(false)
    expect(await withdrawCa(d, { dn: dnA, sha: sha256Hex(derA), owned: true })).toEqual({ ok: true, action: 'absent' })
  })
  it('un objet étranger n\'est pas supprimé ; publié par nous, il l\'est même s\'il a été modifié', async () => {
    const d = new FakeDir(); d.objects.set(dnI, { cn: 'Lab-Sub', certs: [derB], extra: {} })
    expect(await withdrawCa(d, { dn: dnI, sha: sha256Hex(derA), owned: false })).toEqual({ ok: false, reason: 'conflict' }); expect(d.objects.has(dnI)).toBe(true)
    expect(await withdrawCa(d, { dn: dnI, sha: sha256Hex(derA), owned: true })).toEqual({ ok: true, action: 'deleted' })
  })
  it('suppression qui ne tient pas : échec visible ; refus de l\'annuaire : raison', async () => {
    const d = new FakeDir(); await publishCa(d, { dn: dnA, name: 'Lab-Root', der: derA, owned: false }); d.keepOnDelete = true
    expect(await withdrawCa(d, { dn: dnA, sha: sha256Hex(derA), owned: true })).toEqual({ ok: false, reason: 'mismatch' })
    d.fail.del = lerr('InsufficientAccessError', 50); expect(await withdrawCa(d, { dn: dnA, sha: sha256Hex(derA), owned: true })).toEqual({ ok: false, reason: 'denied' })
  })
})

describe('compte de liaison', () => {
  it('SID binaire → texte', () => {
    const b = Buffer.alloc(8 + 4 * 5); b[0] = 1; b[1] = 5; b[7] = 5
    ;[21, 229740459, 2744776875, 25628710, 1114].forEach((v, i) => b.writeUInt32LE(v, 8 + 4 * i))
    expect(sidToString(b)).toBe('S-1-5-21-229740459-2744776875-25628710-1114')
    expect(sidToString(Buffer.from([1, 2, 0, 0, 0, 0, 0, 5]))).toBeNull(); expect(sidToString(Buffer.alloc(4))).toBeNull(); expect(sidToString(Buffer.from([2, 0, 0, 0, 0, 0, 0, 5]))).toBeNull()
  })
  it('retrouve le compte par DN ou par nom (UPN / sAMAccountName) ; filtre échappé', async () => {
    const sid = Buffer.alloc(16); sid[0] = 1; sid[1] = 2; sid[7] = 5; sid.writeUInt32LE(21, 8); sid.writeUInt32LE(1114, 12)
    const seen: string[] = []
    const d = new FakeDir(); d.search = async (b: string, o: any) => { seen.push(`${b}|${o.scope}|${o.filter}`); return { searchEntries: [{ dn: 'x', sAMAccountName: 'svc-ddi-pki', userPrincipalName: 'svc-ddi-pki@lab.test', objectSid: sid }] } }
    expect(await accountInfo(d, 'svc-ddi-pki@lab.test', 'DC=lab,DC=test')).toEqual({ sam: 'svc-ddi-pki', upn: 'svc-ddi-pki@lab.test', sid: 'S-1-5-21-1114' })
    expect(seen[0]).toBe('DC=lab,DC=test|sub|(&(objectClass=user)(|(userPrincipalName=svc-ddi-pki@lab.test)(sAMAccountName=svc-ddi-pki@lab.test)))')
    await accountInfo(d, 'a)(uid=*', 'DC=lab,DC=test'); expect(seen[1]).toContain('a\\29\\28uid=\\2a')
    await accountInfo(d, 'CN=svc,CN=Users,DC=lab,DC=test', 'DC=lab,DC=test'); expect(seen[2]).toBe('CN=svc,CN=Users,DC=lab,DC=test|base|(objectClass=*)')
  })
  it('compte introuvable, ambigu ou panne : null', async () => {
    const d = new FakeDir(); d.search = async () => ({ searchEntries: [] }); expect(await accountInfo(d, 'x', 'DC=a')).toBeNull()
    d.search = async () => ({ searchEntries: [{ dn: '1' }, { dn: '2' }] }); expect(await accountInfo(d, 'x', 'DC=a')).toBeNull()
    d.search = async () => { throw lerr('Error', -1, 'boom') }; expect(await accountInfo(d, 'x', 'DC=a')).toBeNull()
  })
})

describe('délégation à faire', () => {
  it('une commande par conteneur, SDDL et samba-tool seulement si le SID est connu', () => {
    const [r, a] = delegation({ configNc: NC, account: 'LAB\\svc-ddi-pki', sid: 'S-1-5-21-1-2-3-1114' })
    expect(r!.dsacls).toBe('dsacls "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=test" /I:T /G "LAB\\svc-ddi-pki:CCDCLCLORPWPSDRC"')
    expect(a!.sddl).toBe('(A;CIOI;CCDCLCLORPWPSDRC;;;S-1-5-21-1-2-3-1114)')
    expect(a!.samba).toBe('samba-tool dsacl set --objectdn="CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=test" --sddl="(A;CIOI;CCDCLCLORPWPSDRC;;;S-1-5-21-1-2-3-1114)"')
    const sans = delegation({ configNc: NC, account: 'svc@lab.test' }); expect(sans.every((x) => x.sddl === null && x.samba === null)).toBe(true); expect(sans[1]!.dsacls).toContain('"svc@lab.test:CCDCLCLORPWPSDRC"')
  })
})

describe('script de repli (certutil)', () => {
  it('intègre les certificats publics avec leur empreinte, racines en RootCA et émettrices en SubCA', () => {
    const s = fallbackScript([{ name: 'Lab-Root', container: 'roots', der: derA }, { name: 'Lab-Sub', container: 'aia', der: derB }])
    expect(s).toContain(`@{ Name = 'Lab-Root'; Store = 'RootCA'; Sha256 = '${sha256Hex(derA)}'; Cert = '${derA.toString('base64')}' }`)
    expect(s).toContain(`@{ Name = 'Lab-Sub'; Store = 'SubCA'; Sha256 = '${sha256Hex(derB)}'; Cert = '${derB.toString('base64')}' }`)
    expect(s).toContain('certutil -dspublish -f $file $i.Store'); expect(s).toContain('Get-FileHash -Algorithm SHA256')
    expect(s).not.toMatch(/PRIVATE KEY|password|motdepasse/i)
  })
})

describe('divers', () => {
  it('attente avant une nouvelle tentative : 1 min, 2, 4… plafonnée à 1 h', () => {
    expect([0, 1, 2, 3, 5, 6, 7, 20, -1].map(backoffSeconds)).toEqual([60, 120, 240, 480, 1920, 3600, 3600, 3600, 60])
  })
  it('classification des erreurs : le code LDAP prime sur le texte (une adresse en « .19 » n\'est pas une violation de schéma)', () => {
    expect(classifyWrite(lerr('Error', -1, 'connect ECONNREFUSED 10.0.0.19:636'))).toBe('unreachable')
    expect(classifyWrite(lerr('Error', -1, 'unable to verify the first certificate'))).toBe('tls')
    expect(classifyWrite(lerr('Error', -1, 'Hostname/IP does not match certificate\'s altnames'))).toBe('tls')
    expect(classifyWrite(lerr('InsufficientAccessError', 50))).toBe('denied'); expect(classifyWrite(lerr('Whatever', 32))).toBe('no_container')
    expect(classifyWrite(lerr('Error', -1, 'quelque chose'))).toBe('other'); expect(classifyWrite(null)).toBe('other')
  })
})
