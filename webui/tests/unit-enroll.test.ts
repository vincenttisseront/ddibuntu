// 0.18.0 — enrôlement des postes : lecture du keytab, nom de compte machine, jeton « Negotiate », réglages, script PowerShell.
// Le côté Kerberos (ticket réel, annuaire réel, émission) est vérifié par e2e-iter62.test.ts contre un Samba AD.
import { describe, expect, it } from 'vitest'
process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'
import { dnsInDomain, dnsMatchesAccount, domainOfDn, principalAllowed, principalAuditOk, ENROLL_DEFAULTS, enrollBody, enrollComplete, enrollSerial, keytabProblem, keytabShapeProblem, machineFromPrincipal, negotiateToken, parseKeytab, preAuthAuditOk, sealKeytab } from '../server/utils/enroll'
import { enrollScript } from '../server/utils/enroll-script'
import { gpoScript, mergeExtensions, scriptsIni, trustAnchors } from '../server/utils/enroll-gpo'
import { filterGpoAcl, guidBytes, AUTHENTICATED_USERS, ridOf, APPLY_GROUP_POLICY } from '../server/utils/gpo-acl'
import { ACCOUNT_RE, createOu, GpoError, pushGpo } from '../server/utils/enroll-gpo-push'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

function kt(entries: Array<{ comps: string[]; realm: string; enctype: number; kvno?: number; hole?: number }>): Buffer {
  const parts: Buffer[] = [Buffer.from([5, 2])]
  const u16 = (n: number) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b }
  const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b }
  const s = (v: string) => Buffer.concat([u16(Buffer.byteLength(v)), Buffer.from(v)])
  for (const e of entries) {
    if (e.hole) { const h = Buffer.alloc(4); h.writeInt32BE(-e.hole); parts.push(h, Buffer.alloc(e.hole)); continue }
    const body = Buffer.concat([u16(e.comps.length), s(e.realm), ...e.comps.map(s), u32(1), u32(1700000000), Buffer.from([e.kvno ?? 1]), u16(e.enctype), u16(32), Buffer.alloc(32, 7), u32(e.kvno ?? 1)])
    parts.push(u32(body.length), body)
  }
  return Buffer.concat(parts)
}

describe('parseKeytab', () => {
  it('lit les principaux, les numéros de version et les types de chiffrement', () => {
    const i = parseKeytab(kt([{ comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 18, kvno: 4 }, { comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 17, kvno: 4 }]))
    expect(i.principals).toEqual(['HTTP/ddi.lab.test@LAB.TEST']); expect(i.realm).toBe('LAB.TEST'); expect(i.entries.map((e) => [e.kvno, e.enctype])).toEqual([[4, 18], [4, 17]])
  })
  it('saute les trous laissés par une suppression', () => {
    const i = parseKeytab(kt([{ comps: [], realm: '', enctype: 0, hole: 20 }, { comps: ['HTTP', 'a.test'], realm: 'A.TEST', enctype: 18 }]))
    expect(i.principals).toEqual(['HTTP/a.test@A.TEST'])
  })
  it('refuse le vide, le mauvais en-tête, les entrées tronquées et les domaines mélangés', () => {
    expect(() => parseKeytab(Buffer.from([5, 2]))).toThrow()
    expect(() => parseKeytab(Buffer.from('pas un keytab du tout'))).toThrow('keytab_format')
    expect(() => parseKeytab(Buffer.concat([Buffer.from([5, 1]), Buffer.alloc(20)]))).toThrow('keytab_format')
    const ok = kt([{ comps: ['HTTP', 'a.test'], realm: 'A.TEST', enctype: 18 }])
    expect(() => parseKeytab(ok.subarray(0, ok.length - 9))).toThrow('keytab_format')
    expect(() => parseKeytab(kt([{ comps: ['HTTP', 'a.test'], realm: 'A.TEST', enctype: 18 }, { comps: ['HTTP', 'b.test'], realm: 'B.TEST', enctype: 18 }]))).toThrow('keytab_realms')
    expect(() => parseKeytab(Buffer.alloc(70000, 1))).toThrow('keytab_format')
  })
  it('exige le service HTTP/<hôte> et de l\'AES', () => {
    const aes = parseKeytab(kt([{ comps: ['HTTP', 'DDI.lab.test'], realm: 'LAB.TEST', enctype: 18 }]))
    expect(keytabProblem(aes, 'ddi.lab.test')).toBeNull()
    expect(keytabProblem(aes, 'autre.lab.test')).toBe('keytab_spn')
    expect(keytabProblem(parseKeytab(kt([{ comps: ['host', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 18 }])), 'ddi.lab.test')).toBe('keytab_spn')
    expect(keytabProblem(parseKeytab(kt([{ comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 23 }])), 'ddi.lab.test')).toBe('keytab_enctype')
    expect(keytabProblem(parseKeytab(kt([{ comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 23 }, { comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 18 }])), 'ddi.lab.test')).toBeNull()
  })
  it('refuse un keytab qui porte aussi un autre service que HTTP/…', () => {
    const k = parseKeytab(kt([{ comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 18 }, { comps: ['host', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 18 }]))
    expect(keytabProblem(k, 'ddi.lab.test')).toBe('keytab_extra')
  })
  it('le keytab mis en base est chiffré, et rien du secret ne reste dans les champs lisibles', () => {
    const raw = kt([{ comps: ['HTTP', 'ddi.lab.test'], realm: 'LAB.TEST', enctype: 18, kvno: 2 }])
    const s = sealKeytab(raw, parseKeytab(raw))
    expect(s.enc).toMatch(/^v1:/); expect(s.kvno).toEqual({ 'HTTP/ddi.lab.test@LAB.TEST': 2 }); expect(s.size).toBe(raw.length)
    expect(JSON.stringify({ ...s, enc: '' })).not.toContain(raw.toString('base64'))
  })
})

describe('machineFromPrincipal', () => {
  it('ne retient qu\'un compte d\'ordinateur du bon domaine', () => {
    expect(machineFromPrincipal('PC003$@LAB.TEST', 'LAB.TEST')).toBe('PC003$')
    expect(machineFromPrincipal('pc-003$@lab.test', 'LAB.TEST')).toBe('pc-003$')
    for (const p of ['alice@LAB.TEST', 'PC003@LAB.TEST', 'PC003$@AUTRE.TEST', 'PC003$', 'host/pc003.lab.test@LAB.TEST', 'PC 003$@LAB.TEST', '$@LAB.TEST', 'A2345678901234567890$@LAB.TEST', 'PC003$@LAB.TEST\n', '../x$@LAB.TEST']) expect(machineFromPrincipal(p, 'LAB.TEST'), p).toBeNull()
  })
})

describe('dnsMatchesAccount', () => {
  it('le premier label du nom DNS est celui du compte (nom NetBIOS tronqué à 15 caractères admis)', () => {
    expect(dnsMatchesAccount('pc003.lab.test', 'PC003$')).toBe(true); expect(dnsMatchesAccount('PC003.lab.test', 'pc003$')).toBe(true)
    expect(dnsMatchesAccount('srv01.lab.test', 'PC003$')).toBe(false); expect(dnsMatchesAccount('pc0031.lab.test', 'PC003$')).toBe(false); expect(dnsMatchesAccount('pc.lab.test', 'PC003$')).toBe(false)
    expect(dnsMatchesAccount('abcdefghijklmnop.lab.test', 'ABCDEFGHIJKLMN$')).toBe(false)   // 14 caractères : pas tronqué, le label doit être identique
    expect(dnsMatchesAccount('abcdefghijklmnopqrst.lab.test', 'ABCDEFGHIJKLMNO$')).toBe(true)   // 15 caractères : nom tronqué, préfixe admis
  })
})

describe('serialisation et journal borné', () => {
  it('enrollSerial exécute les créneaux l\'un après l\'autre, même si l\'un échoue', async () => {
    const order: string[] = []
    const a = enrollSerial(async () => { order.push('a1'); await new Promise((r) => setTimeout(r, 30)); order.push('a2'); return 1 })
    const b = enrollSerial(async () => { order.push('b1'); throw new Error('boum') })
    const c = enrollSerial(async () => { order.push('c1'); return 3 })
    expect(await a).toBe(1); await expect(b).rejects.toThrow('boum'); expect(await c).toBe(3)
    expect(order).toEqual(['a1', 'a2', 'b1', 'c1'])
  })
  it('les refus avant authentification ne sont écrits que 20 fois par minute', () => {
    const t0 = 10_000_000, ok = Array.from({ length: 30 }, (_, i) => preAuthAuditOk(t0 + i))
    expect(ok.filter(Boolean).length).toBe(20); expect(preAuthAuditOk(t0 + 61_000)).toBe(true)
  })
})

describe('en-tête du jeton, domaine et plafonds par principal', () => {
  it('un jeton qui ne commence pas par une étiquette SPNEGO est refusé avant tout déchiffrement', () => {
    expect(negotiateToken('Negotiate AAAAAAAAAAAAAAAAAAAAAAAA')).toBeNull()
    expect(negotiateToken('Negotiate bm9wZW5vcGVub3Blbm9wZW5vcGVu')).toBeNull()
    expect(negotiateToken('Negotiate YIIAAAAAAAAAAAAAAAAAAAAA')).toBe('YIIAAAAAAAAAAAAAAAAAAAAA')   // 0x60
    expect(negotiateToken('Negotiate oYIAAAAAAAAAAAAAAAAAAAAA')).toBe('oYIAAAAAAAAAAAAAAAAAAAAA')   // 0xA1
  })
  it('le domaine vient des composants DC= du DN, et le nom DNS doit s\'y trouver', () => {
    expect(domainOfDn('CN=PC003,CN=Computers,DC=lab,DC=test')).toBe('lab.test')
    expect(domainOfDn('CN=PC003,OU=Postes,DC=Corp,DC=Example,DC=com')).toBe('corp.example.com')
    expect(domainOfDn('CN=PC003')).toBe('')
    expect(dnsInDomain('pc003.lab.test', 'lab.test')).toBe(true); expect(dnsInDomain('PC003.LAB.TEST', 'lab.test')).toBe(true)
    expect(dnsInDomain('pc003.autre.example', 'lab.test')).toBe(false); expect(dnsInDomain('pc003.xlab.test', 'lab.test')).toBe(false); expect(dnsInDomain('pc003.lab.test', '')).toBe(false)
  })
  it('60 demandes et 20 refus écrits par minute et par principal (casse ignorée)', () => {
    const t0 = 20_000_000
    expect(Array.from({ length: 70 }, (_, i) => principalAllowed('PC9$@LAB.TEST', t0 + i)).filter(Boolean).length).toBe(60)
    expect(Array.from({ length: 30 }, (_, i) => principalAuditOk('pc9$@lab.test', t0 + i)).filter(Boolean).length).toBe(20)
    expect(principalAllowed('pc9$@lab.test', t0 + 61_000)).toBe(true)
    expect(principalAllowed('pc8$@lab.test', t0)).toBe(true)   // un autre principal a ses propres plafonds
  })
})

describe('negotiateToken', () => {
  it('extrait le jeton d\'un en-tête « Negotiate » bien formé, rien d\'autre', () => {
    expect(negotiateToken('Negotiate YIIBsgYGKwYBBQUCoIIBpjCCAaKgMDAuBgkqhkiC8RIBAgIGCSqGSIb3EgECAgYKKwYBBAGCNwICHgYKKwYBBAGCNwICCqKCAX8EggF7')).toMatch(/^YIIB/)
    for (const h of [undefined, '', 'Negotiate', 'Negotiate ', 'Negotiate abc', 'Basic dXNlcjpwdw==', 'Bearer ddi_xxxxxxxxxxxxxxxxxxxxxxxx', 'Negotiate AAAA AAAA AAAA AAAA', 'Negotiate ' + 'A'.repeat(32769), 'Negotiate AAAAAAAAAAAAAAAA\nX-Evil: 1']) expect(negotiateToken(h), String(h)).toBeNull()
  })
})

describe('réglages', () => {
  it('par défaut éteint et incomplet', () => {
    expect(ENROLL_DEFAULTS.enabled).toBe(false); expect(enrollComplete(ENROLL_DEFAULTS)).toBe(false)
    expect(enrollComplete({ ...ENROLL_DEFAULTS, ca: 'Sub', groupDn: 'CN=g,DC=a,DC=b', host: 'ddi.a.b' })).toBe(true)
  })
  it('bornes et formes', () => {
    const ok = { enabled: true, ca: 'Lab-Sub', groupDn: 'CN=grp,CN=Users,DC=lab,DC=test', host: 'DDI.Lab.Test', minIntervalSec: 300, maxPerDay: 6, maxPerMinute: 30 }
    expect(enrollBody.parse(ok).host).toBe('ddi.lab.test')
    for (const bad of [{ ca: 'ManagementCA' }, { ca: 'ExtRoot-x' }, { host: 'https://ddi' }, { host: 'a b' }, { groupDn: 'x' }, { groupDn: 'CN=a${x}' }, { minIntervalSec: 29 }, { minIntervalSec: 86401 }, { maxPerDay: 0 }, { maxPerDay: 51 }, { maxPerMinute: 601 }, { extra: 1 }]) expect(enrollBody.safeParse({ ...ok, ...bad }).success, JSON.stringify(bad)).toBe(false)
  })
})

describe('script PowerShell', () => {
  it('insère la console et l\'autorité, en CRLF, et échappe les apostrophes', () => {
    const s = enrollScript('ddi.lab.test', "Autorité d'essai")
    expect(s).toContain("$Console   = 'ddi.lab.test'"); expect(s).toContain("$IssuerCn  = 'Autorité d''essai'")
    expect(s).not.toContain('__HOST__'); expect(s).not.toContain('__ISSUER__')
    expect(s.split('\r\n').length).toBeGreaterThan(50); expect(s.replace(/\r\n/g, '')).not.toContain('\n')
    for (const must of ['-UseDefaultCredentials', 'Exportable = FALSE', 'MachineKeySet = TRUE', 'Register-ScheduledTask', 'Start-ScheduledTask -TaskName', "'SYSTEM'", 'certreq.exe -accept -machine', '/api/enroll/v1/machine']) expect(s, must).toContain(must)
  })
  it('un nom d\'autorité hostile ne sort pas de sa chaîne PowerShell (apostrophes typographiques, « $\' », « $& »)', () => {
    const s = enrollScript('ddi.lab.test', "A\u2019b\u2018c\u201Ad\u201Be'f $' $& $$ $1")
    expect(s).toContain("$IssuerCn  = 'A\u2019\u2019b\u2018\u2018c\u201A\u201Ad\u201B\u201Be''f $'' $& $$ $1'")
    expect(s.split('param([switch]$Install').length).toBe(2)   // le gabarit n'est pas recopié par un motif de remplacement
    expect(s).toContain("$env:ProgramFiles 'DDI-Buntu'"); expect(s).not.toContain('$env:ProgramData')
  })
  it('refuse une console ou une autorité douteuse', () => {
    for (const h of ['', 'a b', "x'; Remove-Item *; '", 'https://x', 'x.test/../y']) expect(() => enrollScript(h, 'CA'), h).toThrow('enroll_host')
    for (const i of ['', 'x'.repeat(129), 'a\nb']) expect(() => enrollScript('ddi.lab.test', i)).toThrow('enroll_issuer')
  })
})

describe('script de mise en place de la GPO', () => {
  function pems() {
    const d = mkdtempSync(join(tmpdir(), 'gpo-'))
    try {
      const sh = (...a: string[]) => execFileSync('openssl', a, { cwd: d, stdio: 'pipe' })
      sh('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-subj', '/CN=Racine essai', '-days', '30')
      sh('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'sub.key', '-out', 'sub.csr', '-subj', '/CN=Sub essai')
      sh('x509', '-req', '-in', 'sub.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'sub.pem', '-days', '30')
      return { root: readFileSync(join(d, 'root.pem'), 'utf8'), sub: readFileSync(join(d, 'sub.pem'), 'utf8') }
    } finally { rmSync(d, { recursive: true, force: true }) }
  }
  it('ne retient que les autorités racines (auto-signées), une fois chacune, sous un nom dérivé de l\'empreinte', () => {
    const { root, sub } = pems()
    const a = trustAnchors(sub + root, root, 'pas un certificat', '')
    expect(Object.keys(a)).toHaveLength(1); expect(Object.keys(a)[0]).toMatch(/^anchor-[0-9A-F]{40}\.cer$/)
    expect(a[Object.keys(a)[0]!]!.length).toBeGreaterThan(100)
    expect(trustAnchors(sub)).toEqual({})
  })
  it('embarque enroll.ps1 (avec marque d\'ordre d\'octets), le démarrage et les racines ; CRLF ; aucun gabarit résiduel', () => {
    const { root } = pems(), a = trustAnchors(root)
    const s = gpoScript(enrollScript('ddi.lab.test', 'Lab Sub CA'), a)
    expect(s).not.toContain('__FILES__'); expect(s.replace(/\r\n/g, '')).not.toContain('\n')
    for (const must of ['SupportsShouldProcess', 'Get-ADOrganizationalUnit', 'New-GPO', 'New-GPLink', 'gPCMachineExtensionNames', 'GPT.INI', 'scripts.ini', '42B5FAAE-6536-11D2-AE5A-0000F87571E3', '40B6664F-4972-11D1-A7CA-0000F87571E3']) expect(s, must).toContain(must)
    expect(s).not.toContain(String.fromCharCode(96))   // pas de backtick PowerShell : le gabarit est un littéral JavaScript
    const files = Object.fromEntries([...s.matchAll(/^ {2}'([^']+)' = '([A-Za-z0-9+/=]+)'\r$/gm)].map((m) => [m[1]!, Buffer.from(m[2]!, 'base64')]))
    expect(Object.keys(files).sort()).toEqual(['ddi-demarrage.ps1', 'enroll.ps1', ...Object.keys(a)].sort())
    expect([...files['enroll.ps1']!.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]); expect(files['enroll.ps1']!.toString('utf8')).toContain("$Console   = 'ddi.lab.test'")
    expect(files['ddi-demarrage.ps1']!.toString('ascii')).toContain("-Filter 'anchor-*.cer'"); expect(files['ddi-demarrage.ps1']!.toString('ascii')).toContain("'enroll.ps1') -Install")
    expect(files[Object.keys(a)[0]!]!.equals(a[Object.keys(a)[0]!]!)).toBe(true)
    expect([...s].every((ch) => ch.charCodeAt(0) < 128)).toBe(true)   // PowerShell 5.1 lit un fichier sans marque d'ordre d'octets en ANSI : le script reste en ASCII
  })
  it('refuse un nom de fichier douteux', () => {
    expect(() => gpoScript('x', { "a'; Remove-Item *; '.cer": Buffer.from('x') })).toThrow('enroll_gpo_name')
  })
})

describe('GPO poussée par la console : briques', () => {
  it('fusionne l\'extension « scripts » sans toucher aux autres, sans doublon', () => {
    const E = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
    expect(mergeExtensions('')).toEqual({ value: E, changed: true })
    expect(mergeExtensions(E)).toEqual({ value: E, changed: false })
    const other = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
    expect(mergeExtensions(other)).toEqual({ value: other + E, changed: true })
    expect(mergeExtensions('[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{AUTRE}]').value).toBe('[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{AUTRE}{40B6664F-4972-11D1-A7CA-0000F87571E3}]')
  })
  it('scripts.ini : UTF-16 avec marque d\'ordre d\'octets, appelle le script de démarrage depuis SYSVOL', () => {
    const b = scriptsIni('lab.test', '{ABC}'); expect([...b.subarray(0, 2)]).toEqual([0xff, 0xfe])
    expect(b.subarray(2).toString('utf16le')).toBe('[Startup]\r\n0CmdLine=powershell.exe\r\n0Parameters=-NoProfile -ExecutionPolicy Bypass -File "\\\\lab.test\\SYSVOL\\lab.test\\Policies\\{ABC}\\Machine\\Scripts\\Startup\\ddi-demarrage.ps1"\r\n')
  })
  it('le compte n\'accepte que « utilisateur@domaine » ou « DOMAINE\\utilisateur »', () => {
    for (const ok of ['admin@lab.test', 'a.b-c_d@exemple.org', 'LAB\\admin']) expect(ACCOUNT_RE.test(ok), ok).toBe(true)
    for (const ko of ['admin', 'a b@lab.test', 'x%y@lab.test', '-U@lab.test x', 'admin@', 'LAB\\', 'a@b\nc']) expect(ACCOUNT_RE.test(ko), ko).toBe(false)
  })
  it('refuse un annuaire sans LDAPS avant toute connexion', async () => {
    let touched = false
    const d = { urls: ['ldaps://a.test', 'ldap://b.test'], ldap: () => { touched = true; throw new Error('non') }, smb: async () => ({ ok: true, out: '' }), files: {} }
    await expect(pushGpo(d as any, { ou: 'OU=Postes,DC=lab,DC=test', account: 'a@lab.test', password: 'x', dry: true })).rejects.toMatchObject({ reason: 'tls' })
    await expect(pushGpo({ ...d, urls: [] } as any, { ou: 'OU=P,DC=l,DC=t', account: 'a@l.t', password: 'x', dry: true })).rejects.toBeInstanceOf(GpoError)
    expect(touched).toBe(false)
    await expect(createOu({ urls: ['ldap://b.test'], ldap: () => { touched = true; throw new Error('non') } } as any, { ou: 'OU=P,DC=l,DC=t', account: 'a@l.t', password: 'x' })).rejects.toMatchObject({ reason: 'tls' })
    expect(touched).toBe(false)
  })
})

describe('filtrage de sécurité d\'une GPO (descripteur binaire)', () => {
  const GROUP = Buffer.from([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0x34, 0x12, 0, 0])   // S-1-5-21-1-2-3-4660
  const sid = (rid: number) => Buffer.from([1, 1, 0, 0, 0, 0, 0, 5, rid, 0, 0, 0])
  const ace = (type: number, flags: number, mask: number, s: Buffer, obj?: string) => {
    const head = Buffer.alloc(obj ? 12 : 8); head[0] = type; head[1] = flags; head.writeUInt32LE(mask, 4); if (obj) head.writeUInt32LE(1, 8)
    const b = Buffer.concat(obj ? [head, guidBytes(obj), s] : [head, s]); b.writeUInt16LE(b.length, 2); return b
  }
  const dacl = (aces: Buffer[]) => { const body = Buffer.concat(aces); const h = Buffer.alloc(8); h[0] = 4; h.writeUInt16LE(8 + body.length, 2); h.writeUInt16LE(aces.length, 4); const sd = Buffer.alloc(20); sd[0] = 1; sd.writeUInt16LE(0x8004, 2); sd.writeUInt32LE(20, 16); return Buffer.concat([sd, h, body]) }
  const parse = (sd: Buffer) => { const out: Array<{ type: number; flags: number; mask: number; sid: Buffer; obj?: Buffer }> = []; const n = sd.readUInt16LE(20 + 4); for (let p = 28, i = 0; i < n; i++) { const len = sd.readUInt16LE(p + 2), t = sd[p]!; out.push(t === 5 ? { type: t, flags: sd[p + 1]!, mask: sd.readUInt32LE(p + 4), obj: sd.subarray(p + 12, p + 28), sid: sd.subarray(p + 28, p + len) } : { type: t, flags: sd[p + 1]!, mask: sd.readUInt32LE(p + 4), sid: sd.subarray(p + 8, p + len) }); p += len } return out }
  const AU = AUTHENTICATED_USERS, SY = sid(18)
  const base = () => [ace(0, 2, 0x20094, SY), ace(0, 2, 0x20094, AU), ace(5, 2, 0x100, AU, APPLY_GROUP_POLICY), ace(0, 0x12, 0x20094, sid(32))]

  it('guidBytes : ordre des octets de Windows', () => { expect(guidBytes(APPLY_GROUP_POLICY).toString('hex')).toBe('8ffdacedb3ffd111b41d00a0c968f939'); expect(ridOf(GROUP)).toBe(0x1234) })
  it('retire le droit d\'appliquer à « Utilisateurs authentifiés », le donne au groupe avant les ACE héritées, garde la lecture', () => {
    const r = filterGpoAcl(dacl(base()), GROUP); expect(r.changed).toBe(true)
    const a = parse(r.sd); expect(a).toHaveLength(4)
    expect(a.some((x) => x.type === 5 && x.sid.equals(AU))).toBe(false)                       // plus d'« appliquer » pour tous
    expect(a.some((x) => x.type === 0 && x.sid.equals(AU))).toBe(true)                         // la lecture reste
    const g = a.findIndex((x) => x.type === 5 && x.sid.equals(GROUP)); expect(g).toBeGreaterThanOrEqual(0)
    expect(a[g]!.obj!.equals(guidBytes(APPLY_GROUP_POLICY))).toBe(true); expect(a[g]!.mask).toBe(0x100); expect(a[g]!.flags).toBe(2)
    expect(a.findIndex((x) => x.flags & 0x10)).toBeGreaterThan(g)                              // les explicites avant les héritées
    expect(r.sd.readUInt16LE(20 + 2)).toBe(r.sd.length - 20)                                   // taille de la DACL cohérente
  })
  it('est idempotent', () => {
    const once = filterGpoAcl(dacl(base()), GROUP); const twice = filterGpoAcl(once.sd, GROUP)
    expect(twice.changed).toBe(false); expect(twice.sd.equals(once.sd)).toBe(true)
  })
  it('refuse un descripteur illisible ou qui porte autre chose que la DACL', () => {
    expect(() => filterGpoAcl(Buffer.alloc(10), GROUP)).toThrow('sd')
    const withOwner = dacl(base()); withOwner.writeUInt32LE(99, 4); expect(() => filterGpoAcl(withOwner, GROUP)).toThrow('sd')
    const cut = dacl(base()).subarray(0, 50); expect(() => filterGpoAcl(cut, GROUP)).toThrow('sd')
  })
})

describe('keytab : forme contrôlée sans le nom de la console (0.21.3)', () => {
  const aes = (host: string) => parseKeytab(kt([{ comps: ['HTTP', host], realm: 'LAB.TEST', enctype: 18 }]))
  it('un keytab AES HTTP/… est accepté quel que soit le nom enregistré', () => {
    expect(keytabShapeProblem(aes('virtuel.lab.test'))).toBeNull()
    expect(keytabProblem(aes('virtuel.lab.test'), 'noeud1.lab.test')).toBe('keytab_spn')   // la concordance reste vérifiée à l'activation
  })
  it('sans service HTTP, avec un autre principal ou en RC4 / DES : refusé', () => {
    expect(keytabShapeProblem(parseKeytab(kt([{ comps: ['host', 'pc.lab.test'], realm: 'LAB.TEST', enctype: 18 }])))).toBe('keytab_spn')
    expect(keytabShapeProblem(parseKeytab(kt([{ comps: ['HTTP', 'a.lab.test'], realm: 'LAB.TEST', enctype: 18 }, { comps: ['host', 'a.lab.test'], realm: 'LAB.TEST', enctype: 18 }])))).toBe('keytab_extra')
    expect(keytabShapeProblem(parseKeytab(kt([{ comps: ['HTTP', 'a.lab.test'], realm: 'LAB.TEST', enctype: 23 }])))).toBe('keytab_enctype')
  })
})

describe('enroll.ps1 : hors SYSTEM et motif du refus (0.21.3)', () => {
  const s = enrollScript('ddi.lab.test', 'CA')
  it('refuse de tourner hors SYSTEM avec un message clair, avant tout appel à la console', () => {
    expect(s).toContain('[Security.Principal.WindowsIdentity]::GetCurrent().IsSystem')
    expect(s.indexOf('IsSystem')).toBeLessThan(s.indexOf('Invoke-WebRequest'))
    expect(s).toContain('Register-ScheduledTask -TaskName DDI-test')
  })
  it('lit le corps de la réponse dans ErrorDetails et nomme le motif dans l\'échec', () => {
    expect(s).toContain('$_.ErrorDetails.Message')
    expect(s).toContain("throw ('enrolement refuse (HTTP {0} {1})' -f $code, $why)")
  })
})
