// 0.18.0 — enrôlement des postes : lecture du keytab, nom de compte machine, jeton « Negotiate », réglages, script PowerShell.
// Le côté Kerberos (ticket réel, annuaire réel, émission) est vérifié par e2e-iter62.test.ts contre un Samba AD.
import { describe, expect, it } from 'vitest'
process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'
import { dnsInDomain, dnsMatchesAccount, domainOfDn, principalAllowed, principalAuditOk, ENROLL_DEFAULTS, enrollBody, enrollComplete, enrollSerial, keytabProblem, machineFromPrincipal, negotiateToken, parseKeytab, preAuthAuditOk, sealKeytab } from '../server/utils/enroll'
import { enrollScript } from '../server/utils/enroll-script'

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
    for (const must of ['-UseDefaultCredentials', 'Exportable = FALSE', 'MachineKeySet = TRUE', 'Register-ScheduledTask', "'SYSTEM'", 'certreq.exe -accept -machine', '/api/enroll/v1/machine']) expect(s, must).toContain(must)
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
