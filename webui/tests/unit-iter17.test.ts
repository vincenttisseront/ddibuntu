import { describe, expect, it } from 'vitest'
import { base32Decode, base32Encode, hotp, isRecoveryFormat, newRecoveryCodes, newTotpSecret, normalizeRecovery, otpauthUri, recoveryHash, totpStep, verifyTotp } from '~~/server/utils/totp'

describe('TOTP (RFC 6238 / RFC 4226)', () => {
  const SECRET = base32Encode(Buffer.from('12345678901234567890'))      // clé de test des RFC
  it('base32 aller-retour', () => {
    expect(SECRET).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
    expect(base32Decode(SECRET).toString()).toBe('12345678901234567890')
    expect(base32Decode('gezd gnbv-gy3t qojq gezd gnbv gy3t qojq').toString()).toBe('12345678901234567890')
    expect(() => base32Decode('1!')).toThrow()
    for (let i = 0; i < 20; i++) { const s = newTotpSecret(); expect(s).toMatch(/^[A-Z2-7]{32}$/); expect(base32Encode(base32Decode(s))).toBe(s) }
  })
  it('vecteurs HOTP de la RFC 4226', () => {
    const want = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
    want.forEach((w, i) => expect(hotp(SECRET, i)).toBe(w))
  })
  it('vecteurs TOTP de la RFC 6238 (SHA-1, 6 derniers chiffres)', () => {
    expect(hotp(SECRET, totpStep(59_000))).toBe('287082')          // 94287082
    expect(hotp(SECRET, totpStep(1111111109_000))).toBe('081804')  // 07081804
    expect(hotp(SECRET, totpStep(1234567890_000))).toBe('005924')  // 89005924
  })
  it('vérification : fenêtre ±1 pas, rejeu refusé, format strict', () => {
    const now = 1_700_000_000_000, st = totpStep(now)
    expect(verifyTotp(SECRET, hotp(SECRET, st), null, now)).toBe(st)
    expect(verifyTotp(SECRET, hotp(SECRET, st - 1), null, now)).toBe(st - 1)
    expect(verifyTotp(SECRET, hotp(SECRET, st + 1), null, now)).toBe(st + 1)
    expect(verifyTotp(SECRET, hotp(SECRET, st + 2), null, now)).toBeNull()
    expect(verifyTotp(SECRET, hotp(SECRET, st - 2), null, now)).toBeNull()
    expect(verifyTotp(SECRET, hotp(SECRET, st), st, now)).toBeNull()               // même pas déjà consommé
    expect(verifyTotp(SECRET, hotp(SECRET, st - 1), st, now)).toBeNull()           // pas plus ancien que le dernier consommé
    expect(verifyTotp(SECRET, hotp(SECRET, st + 1), st, now)).toBe(st + 1)
    for (const bad of ['', '12345', '1234567', 'abcdef', ' 123456', '12 3456']) expect(verifyTotp(SECRET, bad, null, now)).toBeNull()
  })
  it('URI otpauth et codes de secours', () => {
    const u = otpauthUri('ABCDEFGH', 'jean.dupont@exemple.fr')
    expect(u).toBe('otpauth://totp/DDI-Buntu:jean.dupont%40exemple.fr?secret=ABCDEFGH&issuer=DDI-Buntu&algorithm=SHA1&digits=6&period=30')
    const codes = newRecoveryCodes(); expect(codes).toHaveLength(10); expect(new Set(codes).size).toBe(10)
    for (const c of codes) { expect(c).toMatch(/^[a-z2-9]{5}-[a-z2-9]{5}$/); expect(isRecoveryFormat(c)).toBe(true) }
    expect(recoveryHash(' ABCDE-FGHJK ')).toBe(recoveryHash('abcde-fghjk')); expect(normalizeRecovery(' AbCde-fGhjk ')).toBe('abcde-fghjk')
    expect(recoveryHash('abcde-fghjk')).not.toBe(recoveryHash('abcde-fghjm'))
    expect(isRecoveryFormat('123456')).toBe(false); expect(isRecoveryFormat('abcde_fghjk')).toBe(false)
  })
})
