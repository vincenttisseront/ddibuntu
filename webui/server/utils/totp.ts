// Double authentification TOTP (RFC 6238 : HMAC-SHA1, 6 chiffres, pas de 30 s), compatible Google/Microsoft Authenticator, Aegis, 1Password, Bitwarden…
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const TOTP_STEP = 30
export const TOTP_WINDOW = 1          // ±30 s de tolérance d'horloge

export const base32Encode = (buf: Buffer): string => {
  let bits = 0, val = 0, out = ''
  for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5 } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31]
  return out
}
export const base32Decode = (s: string): Buffer => {
  let bits = 0, val = 0; const out: number[] = []
  for (const ch of s.toUpperCase().replace(/[\s=-]/g, '')) {
    const i = B32.indexOf(ch); if (i < 0) throw new Error('base32 invalide')
    val = (val << 5) | i; bits += 5
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8 }
  }
  return Buffer.from(out)
}

export const newTotpSecret = (): string => base32Encode(randomBytes(20))

export function hotp(secret: string, counter: number): string {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter))
  const h = createHmac('sha1', base32Decode(secret)).update(msg).digest()
  const o = h[h.length - 1]! & 15
  const n = ((h[o]! & 0x7f) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!
  return String(n % 1_000_000).padStart(6, '0')
}
export const totpStep = (now = Date.now()): number => Math.floor(now / 1000 / TOTP_STEP)

/** Renvoie le pas validé (à mémoriser : un même pas ne sert qu'une fois), ou null. `lastStep` : dernier pas déjà consommé. */
export function verifyTotp(secret: string, code: string, lastStep: number | null, now = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null
  const cur = totpStep(now); let hit: number | null = null
  for (let d = -TOTP_WINDOW; d <= TOTP_WINDOW; d++) {
    const step = cur + d
    const a = Buffer.from(hotp(secret, step)), b = Buffer.from(code)
    if (timingSafeEqual(a, b) && hit === null && (lastStep === null || step > lastStep)) hit = step   // pas de sortie anticipée : temps constant
  }
  return hit
}

export const otpauthUri = (secret: string, account: string, issuer = 'DDI-Buntu'): string =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${TOTP_STEP}`

// ---- Codes de secours : à usage unique, stockés hachés ----
const RC = 'abcdefghjkmnpqrstuvwxyz23456789'
export function newRecoveryCodes(n = 10): string[] {
  return Array.from({ length: n }, () => { const b = randomBytes(10); const s = Array.from(b, (x) => RC[x % RC.length]).join(''); return `${s.slice(0, 5)}-${s.slice(5)}` })
}
export const normalizeRecovery = (c: string): string => c.trim().toLowerCase().replace(/\s/g, '')
export const isRecoveryFormat = (c: string): boolean => /^[a-z0-9]{5}-[a-z0-9]{5}$/.test(normalizeRecovery(c))
export const recoveryHash = (c: string): string => createHash('sha256').update('ddibuntu-recovery\0' + normalizeRecovery(c)).digest('hex')
