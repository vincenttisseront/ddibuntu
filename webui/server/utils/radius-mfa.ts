// Second facteur par client RADIUS (0.17.0). Un client marqué « MFA » n'utilise plus EAP : l'équipement (pare-feu VPN, par exemple) envoie en PAP « mot de passe + code à usage
// unique » collés dans le champ du mot de passe ; le service applique les règles d'accès AVANT tout, puis demande au FOURNISSEUR MFA de vérifier le mot de passe et le code
// (le code n'est jamais vérifié par le DDI). La console ne détient du fournisseur que ses réglages : le secret client est chiffré et n'est jamais renvoyé.
// Fournisseur générique : le premier type pris en charge est l'OAuth2 « mot de passe » (point de jeton, champs configurables) ; d'autres types pourront s'ajouter sans toucher aux clients.
import { createHmac } from 'node:crypto'
import { z } from 'zod'
import { decryptSecret, encryptSecret } from './auth'
import { requireSecret } from './config'
import { getSetting, setSetting } from './db'

export const MFA_KEY = 'radius_mfa'
export const MFA_TYPES = ['oauth2_password'] as const
export type MfaType = (typeof MFA_TYPES)[number]
// Mêmes jeux de caractères que root (validate_authz) : un réglage refusé ici est signalé avant le dépôt, avec un message clair.
export const TOKEN_URL_RE = /^https:\/\/[A-Za-z0-9._-]{1,253}(:[0-9]{1,5})?(\/[A-Za-z0-9._~/:@-]{0,300})?$/
export const FIELD_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,39}$/
export const CLIENT_ID_RE = /^[A-Za-z0-9._~-]{1,200}$/
export const CLIENT_SECRET_RE = /^[A-Za-z0-9._~-]{0,512}$/
export const EXTRA_VALUE_RE = /^[A-Za-z0-9 ._~:/@-]{0,200}$/
const RESERVED = ['grant_type', 'client_id', 'client_secret']

export interface MfaExtra { name: string; value: string }
export interface MfaSettings {
  type: MfaType
  tokenUrl: string
  clientId: string
  clientSecretEnc: string          // '' = client public (aucun secret)
  fields: { identity: string; password: string; otp: string }
  identity: 'typed' | 'account'    // identifiant transmis : tel que saisi, ou le compte (sAMAccountName) trouvé dans l'annuaire
  otpDigits: 6 | 8
  extra: MfaExtra[]
  timeoutSec: number
  tlsVerify: boolean
  caPem: string
}
export const MFA_DEFAULTS: MfaSettings = {
  type: 'oauth2_password', tokenUrl: '', clientId: '', clientSecretEnc: '', fields: { identity: 'username', password: 'password', otp: 'totp' },
  identity: 'typed', otpDigits: 6, extra: [], timeoutSec: 5, tlsVerify: true, caPem: '',
}

const extraItem = z.object({ name: z.string().trim().regex(FIELD_RE), value: z.string().trim().regex(EXTRA_VALUE_RE) }).strict()
/** Corps de la requête d'enregistrement. `clientSecret` : absent ou null = inchangé ; '' = aucun secret (client public). */
export const mfaBody = z.object({
  type: z.enum(MFA_TYPES),
  tokenUrl: z.string().trim().max(400).refine((v) => v === '' || TOKEN_URL_RE.test(v), 'url'),
  clientId: z.string().trim().max(200).refine((v) => v === '' || CLIENT_ID_RE.test(v), 'client_id'),
  clientSecret: z.string().max(512).refine((v) => CLIENT_SECRET_RE.test(v), 'client_secret').nullish(),
  fields: z.object({ identity: z.string().trim().regex(FIELD_RE), password: z.string().trim().regex(FIELD_RE), otp: z.string().trim().regex(FIELD_RE) }).strict(),
  identity: z.enum(['typed', 'account']),
  otpDigits: z.union([z.literal(6), z.literal(8)]),
  extra: z.array(extraItem).max(5),
  timeoutSec: z.number().int().min(2).max(15),
  tlsVerify: z.boolean(),
  caPem: z.string().max(65536).regex(/^(?:\s*-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\s*)*$/),
}).strict().superRefine((b, ctx) => {
  const names = [b.fields.identity, b.fields.password, b.fields.otp]
  if (new Set(names).size !== 3 || names.some((n) => RESERVED.includes(n))) ctx.addIssue({ code: 'custom', path: ['fields'], message: 'fields' })
  const taken = new Set([...RESERVED, ...names])
  for (const e of b.extra) { if (taken.has(e.name)) ctx.addIssue({ code: 'custom', path: ['extra'], message: 'extra' }); taken.add(e.name) }
})

/** Lecture tolérante : une valeur absente ou abîmée retombe sur les valeurs par défaut (aucun fournisseur). */
export function normMfa(x: unknown): MfaSettings {
  const o = (x && typeof x === 'object' ? x : {}) as Record<string, any>
  const f = (o.fields && typeof o.fields === 'object' ? o.fields : {}) as Record<string, unknown>
  const fld = (v: unknown, d: string) => (typeof v === 'string' && FIELD_RE.test(v) ? v : d)
  const extra = (Array.isArray(o.extra) ? o.extra : []).filter((e: any) => e && typeof e.name === 'string' && FIELD_RE.test(e.name) && typeof e.value === 'string' && EXTRA_VALUE_RE.test(e.value)).slice(0, 5)
    .map((e: any) => ({ name: e.name as string, value: e.value as string }))
  return {
    type: 'oauth2_password',
    tokenUrl: typeof o.tokenUrl === 'string' && TOKEN_URL_RE.test(o.tokenUrl) ? o.tokenUrl : '',
    clientId: typeof o.clientId === 'string' && CLIENT_ID_RE.test(o.clientId) ? o.clientId : '',
    clientSecretEnc: typeof o.clientSecretEnc === 'string' ? o.clientSecretEnc.slice(0, 4096) : '',
    fields: { identity: fld(f.identity, 'username'), password: fld(f.password, 'password'), otp: fld(f.otp, 'totp') },
    identity: o.identity === 'account' ? 'account' : 'typed',
    otpDigits: o.otpDigits === 8 ? 8 : 6,
    extra,
    timeoutSec: Number.isInteger(o.timeoutSec) && o.timeoutSec >= 2 && o.timeoutSec <= 15 ? o.timeoutSec : 5,
    tlsVerify: o.tlsVerify !== false,
    caPem: typeof o.caPem === 'string' ? o.caPem.slice(0, 65536) : '',
  }
}
export const loadMfa = async (): Promise<MfaSettings> => normMfa(await getSetting<unknown>(MFA_KEY, MFA_DEFAULTS))
export const saveMfa = (m: MfaSettings) => setSetting(MFA_KEY, m)
/** Ce que la console renvoie : jamais le secret client (seulement s'il existe). */
export function publicMfa(m: MfaSettings) { const { clientSecretEnc, ...rest } = m; return { ...rest, clientSecretSet: clientSecretEnc !== '' } }
/** Fournisseur assez renseigné pour être déployé (adresse et identifiant client). */
export const mfaConfigured = (m: MfaSettings) => m.tokenUrl !== '' && m.clientId !== ''

export const mfaSecret = (m: MfaSettings): string => (m.clientSecretEnc ? decryptSecret(m.clientSecretEnc) : '')
export const sealMfaSecret = (s: string): string => (s ? encryptSecret(s) : '')

/** mfa.json déposé pour root (porte le secret client : fichier 0600, effacé par root après traitement). */
export function mfaJson(m: MfaSettings): string {
  return JSON.stringify({
    type: m.type, tokenUrl: m.tokenUrl, clientId: m.clientId, clientSecret: mfaSecret(m), fields: m.fields, identity: m.identity, otpDigits: m.otpDigits,
    extra: m.extra, timeoutSec: m.timeoutSec, tlsVerify: m.tlsVerify,
  }) + '\n'
}
/** Part de l'empreinte du déploiement : tout ce qui part chez root, le secret seulement sous forme d'empreinte à clé. */
export function mfaDigestPart(m: MfaSettings): unknown {
  const s = mfaSecret(m)
  return [m.type, m.tokenUrl, m.clientId, s ? createHmac('sha256', requireSecret()).update(s).digest('hex') : '', m.fields, m.identity, m.otpDigits, m.extra, m.timeoutSec, m.tlsVerify, m.caPem.trim()]
}
