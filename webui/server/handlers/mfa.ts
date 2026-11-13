// Double authentification (TOTP) des comptes locaux : seconde étape de connexion, activation par l'utilisateur, désactivation, codes de secours.
// Les comptes Active Directory / SSO / annuaire s'appuient sur le second facteur de leur fournisseur.
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { one, query, inRecovery } from '../utils/db'
import { decryptSecret, destroyUserSessions, encryptSecret, loginBlocked, parseMfaChallenge, credentialStamp, recordAttempt, replicaLoginBlocked, replicaRecordAttempt, verifyPassword } from '../utils/auth'
import { isRecoveryFormat, newRecoveryCodes, newTotpSecret, otpauthUri, recoveryHash, verifyTotp } from '../utils/totp'
import { finishLogin } from './auth'
import { MFA_ROLES, mfaPolicy, parseMfaPolicy, saveMfaPolicy } from '../utils/mfa-policy'

export const registered = true

const code = z.string().trim().min(6).max(16)
const replicaSteps = new Map<number, number>()   // secondaire : base en lecture seule, le pas consommé n'est mémorisé qu'en mémoire

/** Vérifie un code TOTP ou de secours pour `u` ; consomme le pas / le code de secours. Renvoie 'totp' | 'recovery' | null. */
async function checkSecondFactor(u: any, input: string, replica: boolean): Promise<'totp' | 'recovery' | null> {
  const c = input.trim()
  if (isRecoveryFormat(c)) {
    if (replica) return null                                   // un code de secours se consomme en base : primaire seulement
    const h = recoveryHash(c)
    const r = await one<any>('update users set recovery_hashes = array_remove(recovery_hashes, $2) where id = $1 and $2 = any(recovery_hashes) returning id', [u.id, h])
    return r ? 'recovery' : null
  }
  if (!u.totp_secret_enc) return null
  const last = replica ? replicaSteps.get(u.id) ?? null : u.totp_last_step === null ? null : Number(u.totp_last_step)
  const step = verifyTotp(decryptSecret(u.totp_secret_enc), c.replace(/\s/g, ''), last)
  if (step === null) return null
  if (replica) { replicaSteps.set(u.id, step); return 'totp' }
  // un même code ne sert qu'une fois : mise à jour conditionnelle (deux requêtes simultanées avec le même code : une seule passe)
  const ok = await one<any>('update users set totp_last_step = $2 where id = $1 and (totp_last_step is null or totp_last_step < $2) returning id', [u.id, step])
  return ok ? 'totp' : null
}

route('POST', '/auth/login/mfa', 'public', async (c) => {
  const b = await c.body(z.object({ challenge: z.string().min(10).max(500), code }))
  const ch = parseMfaChallenge(b.challenge)
  if (!ch) fail(401, 'mfa_expired')
  const u = await one<any>('select * from users where id = $1', [ch.uid])
  if (!u || u.disabled || u.source !== 'local' || !u.totp_enabled || credentialStamp(u) !== ch.stamp) fail(401, 'mfa_expired')
  const replica = await inRecovery()
  if (replica ? replicaLoginBlocked(u.username, c.ip) || await loginBlocked(u.username, c.ip) : await loginBlocked(u.username, c.ip)) fail(429, 'too_many_attempts')
  const how = await checkSecondFactor(u, b.code, replica)
  if (replica) replicaRecordAttempt(u.username, c.ip, how !== null); else await recordAttempt(u.username, c.ip, how !== null)
  if (!how) { await audit(c, 'login_failed', 'user', u.id, { username: u.username, mfa: true }); fail(401, 'bad_code') }
  if (how === 'recovery') await audit(c, 'mfa_recovery_used', 'user', u.id, { left: (u.recovery_hashes?.length ?? 1) - 1 })
  return await finishLogin(c, u.id, replica)
})

const localOnly = (c: any) => { if (c.user!.source !== 'local') fail(400, 'mfa_local_only') }

route('GET', '/auth/mfa', 'viewer', async (c) => {
  const u = await one<any>('select totp_enabled, cardinality(recovery_hashes) as left from users where id = $1', [c.user!.id])
  return { available: c.user!.source === 'local', enabled: !!u?.totp_enabled, recoveryLeft: u?.left ?? 0 }
})

// 1. Génère un secret « en attente » (mot de passe exigé : une session volée ne suffit pas à poser un facteur contrôlé par l'attaquant)
route('POST', '/auth/mfa/setup', 'viewer', async (c) => {
  localOnly(c)
  const b = await c.body(z.object({ password: z.string().min(1).max(512) }))
  const u = await one<any>('select id, username, password_hash, totp_enabled from users where id = $1', [c.user!.id])
  if (u.totp_enabled) fail(409, 'mfa_already')
  if (!(await verifyPassword(b.password, u.password_hash))) fail(401, 'bad_password')
  const secret = newTotpSecret()
  await query('update users set totp_secret_enc = $2 where id = $1', [u.id, encryptSecret(secret)])
  return { secret, uri: otpauthUri(secret, u.username) }
})

// 2. Active après avoir vérifié un premier code ; renvoie les codes de secours (une seule fois)
route('POST', '/auth/mfa/enable', 'viewer', async (c) => {
  localOnly(c)
  const b = await c.body(z.object({ code }))
  const u = await one<any>('select * from users where id = $1', [c.user!.id])
  if (u.totp_enabled) fail(409, 'mfa_already')
  if (!u.totp_secret_enc) fail(409, 'mfa_no_setup')
  const step = verifyTotp(decryptSecret(u.totp_secret_enc), b.code.replace(/\s/g, ''), null)
  if (step === null) fail(400, 'bad_code')
  const codes = newRecoveryCodes()
  await query('update users set totp_enabled = true, totp_last_step = $2, recovery_hashes = $3 where id = $1', [u.id, step, codes.map(recoveryHash)])
  await audit(c, 'mfa_enable', 'user', u.id)
  return { codes }
})

route('POST', '/auth/mfa/recovery', 'viewer', async (c) => {   // régénère les codes de secours (anciens invalidés)
  localOnly(c)
  const b = await c.body(z.object({ password: z.string().min(1).max(512) }))
  const u = await one<any>('select id, password_hash, totp_enabled from users where id = $1', [c.user!.id])
  if (!u.totp_enabled) fail(409, 'mfa_not_enabled')
  if (!(await verifyPassword(b.password, u.password_hash))) fail(401, 'bad_password')
  const codes = newRecoveryCodes()
  await query('update users set recovery_hashes = $2 where id = $1', [u.id, codes.map(recoveryHash)])
  await audit(c, 'mfa_recovery_regen', 'user', u.id)
  return { codes }
})

route('POST', '/auth/mfa/disable', 'viewer', async (c) => {
  localOnly(c)
  const b = await c.body(z.object({ password: z.string().min(1).max(512), code }))
  const u = await one<any>('select * from users where id = $1', [c.user!.id])
  if (!u.totp_enabled) fail(409, 'mfa_not_enabled')
  if (!(await verifyPassword(b.password, u.password_hash))) fail(401, 'bad_password')
  if (!(await checkSecondFactor(u, b.code, false))) fail(400, 'bad_code')
  await query("update users set totp_enabled = false, totp_secret_enc = null, totp_last_step = null, recovery_hashes = '{}' where id = $1", [u.id])
  await audit(c, 'mfa_disable', 'user', u.id)
  return { ok: true }
})

// Réinitialisation par un administrateur (téléphone perdu, plus de codes de secours) : le compte repasse au mot de passe seul, sessions fermées
route('POST', '/users/:id/mfa/reset', 'admin', async (c) => {
  const id = Number(c.params.id)
  const u = await one<any>('select id, username, totp_enabled from users where id = $1', [id])
  if (!u) fail(404, 'not_found')
  await query("update users set totp_enabled = false, totp_secret_enc = null, totp_last_step = null, recovery_hashes = '{}' where id = $1", [id])
  await destroyUserSessions(id)
  await audit(c, 'mfa_reset', 'user', id, { username: u.username, was_enabled: !!u.totp_enabled })
  return { ok: true }
})

// ---- MFA obligatoire par rôle (0.9.52) : réglage de l'administrateur, commun au cluster
async function policyView() {
  const p = await mfaPolicy()
  const rows = await query<any>("select role, count(*)::int as n from users where source = 'local' and not disabled and not totp_enabled group by role")
  const pending: Record<string, number> = { admin: 0, operator: 0, viewer: 0 }
  for (const r of rows) pending[r.role] = r.n
  return { roles: p.roles, available: MFA_ROLES, pending }       // pending : comptes locaux actifs sans second facteur, par rôle (ils s'inscriront à leur prochaine requête)
}
route('GET', '/mfa/policy', 'admin', async () => policyView())
route('PUT', '/mfa/policy', 'admin', async (c) => {
  const b = await c.body(z.object({ roles: z.array(z.enum(MFA_ROLES)).max(3) }))
  const p = parseMfaPolicy({ roles: b.roles })
  await saveMfaPolicy(p)
  await audit(c, 'mfa_policy', 'settings', 'mfa_policy', { roles: p.roles })
  return policyView()
})
