import { describe, expect, it } from 'vitest'
import { enrolRequired, parseMfaPolicy, ENROL_PATHS } from '../server/utils/mfa-policy'

describe('MFA obligatoire par rôle : politique', () => {
  it('relit strictement : rôles inconnus, doublons et types invalides ignorés, ordre fixe', () => {
    expect(parseMfaPolicy(null)).toEqual({ roles: [] })
    expect(parseMfaPolicy('admin')).toEqual({ roles: [] })
    expect(parseMfaPolicy({ roles: 'admin' })).toEqual({ roles: [] })
    expect(parseMfaPolicy({ roles: ['viewer', 'root', 'admin', 'admin', 3, null] })).toEqual({ roles: ['admin', 'viewer'] })
  })
  it('seul un compte LOCAL, du bon rôle, sans second facteur doit s’inscrire', () => {
    const p = { roles: ['admin', 'operator'] as ('admin' | 'operator')[] }
    expect(enrolRequired({ source: 'local', role: 'admin', totpEnabled: false }, p)).toBe(true)
    expect(enrolRequired({ source: 'local', role: 'admin', totpEnabled: true }, p)).toBe(false)
    expect(enrolRequired({ source: 'local', role: 'viewer', totpEnabled: false }, p)).toBe(false)
    for (const s of ['ad', 'ldap', 'oidc', 'token']) expect(enrolRequired({ source: s, role: 'admin', totpEnabled: false }, p)).toBe(false)
    expect(enrolRequired({ source: 'local', role: 'admin', totpEnabled: false }, { roles: [] })).toBe(false)
  })
  it('les routes ouvertes pendant l’inscription sont exactement celles de l’activation', () => {
    expect([...ENROL_PATHS].sort()).toEqual(['/auth/logout', '/auth/me', '/auth/mfa', '/auth/mfa/enable', '/auth/mfa/setup', '/auth/profile', '/health'])
  })
})
