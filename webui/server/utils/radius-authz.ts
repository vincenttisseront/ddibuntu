// Règles d'accès RADIUS — dépôt pour root (0.13.3). La console ne produit AUCUNE configuration FreeRADIUS : elle dépose des données (règles compilées,
// réglages de l'annuaire, autorité de confiance LDAPS) que root revalide champ par champ avant de générer lui-même le module LDAP et la décision.
import { createHash, createHmac } from 'node:crypto'
import { requireSecret } from './config'
import type { DirSettings } from './radius-dir'
import type { AuthzDeposit } from './radius'
import { rulesJson } from './radius-rules'
import type { CompiledRule } from './radius-rules'
import { authJson, passwordMethods } from './radius-auth'
import type { AuthSettings } from './radius-auth'

// Mêmes contrôles que root (validate_authz) : un réglage refusé ici est signalé AVANT le dépôt, avec un message clair.
const LDAP_URL_RE = /^ldaps:\/\/[A-Za-z0-9._-]{1,253}(:[0-9]{1,5})?$/
const BASE_DN_RE = /^[^\x00-\x1f\x7f"$%{}`\\]{3,500}$/
const CTRL_RE = /[\x00-\x1f\x7f]/
const EXPANSION_RE = /\$(\{|ENV|\()/   // FreeRADIUS interprète « ${…} », « $ENV{…} » et « $(…) » dans une chaîne de configuration

export type AuthzProblem = 'eap_required' | 'directory_incomplete' | 'directory_settings' | 'directory_chars' | 'ldap_module_missing' | 'auth_needs_rules' | 'auth_needs_netbios'

/** Ce qui empêche de déployer les règles. Liste vide = prêt. `ldapModule` : null = état inconnu (root refusera de toute façon si le module manque). */
export function authzProblems(a: { rules: CompiledRule[]; pkiEmpty: boolean; pkiReady: boolean; dir: DirSettings; password: string | null; ldapModule: boolean | null; auth?: AuthSettings }): AuthzProblem[] {
  // identifiant + mot de passe : mêmes règles d'accès qu'EAP-TLS (sans règle, personne n'entre) ; PEAP a besoin du nom NetBIOS du domaine (« DOMAINE\compte »)
  const pw = !!a.auth && passwordMethods(a.auth)
  if (!a.rules.length) return pw ? ['auth_needs_rules'] : []
  const p: AuthzProblem[] = []
  if (a.auth?.peap && !a.auth.netbios) p.push('auth_needs_netbios')
  if (a.pkiEmpty || !a.pkiReady) p.push('eap_required')
  if (!a.dir.urls.length || !a.dir.baseDn || !a.dir.bindDn || !a.password) p.push('directory_incomplete')
  else {
    if (!a.dir.urls.every((u) => LDAP_URL_RE.test(u)) || !BASE_DN_RE.test(a.dir.baseDn) || !a.dir.baseDn.includes('=')) p.push('directory_settings')
    const secrets = [a.dir.bindDn, a.password]
    if (secrets.some((s) => CTRL_RE.test(s) || EXPANSION_RE.test(s)) || a.password.length > 200 || a.dir.bindDn.length > 500) p.push('directory_chars')
  }
  if (a.ldapModule === false) p.push('ldap_module_missing')
  return p
}

/** Dépôt pour root. Suppose authzProblems(...) vide. */
export function buildAuthzDeposit(rules: CompiledRule[], dir: DirSettings, password: string, auth?: AuthSettings): AuthzDeposit {
  const aj = auth ? authJson(auth) : undefined
  return {
    rules: rulesJson(rules),
    ldap: JSON.stringify({ urls: dir.urls, baseDn: dir.baseDn, bindDn: dir.bindDn, bindPassword: password, tlsRejectUnauthorized: dir.tlsRejectUnauthorized }) + '\n',
    ...(dir.caPem?.trim() ? { caPem: dir.caPem.trim() + '\n' } : {}),
    ...(aj ? { auth: aj } : {}),
  }
}

/** Empreinte de ce qui sera déployé (règles compilées + réglages de l'annuaire, mot de passe sous forme d'empreinte à clé) : sert à dire « des modifications
 *  ne sont pas encore déployées ». `'none'` = aucune règle active. Ne contient jamais le mot de passe. */
export function authzDigest(rules: CompiledRule[], dir: DirSettings, password: string | null, auth?: AuthSettings): string {
  if (!rules.length) return 'none'
  const pw = password ? createHmac('sha256', requireSecret()).update(password).digest('hex') : ''
  const parts: unknown[] = [dir.urls, dir.baseDn, dir.bindDn, dir.tlsRejectUnauthorized, dir.caPem ?? '', pw]
  const aj = auth ? authJson(auth) : undefined
  if (aj) parts.push(aj)   // seulement quand une méthode par mot de passe est réglée : l'empreinte d'un déploiement de la 0.15 reste la même après la mise à jour
  return createHash('sha256').update(rulesJson(rules)).update(JSON.stringify(parts)).digest('hex')
}
