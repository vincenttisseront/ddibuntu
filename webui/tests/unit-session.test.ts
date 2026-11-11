// Régression 0.9.3 : le bouton « Test » de la source NetBox déconnectait l'utilisateur. NetBox refusait le jeton, la console renvoyait
// ce refus en 401, et l'interface prenait tout 401 pour une session expirée. Seul « unauthenticated » doit renvoyer à la connexion.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { isSessionExpired } from '../app/utils/session'

describe('session expirée ou simple refus ?', () => {
  it('absence de session : retour à la connexion', () => { expect(isSessionExpired(401, 'unauthenticated')).toBe(true) })
  it('refus d\'un service tiers : aucune déconnexion', () => {
    for (const code of ['netbox_auth', 'bad_credentials', 'internal', '', 'network']) expect(isSessionExpired(401, code)).toBe(false)
  })
  it('les autres statuts ne déconnectent jamais', () => {
    for (const st of [0, 200, 400, 403, 404, 409, 500, 502]) expect(isSessionExpired(st, 'unauthenticated')).toBe(false)
  })
  it('l\'appel d\'API passe par cette règle (pas de test brut sur le statut 401)', () => {
    const src = readFileSync(new URL('../app/composables/useApi.ts', import.meta.url), 'utf8')
    expect(src).toContain('isSessionExpired(info.status, info.code)')
    expect(src).not.toMatch(/status\s*===\s*401/)
  })
  it('les refus des services tiers ne sortent jamais en 401 côté serveur', () => {
    const src = readFileSync(new URL('../server/utils/netbox.ts', import.meta.url), 'utf8')
    expect(src).not.toMatch(/NetboxError\([^)]*,\s*401\)/)
  })
  it('les assistants affichent leur message d\'erreur (le cadre commun rend le contenu par défaut)', () => {
    const shell = readFileSync(new URL('../app/components/WizardShell.vue', import.meta.url), 'utf8')
    expect(shell).toMatch(/<slot\s*\/>/)   // sans lui, l'alerte d'erreur de NetboxWizard / AdWizard n'était jamais affichée
  })
})
