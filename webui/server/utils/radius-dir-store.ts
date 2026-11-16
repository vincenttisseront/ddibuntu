// Réglages de l'annuaire RADIUS lus en base (partagés par les routes « Annuaire » et la vérification d'un certificat client, 0.13.2).
import { defaultLdapFactory } from './ad'
import type { AdSettings } from './ad'
import { decryptSecret } from './auth'
import { getSetting } from './db'
import { DIR_DEFAULTS, DIR_KEY } from './radius-dir'
import type { DirSettings, Factory } from './radius-dir'

export const loadDir = async (): Promise<DirSettings> => ({ ...DIR_DEFAULTS, ...(await getSetting<DirSettings>(DIR_KEY, DIR_DEFAULTS)) })
export const factoryFor = (s: DirSettings): Factory => defaultLdapFactory(s as unknown as AdSettings)
/** Réglages complets (serveur, base, compte et mot de passe de liaison) : sinon null. */
export const dirComplete = (s: DirSettings) => s.urls.length > 0 && !!s.baseDn && !!s.bindDn && !!s.bindPasswordEnc
export const dirPassword = (s: DirSettings) => decryptSecret(s.bindPasswordEnc!)
