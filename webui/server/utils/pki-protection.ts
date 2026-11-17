// Protection des secrets de la PKI (0.14.5) : fonction PURE (aucun accès disque, base ou réseau), partagée par l'écran de la PKI et par les règles d'alerte.
import type { PkiStatus } from './pki'
import type { BackupItem, BackupStatus } from './backup'

// Les secrets de la PKI sont-ils dans la dernière sauvegarde, chiffrés pour la clé de récupération actuelle ?
/**
 * none      rien à protéger (PKI absente, sans secrets sur cette machine)
 * no_key    aucune clé de récupération enregistrée : les sauvegardes de la base ne suffisent pas à rouvrir la PKI
 * backup_off  sauvegardes désactivées : aucun lot n'est fabriqué
 * unknown   état des sauvegardes illisible ou périmé
 * pending   clé enregistrée après la dernière sauvegarde : la prochaine l'inclura (« Sauvegarder maintenant »)
 * no_bundle la dernière sauvegarde ne contient pas de lot (échec, ou ddibuntu-backup n'a pas pu le faire)
 * ok        la dernière sauvegarde contient un lot chiffré pour la clé de récupération actuelle
 */
export type ProtectionState = 'none' | 'no_key' | 'backup_off' | 'unknown' | 'pending' | 'no_bundle' | 'ok'
export interface Protection { state: ProtectionState; last: BackupItem | null; lastWithBundle: BackupItem | null; reason: string }
export function pkiProtection(pki: PkiStatus | null, backup: BackupStatus | null): Protection {
  const none = (state: ProtectionState, reason = ''): Protection => ({ state, last: null, lastWithBundle: null, reason })
  if (!pki || (!pki.secretsPresent && !pki.installed)) return none('none')
  if (!pki.recovery) return none('no_key')
  if (!backup || backup.stale) return none('unknown')
  const items = [...backup.backups].sort((a, b) => a.finishedAt - b.finishedAt)
  const last = items.at(-1) ?? null
  const lastWithBundle = [...items].reverse().find((b) => b.pki.bundle) ?? null
  if (!backup.enabled) return { state: 'backup_off', last, lastWithBundle, reason: '' }
  if (!last) return { state: 'pending', last, lastWithBundle, reason: '' }
  const covers = last.pki.bundle && last.pki.recoveryFp === pki.recovery.fingerprint
  if (covers) return { state: 'ok', last, lastWithBundle, reason: '' }
  // la clé (ou son remplacement) est plus récente que la dernière sauvegarde : la prochaine suffira
  if (pki.recovery.registeredAt >= last.finishedAt) return { state: 'pending', last, lastWithBundle, reason: '' }
  return { state: 'no_bundle', last, lastWithBundle, reason: last.pki.bundle ? 'other_key' : last.pki.reason }
}
