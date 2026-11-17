// Clé de récupération de la PKI (0.14.5) : la console fabrique la paire de clés, root n'enregistre que le certificat PUBLIC, la clé privée est rendue UNE fois à
// l'administrateur (jamais stockée) : voir utils/pki-recovery.ts. La restauration des secrets se fait en ligne de commande (« ddibuntu-backup pki-restore ») : la clé
// privée ne doit jamais passer par l'appliance en fonctionnement, ni par cette console.
import { audit, fail, route } from '../utils/router'
import { depositPkiRequest, pkiRequestPending, readPkiStatus } from '../utils/pki'
import { readBackupStatus } from '../utils/backup'
import { awaitRecovery, dropRecoveryDeposit, newRecoveryKey, putRecoveryDeposit, RECOVERY_BITS, recoveryBody } from '../utils/pki-recovery'
import { pkiProtection } from '../utils/pki-protection'

export const registered = true

route('GET', '/pki/recovery', 'admin', async () => {
  const [pki, backup] = await Promise.all([readPkiStatus(), readBackupStatus()])
  const p = pkiProtection(pki, backup)
  const slim = (b: typeof p.last) => b && { id: b.id, finishedAt: b.finishedAt, sizeBytes: b.sizeBytes, pki: b.pki }
  return {
    recovery: pki?.recovery ?? null, casCount: pki?.casCount ?? null, installed: !!pki?.installed, dataPresent: !!pki?.dataPresent,
    protection: { state: p.state, reason: p.reason, last: slim(p.last), lastWithBundle: slim(p.lastWithBundle) },
    backup: backup ? { enabled: backup.enabled, role: backup.role, count: backup.backups.length, withBundle: backup.backups.filter((x) => x.pki.bundle).length, stale: backup.stale } : null,
    bits: RECOVERY_BITS,
  }
})

// Création (ou remplacement) de la clé de récupération. La clé privée n'est rendue QUE si root a enregistré le certificat : jamais une clé qui ne protège rien.
route('POST', '/pki/recovery', 'admin', async (c) => {
  const b = await c.body(recoveryBody)
  const st = await readPkiStatus()
  if (st?.recovery && !b.replace) fail(409, 'pki_recovery_exists')
  if (await pkiRequestPending()) fail(409, 'request_pending')
  const k = await newRecoveryKey(b.passphrase)
  const startedAt = Math.floor(Date.now() / 1000)
  await putRecoveryDeposit(k.certPem)
  try { await depositPkiRequest({ action: 'recovery_set' }) } catch (e) { await dropRecoveryDeposit(); throw e }
  const r = await awaitRecovery(k.fingerprint, startedAt)
  // jamais la clé ni la phrase dans l'audit : seulement l'empreinte du certificat public
  await audit(c, 'pki.recovery_create', 'pki', undefined, { fingerprint: k.fingerprint, encrypted: k.encrypted, replaced: !!st?.recovery, ok: r.ok })
  if (!r.ok) {
    await dropRecoveryDeposit()
    if (r.code === 'timeout') fail(504, 'pki_recovery_timeout')
    fail(409, 'pki_recovery_refused', undefined, { message: r.message })
  }
  return { fingerprint: k.fingerprint, bits: RECOVERY_BITS, encrypted: k.encrypted, replaced: !!st?.recovery, keyPem: k.keyPem, createdAt: startedAt }
})
