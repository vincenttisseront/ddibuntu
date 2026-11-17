// Unitaires de la clé de récupération de la PKI (0.14.5) : lecture défensive de l'état publié, protection des secrets, corps de la demande, fabrication réelle de la clé (openssl).
import { describe, expect, it } from 'vitest'
import { createPrivateKey, X509Certificate, publicEncrypt, privateDecrypt, constants } from 'node:crypto'
import { parseBackupPki, parseBackupStatus, type BackupStatus } from '../server/utils/backup'
import { parseRecovery } from '../server/utils/pki'
import type { PkiStatus } from '../server/utils/pki'
import { pkiProtection } from '../server/utils/pki-protection'
import { newRecoveryKey, recoveryBody } from '../server/utils/pki-recovery'
import { openssl, withTmp } from '../server/utils/openssl'

const NOW = 1_800_000_000
const FP = 'c'.repeat(64), FP2 = 'd'.repeat(64)

describe('lecture défensive', () => {
  it('parseRecovery : empreinte hexadécimale de 64 caractères exigée, texte nettoyé et borné', () => {
    expect(parseRecovery(null)).toBeNull(); expect(parseRecovery({ fingerprint: 'zz' })).toBeNull(); expect(parseRecovery({ fingerprint: FP.toUpperCase() })).toBeNull()
    const r = parseRecovery({ fingerprint: FP, bits: 4096, notAfter: 5.9, subject: 'CN=ok\u0000\n' + 'x'.repeat(500), registeredAt: 'hier' })!
    expect(r).toMatchObject({ fingerprint: FP, bits: 4096, notAfter: 5, registeredAt: 0 }); expect(r.subject).toMatch(/^CN=ok/); expect(r.subject.length).toBeLessThanOrEqual(100); expect(/[^\x20-\x7e]/.test(r.subject)).toBe(false)
  })
  it('parseBackupPki : ancienne sauvegarde → unknown ; lot valide ; lot sans empreinte valide refusé ; motif inconnu → unknown', () => {
    expect(parseBackupPki(undefined)).toMatchObject({ bundle: false, reason: 'unknown', recoveryFp: '' })
    expect(parseBackupPki({ secrets: true, recoveryFp: FP, bytes: 12.7, cas: 2, tag: '9.1' })).toEqual({ bundle: true, recoveryFp: FP, reason: 'unknown', bytes: 12, cas: 2, tag: '9.1' })
    expect(parseBackupPki({ secrets: true, recoveryFp: 'pas-une-empreinte' })).toMatchObject({ bundle: false, recoveryFp: '' })
    expect(parseBackupPki({ secrets: false, reason: 'no-recovery-key' }).reason).toBe('no-recovery-key')
    expect(parseBackupPki({ secrets: false, reason: '<script>' }).reason).toBe('unknown')
    expect(parseBackupPki({ secrets: false, reason: 'none', tag: 'x'.repeat(99) }).tag).toHaveLength(24)
  })
})

const bkRaw = (over: Record<string, unknown> = {}, items: Array<Record<string, unknown>> = [{ id: '20261111T080000Z', finishedAt: NOW - 3600, pki: { secrets: true, recoveryFp: FP, cas: 1 } }]) => parseBackupStatus(JSON.stringify({
  at: NOW - 60, enabled: true, role: 'primary', node: 'n1', hostname: 'h', cluster: null, repo: '/r', keepFull: 3, intervalHours: 24, startHour: 2, mirrorDir: null, archiveMode: 'on', archiver: null,
  diskFreeBytes: 1, preRestoreDirs: 0, walFiles: 1, walBytes: 1, lastWalAt: NOW, pitrFrom: NOW - 7200,
  backups: items.map((b) => ({ node: 'n1', startedAt: (b.finishedAt as number) - 10, sizeBytes: 5, timeline: 1, walArchived: true, ...b })), ...over }), NOW) as BackupStatus
const pk = (over: Record<string, unknown> = {}): PkiStatus => ({ at: NOW, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab', version: '9', digest: '', nets: [], health: 'ok', port: 8443,
  dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab', casCount: 1, resetAllowed: false, recovery: { fingerprint: FP, bits: 4096, notAfter: NOW + 9e8, subject: 'CN=x', registeredAt: NOW - 90000 }, ...over } as PkiStatus)

describe('pkiProtection', () => {
  it('ok : la dernière sauvegarde est chiffrée pour la clé actuelle', () => { const p = pkiProtection(pk(), bkRaw()); expect(p.state).toBe('ok'); expect(p.last?.id).toBe('20261111T080000Z'); expect(p.lastWithBundle?.id).toBe('20261111T080000Z') })
  it('none : PKI absente, ou ni installée ni secrets', () => {
    expect(pkiProtection(null, bkRaw()).state).toBe('none'); expect(pkiProtection(pk({ installed: false, secretsPresent: false, dataPresent: false }), bkRaw()).state).toBe('none')
  })
  it('no_key : aucune clé enregistrée (même sans sauvegarde lisible)', () => { expect(pkiProtection(pk({ recovery: null }), bkRaw()).state).toBe('no_key'); expect(pkiProtection(pk({ recovery: null }), null).state).toBe('no_key') })
  it('unknown : état des sauvegardes absent ou périmé', () => { expect(pkiProtection(pk(), null).state).toBe('unknown'); expect(pkiProtection(pk(), bkRaw({ at: NOW - 9999 })).state).toBe('unknown') })
  it('backup_off : sauvegardes désactivées', () => { expect(pkiProtection(pk(), bkRaw({ enabled: false })).state).toBe('backup_off') })
  it('pending : aucune sauvegarde encore, ou clé enregistrée après la dernière', () => {
    expect(pkiProtection(pk(), bkRaw({}, [])).state).toBe('pending')
    const newer = pk({ recovery: { fingerprint: FP2, bits: 4096, notAfter: NOW + 9e8, subject: 'CN=y', registeredAt: NOW - 10 } })
    expect(pkiProtection(newer, bkRaw()).state).toBe('pending')
  })
  it('no_bundle : sans lot (motif repris), chiffré pour une autre clé (other_key), sauvegarde plus récente sans lot mais une plus ancienne en a un', () => {
    expect(pkiProtection(pk(), bkRaw({}, [{ id: '20261111T080000Z', finishedAt: NOW - 3600, pki: { secrets: false, reason: 'error' } }]))).toMatchObject({ state: 'no_bundle', reason: 'error', lastWithBundle: null })
    expect(pkiProtection(pk(), bkRaw({}, [{ id: '20261111T080000Z', finishedAt: NOW - 3600, pki: { secrets: true, recoveryFp: FP2 } }]))).toMatchObject({ state: 'no_bundle', reason: 'other_key' })
    const p = pkiProtection(pk(), bkRaw({}, [{ id: '20261110T080000Z', finishedAt: NOW - 90000, pki: { secrets: true, recoveryFp: FP } }, { id: '20261111T080000Z', finishedAt: NOW - 3600, pki: { secrets: false, reason: 'none' } }]))
    expect(p).toMatchObject({ state: 'no_bundle', reason: 'none' }); expect(p.lastWithBundle?.id).toBe('20261110T080000Z'); expect(p.last?.id).toBe('20261111T080000Z')
  })
  it('une sauvegarde d\'avant 0.14.5 (sans champ pki) n\'est jamais comptée comme protégée', () => {
    expect(pkiProtection(pk(), bkRaw({}, [{ id: '20261111T080000Z', finishedAt: NOW - 3600 }])).state).toBe('no_bundle')
  })
})

describe('corps de la demande', () => {
  it('phrase secrète facultative de 10 à 128 caractères sans caractère de contrôle ; champs inconnus refusés', () => {
    expect(recoveryBody.safeParse({}).success).toBe(true); expect(recoveryBody.safeParse({ replace: true, passphrase: 'a'.repeat(10) }).success).toBe(true)
    expect(recoveryBody.safeParse({ passphrase: 'court' }).success).toBe(false); expect(recoveryBody.safeParse({ passphrase: 'a'.repeat(129) }).success).toBe(false)
    expect(recoveryBody.safeParse({ passphrase: 'abcdefghij\n' }).success).toBe(false); expect(recoveryBody.safeParse({ passphrase: 'abcdefghij\u0000k' }).success).toBe(false)
    expect(recoveryBody.safeParse({ replace: 'oui' }).success).toBe(false); expect(recoveryBody.safeParse({ autre: 1 }).success).toBe(false)
  })
})

describe('newRecoveryKey (openssl réel)', () => {
  it('RSA 4096, certificat 100 ans sans usage d\'autorité, clé chiffrée par la phrase, empreinte = SHA-256 du certificat', async () => {
    const pass = 'phrase secrète très longue 123'
    const k = await newRecoveryKey(pass, new Date('2026-11-17T10:00:00Z'))
    expect(k.encrypted).toBe(true); expect(k.keyPem).toContain('BEGIN ENCRYPTED PRIVATE KEY'); expect(k.keyPem).not.toContain('BEGIN PRIVATE KEY'); expect(k.certPem).toContain('BEGIN CERTIFICATE')
    const c = new X509Certificate(k.certPem)
    expect(k.fingerprint).toBe(c.fingerprint256.replace(/:/g, '').toLowerCase()); expect(k.fingerprint).toMatch(/^[0-9a-f]{64}$/)
    expect((c.publicKey.asymmetricKeyDetails as any).modulusLength).toBe(4096); expect(c.subject).toContain('DDI-Buntu PKI recovery'); expect(c.ca).toBe(false)
    expect((new Date(c.validTo).getTime() - new Date(c.validFrom).getTime()) / 86400000).toBeGreaterThan(36000)
    // la clé privée, rouverte avec la phrase, correspond au certificat ; une mauvaise phrase échoue
    const priv = createPrivateKey({ key: k.keyPem, passphrase: pass })
    const msg = Buffer.from('secret'); const enc = publicEncrypt({ key: c.publicKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, msg)
    expect(privateDecrypt({ key: priv, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, enc).toString()).toBe('secret')
    expect(() => createPrivateKey({ key: k.keyPem, passphrase: 'mauvaise phrase' })).toThrow()
    // le certificat est exactement ce que root accepte : CMS chiffré par openssl avec le certificat seul
    const r = await withTmp(async (_d, put) => { const cf = await put('c.pem', k.certPem); const x = await put('in', 'bonjour'); return openssl(['cms', '-encrypt', '-aes256', '-binary', '-outform', 'DER', '-recip', cf, '-keyopt', 'rsa_padding_mode:oaep', '-keyopt', 'rsa_oaep_md:sha256', '-in', x]) }, { ram: true })
    expect(r.code).toBe(0)
  }, 120_000)
  it('sans phrase : clé PKCS#8 en clair', async () => {
    const k = await newRecoveryKey()
    expect(k.encrypted).toBe(false); expect(k.keyPem).toContain('BEGIN PRIVATE KEY'); expect(() => createPrivateKey(k.keyPem)).not.toThrow()
  }, 120_000)
})
