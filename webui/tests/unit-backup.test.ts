// Unitaires des sauvegardes (sans base) : lecture défensive de l'état publié par root, refus d'actions et de restaurations.
import { describe, expect, it } from 'vitest'
import { backupActionRefusal, parseBackupStatus, restoreRefusal, type BackupStatus } from '../server/utils/backup'

const NOW = 1_800_000_000
const bk = (id: string, finishedAt: number) => ({ id, node: 'n1', type: 'full', startedAt: finishedAt - 10, finishedAt, sizeBytes: 1000, timeline: 1, walArchived: true })
const raw = (o: Record<string, unknown> = {}) => JSON.stringify({ at: NOW - 60, enabled: true, role: 'primary', node: 'n1', hostname: 'vm', cluster: 'lab', repo: '/r', keepFull: 3, intervalHours: 24, startHour: 2,
  mirrorDir: null, archiveMode: 'on', archiver: null, diskFreeBytes: 1, preRestoreDirs: 0, walFiles: 1, walBytes: 1, lastWalAt: NOW - 10, pitrFrom: NOW - 7200,
  backups: [bk('20260101T000000Z', NOW - 7200), bk('20260102T000000Z', NOW - 600)], ...o })
const st = (o: Record<string, unknown> = {}): BackupStatus => parseBackupStatus(raw(o), NOW)!

describe('parseBackupStatus', () => {
  it('lit l\'état, mot de confirmation = cluster, sinon nom de machine', () => {
    expect(st()).toMatchObject({ enabled: true, role: 'primary', cluster: 'lab', confirmWord: 'lab', stale: false, ageSeconds: 60 })
    expect(st({ cluster: null }).confirmWord).toBe('vm'); expect(st({ cluster: '' }).confirmWord).toBe('vm')
  })
  it('rejette tout ce qui n\'est pas un état valide', () => {
    for (const bad of ['', 'x', '[]', 'null', '{}', JSON.stringify({ enabled: 1, backups: [] }), JSON.stringify({ enabled: true, backups: 3 })]) expect(parseBackupStatus(bad, NOW)).toBeNull()
  })
  it('identifiants piégés écartés, rôle inconnu → unknown, listes et textes bornés', () => {
    const many = Array.from({ length: 200 }, (_, i) => bk(`2026${String(i % 12 + 1).padStart(2, '0')}01T000000Z`, NOW - i))
    const s = st({ role: 'dieu', repo: 'x'.repeat(999), backups: [bk('../x', 1), bk('20260101T000000Z; id', 1), ...many] })
    expect(s.role).toBe('unknown'); expect(s.repo).toHaveLength(200); expect(s.backups.length).toBeLessThanOrEqual(64); expect(s.backups.length).toBeGreaterThan(0); expect(s.backups.every((b) => /^\d{8}T\d{6}Z$/.test(b.id))).toBe(true)
  })
  it('état périmé au-delà d\'une heure', () => { expect(st({ at: NOW - 3601 }).stale).toBe(true); expect(st({ at: NOW - 3599 }).stale).toBe(false) })
  it('valeurs non numériques neutralisées', () => {
    const s = st({ keepFull: 'beaucoup', sizeBytes: 'x', walBytes: NaN, pitrFrom: 'hier', lastWalAt: null })
    expect(s.keepFull).toBe(3); expect(s.walBytes).toBe(0); expect(s.pitrFrom).toBeNull(); expect(s.lastWalAt).toBeNull()
  })
})

describe('backupActionRefusal', () => {
  it('sans état : indisponible ; arbitre : refusé même pour activer', () => {
    expect(backupActionRefusal(null, { action: 'run' })).toBe('backup_unavailable'); expect(backupActionRefusal(st({ role: 'witness' }), { action: 'enable' })).toBe('backup_witness')
  })
  it('activer toujours possible, désactiver seulement si activé', () => {
    expect(backupActionRefusal(st({ enabled: false }), { action: 'enable' })).toBeNull(); expect(backupActionRefusal(st({ enabled: false }), { action: 'disable' })).toBe('backup_disabled'); expect(backupActionRefusal(st(), { action: 'disable' })).toBeNull()
  })
  it('sauvegarde : primaire seulement ; secondaire peut vérifier/purger', () => {
    expect(backupActionRefusal(st({ role: 'standby' }), { action: 'run' })).toBe('backup_primary_only'); expect(backupActionRefusal(st({ role: 'standby' }), { action: 'prune' })).toBeNull(); expect(backupActionRefusal(st(), { action: 'run' })).toBeNull()
    expect(backupActionRefusal(st({ enabled: false }), { action: 'run' })).toBe('backup_disabled')
  })
  it('suppression/vérification : identifiant connu, jamais la dernière sauvegarde', () => {
    expect(backupActionRefusal(st(), { action: 'delete', id: '20250101T000000Z' })).toBe('backup_unknown'); expect(backupActionRefusal(st(), { action: 'verify', id: '20250101T000000Z' })).toBe('backup_unknown')
    expect(backupActionRefusal(st(), { action: 'delete', id: '20260101T000000Z' })).toBeNull(); expect(backupActionRefusal(st({ backups: [bk('20260101T000000Z', 1)] }), { action: 'delete', id: '20260101T000000Z' })).toBe('backup_last')
  })
})

describe('restoreRefusal', () => {
  const ok = { mode: 'latest' as const, confirm: 'lab' }
  const iso = (t: number) => new Date(t * 1000).toISOString().slice(0, 19) + 'Z'
  it('cas acceptés', () => {
    expect(restoreRefusal(st(), ok, null, NOW)).toBeNull(); expect(restoreRefusal(st(), { mode: 'id', id: '20260102T000000Z', confirm: 'lab' }, null, NOW)).toBeNull()
    expect(restoreRefusal(st(), { mode: 'at', at: iso(NOW - 1800), confirm: 'lab' }, null, NOW)).toBeNull()
  })
  it('ordre des refus : état, arbitre, désactivé, en cours, secondaire, aucune sauvegarde, confirmation', () => {
    expect(restoreRefusal(null, ok, null, NOW)).toBe('backup_unavailable'); expect(restoreRefusal(st({ role: 'witness' }), ok, null, NOW)).toBe('backup_witness')
    expect(restoreRefusal(st({ enabled: false }), ok, null, NOW)).toBe('backup_disabled')
    expect(restoreRefusal(st(), ok, { at: NOW, phase: 'recovering', message: '', active: true }, NOW)).toBe('restore_in_progress')
    expect(restoreRefusal(st({ role: 'standby' }), ok, null, NOW)).toBe('restore_primary_only'); expect(restoreRefusal(st({ backups: [] }), ok, null, NOW)).toBe('no_backup')
    expect(restoreRefusal(st(), { ...ok, confirm: 'LAB' }, null, NOW)).toBe('confirm_mismatch'); expect(restoreRefusal(st(), { ...ok, confirm: '' }, null, NOW)).toBe('confirm_mismatch')
  })
  it('restauration terminée (inactive) ne bloque pas', () => { expect(restoreRefusal(st(), ok, { at: NOW, phase: 'done', message: '', active: false }, NOW)).toBeNull() })
  it('heure visée : futur, avant la première sauvegarde, identifiant inconnu', () => {
    expect(restoreRefusal(st(), { mode: 'at', at: iso(NOW + 5), confirm: 'lab' }, null, NOW)).toBe('time_in_future')
    expect(restoreRefusal(st(), { mode: 'at', at: iso(NOW - 8000), confirm: 'lab' }, null, NOW)).toBe('time_before_first_backup')
    expect(restoreRefusal(st({ pitrFrom: null }), { mode: 'at', at: iso(NOW - 8000), confirm: 'lab' }, null, NOW)).toBeNull()
    expect(restoreRefusal(st(), { mode: 'at', at: 'n\'importe quoi', confirm: 'lab' }, null, NOW)).toBe('time_invalid')
    expect(restoreRefusal(st(), { mode: 'id', id: '20200101T000000Z', confirm: 'lab' }, null, NOW)).toBe('backup_unknown')
  })
})
