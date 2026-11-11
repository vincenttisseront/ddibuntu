// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : sauvegardes de la base et restauration à un instant donné (demandes déposées pour root).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const PORT = 3394, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s10-')); mkdirSync(join(TMP, 'gen'))
let srv: ChildProcess, db: pg.Client, srvLog = ''

class Client {
  cookie = ''; csrf = ''
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { cookie: this.cookie }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* HTML */ }
    return { status: r.status, json, text }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
const admin = new Client(), viewer = new Client(), operator = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }

const GEN = join(TMP, 'gen'), REQ = join(GEN, '.backup-request'), ST = join(TMP, 'bk-status.json'), RES = join(TMP, 'bk-result.json'), RS = join(TMP, 'bk-restore.json')
beforeAll(async () => {
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: GEN, DDI_RELOAD_STATUS: join(TMP, 'rs'),
    DDI_BACKUP_STATUS: ST, DDI_BACKUP_RESULT: RES, DDI_BACKUP_RESTORE: RS } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'oper', role: 'operator', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200); expect((await operator.login('oper', PW)).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })

const now = () => Math.floor(Date.now() / 1000)
const bk = (id: string, finishedAt: number, over: Record<string, unknown> = {}) => ({ id, node: 'n1', type: 'full', startedAt: finishedAt - 20, finishedAt, sizeBytes: 5_000_000, timeline: 1, walArchived: true, ...over })
const status = (over: Record<string, unknown> = {}) => ({
  at: now(), enabled: true, role: 'primary', node: 'n1', hostname: 'vm-ddi', cluster: 'lab', repo: '/var/lib/ddibuntu/backup', keepFull: 3, intervalHours: 24, startHour: 2, mirrorDir: null,
  archiveMode: 'on', archiver: { archived_count: 12, last_archived_wal: '000000010000000000000009', last_archived_at: now() - 30, failed_count: 0, last_failed_wal: null, last_failed_at: null },
  diskFreeBytes: 9e9, preRestoreDirs: 0, walFiles: 12, walBytes: 3e7, lastWalAt: now() - 30, pitrFrom: now() - 7200,
  backups: [bk('20261111T080000Z', now() - 7200), bk('20261111T100000Z', now() - 600)], ...over })
const publish = (o?: Record<string, unknown>) => writeFileSync(ST, JSON.stringify(status(o)))
const clear = () => rmSync(REQ, { force: true })
const sent = () => JSON.parse(readFileSync(REQ, 'utf8'))
const iso = (offsetS: number) => new Date(Date.now() + offsetS * 1000).toISOString().slice(0, 19) + 'Z'

describe('état', () => {
  it('rien de publié : état absent (pas d\'erreur)', async () => {
    rmSync(ST, { force: true })
    const r = await admin.get('/api/backup/status'); expect(r.status).toBe(200); expect(r.json.status).toBeNull()
  })
  it('droits : opérateur oui, lecteur et anonyme non', async () => {
    publish()
    code(await viewer.get('/api/backup/status'), 403, 'forbidden'); code(await anon.get('/api/backup/status'), 401, 'unauthenticated')
    expect((await operator.get('/api/backup/status')).status).toBe(200)
  })
  it('catalogue relayé, mot de confirmation = nom du cluster', async () => {
    publish(); const s = (await admin.get('/api/backup/status')).json.status
    expect(s).toMatchObject({ enabled: true, role: 'primary', node: 'n1', cluster: 'lab', confirmWord: 'lab', keepFull: 3, stale: false })
    expect(s.backups.map((b: any) => b.id)).toEqual(['20261111T080000Z', '20261111T100000Z']); expect(s.archiver).toMatchObject({ archivedCount: 12, failedCount: 0 })
    publish({ cluster: null }); expect((await admin.get('/api/backup/status')).json.status.confirmWord).toBe('vm-ddi')
  })
  it('champs inconnus ignorés, identifiants piégés écartés, valeurs bornées, état périmé signalé', async () => {
    publish({ secret: 'x', repo: 'r'.repeat(900), backups: [bk('../../etc/passwd', 1), bk('20261111T100000Z', now() - 5, { node: 'n'.repeat(300), extra: 1 }), 'x', null] , at: now() - 4000 })
    const s = (await admin.get('/api/backup/status')).json.status
    expect(JSON.stringify(s)).not.toMatch(/secret|extra|passwd/); expect(s.backups).toHaveLength(1); expect(s.backups[0].node.length).toBe(63); expect(s.repo.length).toBe(200); expect(s.stale).toBe(true)
  })
  it('fichier illisible ou hostile : état absent', async () => {
    writeFileSync(ST, 'pas du json'); expect((await admin.get('/api/backup/status')).json.status).toBeNull()
    writeFileSync(ST, JSON.stringify({ enabled: 'oui', backups: 3 })); expect((await admin.get('/api/backup/status')).json.status).toBeNull()
  })
  it('résultat de la dernière demande et phase de restauration', async () => {
    publish(); writeFileSync(RES, JSON.stringify({ at: now(), action: 'run', ok: true, message: 'terminé', id: '20261111T100000Z' }))
    writeFileSync(RS, JSON.stringify({ at: now(), phase: 'recovering', message: 'relecture' }))
    const r = (await admin.get('/api/backup/status')).json
    expect(r.result).toMatchObject({ action: 'run', ok: true, id: '20261111T100000Z' }); expect(r.restore).toMatchObject({ phase: 'recovering', active: true })
    writeFileSync(RES, JSON.stringify({ at: now(), action: 'x', ok: true, message: 'm', id: '../x' })); expect((await admin.get('/api/backup/status')).json.result.id).toBeNull()
    writeFileSync(RS, JSON.stringify({ at: now() - 9000, phase: 'recovering', message: '' })); expect((await admin.get('/api/backup/status')).json.restore.active).toBe(false)
  })
})

describe('actions', () => {
  it('droits et validation', async () => {
    clear(); publish()
    code(await viewer.post('/api/backup/action', { action: 'run' }), 403, 'forbidden'); code(await operator.post('/api/backup/action', { action: 'run' }), 403, 'forbidden'); code(await anon.post('/api/backup/action', { action: 'run' }), 401, 'unauthenticated')
    for (const bad of [{}, { action: 'format' }, { action: 'run', x: 1 }, { action: 'delete' }, { action: 'delete', id: '../x' }, { action: 'delete', id: '20261111T080000Z', extra: 1 }, { action: 'verify', id: "1'; drop" }, { action: 'restore' }])
      code(await admin.post('/api/backup/action', bad), 400, 'validation')
    expect(existsSync(REQ)).toBe(false)
  })
  it('refus contre l\'état publié', async () => {
    publish(); rmSync(ST); code(await admin.post('/api/backup/action', { action: 'run' }), 409, 'backup_unavailable')
    publish({ role: 'witness' }); code(await admin.post('/api/backup/action', { action: 'enable' }), 409, 'backup_witness')
    publish({ role: 'standby' }); code(await admin.post('/api/backup/action', { action: 'run' }), 409, 'backup_primary_only')
    publish({ enabled: false }); code(await admin.post('/api/backup/action', { action: 'run' }), 409, 'backup_disabled'); code(await admin.post('/api/backup/action', { action: 'disable' }), 409, 'backup_disabled')
    publish(); code(await admin.post('/api/backup/action', { action: 'delete', id: '20260101T000000Z' }), 409, 'backup_unknown'); code(await admin.post('/api/backup/action', { action: 'verify', id: '20260101T000000Z' }), 409, 'backup_unknown')
    publish({ backups: [bk('20261111T100000Z', now() - 600)] }); code(await admin.post('/api/backup/action', { action: 'delete', id: '20261111T100000Z' }), 409, 'backup_last')
    expect(existsSync(REQ)).toBe(false)
  })
  it('demande déposée telle quelle, une seule en attente, audit', async () => {
    clear(); publish()
    expect((await admin.post('/api/backup/action', { action: 'run' })).json).toEqual({ accepted: true }); expect(sent()).toEqual({ action: 'run' })
    code(await admin.post('/api/backup/action', { action: 'prune' }), 409, 'action_pending'); clear()
    expect((await admin.post('/api/backup/action', { action: 'delete', id: '20261111T080000Z' })).status).toBe(200); expect(sent()).toEqual({ action: 'delete', id: '20261111T080000Z' }); clear()
    expect((await admin.post('/api/backup/action', { action: 'verify', id: '20261111T100000Z' })).status).toBe(200); expect(sent()).toEqual({ action: 'verify', id: '20261111T100000Z' }); clear()
    publish({ enabled: false }); expect((await admin.post('/api/backup/action', { action: 'enable' })).status).toBe(200); expect(sent()).toEqual({ action: 'enable' }); clear()
    const a = await db.query("select action from audit_log where action like 'backup.%' order by id"); expect(a.rows.map((x: any) => x.action)).toEqual(expect.arrayContaining(['backup.run', 'backup.delete', 'backup.verify', 'backup.enable']))
  })
  it('actualisation : opérateur oui, lecteur non', async () => {
    clear(); publish()
    code(await viewer.post('/api/backup/refresh', {}), 403, 'forbidden')
    expect((await operator.post('/api/backup/refresh', {})).status).toBe(200); expect(sent()).toEqual({ action: 'refresh' }); clear()
  })
})

describe('réglages', () => {
  const ok = { keepFull: 5, intervalHours: 12, startHour: 3, mirrorDir: '/mnt/sauvegardes' }
  it('valeurs hors bornes et chemins hostiles refusés', async () => {
    clear(); publish()
    for (const bad of [{ ...ok, keepFull: 0 }, { ...ok, keepFull: 31 }, { ...ok, intervalHours: 0 }, { ...ok, intervalHours: 169 }, { ...ok, startHour: 24 }, { ...ok, startHour: -1 }, { ...ok, keepFull: 1.5 }, { ...ok, keepFull: '3' },
      { ...ok, mirrorDir: '../etc' }, { ...ok, mirrorDir: 'relatif' }, { ...ok, mirrorDir: '/a b' }, { ...ok, mirrorDir: '/a/../b' }, { ...ok, mirrorDir: '/x;rm' }, { ...ok, extra: 1 }, { keepFull: 3 }])
      code(await admin.post('/api/backup/configure', bad), 400, 'validation')
    code(await viewer.post('/api/backup/configure', ok), 403, 'forbidden'); expect(existsSync(REQ)).toBe(false)
  })
  it('réglages valides déposés ; copie externe vide acceptée ; arbitre refusé', async () => {
    clear(); publish()
    expect((await admin.post('/api/backup/configure', ok)).status).toBe(200); expect(sent()).toEqual({ action: 'configure', ...ok }); clear()
    expect((await admin.post('/api/backup/configure', { ...ok, mirrorDir: '' })).status).toBe(200); expect(sent().mirrorDir).toBe(''); clear()
    publish({ role: 'witness' }); code(await admin.post('/api/backup/configure', ok), 409, 'backup_witness'); expect(existsSync(REQ)).toBe(false)
  })
})

describe('restauration', () => {
  it('validation et droits', async () => {
    clear(); publish()
    code(await viewer.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' }), 403, 'forbidden'); code(await operator.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' }), 403, 'forbidden')
    for (const bad of [{}, { mode: 'latest' }, { mode: 'now', confirm: 'lab' }, { mode: 'at', confirm: 'lab' }, { mode: 'at', at: '2026-11-11 10:00:00', confirm: 'lab' }, { mode: 'at', at: '2026-11-11T10:00:00+01:00', confirm: 'lab' },
      { mode: 'at', at: "2026-11-11T10:00:00Z'; drop", confirm: 'lab' }, { mode: 'id', id: '../x', confirm: 'lab' }, { mode: 'id', confirm: 'lab' }, { mode: 'latest', confirm: 'lab', id: '20261111T100000Z' }, { mode: 'latest', confirm: 'x'.repeat(100) }])
      code(await admin.post('/api/backup/restore', bad), 400, 'validation')
    expect(existsSync(REQ)).toBe(false)
  })
  it('refus : confirmation, rôle, état, cible hors fenêtre, restauration en cours', async () => {
    clear(); publish(); rmSync(RS, { force: true })
    code(await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'autre' }), 409, 'confirm_mismatch')
    code(await admin.post('/api/backup/restore', { mode: 'id', id: '20250101T000000Z', confirm: 'lab' }), 409, 'backup_unknown')
    code(await admin.post('/api/backup/restore', { mode: 'at', at: iso(3600), confirm: 'lab' }), 409, 'time_in_future')
    code(await admin.post('/api/backup/restore', { mode: 'at', at: iso(-86400), confirm: 'lab' }), 409, 'time_before_first_backup')
    publish({ role: 'standby' }); code(await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' }), 409, 'restore_primary_only')
    publish({ role: 'witness' }); code(await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' }), 409, 'backup_witness')
    publish({ enabled: false }); code(await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' }), 409, 'backup_disabled')
    publish({ backups: [], pitrFrom: null }); code(await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' }), 409, 'no_backup')
    publish(); writeFileSync(RS, JSON.stringify({ at: now(), phase: 'extracting', message: '' })); code(await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' }), 409, 'restore_in_progress')
    rmSync(RS, { force: true }); rmSync(ST); code(await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' }), 409, 'backup_unavailable')
    expect(existsSync(REQ)).toBe(false)
  })
  it('demandes valides déposées telles quelles (heure UTC, sauvegarde choisie, plus récent)', async () => {
    clear(); publish(); rmSync(RS, { force: true })
    const at = iso(-1800)
    expect((await admin.post('/api/backup/restore', { mode: 'at', at, confirm: 'lab' })).json).toEqual({ accepted: true }); expect(sent()).toEqual({ mode: 'at', at, confirm: 'lab' }); clear()
    expect((await admin.post('/api/backup/restore', { mode: 'id', id: '20261111T100000Z', confirm: 'lab' })).status).toBe(200); expect(sent()).toEqual({ mode: 'id', id: '20261111T100000Z', confirm: 'lab' }); clear()
    expect((await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' })).status).toBe(200); expect(sent()).toEqual({ mode: 'latest', confirm: 'lab' }); clear()
    const a = await db.query("select entity_id from audit_log where action = 'backup.restore' order by id"); expect(a.rows.map((x: any) => x.entity_id)).toEqual([at, '20261111T100000Z', 'latest'])
  })
  it('hors cluster : le mot de confirmation est le nom de la machine', async () => {
    clear(); publish({ cluster: null }); rmSync(RS, { force: true })
    code(await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'lab' }), 409, 'confirm_mismatch')
    expect((await admin.post('/api/backup/restore', { mode: 'latest', confirm: 'vm-ddi' })).status).toBe(200); clear()
  })
})
