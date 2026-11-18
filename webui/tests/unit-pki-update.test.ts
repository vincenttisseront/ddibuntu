// 0.14.7 — mises à jour d'EJBCA Community : lecture bornée de l'état publié par root (pki-update.json), validation des demandes de la console (la même règle que root :
// test différentiel avec pki-helper.py), refus pendant une mise à jour, règles d'alerte.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-pki-upd-'))
const FILE = join(TMP, 'pki-update.json')
process.env.DDI_PKI_UPDATE = FILE; process.env.DDI_PKI_STATUS = join(TMP, 'status.json'); process.env.DDI_PKI_RESULT = join(TMP, 'result.json'); process.env.DDI_GENERATED_DIR = TMP
process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'
const ROOT = resolve(__dirname, '../..')
const HELPER = join(ROOT, 'src/rootfs/usr/local/lib/ddibuntu/pki-helper.py')
let upd: typeof import('../server/utils/pki-update'), pki: typeof import('../server/utils/pki')
let rules: typeof import('../server/utils/alert-rules'), text: typeof import('../server/utils/alert-text')
beforeAll(async () => { upd = await import('../server/utils/pki-update'); pki = await import('../server/utils/pki'); rules = await import('../server/utils/alert-rules'); text = await import('../server/utils/alert-text') })
afterEach(() => rmSync(FILE, { force: true }))

const NOW = 1_800_000_000
const D = (c: string) => 'sha256:' + c.repeat(64)
const item = (over: Record<string, unknown> = {}) => ({ tag: '9.6.3', pushedAt: '2026-09-01', kind: 'minor', allowed: true, reason: '', digest: D('b'),
  notes: { release: 'https://docs.keyfactor.com/ejbca/latest/ejbca-9-6-release-notes', upgrade: 'https://docs.keyfactor.com/ejbca/latest/ejbca-9-6-upgrade-notes' }, ...over })
const job = (over: Record<string, unknown> = {}) => ({ state: 'pending', step: 'checks', from: '9.3.7', to: '9.6.3', message: 'ok', reason: '', startedAt: NOW - 600, finishedAt: NOW - 60, updatedAt: NOW - 60,
  certsAtBackup: 5, casAtBackup: 2, backupBytes: 3_145_728, steps: [{ id: 'pull', status: 'done' }, { id: 'checks', status: 'done' }], checks: [{ id: 'health', ok: true, detail: '' }], rollbackAvailable: true, ...over })
const doc = (over: Record<string, unknown> = {}) => ({ at: NOW, current: '9.3.7', dbTag: '9.3.7', checkedAt: NOW - 3600, checkError: '', latest: '9.6.3', available: [item()], job: null, certsSince: null, ...over })

describe('lecture de pki-update.json', () => {
  it('lit un état complet', () => {
    const r = upd.parsePkiUpdate(doc({ job: job() }))!
    expect(r.current).toBe('9.3.7'); expect(r.latest).toBe('9.6.3'); expect(r.available).toHaveLength(1)
    expect(r.available[0]!.notes.release).toContain('9-6-release-notes'); expect(r.job?.state).toBe('pending'); expect(r.job?.rollbackAvailable).toBe(true); expect(r.job?.steps).toHaveLength(2)
  })
  it.each([null, 'texte', 12, [], {}, { at: 'x' }])('refuse un document illisible : %j', (v) => { expect(upd.parsePkiUpdate(v)).toBeNull() })
  it('ne reprend jamais une adresse de notes qui n\'est pas celle de Keyfactor', () => {
    for (const u of ['https://evil.example/ejbca-9-6-release-notes', 'http://docs.keyfactor.com/ejbca/latest/ejbca-9-6-release-notes', 'https://docs.keyfactor.com.evil.test/ejbca/latest/ejbca-9-6-release-notes',
      'https://docs.keyfactor.com/ejbca/latest/ejbca-9-6-release-notes#x', 'javascript:alert(1)', 'https://docs.keyfactor.com/ejbca/latest/ejbca-9-6-release-notes\nx']) {
      const r = upd.parsePkiUpdate(doc({ available: [item({ notes: { release: u, upgrade: u } })] }))!
      expect(r.available[0]!.notes, u).toEqual({})
    }
  })
  it('écarte les versions illisibles, les empreintes invalides et borne la liste à 20', () => {
    const many = Array.from({ length: 30 }, (_v, i) => item({ tag: `9.6.${i}` }))
    const r = upd.parsePkiUpdate(doc({ available: [item({ tag: 'latest' }), item({ tag: '9.6.3; rm -rf /' }), item({ digest: 'pas-une-empreinte' }), 'x', null, ...many] }))!
    expect(r.available.every((a) => /^[0-9]+\.[0-9]+\.[0-9]+$/.test(a.tag))).toBe(true)
    expect(r.available.length).toBeLessThanOrEqual(20); expect(r.available.find((a) => a.digest === 'pas-une-empreinte')).toBeUndefined()
    expect(upd.parsePkiUpdate(doc({ available: [item({ digest: 'pas-une-empreinte' })] }))!.available[0]!.digest).toBe('')
  })
  it('état de tâche inconnu : tâche ignorée ; étapes et contrôles filtrés et nettoyés', () => {
    expect(upd.parsePkiUpdate(doc({ job: job({ state: 'exploded' }) }))!.job).toBeNull()
    const r = upd.parsePkiUpdate(doc({ job: job({ steps: [{ id: 'pull', status: 'done' }, { id: '../x', status: 'done' }, { id: 'stop', status: 'bizarre' }, 7],
      checks: [{ id: 'signing', ok: false, detail: 'jeton\u0001 hors ligne' }, { id: 'X;y', ok: true }], message: 'a\u0007b' }) }))!
    expect(r.job!.steps).toEqual([{ id: 'pull', status: 'done' }, { id: 'stop', status: 'todo' }])
    expect(r.job!.checks).toEqual([{ id: 'signing', ok: false, detail: 'jeton  hors ligne' }]); expect(r.job!.message).toBe('a b')
  })
  it('nombres : entiers seulement, le décompte de certificats ne peut pas être négatif', () => {
    expect(upd.parsePkiUpdate(doc({ certsSince: -3 }))!.certsSince).toBeNull(); expect(upd.parsePkiUpdate(doc({ certsSince: 2.5 }))!.certsSince).toBeNull()
    expect(upd.parsePkiUpdate(doc({ certsSince: 4 }))!.certsSince).toBe(4); expect(upd.parsePkiUpdate(doc({ job: job({ backupBytes: -9 }) }))!.job!.backupBytes).toBe(0)
  })
  it('code d\'erreur de recherche : lettres et soulignés seulement', () => {
    expect(upd.parsePkiUpdate(doc({ checkError: 'unreachable' }))!.checkError).toBe('unreachable'); expect(upd.parsePkiUpdate(doc({ checkError: '<script>' }))!.checkError).toBe('')
  })
  it('lecture du fichier : absent ou corrompu → null ; « en cours » détecté', async () => {
    expect(await upd.readPkiUpdate()).toBeNull(); expect(await upd.pkiUpdateRunning()).toBe(false)
    writeFileSync(FILE, '{pas du json'); expect(await upd.readPkiUpdate()).toBeNull()
    writeFileSync(FILE, JSON.stringify(doc({ job: job({ state: 'running' }) }))); expect(await upd.pkiUpdateRunning()).toBe(true)
    writeFileSync(FILE, JSON.stringify(doc({ job: job({ state: 'pending' }) }))); expect(await upd.pkiUpdateRunning()).toBe(false)
  })
})

describe('demandes de la console', () => {
  const root = (image: string) => spawnSync('python3', ['-I', HELPER, 'parse-request'], { input: JSON.stringify({ action: 'update_apply', image }), encoding: 'utf8' }).stdout.trim()
  it('version : ce que la console envoie, root l\'accepte ; ce qu\'elle refuse, root le refuse aussi (test différentiel)', () => {
    for (const v of ['9.6.3', '9.3.7', '10.0.0', '99.99.999', '9.6.10', '0.0.0', '9.6', '9', 'latest', '9.6.3-rc1', 'v9.6.3', '9.6.3; id', '', '999.1.1', '9.6.3 ', ' 9.6.3', '9.6.3\n', '9.6.0003', '١٢.٣.٤']) {
      const p = upd.updateApplyBody.safeParse({ version: v })
      if (p.success) expect(root(pki.imageOf(p.data.version)), `root doit accepter ce que la console envoie pour ${JSON.stringify(v)}`).toContain(`image\t${pki.imageOf(p.data.version)}`)
      else expect(root(pki.imageOf(v)), `root doit refuser ${JSON.stringify(v)}, comme la console`).toBe('')
    }
  })
  it('refuse les champs inconnus et les types faux', () => {
    expect(upd.updateApplyBody.safeParse({ version: '9.6.3', image: 'x' }).success).toBe(false); expect(upd.updateApplyBody.safeParse({ version: 963 }).success).toBe(false)
    expect(upd.updateApplyBody.safeParse({}).success).toBe(false); expect(upd.confirmBody.safeParse({ confirm: true }).success).toBe(true)
    for (const b of [{}, { confirm: false }, { confirm: 'true' }, { confirm: true, x: 1 }, null]) expect(upd.confirmBody.safeParse(b).success).toBe(false)
  })
})

describe('règles d\'alerte (0.14.7)', () => {
  const pk: any = { at: NOW - 5, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab', version: '9.3.7', digest: '', nets: [], health: 'ok', port: 8080,
    dataPresent: true, secretsPresent: true, dataHostname: 'pki.lab', casCount: 0, resetAllowed: true, recovery: null }
  const snap = (u: any, p: any = pk): any => ({ now: NOW, cluster: null, localHealth: null, backup: null, backupResult: null, pki: p, pkiUpdate: u ? upd.parsePkiUpdate(u) : null, subnets: [] })
  const fx = (u: any, p: any = pk) => rules.evaluate(snap(u, p), rules.DEFAULT_THRESHOLDS, { leader: null, leaderChangedAt: null }).findings.filter((f) => f.rule.startsWith('pki.update'))
  it('version permise disponible : information, avec la version dans la clé (une version plus récente rouvre l\'alerte)', () => {
    const f = fx(doc()); expect(f.map((x) => [x.rule, x.severity, x.subject])).toEqual([['pki.update_available', 'info', '9.6.3']])
    expect(fx(doc({ latest: '9.6.4' }))[0]!.key).not.toBe(f[0]!.key)
  })
  it('rien à proposer, PKI non installée ou état non évalué : aucune alerte', () => {
    expect(fx(doc({ latest: null, available: [] }))).toEqual([]); expect(fx(doc(), { ...pk, installed: false })).toEqual([]); expect(fx(doc(), null)).toEqual([]); expect(fx(null)).toEqual([])
  })
  it('pendant une mise à jour ou tant qu\'une attend sa validation : pas d\'annonce d\'une autre', () => {
    expect(fx(doc({ job: job({ state: 'running' }) }))).toEqual([]); expect(fx(doc({ job: job({ state: 'pending' }) }))).toEqual([])
  })
  it('mise à jour sans validation depuis plus d\'un jour : avertissement', () => {
    const f = fx(doc({ job: job({ state: 'pending', finishedAt: NOW - 90000 }) })); expect(f.map((x) => [x.rule, x.severity])).toEqual([['pki.update_pending', 'warning']]); expect(f[0]!.params.hours).toBe(25)
  })
  it('échec ou retour arrière d\'office : avertissement pendant sept jours ; retour arrière voulu : rien', () => {
    expect(fx(doc({ latest: null, job: job({ state: 'failed' }) })).map((x) => x.rule)).toEqual(['pki.update_failed'])
    expect(fx(doc({ latest: null, job: job({ state: 'rolled_back', reason: 'health', rollbackAvailable: false }) })).map((x) => x.rule)).toEqual(['pki.update_failed'])
    expect(fx(doc({ latest: null, job: job({ state: 'rolled_back', reason: 'manual', rollbackAvailable: false }) }))).toEqual([])
    expect(fx(doc({ latest: null, job: job({ state: 'failed', finishedAt: NOW - 8 * 86400 }) }))).toEqual([])
    expect(fx(doc({ latest: null, job: job({ state: 'validated', rollbackAvailable: false }) }))).toEqual([])
  })
  it('le catalogue connaît les règles et les textes (fr et en) citent la version', () => {
    for (const id of ['pki.update_available', 'pki.update_pending', 'pki.update_failed']) expect(Object.keys(rules.RULES)).toContain(id)
    const p = { version: '9.6.3', current: '9.3.7', to: '9.6.3', hours: 30, state: 'rolled_back' }
    for (const id of ['pki.update_available', 'pki.update_pending', 'pki.update_failed']) for (const l of ['fr', 'en'] as const) {
      const t = text.describe(id, 'n1', '9.6.3', p, l); expect(t, `${id} ${l}`).not.toBe(id); expect(t).toContain('9.6.3'); expect(t).not.toMatch(/undefined|\[object/)
    }
  })
})
