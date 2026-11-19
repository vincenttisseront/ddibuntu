// 0.14.12 — suivi en direct d'une demande traitée par root (pki-progress.json) : lecture bornée côté console, valeurs piégées écartées, tâche abandonnée repérée,
// et le fichier est relu tel que le produit réellement ddibuntu-pki (commande « progress » du helper, la même que celle des tests de tests/b31-pki-service.sh).
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-pki-prog-'))
const FILE = join(TMP, 'pki-progress.json')
process.env.DDI_PKI_PROGRESS = FILE; process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'
const ROOT = resolve(__dirname, '../..')
const HELPER = join(ROOT, 'src/rootfs/usr/local/lib/ddibuntu/pki-helper.py')
let pki: typeof import('../server/utils/pki')
beforeAll(async () => { pki = await import('../server/utils/pki') })
afterAll(() => rmSync(TMP, { recursive: true, force: true }))
const read = (rel: string) => readFileSync(resolve(__dirname, rel), 'utf8')
const helper = (...a: string[]) => spawnSync('python3', ['-I', HELPER, 'progress', FILE, ...a], { encoding: 'utf8' })

describe('parsePkiProgress', () => {
  const now = 1_800_000_000
  const base = { action: 'apply', state: 'running', startedAt: now - 30, at: now - 5, finishedAt: 0, steps: [{ id: 'podman', status: 'done', detail: '' }, { id: 'image', status: 'running', detail: '9.6.3 : tirage depuis docker.io' }, { id: 'start', status: 'todo', detail: '' }] }
  it('relit une tâche en cours', () => {
    const p = pki.parsePkiProgress(JSON.stringify(base), now)!
    expect(p.state).toBe('running'); expect(p.stale).toBe(false); expect(p.ageSeconds).toBe(5)
    expect(p.steps.map((s) => s.status)).toEqual(['done', 'running', 'todo']); expect(p.steps[1]!.detail).toContain('tirage')
  })
  it('une tâche sans nouvelle de root depuis 40 minutes est tenue pour abandonnée, pas une tâche terminée', () => {
    expect(pki.parsePkiProgress(JSON.stringify({ ...base, at: now - 41 * 60 }), now)!.stale).toBe(true)
    expect(pki.parsePkiProgress(JSON.stringify({ ...base, at: now - 39 * 60 }), now)!.stale).toBe(false)
    expect(pki.parsePkiProgress(JSON.stringify({ ...base, state: 'done', at: now - 3600 }), now)!.stale).toBe(false)
  })
  it.each([['pas du json'], ['null'], ['[]'], [JSON.stringify({ ...base, action: 'rm -rf /' })], [JSON.stringify({ ...base, at: 'hier' })]])('refuse %s', (raw) => {
    expect(pki.parsePkiProgress(raw, now)).toBeNull()
  })
  it('écarte les étapes et valeurs piégées, borne le nombre et la taille', () => {
    const p = pki.parsePkiProgress(JSON.stringify({ ...base, state: 'exploded', steps: [{ id: 'ok_1', status: 'weird', detail: 'a\u0000b\nc' + 'x'.repeat(500) }, { id: '../etc', status: 'done' }, null, ...Array.from({ length: 30 }, (_, i) => ({ id: 's' + String.fromCharCode(97 + (i % 26)), status: 'todo' }))] }), now)!
    expect(p.state).toBe('running'); expect(p.steps.length).toBeLessThanOrEqual(12)
    expect(p.steps[0]!.status).toBe('todo'); expect(p.steps[0]!.detail.length).toBeLessThanOrEqual(120); expect(p.steps[0]!.detail).not.toMatch(/[\u0000\n]/)
    expect(p.steps.some((s) => s.id.includes('/'))).toBe(false)
  })
})

describe('lecture du fichier publié par root', () => {
  it('absent ou trop gros : null', async () => {
    expect(await pki.readPkiProgress()).toBeNull()
    writeFileSync(FILE, JSON.stringify({ action: 'apply', at: 1, steps: [], pad: 'x'.repeat(20000) }))
    expect(await pki.readPkiProgress()).toBeNull()
  })
  it('relit ce que produit « ddibuntu-pki » (helper progress) : début, étapes, fin', async () => {
    expect(helper('begin', 'apply', 'podman', 'prepare', 'image', 'unit', 'start').status).toBe(0)
    let p = (await pki.readPkiProgress())!
    expect(p.action).toBe('apply'); expect(p.state).toBe('running'); expect(p.steps.map((s) => s.id)).toEqual(['podman', 'prepare', 'image', 'unit', 'start']); expect(p.steps[0]!.status).toBe('running')
    expect(helper('step', 'image', 'running', '9.6.3 : tirage depuis docker.io').status).toBe(0)
    p = (await pki.readPkiProgress())!
    expect(p.steps.map((s) => s.status)).toEqual(['done', 'todo', 'running', 'todo', 'todo'])   // l'étape qui commence clôt « podman »
    expect(helper('end', 'true').status).toBe(0)
    p = (await pki.readPkiProgress())!
    expect(p.state).toBe('done'); expect(p.finishedAt).toBeGreaterThan(0); expect(p.steps.filter((s) => s.status === 'running')).toHaveLength(0)
  })
  it('entrées invalides refusées par le helper', () => {
    expect(helper('begin', 'Apply', 'podman').status).not.toBe(0)
    expect(helper('step', 'podman', 'exploded').status).not.toBe(0)
    expect(helper('end', 'peut-être').status).not.toBe(0)
  })
})

describe('page et textes', () => {
  const page = read('../app/pages/pki.vue')
  it('la page affiche la carte en haut et suit les étapes tant que root travaille', () => {
    expect(page).toContain('<PkiProgress :progress="progress" :status="status" :result="result" />')
    expect(page).toMatch(/progressRunning\.value \|\| data\.value\?\.requestPending \? 2000/)   // sondage toutes les 2 s pendant l'opération
    expect(page).toMatch(/!data\.value\?\.requestPending && !progressRunning\.value\) return/)   // settle() attend la fin du traitement, pas seulement la prise en charge
    expect(page).toMatch(/const waiting = computed\(\(\) => [^\n]*progressRunning\.value/)   // boutons inactifs pendant l'opération
  })
  it.each([['fr', '../app/i18n/fr.ts'], ['en', '../app/i18n/en.ts']])('textes %s : titres et étapes de chaque action suivie', (_l, rel) => {
    const src = read(rel)
    const keys = ['pki.prog.reason', 'pki.prog.live', 'pki.prog.elapsed', 'pki.prog.init_hint', ...['podman', 'prepare', 'image', 'unit', 'start', 'init', 'work'].map((x) => `pki.prog.step.${x}`),
      ...['apply', 'start', 'stop', 'restart', 'uninstall', 'other'].flatMap((a) => ['run', 'ok', 'ko'].map((s) => `pki.prog.title.${s}.${a}`))]
    for (const k of keys) expect(src.split('\n').some((x) => x.startsWith(`  "${k}":`)), k).toBe(true)
  })
  it('les étapes publiées par ddibuntu-pki ont toutes un libellé', () => {
    const sh = read('../../src/rootfs/usr/local/sbin/ddibuntu-pki')
    const ids = new Set([...sh.matchAll(/\bpstep ([a-z_]+)/g)].map((m) => m[1]!)); for (const x of (sh.match(/prog begin apply ([a-z_ ]+)/)?.[1] ?? '').split(' ')) ids.add(x)
    ids.add('work')
    const fr = read('../app/i18n/fr.ts')
    for (const id of ids) expect(fr, id).toContain(`"pki.prog.step.${id}":`)
  })
})
