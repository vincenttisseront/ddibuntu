// Unitaires des mises à jour en ligne (sans base) : lecture assainie de l'état écrit par root, dépôt de la demande.
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileUpdateRequest, isBusy, readUpdateStatus } from '../server/utils/selfupdate'

let dir = ''
beforeAll(() => { dir = mkdtempSync(join(tmpdir(), 'ddi-su-')); process.env.DDI_UPDATE_STATUS = join(dir, 'status.json'); process.env.DDI_GENERATED_DIR = dir })
afterAll(() => { rmSync(dir, { recursive: true, force: true }); delete process.env.DDI_UPDATE_STATUS; delete process.env.DDI_GENERATED_DIR })
const put = (o: unknown) => writeFileSync(join(dir, 'status.json'), typeof o === 'string' ? o : JSON.stringify(o))

describe('mises à jour en ligne : lecture de l\'état', () => {
  it('fichier absent ou illisible : null (aucune exception)', async () => {
    rmSync(join(dir, 'status.json'), { force: true }); expect(await readUpdateStatus()).toBeNull()
    put('pas du json'); expect(await readUpdateStatus()).toBeNull()
  })
  it('état valide : champs repris', async () => {
    put({ current: '0.4.0', latest: '0.5.0', available: true, notes: 'a\nb', url: 'https://github.com/o/r/releases/tag/v0.5.0', checked_at: 1700000000, state: 'idle', updated_at: 1700000001 })
    expect(await readUpdateStatus()).toMatchObject({ current: '0.4.0', latest: '0.5.0', available: true, url: 'https://github.com/o/r/releases/tag/v0.5.0', checkedAt: 1700000000, state: 'idle' })
  })
  it('valeurs hostiles neutralisées : version invalide, URL non https, état inconnu, types incorrects', async () => {
    put({ current: '1.0; rm -rf /', latest: '<script>', available: true, url: 'javascript:alert(1)', state: 'hack', checked_at: 'x', notes: 42, error: 'e'.repeat(5000) })
    const s = (await readUpdateStatus())!
    expect(s.current).toBe(''); expect(s.latest).toBe(''); expect(s.available).toBe(false); expect(s.url).toBe('')
    expect(s.state).toBe('idle'); expect(s.checkedAt).toBe(0); expect(s.notes).toBe(''); expect(s.error.length).toBe(300)
  })
  it('« available » exige une version valide', async () => {
    put({ latest: 'abc', available: true }); expect((await readUpdateStatus())!.available).toBe(false)
  })
})

describe('mises à jour en ligne : occupation', () => {
  const base = { current: '', latest: '', available: false, notes: '', url: '', publishedAt: '', checkedAt: 0, message: '', error: '', target: '' }
  it('actif et récent = occupé ; terminé, en échec, ou périmé = libre', () => {
    const now = 2_000_000
    expect(isBusy({ ...base, state: 'installing', updatedAt: now - 10 }, now)).toBe(true)
    expect(isBusy({ ...base, state: 'downloading', updatedAt: now - 3000 }, now)).toBe(true)
    expect(isBusy({ ...base, state: 'installing', updatedAt: now - 7200 }, now)).toBe(false)
    for (const s of ['idle', 'done', 'failed']) expect(isBusy({ ...base, state: s, updatedAt: now }, now)).toBe(false)
    expect(isBusy(null, now)).toBe(false)
  })
})

describe('mises à jour en ligne : demande déposée pour root', () => {
  it('apply : JSON {action, version} écrit de façon atomique, sans fichier temporaire résiduel', async () => {
    await fileUpdateRequest('apply', '0.5.0')
    expect(JSON.parse(readFileSync(join(dir, '.update-request'), 'utf8'))).toEqual({ action: 'apply', version: '0.5.0' })
    expect(readdirSync(dir).filter((f) => f.endsWith('.tmp'))).toEqual([])
  })
  it('check : pas de version ; apply avec version invalide refusé avant toute écriture', async () => {
    rmSync(join(dir, '.update-request'), { force: true })
    await fileUpdateRequest('check'); expect(JSON.parse(readFileSync(join(dir, '.update-request'), 'utf8'))).toEqual({ action: 'check' })
    rmSync(join(dir, '.update-request'), { force: true })
    await expect(fileUpdateRequest('apply', '0.5.0; reboot')).rejects.toThrow('invalid_version')
    await expect(fileUpdateRequest('apply')).rejects.toThrow('invalid_version')
    expect(existsSync(join(dir, '.update-request'))).toBe(false)
  })
})
