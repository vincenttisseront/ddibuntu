// 0.22.0 — licence affichée dans « À propos » : lecture du fichier livré, plafond de taille, absence tolérée, cohérence avec le dépôt
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

const dir = mkdtempSync(join(tmpdir(), 'ddi-lic-'))
afterEach(() => { delete process.env.DDI_LICENSE_FILE; delete process.env.DDI_OPENSOURCE_FILE })
const load = async () => { const { readLicence } = await import('../server/utils/licence'); return readLicence() }

describe('licence', () => {
  it('renvoie le texte et la liste des composants quand les fichiers existent', async () => {
    writeFileSync(join(dir, 'LICENSE'), 'GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3\n'); writeFileSync(join(dir, 'OS.md'), '# Composants libres\n')
    process.env.DDI_LICENSE_FILE = join(dir, 'LICENSE'); process.env.DDI_OPENSOURCE_FILE = join(dir, 'OS.md')
    const r = await load()
    expect(r.text).toContain('AFFERO'); expect(r.thirdParty).toContain('Composants'); expect(r.info.spdx).toBe('AGPL-3.0-or-later')
    expect(r.info.source).toBe('https://github.com/vincenttisseront/ddibuntu'); expect(r.info.copyright).toContain('Vincent Tisseront')
  })
  it('un fichier absent ou démesuré donne null (jamais d\'erreur, jamais de contenu énorme)', async () => {
    process.env.DDI_LICENSE_FILE = join(dir, 'absent'); writeFileSync(join(dir, 'gros.md'), 'x'.repeat(200 * 1024)); process.env.DDI_OPENSOURCE_FILE = join(dir, 'gros.md')
    const r = await load(); expect(r.text).toBeNull(); expect(r.thirdParty).toBeNull()
  })
  it('le LICENSE du dépôt est bien l\'AGPL-3.0 complète', () => {
    const t = readFileSync(join(__dirname, '..', '..', 'LICENSE'), 'utf8')
    expect(t.startsWith('GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007')).toBe(true)
    expect(t).toContain('END OF TERMS AND CONDITIONS'); expect(t).toContain('13. Remote Network Interaction'); expect(t.length).toBeGreaterThan(30000)
  })
})
