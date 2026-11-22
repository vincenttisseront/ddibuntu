// Licence du logiciel, affichée dans « À propos » (AGPL-3.0, art. 13 : les utilisateurs d'une version modifiée atteignant le service par le réseau doivent pouvoir obtenir ses sources)
import { readFileSync, statSync } from 'node:fs'
import { cfg } from './config'

export const LICENCE_INFO = {
  spdx: 'AGPL-3.0-or-later',
  name: 'GNU Affero General Public License v3.0 ou ultérieure',
  copyright: 'Copyright (C) 2026 Vincent Tisseront',
  source: 'https://github.com/vincenttisseront/ddibuntu',
  url: 'https://www.gnu.org/licenses/agpl-3.0.html',
} as const

const MAX_BYTES = 128 * 1024   // le texte de l'AGPL fait ~34 Ko ; un fichier démesuré n'est jamais renvoyé

function readText(path: string): string | null {
  try { if (statSync(path).size > MAX_BYTES) return null; return readFileSync(path, 'utf8') } catch { return null }
}

/** Texte de la licence et liste des composants libres tels que livrés sur l'appliance ; null si le fichier manque ou est trop gros. */
export function readLicence(): { info: typeof LICENCE_INFO; text: string | null; thirdParty: string | null } {
  return { info: LICENCE_INFO, text: readText(cfg().licenseFile), thirdParty: readText(cfg().openSourceFile) }
}
