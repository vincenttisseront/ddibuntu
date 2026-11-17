// Labels IPAM (équivalent des tags NetBox) : étiquettes libres posées sur les espaces, réseaux, adresses et VLAN.
// Chaque objet porte un tableau de noms (colonne « tags ») ; le catalogue « ipam_labels » ajoute couleur et description.
import { z } from 'zod'
import type { PoolClient } from 'pg'
import { getPool } from './db'

export const LABEL_RE = /^[\p{L}\p{N}][\p{L}\p{N} ._:/@+-]{0,39}$/u
export const normLabel = (s: string) => s.normalize('NFC').trim().replace(/\s+/g, ' ').toLowerCase()
/** Tableau de labels : normalisés (minuscules, espaces simples), sans doublon, 20 au maximum. */
export const labelsS = z.array(z.string().max(80)).max(20).transform((a) => [...new Set(a.map(normLabel).filter(Boolean))])
  .refine((a) => a.every((x) => LABEL_RE.test(x)), 'label')
export const colorS = z.string().trim().toLowerCase().regex(/^#[0-9a-f]{6}$/, 'color')

/** Objets qui portent des labels : clé d'API → table. */
export const LABELLED = { subnet: 'subnets', address: 'addresses', vlan: 'vlans', space: 'ipam_spaces' } as const
export type LabelKind = keyof typeof LABELLED

type Runner = Pick<PoolClient, 'query'>
/** Fait exister au catalogue les labels posés sur un objet (sans toucher à ceux qui y sont déjà). */
export async function ensureLabels(names: string[] | null | undefined, r: Runner = getPool()): Promise<void> {
  if (!names?.length) return
  await r.query('insert into ipam_labels (name) select unnest($1::text[]) on conflict do nothing', [names])
}
