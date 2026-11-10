// Kerberos / GSS-TSIG : la console ne détient ni le domaine « officiel » ni le keytab. Root (ddibuntu-ad) les garde, valide chaque demande déposée ici
// et publie un état sans secret (/run/ddibuntu/ad-status.json) ainsi que le résultat de la dernière demande (ad-result.json).
import { promises as fs } from 'node:fs'
import { dirname, join } from 'node:path'
import { cfg } from './config'

const str = (v: unknown, max = 128) => (typeof v === 'string' ? v.slice(0, max) : '')
export const REALM_RE = /^[A-Z0-9]([A-Z0-9.-]{0,60}[A-Z0-9])?$/
export const KDC_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,200}[A-Za-z0-9])?(:[0-9]{1,5})?$/

export interface AdKeytab { present: boolean; principals: string[]; enctypes: string[]; kvno: Record<string, number>; mtime: number | null; size: number }
export interface AdKrbState { at: number; ageSeconds: number; configured: boolean; realm: string; kdcs: string[]; keytab: AdKeytab }
export interface AdKrbResult { at: number; action: string; ok: boolean; message: string }

export function parseAdState(raw: string, nowSec = Date.now() / 1000): AdKrbState | null {
  let j: any
  try { j = JSON.parse(raw) } catch { return null }
  if (!j || typeof j !== 'object' || Array.isArray(j)) return null
  const kt = j.keytab && typeof j.keytab === 'object' ? j.keytab : {}
  const kvno: Record<string, number> = {}
  if (kt.kvno && typeof kt.kvno === 'object') for (const [k, v] of Object.entries(kt.kvno).slice(0, 32)) if (Number.isFinite(v)) kvno[str(k, 255)] = Number(v)
  const realm = typeof j.realm === 'string' && REALM_RE.test(j.realm) ? j.realm : ''
  const at = Number(j.at) || 0
  return {
    at, ageSeconds: Math.max(0, Math.round(nowSec - at)),
    configured: !!realm && j.configured === true, realm,
    kdcs: Array.isArray(j.kdcs) ? j.kdcs.filter((k: unknown) => typeof k === 'string' && KDC_RE.test(k)).slice(0, 8) : [],
    keytab: {
      present: kt.present === true,
      principals: Array.isArray(kt.principals) ? kt.principals.slice(0, 32).map((p: unknown) => str(p, 255)) : [],
      enctypes: Array.isArray(kt.enctypes) ? kt.enctypes.slice(0, 8).map((p: unknown) => str(p, 48)) : [],
      kvno, mtime: Number.isFinite(kt.mtime) ? Number(kt.mtime) : null, size: Number(kt.size) || 0,
    },
  }
}
export async function readAdState(): Promise<AdKrbState | null> {
  try {
    const st = await fs.stat(cfg().adStatusFile)
    if (!st.isFile() || st.size > 64 * 1024) return null
    return parseAdState(await fs.readFile(cfg().adStatusFile, 'utf8'))
  } catch { return null }
}
export async function readAdResult(): Promise<AdKrbResult | null> {
  try {
    const j = JSON.parse(await fs.readFile(join(dirname(cfg().adStatusFile), 'ad-result.json'), 'utf8'))
    if (typeof j?.at !== 'number') return null
    return { at: j.at, action: str(j.action, 32), ok: j.ok === true, message: str(j.message, 240) }
  } catch { return null }
}

export interface AdSync { at: number; state: 'synced' | 'published' | 'applied' | 'failed'; message: string; hash: string }
/** État de la synchronisation du keytab avec le cluster (publié par root ; absent hors cluster). */
export async function readAdSync(): Promise<AdSync | null> {
  try {
    const j = JSON.parse(await fs.readFile(join(dirname(cfg().adStatusFile), 'ad-sync.json'), 'utf8'))
    if (typeof j?.at !== 'number' || !['synced', 'published', 'applied', 'failed'].includes(j?.state)) return null
    return { at: j.at, state: j.state, message: str(j.message, 200), hash: /^[0-9a-f]{0,12}$/.test(j.hash ?? '') ? j.hash : '' }
  } catch { return null }
}

export type AdRequest =
  | { action: 'configure'; realm: string; kdcs: string[] }
  | { action: 'install-keytab' } | { action: 'remove' } | { action: 'test' }

/** Dépose la demande pour root. Le keytab (secret) transite par un fichier 0600 que root supprime après lecture, même en cas de refus. */
export async function depositAdRequest(req: AdRequest, keytab?: Buffer): Promise<{ requestedAt: number }> {
  const dir = cfg().generatedDir
  if (req.action === 'install-keytab') {
    if (!keytab || !keytab.length || keytab.length > 65536) throw new Error('keytab_size')
    await fs.writeFile(join(dir, '.ad-keytab'), keytab, { mode: 0o600 })
  }
  const requestedAt = Math.floor(Date.now() / 1000)
  await fs.writeFile(join(dir, '.ad-request'), JSON.stringify(req) + '\n', { mode: 0o640 })
  return { requestedAt }
}
