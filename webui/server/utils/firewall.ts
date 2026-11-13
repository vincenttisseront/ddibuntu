// Pare-feu de l'appliance : réseaux autorisés à administrer (SSH + console). La console ne touche jamais aux règles : elle dépose une demande
// que root (ddibuntu-fw) revalide, applique avec retour arrière automatique, puis publie le résultat et le délai de confirmation.
import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { cfg } from './config'
import { cidrContainsIp, normCidr, parseCidr, parseIp } from './net'

export const MAX_ADMIN_NETS = 32
export interface FwState { adminNets: string[]; adminTcp: string }
export interface FwResult { at: number; action: string; ok: boolean; message: string }
export interface FwPending { at: number; until: number }

/** Normalise une liste de réseaux : CIDR ou adresse seule (→ /32 ou /128) ; /0 refusé ; doublons retirés. Retourne null si l'un d'eux est invalide. */
export function normNets(list: string[]): string[] | null {
  const out: string[] = []
  for (const raw of list) {
    const v = raw.trim()
    if (!v) continue
    const n = normCidr(v.includes('/') ? v : `${v}${v.includes(':') ? '/128' : '/32'}`)
    const c = n ? parseCidr(n) : null
    if (!n || !c || c.prefix === 0) return null
    if (!out.includes(n)) out.push(n)
  }
  return out
}
export const splitNets = (v: string) => v.split(/[\s,;]+/).filter(Boolean)

/** Vrai si l'adresse (celle du poste qui administre) est couverte par l'un des réseaux. */
export function covers(nets: string[], ip: string | null | undefined): boolean {
  if (!ip) return false
  const a = parseIp(ip.replace(/^::ffff:/i, ''))
  if (!a) return false
  return nets.some((n) => { const c = parseCidr(n); return !!c && c.v === a.v && cidrContainsIp(c, a) })
}

export async function readFwState(): Promise<FwState> {
  let adminNets: string[] = [], adminTcp = '22,443'
  try {
    const raw = await fs.readFile(cfg().fwConfFile, 'utf8')
    for (const line of raw.split('\n')) {
      const m = /^(ADMIN_NETS|ADMIN_TCP)="([^"]*)"$/.exec(line.trim())
      if (!m) continue
      if (m[1] === 'ADMIN_NETS') adminNets = (normNets(splitNets(m[2]!)) ?? []).slice(0, MAX_ADMIN_NETS)
      else if (/^[0-9, ]{0,64}$/.test(m[2]!)) adminTcp = m[2]!.replace(/\s+/g, '')
    }
  } catch { /* fichier absent : aucun réseau défini */ }
  return { adminNets, adminTcp }
}
export async function readFwResult(): Promise<FwResult | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().fwResultFile, 'utf8'))
    if (typeof j?.at !== 'number') return null
    return { at: j.at, action: String(j.action ?? '').slice(0, 24), ok: j.ok === true, message: String(j.message ?? '').slice(0, 240) }
  } catch { return null }
}
/** Application en attente de confirmation (délai non écoulé), sinon null. */
export async function readFwPending(nowSec = Date.now() / 1000): Promise<FwPending | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().fwPendingFile, 'utf8'))
    if (typeof j?.until !== 'number' || j.until <= nowSec) return null
    return { at: Number(j.at) || 0, until: j.until }
  } catch { return null }
}
export type FwRequest = { action: 'set'; nets: string[] } | { action: 'confirm' } | { action: 'rollback' }
export async function fwRequestPending(): Promise<boolean> {
  try { await fs.lstat(join(cfg().generatedDir, '.fw-request')); return true } catch { return false }
}
export async function depositFwRequest(req: FwRequest): Promise<{ requestedAt: number }> {
  const requestedAt = Math.floor(Date.now() / 1000)
  await fs.writeFile(join(cfg().generatedDir, '.fw-request'), JSON.stringify(req) + '\n', { mode: 0o640 })
  return { requestedAt }
}
