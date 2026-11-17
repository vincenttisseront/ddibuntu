// Service PKI (0.14.0) : EJBCA Community dans un conteneur Podman, piloté par root (ddibuntu-pki). La console ne démarre rien et ne touche à aucune
// configuration système : elle dépose .pki-request (une demande JSON courte : image, nom public, réseaux) que root revalide champ par champ, puis
// elle lit l'état et le résultat que root publie. Aucun secret ne transite par ici : root crée lui-même les secrets de l'instance.
import { promises as fs } from 'node:fs'
import os from 'node:os'
import { join } from 'node:path'
import { z } from 'zod'
import { cfg } from './config'
import { getSetting, setSetting } from './db'
import { cidrToString, parseCidr, parseIp } from './net'
import type { Cidr } from './net'

export const IMAGE_REPO = 'docker.io/keyfactor/ejbca-ce'
/** Version d'EJBCA Community installée par défaut (dernière version publiée vérifiée avec le DDI). La mise à jour d'une instance existante a son propre parcours (0.14.5). */
export const DEFAULT_VERSION = '9.6.3'
/** Port public d'EJBCA (CRL, SCEP, OCSP) : gravé dans les certificats avec le nom public, il ne change donc jamais. */
export const PUBLIC_PORT = 8080
export const MAX_NETS = 64
export const VERSION_RE = /^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}$/
/** Nom public : au moins deux étiquettes, minuscules, chiffres et tirets, 253 caractères au plus, dernière étiquette non numérique (jamais une adresse IP). Mêmes bornes que root. */
export const HOST_RE = /^(?=.{3,253}$)(?!.*\.[0-9]+$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

export const imageOf = (version: string) => `${IMAGE_REPO}:${version}`

/** Réseau ou adresse d'un client de la PKI → réseau normalisé, ou null. Pas de /0 (même règle que le pare-feu). */
export function normPkiNet(raw: string): string | null {
  const v = raw.trim()
  if (!v || v.length > 64) return null
  let c: Cidr | null
  if (v.includes('/')) c = parseCidr(v)
  else { const ip = parseIp(v); c = ip ? { v: ip.v, n: ip.n, prefix: ip.v === 4 ? 32 : 128 } : null }
  if (!c || c.prefix === 0) return null
  return cidrToString(c)
}

export const applyBody = z.object({
  hostname: z.string().trim().toLowerCase().regex(HOST_RE),
  version: z.string().trim().regex(VERSION_RE).default(DEFAULT_VERSION),
  nets: z.array(z.string().trim().max(64)).max(MAX_NETS).default([]),
}).strict().transform((b, ctx) => {
  const nets: string[] = []
  for (const [i, raw] of b.nets.entries()) {
    const n = normPkiNet(raw)
    if (!n) { ctx.addIssue({ code: 'custom', path: ['nets', i], message: 'net' }); return z.NEVER }
    if (!nets.includes(n)) nets.push(n)
  }
  return { hostname: b.hostname, version: b.version, nets }
})
export type ApplyBody = z.infer<typeof applyBody>

// ---- Réglages (choix de l'administrateur, conservés même avant l'installation) ----
export interface PkiSettings { hostname: string; version: string; nets: string[] }
export const PKI_KEY = 'pki_settings'
export const PKI_DEFAULTS: PkiSettings = { hostname: '', version: DEFAULT_VERSION, nets: [] }
export const loadPkiSettings = async (): Promise<PkiSettings> => ({ ...PKI_DEFAULTS, ...(await getSetting<PkiSettings>(PKI_KEY, PKI_DEFAULTS)) })
export const savePkiSettings = (s: PkiSettings) => setSetting(PKI_KEY, s)

/** Nom public proposé : « pki. » + domaine du nœud (domaine de recherche du système, sinon celui du nom d'hôte). Vide si introuvable. */
export async function suggestHostname(): Promise<string> {
  const norm = (d: string) => d.trim().toLowerCase().replace(/\.$/, '')
  const ok = (d: string) => HOST_RE.test(`pki.${d}`)
  try {
    const m = /^(?:search|domain)\s+(\S+)/m.exec(await fs.readFile('/etc/resolv.conf', 'utf8'))
    if (m && ok(norm(m[1]!))) return `pki.${norm(m[1]!)}`
  } catch { /* fichier illisible : on essaie le nom d'hôte */ }
  const h = norm(os.hostname()), dot = h.indexOf('.')
  if (dot > 0 && ok(h.slice(dot + 1))) return `pki.${h.slice(dot + 1)}`
  return ''
}

/** Adresses IPv4 de ce nœud (hors bouclage et lien local) : proposées pour l'enregistrement DNS du nom public. */
export function nodeAddresses(): string[] {
  const out: string[] = []
  for (const list of Object.values(os.networkInterfaces())) for (const a of list ?? []) {
    if (a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.') && !out.includes(a.address)) out.push(a.address)
  }
  return out
}

// ---- Dépôt de la demande et lecture de l'état publié par root ----
export type PkiState = 'absent' | 'starting' | 'healthy' | 'unhealthy' | 'stopped'
export const STATES: readonly PkiState[] = ['absent', 'starting', 'healthy', 'unhealthy', 'stopped']
export interface PkiStatus {
  at: number; podman: boolean; installed: boolean; active: boolean; state: PkiState; hostname: string; version: string; digest: string; nets: string[]; health: string; port: number
  /** La base « ejbca » contient des données (même si le conteneur est désinstallé), nom public de ces données, nombre d'autorités avec clé, et remise à zéro permise. */
  dataPresent: boolean; secretsPresent: boolean; dataHostname: string; casCount: number | null; resetAllowed: boolean
}
/** `ref` : identifiant de la demande d'émission à laquelle ce résultat répond (root le recopie ; vide pour les autres actions). */
export interface PkiResult { at: number; action: string; ok: boolean; message: string; ref?: string }

export async function readPkiStatus(): Promise<PkiStatus | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().pkiStatusFile, 'utf8'))
    if (typeof j?.at !== 'number') return null
    const state = STATES.includes(j.state) ? (j.state as PkiState) : 'absent'
    return { at: j.at, podman: j.podman === true, installed: j.installed === true, active: j.active === true, state,
      hostname: String(j.hostname ?? '').slice(0, 253), version: String(j.version ?? '').slice(0, 24), digest: String(j.digest ?? '').slice(0, 80),
      nets: (Array.isArray(j.nets) ? j.nets : []).slice(0, MAX_NETS).map((x: unknown) => String(x).slice(0, 64)), health: String(j.health ?? '').slice(0, 64),
      port: Number(j.port) || PUBLIC_PORT, dataPresent: j.dataPresent === true, secretsPresent: j.secretsPresent === true, dataHostname: String(j.dataHostname ?? '').slice(0, 253),
      casCount: Number.isInteger(j.casCount) && j.casCount >= 0 ? j.casCount : null, resetAllowed: j.resetAllowed === true }
  } catch { return null }
}
export async function readPkiResult(): Promise<PkiResult | null> {
  try {
    const j = JSON.parse(await fs.readFile(cfg().pkiResultFile, 'utf8'))
    if (typeof j?.at !== 'number') return null
    return { at: j.at, action: String(j.action ?? '').slice(0, 24), ok: j.ok === true, message: String(j.message ?? '').slice(0, 300), ...(typeof j.ref === 'string' && /^[0-9a-f]{16}$/.test(j.ref) ? { ref: j.ref } : {}) }
  } catch { return null }
}
export async function pkiRequestPending(): Promise<boolean> {
  try { await fs.lstat(join(cfg().generatedDir, '.pki-request')); return true } catch { return false }
}
export interface CaDn { cn: string; ou?: string; o?: string; c?: string }
export type PkiRequest =
  | { action: 'apply'; image: string; hostname: string; nets: string[] }
  | { action: 'start' | 'stop' | 'restart' | 'status' | 'uninstall' | 'reset' }
  | ({ action: 'ca_root'; name: string; alg: string; days: number } & CaDn)
  | ({ action: 'ca_issuing'; name: string; alg: string; days: number; signedBy: string } & CaDn)
  | { action: 'ca_import' | 'ca_crl' | 'ca_rootcrl'; name: string }
  | ({ action: 'cert_issue'; id: string; ca: string; profile: string; dns?: string[]; ip?: string[]; mail?: string[]; upn?: string[] } & CaDn)
  | { action: 'cert_revoke'; ca: string; serial: string; reason: number }
export async function depositPkiRequest(req: PkiRequest): Promise<{ requestedAt: number }> {
  await fs.writeFile(join(cfg().generatedDir, '.pki-request'), JSON.stringify(req) + '\n', { mode: 0o640 })
  return { requestedAt: Math.floor(Date.now() / 1000) }
}
