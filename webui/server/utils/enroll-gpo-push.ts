// Mise en place de la GPO d'enrôlement par la console (0.19.0). L'administrateur donne l'unité d'organisation et UN compte (administrateur du domaine ou
// délégué) pour cette seule opération : le mot de passe ne sert qu'à la liaison LDAP et à smbclient (variable d'environnement, jamais en argument), il n'est ni
// stocké, ni journalisé, ni renvoyé. Deux protocoles : LDAPS pour les objets d'annuaire (la GPO et le lien sur l'unité d'organisation) et SMB pour SYSVOL
// (les fichiers de la GPO). Relançable : une GPO du même nom est mise à jour, jamais dupliquée.
import { randomUUID } from 'node:crypto'
import { Attribute, Change, Client } from 'ldapts'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { escapeFilter } from './ad'
import { classifyWrite } from './pki-ad'
import { GPO_NAME, mergeExtensions, scriptsIni } from './enroll-gpo'
import type { GpoFiles } from './enroll-gpo'

/** Raisons d'échec dites à l'administrateur (le texte vient de « err.enroll_gpo_<raison> »). */
export type GpoReason = 'tls' | 'bind' | 'unreachable' | 'denied' | 'ou' | 'ldap' | 'smb' | 'smbclient' | 'no_dc'
export class GpoError extends Error { constructor(readonly reason: GpoReason, readonly detail = '') { super(`enroll_gpo_${reason}`) } }

export interface GpoLdap {
  bind(dn: string, pw: string): Promise<unknown>
  search(base: string, o: { scope: 'base' | 'one' | 'sub'; filter: string; attributes: string[]; sizeLimit?: number }): Promise<{ searchEntries: Array<Record<string, unknown>> }>
  add(dn: string, entry: Record<string, unknown>): Promise<unknown>
  replace(dn: string, attr: string, values: string[]): Promise<unknown>
  del(dn: string): Promise<unknown>
  unbind(): Promise<unknown>
}
export type GpoLdapFactory = (url: string) => GpoLdap
export type SmbRunner = (host: string, user: string, password: string, cmds: string[]) => Promise<{ ok: boolean; out: string }>

export interface GpoStep { id: 'bind' | 'ou' | 'gpo' | 'files' | 'link'; action: 'check' | 'create' | 'update' | 'keep' }
export interface GpoResult { dry: boolean; created: boolean; gpoId: string; domain: string; dc: string; ou: string; steps: GpoStep[] }

/** Le compte : nom d'utilisateur principal (« admin@exemple.org ») ou « DOMAINE\\admin ». Rien qui puisse ressembler à un mot de passe ou à une option. */
export const ACCOUNT_RE = /^(?:[\w.-]{1,64}@[A-Za-z0-9.-]{1,253}|[\w.-]{1,15}\\[\w.-]{1,64})$/
const HOST_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$/

const first = (v: unknown): string => (Array.isArray(v) ? String(v[0] ?? '') : v == null ? '' : String(v))
const all = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : v == null || v === '' ? [] : [String(v)])
const dnsOfNc = (nc: string) => nc.split(',').map((x) => /^DC=(.+)$/i.exec(x.trim())?.[1] ?? '').filter(Boolean).join('.')
const noObject = (e: any) => e?.code === 32 || /NoSuchObject/i.test(`${e?.name}`)

function ldapError(e: any): GpoError {
  const r = classifyWrite(e)
  if (r === 'bind') return new GpoError('bind'); if (r === 'tls') return new GpoError('tls'); if (r === 'unreachable') return new GpoError('unreachable')
  if (r === 'denied') return new GpoError('denied'); return new GpoError('ldap')
}

/** Un seul passage à la fois : deux administrateurs ne créent pas deux GPO du même nom en parallèle. */
let lock: Promise<unknown> = Promise.resolve()
export function pushGpoSerial<T>(fn: () => Promise<T>): Promise<T> { const run = lock.then(fn); lock = run.catch(() => undefined); return run }

const smbStatus = (out: string, ignore: string[]): string | null => {
  for (const m of out.matchAll(/NT_STATUS_[A-Z0-9_]+/g)) if (!ignore.includes(m[0])) return m[0]
  return null
}
function smbFailure(out: string, ignore: string[] = []): GpoError | null {
  const st = smbStatus(out, ignore)
  if (!st) return null
  if (/LOGON_FAILURE|WRONG_PASSWORD|ACCOUNT_|PASSWORD_/.test(st)) return new GpoError('bind', st)
  if (/ACCESS_DENIED/.test(st)) return new GpoError('denied', st)
  if (/UNREACHABLE|CONNECTION|IO_TIMEOUT|HOST_UNREACHABLE/.test(st)) return new GpoError('unreachable', st)
  return new GpoError('smb', st)
}

/** smbclient : le mot de passe passe par l'environnement du processus fils (PASSWD), pas par ses arguments (visibles dans la liste des processus). */
export const smbclientRunner: SmbRunner = (host, user, password, cmds) => new Promise((resolve, reject) => {
  const p = spawn('smbclient', [`//${host}/SYSVOL`, '-U', user, '-s', '/dev/null', '--option=client signing=mandatory', '-c', cmds.join('; ')],
    { env: { PATH: process.env.PATH ?? '/usr/bin:/bin', LANG: 'C', PASSWD: password, HOME: tmpdir() }, stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''
  const add = (b: Buffer) => { if (out.length < 65536) out += b.toString('utf8') }
  p.stdout.on('data', add); p.stderr.on('data', add)
  const timer = setTimeout(() => p.kill('SIGKILL'), 60000)
  p.on('error', (e: any) => { clearTimeout(timer); reject(e?.code === 'ENOENT' ? new GpoError('smbclient') : new GpoError('smb')) })
  p.on('close', (code) => { clearTimeout(timer); resolve({ ok: code === 0, out }) })
})

const q = (v: string) => `"${v}"`

export interface PushDeps { urls: string[]; ldap: GpoLdapFactory; smb: SmbRunner; files: GpoFiles }
export interface PushInput { ou: string; account: string; password: string; dry: boolean }

export async function pushGpo(d: PushDeps, i: PushInput): Promise<GpoResult> {
  if (!d.urls.length || d.urls.some((u) => !/^ldaps:\/\//i.test(u))) throw new GpoError('tls')   // des identifiants d'administrateur ne passent jamais en clair
  let c: GpoLdap | null = null, lastErr: GpoError = new GpoError('unreachable'), url = ''
  try {
    for (const u of d.urls) {
      const cand = d.ldap(u)
      try { await cand.bind(i.account, i.password); c = cand; url = u; break } catch (e) {
        lastErr = ldapError(e); await cand.unbind().catch(() => undefined)
        if (lastErr.reason === 'bind') throw lastErr   // mauvais identifiants : inutile d'essayer les autres contrôleurs
      }
    }
    if (!c) throw lastErr
    return await run(c, d, i, url)
  } finally { await c?.unbind().catch(() => undefined) }
}

async function run(c: GpoLdap, d: PushDeps, i: PushInput, url: string): Promise<GpoResult> {
  const steps: GpoStep[] = [{ id: 'bind', action: 'check' }]
  const guard = async <T>(f: () => Promise<T>): Promise<T> => { try { return await f() } catch (e) { throw e instanceof GpoError ? e : ldapError(e) } }
  const root = (await guard(() => c.search('', { scope: 'base', filter: '(objectClass=*)', attributes: ['defaultNamingContext', 'dnsHostName'] }))).searchEntries[0] ?? {}
  const nc = first(root.defaultNamingContext), domain = dnsOfNc(nc)
  if (!nc || !domain) throw new GpoError('ldap')
  const advertised = first(root.dnsHostName), fromUrl = new URL(url).hostname
  const dc = HOST_RE.test(advertised) ? advertised : fromUrl
  if (!HOST_RE.test(dc)) throw new GpoError('no_dc')

  // l'unité d'organisation : dans le domaine, ni la racine (tous les postes… et les contrôleurs) ni « Domain Controllers »
  const ou = i.ou.trim()
  if (!ou.toLowerCase().endsWith(',' + nc.toLowerCase()) || /^ou=domain controllers,/i.test(ou)) throw new GpoError('ou')
  let target: Record<string, unknown>
  try { target = (await c.search(ou, { scope: 'base', filter: '(objectClass=*)', attributes: ['gPLink', 'objectClass'] })).searchEntries[0] ?? {} } catch (e) { throw noObject(e) ? new GpoError('ou') : ldapError(e) }
  if (!all(target.objectClass).some((x) => x.toLowerCase() === 'organizationalunit')) throw new GpoError('ou')
  steps.push({ id: 'ou', action: 'check' })

  const policies = `CN=Policies,CN=System,${nc}`
  const found = (await guard(() => c.search(policies, { scope: 'one', filter: `(&(objectClass=groupPolicyContainer)(displayName=${escapeFilter(GPO_NAME)}))`, attributes: ['cn', 'versionNumber', 'gPCMachineExtensionNames'], sizeLimit: 2 }))).searchEntries
  const existing = found[0]
  const guid = existing ? first(existing.cn).toUpperCase() : `{${randomUUID().toUpperCase()}}`
  if (!/^\{[0-9A-F-]{36}\}$/.test(guid)) throw new GpoError('ldap')
  const gpoDn = `CN=${guid},${policies}`
  const link = `[LDAP://${gpoDn};0]`
  const linked = all(target.gPLink).join('').toLowerCase().includes(`cn=${guid.toLowerCase()},`)
  const version = (existing ? Number(first(existing.versionNumber)) || 0 : 0) + 1
  const action = existing ? 'update' : 'create'
  steps.push({ id: 'gpo', action }, { id: 'files', action }, { id: 'link', action: linked ? 'keep' : 'create' })
  const result: GpoResult = { dry: i.dry, created: !existing, gpoId: guid, domain, dc, ou, steps }

  // SMB : la simulation ne fait que lister le partage (identifiants et accès vérifiés), sans rien écrire
  const base = `${domain}\\Policies\\${guid}`
  if (i.dry) {
    const r = await d.smb(dc, i.account, i.password, [`ls ${q(domain + '\\Policies\\*')}`])
    const f = smbFailure(r.out); if (f) throw f
    if (!r.ok) throw new GpoError('smb')
    return result
  }
  const tmp = mkdtempSync(join(tmpdir(), 'ddi-gpo-'))
  try {
    const gpt = `[General]\r\nVersion=${version}\r\n`
    const local: Array<[string, string]> = []
    const stage = (data: Buffer | string, remote: string) => { const p = join(tmp, `f${local.length}`); writeFileSync(p, data, { mode: 0o600 }); local.push([p, remote]) }
    stage(gpt, `${base}\\GPT.INI`)
    stage(scriptsIni(domain, guid), `${base}\\Machine\\Scripts\\scripts.ini`)
    for (const [name, data] of Object.entries(d.files)) stage(data, `${base}\\Machine\\Scripts\\Startup\\${name}`)
    const dirs = [base, `${base}\\Machine`, `${base}\\Machine\\Scripts`, `${base}\\Machine\\Scripts\\Startup`, `${base}\\User`]
    const r = await d.smb(dc, i.account, i.password, [...dirs.map((x) => `mkdir ${q(x)}`), ...local.map(([l, remote]) => `put ${q(l)} ${q(remote)}`)])
    const f = smbFailure(r.out, ['NT_STATUS_OBJECT_NAME_COLLISION']); if (f) throw f
    if ((r.out.match(/putting file/g) ?? []).length !== local.length) throw new GpoError('smb', 'put')   // chaque fichier doit être confirmé
  } finally { rmSync(tmp, { recursive: true, force: true }) }

  // l'annuaire : l'objet de la GPO (ou sa version), puis le lien sur l'unité d'organisation
  const ext = mergeExtensions(first(existing?.gPCMachineExtensionNames))
  try {
    if (!existing) {
      await c.add(gpoDn, { objectClass: ['top', 'container', 'groupPolicyContainer'], displayName: GPO_NAME, gPCFunctionalityVersion: '2', flags: '0', versionNumber: String(version),
        gPCFileSysPath: `\\\\${domain}\\SysVol\\${domain}\\Policies\\${guid}`, gPCMachineExtensionNames: ext.value })
      await c.add(`CN=User,${gpoDn}`, { objectClass: ['top', 'container'] })
      await c.add(`CN=Machine,${gpoDn}`, { objectClass: ['top', 'container'] })
    } else {
      await c.replace(gpoDn, 'gPCMachineExtensionNames', [ext.value]); await c.replace(gpoDn, 'versionNumber', [String(version)])
    }
  } catch (e) {
    if (!existing) {   // rien d'à moitié fait : on retire ce qu'on vient de déposer dans SYSVOL (au mieux)
      await c.del(`CN=Machine,${gpoDn}`).catch(() => undefined); await c.del(`CN=User,${gpoDn}`).catch(() => undefined); await c.del(gpoDn).catch(() => undefined)
      await d.smb(dc, i.account, i.password, ['recurse ON', 'prompt OFF', `deltree ${q(base)}`]).catch(() => undefined)
    }
    throw ldapError(e)
  }
  if (!linked) { try { await c.replace(ou, 'gPLink', [all(target.gPLink).join('') + link]) } catch (e) { throw ldapError(e) } }
  return result
}

/** Client LDAP réel : mêmes règles TLS que l'annuaire des réglages (certificat vérifié, autorité éventuelle). */
export const gpoLdapFactory = (tls: { tlsRejectUnauthorized: boolean; caPem?: string }): GpoLdapFactory => (url) => {
  const c = new Client({ url, timeout: 15000, connectTimeout: 5000, tlsOptions: { rejectUnauthorized: tls.tlsRejectUnauthorized, ...(tls.caPem ? { ca: tls.caPem } : {}) } })
  return {
    bind: (dn, pw) => c.bind(dn, pw), search: (b, o) => c.search(b, o as any) as any, unbind: () => c.unbind(), add: (dn, e) => c.add(dn, e as any), del: (dn) => c.del(dn),
    replace: (dn, attr, values) => c.modify(dn, new Change({ operation: 'replace', modification: new Attribute({ type: attr, values }) })),
  }
}
