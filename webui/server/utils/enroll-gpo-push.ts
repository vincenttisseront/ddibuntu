// Mise en place de la GPO d'enrôlement par la console (0.19.0). L'administrateur donne l'unité d'organisation et UN compte (administrateur du domaine ou
// délégué) pour cette seule opération : le mot de passe ne sert qu'à la liaison LDAP et à smbclient (variable d'environnement, jamais en argument), il n'est ni
// stocké, ni journalisé, ni renvoyé. Deux protocoles : LDAPS pour les objets d'annuaire (la GPO et le lien sur l'unité d'organisation) et SMB pour SYSVOL
// (les fichiers de la GPO). Relançable : une GPO du même nom est mise à jour, jamais dupliquée.
import { randomUUID } from 'node:crypto'
import { Attribute, BerWriter, Change, Client, Control } from 'ldapts'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { escapeFilter } from './ad'
import { classifyWrite } from './pki-ad'
import { GPO_NAME, GPO_NAME_GROUP, mergeExtensions, scriptsIni } from './enroll-gpo'
import { filterGpoAcl, ridOf } from './gpo-acl'
import type { GpoFiles } from './enroll-gpo'

/** Raisons d'échec dites à l'administrateur (le texte vient de « err.enroll_gpo_<raison> »). */
export type GpoReason = 'tls' | 'bind' | 'unreachable' | 'denied' | 'ou' | 'ou_missing' | 'ou_container' | 'group' | 'group_missing' | 'group_broad' | 'group_dc' | 'ldap' | 'smb' | 'smbclient' | 'no_dc'
export class GpoError extends Error { constructor(readonly reason: GpoReason, readonly detail = '') { super(`enroll_gpo_${reason}`) } }

export interface GpoLdap {
  bind(dn: string, pw: string): Promise<unknown>
  search(base: string, o: { scope: 'base' | 'one' | 'sub'; filter: string; attributes: string[]; sizeLimit?: number }): Promise<{ searchEntries: Array<Record<string, unknown>> }>
  add(dn: string, entry: Record<string, unknown>): Promise<unknown>
  replace(dn: string, attr: string, values: string[]): Promise<unknown>
  del(dn: string): Promise<unknown>
  /** Valeur binaire d'un attribut (objectSid, nTSecurityDescriptor) ; `dacl` : ne lire que la DACL (contrôle SD_FLAGS). */
  readBin(dn: string, attr: string, dacl?: boolean): Promise<Buffer | null>
  writeBin(dn: string, attr: string, value: Buffer, dacl?: boolean): Promise<unknown>
  unbind(): Promise<unknown>
}
export type GpoLdapFactory = (url: string) => GpoLdap
export type SmbRunner = (host: string, user: string, password: string, cmds: string[]) => Promise<{ ok: boolean; out: string }>

export interface GpoStep { id: 'bind' | 'ou' | 'group' | 'gpo' | 'files' | 'filter' | 'link'; action: 'check' | 'create' | 'update' | 'keep' }
export interface GpoMembers { count: number; names: string[]; truncated: boolean }
export interface GpoResult { dry: boolean; created: boolean; gpoId: string; domain: string; dc: string; ou: string; group?: string; members?: GpoMembers; steps: GpoStep[] }

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
  const p = spawn('/usr/bin/smbclient', [`//${host}/SYSVOL`, '-U', user, '-s', '/dev/null', '--option=client signing=mandatory', '-c', cmds.join('; ')],
    { env: { PATH: '/usr/bin:/bin', LANG: 'C', PASSWD: password, HOME: tmpdir() }, stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''
  const add = (b: Buffer) => { if (out.length < 65536) out += b.toString('utf8') }
  p.stdout.on('data', add); p.stderr.on('data', add)
  const timer = setTimeout(() => p.kill('SIGKILL'), 60000)
  p.on('error', (e: any) => { clearTimeout(timer); reject(e?.code === 'ENOENT' ? new GpoError('smbclient') : new GpoError('smb')) })
  p.on('close', (code) => { clearTimeout(timer); resolve({ ok: code === 0, out }) })
})

const q = (v: string) => `"${v}"`

export interface PushDeps { urls: string[]; ldap: GpoLdapFactory; smb: SmbRunner; files: GpoFiles }
/** Cible : une unité d'organisation (`ou`) OU un groupe d'ordinateurs (`group`, GPO liée à la racine du domaine et filtrée sur ce groupe). */
export interface PushInput { ou?: string; group?: string; account: string; password: string; dry: boolean }

/** Ouvre une liaison LDAPS avec le compte donné (jamais autre chose que LDAPS) ; un mot de passe refusé arrête l'essai, un contrôleur injoignable passe au suivant. */
async function connect(d: Pick<PushDeps, 'urls' | 'ldap'>, account: string, password: string): Promise<{ c: GpoLdap; url: string }> {
  if (!d.urls.length || d.urls.some((u) => !/^ldaps:\/\//i.test(u))) throw new GpoError('tls')   // des identifiants d'administrateur ne passent jamais en clair
  let lastErr: GpoError = new GpoError('unreachable')
  for (const u of d.urls) {
    const cand = d.ldap(u)
    try { await cand.bind(account, password); return { c: cand, url: u } } catch (e) {
      lastErr = ldapError(e); await cand.unbind().catch(() => undefined)
      if (lastErr.reason === 'bind') throw lastErr   // mauvais identifiants : inutile d'essayer les autres contrôleurs
    }
  }
  throw lastErr
}

export async function pushGpo(d: PushDeps, i: PushInput): Promise<GpoResult> {
  const { c, url } = await connect(d, i.account, i.password)
  try { return await run(c, d, i, url) } finally { await c.unbind().catch(() => undefined) }
}

/** Contexte du domaine lu dans le RootDSE du contrôleur. */
async function domainOf(c: GpoLdap, url: string): Promise<{ nc: string; domain: string; dc: string }> {
  let root: Record<string, unknown>
  try { root = (await c.search('', { scope: 'base', filter: '(objectClass=*)', attributes: ['defaultNamingContext', 'dnsHostName'] })).searchEntries[0] ?? {} } catch (e) { throw ldapError(e) }
  const nc = first(root.defaultNamingContext), domain = dnsOfNc(nc)
  if (!nc || !domain) throw new GpoError('ldap')
  const advertised = first(root.dnsHostName), dc = HOST_RE.test(advertised) ? advertised : new URL(url).hostname
  if (!HOST_RE.test(dc)) throw new GpoError('no_dc')
  return { nc, domain, dc }
}

/** Une unité d'organisation sous une autre, dans le domaine : jamais la racine ni « Domain Controllers ». */
const OU_RE = /^OU=((?:[^,\\]|\\.)+),(.+)$/i
export interface OuInput { ou: string; account: string; password: string }
/** Crée l'unité d'organisation demandée (son parent doit exister) ; sans effet si elle existe déjà. */
export async function createOu(d: Pick<PushDeps, 'urls' | 'ldap'>, i: OuInput): Promise<{ ou: string; created: boolean }> {
  const { c, url } = await connect(d, i.account, i.password)
  try {
    const { nc } = await domainOf(c, url)
    const ou = i.ou.trim(), m = OU_RE.exec(ou)
    if (!m || !ou.toLowerCase().endsWith(',' + nc.toLowerCase()) || /^ou=domain controllers,/i.test(ou)) throw new GpoError('ou')
    try { await c.search(ou, { scope: 'base', filter: '(objectClass=*)', attributes: ['objectClass'] }); return { ou, created: false } } catch (e) { if (!noObject(e)) throw ldapError(e) }
    try { await c.search(m[2]!, { scope: 'base', filter: '(objectClass=*)', attributes: ['objectClass'] }) } catch (e) { throw noObject(e) ? new GpoError('ou') : ldapError(e) }   // le parent doit exister
    try { await c.add(ou, { objectClass: ['top', 'organizationalUnit'], ou: m[1]!.replace(/\\(.)/g, '$1') }) } catch (e) { throw ldapError(e) }
    return { ou, created: true }
  } finally { await c.unbind().catch(() => undefined) }
}

const CN_RE = /^CN=((?:[^,\\]|\\.)+),(.+)$/i
export interface GroupInput { group: string; account: string; password: string }
/** Crée un groupe de sécurité global (vide : on y ajoute ensuite les ordinateurs) ; sans effet s'il existe déjà. */
export async function createGroup(d: Pick<PushDeps, 'urls' | 'ldap'>, i: GroupInput): Promise<{ group: string; created: boolean }> {
  const { c, url } = await connect(d, i.account, i.password)
  try {
    const { nc } = await domainOf(c, url)
    const dn = i.group.trim(), m = CN_RE.exec(dn), name = m?.[1]?.replace(/\\(.)/g, '$1') ?? ''
    if (!m || !dn.toLowerCase().endsWith(',' + nc.toLowerCase()) || !/^[A-Za-z0-9][A-Za-z0-9._ -]{0,19}$/.test(name)) throw new GpoError('group')   // nom court d'un groupe : 20 caractères au plus
    try {
      const e = (await c.search(dn, { scope: 'base', filter: '(objectClass=*)', attributes: ['objectClass'] })).searchEntries[0] ?? {}
      if (all(e.objectClass).some((x) => x.toLowerCase() === 'group')) return { group: dn, created: false }
      throw new GpoError('group')
    } catch (e) { if (e instanceof GpoError) throw e; if (!noObject(e)) throw ldapError(e) }
    try { await c.search(m[2]!, { scope: 'base', filter: '(objectClass=*)', attributes: ['objectClass'] }) } catch (e) { throw noObject(e) ? new GpoError('group') : ldapError(e) }   // le parent doit exister
    try { await c.add(dn, { objectClass: ['top', 'group'], cn: name, sAMAccountName: name, groupType: '-2147483646' }) } catch (e) { throw ldapError(e) }
    return { group: dn, created: true }
  } finally { await c.unbind().catch(() => undefined) }
}

interface Target { linkDn: string; label: string; gPLink: string; groupSid?: Buffer; members?: GpoMembers }

/** Unité d'organisation : dans le domaine, ni la racine ni « Domain Controllers » ; un conteneur « CN= » n'accepte pas de GPO. */
async function ouTarget(c: GpoLdap, nc: string, raw: string): Promise<Target> {
  const ou = raw.trim()
  if (!ou.toLowerCase().endsWith(',' + nc.toLowerCase()) || /^ou=domain controllers,/i.test(ou)) throw new GpoError('ou')
  let target: Record<string, unknown>
  try { target = (await c.search(ou, { scope: 'base', filter: '(objectClass=*)', attributes: ['gPLink', 'objectClass'] })).searchEntries[0] ?? {} } catch (e) { throw noObject(e) ? new GpoError(OU_RE.test(ou) ? 'ou_missing' : 'ou') : ldapError(e) }
  if (!all(target.objectClass).some((x) => x.toLowerCase() === 'organizationalunit')) throw new GpoError('ou_container')   // « CN=Computers » : une GPO ne se lie qu'à une unité d'organisation
  return { linkDn: ou, label: ou, gPLink: all(target.gPLink).join('') }
}

/** RID des groupes qui couvrent (presque) tout le domaine : Utilisateurs, Invités, Ordinateurs, Contrôleurs de domaine (et en lecture seule), Contrôleurs d'entreprise. */
const BROAD_RIDS = [513, 514, 515, 516, 521, 498]
const IN_CHAIN = '1.2.840.113556.1.4.1941'
const sizeLimited = (e: any) => e?.code === 4 || /SizeLimitExceeded/i.test(`${e?.name}`)

/** Groupe d'ordinateurs : la GPO est liée à la racine du domaine, filtrée sur ce groupe. Refus d'un groupe trop large ou qui contient un contrôleur de domaine. */
async function groupTarget(c: GpoLdap, nc: string, raw: string): Promise<Target> {
  const dn = raw.trim()
  if (!dn.toLowerCase().endsWith(',' + nc.toLowerCase())) throw new GpoError('group')
  let entry: Record<string, unknown>
  try { entry = (await c.search(dn, { scope: 'base', filter: '(objectClass=*)', attributes: ['objectClass'] })).searchEntries[0] ?? {} } catch (e) { throw noObject(e) ? new GpoError(/^CN=/i.test(dn) ? 'group_missing' : 'group') : ldapError(e) }
  if (!all(entry.objectClass).some((x) => x.toLowerCase() === 'group')) throw new GpoError('group')   // « CN=Computers » est un conteneur, pas un groupe
  const sid = await c.readBin(dn, 'objectSid'); if (!sid || sid.length < 12) throw new GpoError('ldap')
  if (BROAD_RIDS.includes(ridOf(sid))) throw new GpoError('group_broad')
  const inGroup = `(memberOf:${IN_CHAIN}:=${escapeFilter(dn)})`
  try {
    if ((await c.search(nc, { scope: 'sub', filter: `(&(objectClass=computer)(|(primaryGroupID=516)(primaryGroupID=521))${inGroup})`, attributes: ['cn'], sizeLimit: 1 })).searchEntries.length) throw new GpoError('group_dc')
  } catch (e) { if (e instanceof GpoError) throw e; if (!sizeLimited(e)) throw ldapError(e); throw new GpoError('group_dc') }
  let names: string[] = [], truncated = false
  try { names = (await c.search(nc, { scope: 'sub', filter: `(&(objectClass=computer)${inGroup})`, attributes: ['cn'], sizeLimit: 500 })).searchEntries.map((e) => first(e.cn)) } catch (e) { if (!sizeLimited(e)) throw ldapError(e); truncated = true }
  let root: Record<string, unknown>
  try { root = (await c.search(nc, { scope: 'base', filter: '(objectClass=*)', attributes: ['gPLink'] })).searchEntries[0] ?? {} } catch (e) { throw ldapError(e) }
  return { linkDn: nc, label: dn, gPLink: all(root.gPLink).join(''), groupSid: sid, members: { count: names.length, names: names.sort((a, b) => a.localeCompare(b)).slice(0, 20), truncated } }
}

async function run(c: GpoLdap, d: PushDeps, i: PushInput, url: string): Promise<GpoResult> {
  const steps: GpoStep[] = [{ id: 'bind', action: 'check' }]
  const guard = async <T>(f: () => Promise<T>): Promise<T> => { try { return await f() } catch (e) { throw e instanceof GpoError ? e : ldapError(e) } }
  const { nc, domain, dc } = await domainOf(c, url)

  const tgt = i.group ? await groupTarget(c, nc, i.group) : await ouTarget(c, nc, i.ou ?? '')
  steps.push({ id: i.group ? 'group' : 'ou', action: 'check' })

  const policies = `CN=Policies,CN=System,${nc}`
  const gpoName = tgt.groupSid ? GPO_NAME_GROUP : GPO_NAME
  const found = (await guard(() => c.search(policies, { scope: 'one', filter: `(&(objectClass=groupPolicyContainer)(displayName=${escapeFilter(gpoName)}))`, attributes: ['cn', 'versionNumber', 'gPCMachineExtensionNames'], sizeLimit: 2 }))).searchEntries
  const existing = found[0]
  const guid = existing ? first(existing.cn).toUpperCase() : `{${randomUUID().toUpperCase()}}`
  if (!/^\{[0-9A-F-]{36}\}$/.test(guid)) throw new GpoError('ldap')
  const gpoDn = `CN=${guid},${policies}`
  const link = `[LDAP://${gpoDn};0]`
  const linked = tgt.gPLink.toLowerCase().includes(`cn=${guid.toLowerCase()},`)
  const version = (existing ? Number(first(existing.versionNumber)) || 0 : 0) + 1
  const action = existing ? 'update' : 'create'
  steps.push({ id: 'gpo', action }, { id: 'files', action })
  if (tgt.groupSid) {   // filtrage de sécurité : « Utilisateurs authentifiés » ne peut plus appliquer la GPO, le groupe seul le peut
    let filter: 'create' | 'update' | 'keep' = 'create'
    if (existing) { const sd = await guard(() => c.readBin(gpoDn, 'nTSecurityDescriptor', true)); if (!sd) throw new GpoError('ldap'); filter = filterGpoAcl(sd, tgt.groupSid).changed ? 'update' : 'keep' }
    steps.push({ id: 'filter', action: filter })
  }
  steps.push({ id: 'link', action: linked ? 'keep' : 'create' })
  const result: GpoResult = { dry: i.dry, created: !existing, gpoId: guid, domain, dc, ou: tgt.linkDn, ...(tgt.groupSid ? { group: tgt.label, members: tgt.members } : {}), steps }

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
      await c.add(gpoDn, { objectClass: ['top', 'container', 'groupPolicyContainer'], displayName: gpoName, gPCFunctionalityVersion: '2', flags: '0', versionNumber: String(version),
        gPCFileSysPath: `\\\\${domain}\\SysVol\\${domain}\\Policies\\${guid}`, gPCMachineExtensionNames: ext.value })
      await c.add(`CN=User,${gpoDn}`, { objectClass: ['top', 'container'] })
      await c.add(`CN=Machine,${gpoDn}`, { objectClass: ['top', 'container'] })
    } else {
      await c.replace(gpoDn, 'gPCMachineExtensionNames', [ext.value]); await c.replace(gpoDn, 'versionNumber', [String(version)])
    }
    if (tgt.groupSid) {
      const sd = await c.readBin(gpoDn, 'nTSecurityDescriptor', true); if (!sd) throw new GpoError('ldap')
      const f = filterGpoAcl(sd, tgt.groupSid); if (f.changed) await c.writeBin(gpoDn, 'nTSecurityDescriptor', f.sd, true)
    }
  } catch (e) {
    if (!existing) {   // rien d'à moitié fait : on retire ce qu'on vient de déposer dans SYSVOL (au mieux)
      await c.del(`CN=Machine,${gpoDn}`).catch(() => undefined); await c.del(`CN=User,${gpoDn}`).catch(() => undefined); await c.del(gpoDn).catch(() => undefined)
      await d.smb(dc, i.account, i.password, ['recurse ON', 'prompt OFF', `deltree ${q(base)}`]).catch(() => undefined)
    }
    throw e instanceof GpoError ? e : ldapError(e)
  }
  if (!linked) { try { await c.replace(tgt.linkDn, 'gPLink', [tgt.gPLink + link]) } catch (e) { throw ldapError(e) } }
  return result
}

/** Client LDAP réel : mêmes règles TLS que l'annuaire des réglages (certificat vérifié, autorité éventuelle). */
export const gpoLdapFactory = (tls: { tlsRejectUnauthorized: boolean; caPem?: string }): GpoLdapFactory => (url) => {
  const c = new Client({ url, timeout: 15000, connectTimeout: 5000, tlsOptions: { rejectUnauthorized: tls.tlsRejectUnauthorized, ...(tls.caPem ? { ca: tls.caPem } : {}) } })
  return {
    bind: (dn, pw) => c.bind(dn, pw), search: (b, o) => c.search(b, o as any) as any, unbind: () => c.unbind(), add: (dn, e) => c.add(dn, e as any), del: (dn) => c.del(dn),
    replace: (dn, attr, values) => c.modify(dn, new Change({ operation: 'replace', modification: new Attribute({ type: attr, values }) })),
    readBin: async (dn, attr, dacl) => {
      const r = await c.search(dn, { scope: 'base', filter: '(objectClass=*)', attributes: [attr], explicitBufferAttributes: [attr] }, dacl ? new SdFlags(4) : undefined)
      const v = r.searchEntries[0]?.[attr]; const b = Array.isArray(v) ? v[0] : v
      return Buffer.isBuffer(b) ? b : null
    },
    writeBin: (dn, attr, value, dacl) => c.modify(dn, new Change({ operation: 'replace', modification: new Attribute({ type: attr, values: [value] }) }), dacl ? new SdFlags(4) : undefined),
  }
}

/** Contrôle LDAP « SD_FLAGS » (1.2.840.113556.1.4.801) : n'agir que sur certaines parties du descripteur de sécurité (4 = la DACL). */
class SdFlags extends Control {
  constructor(private readonly flags: number) { super('1.2.840.113556.1.4.801', { critical: true }) }
  protected override writeControl(writer: BerWriter): void {
    const w = new BerWriter(); w.startSequence(); w.writeInt(this.flags); w.endSequence()
    writer.writeBuffer(w.buffer, 4)
  }
}
