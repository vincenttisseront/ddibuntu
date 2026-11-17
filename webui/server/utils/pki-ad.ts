// Publication des autorités de la PKI du DDI dans l'Active Directory (0.14.2) : ce que l'on écrit, où, avec quelle identité, et comment on vérifie.
// Rien ici ne touche la base du DDI ni le disque : ce sont des fonctions pures et des opérations LDAP sur un client injectable (faux annuaire en test).
//
// Où : partition Configuration, « CN=Public Key Services,CN=Services,<config> ». Racines (autosignées ou hors ligne) → « Certification Authorities » ;
// émettrices → « AIA ». Objet « certificationAuthority » nommé comme l'autorité du DDI (CN=<nom>), avec les quatre attributs que le schéma exige (cn,
// cACertificate, certificateRevocationList, authorityRevocationList : les deux listes reçoivent un octet nul, valable pour le schéma et sans péremption).
// Règles : jamais d'écrasement d'un objet qui n'est pas le nôtre ; l'empreinte SHA-256 est RELUE après chaque écriture ; jamais de retrait automatique.
import { createHash, X509Certificate } from 'node:crypto'
import { Attribute, Change, Client } from 'ldapts'
import type { LdapLike } from './ad'

export type Container = 'roots' | 'aia'
export const CONTAINER_CN: Record<Container, string> = { roots: 'Certification Authorities', aia: 'AIA' }
/** Partition Configuration d'une forêt : « CN=Configuration,DC=… ». Validée avant tout usage : une réponse de serveur ne choisit jamais l'endroit où l'on écrit. */
export const CONFIG_NC_RE = /^CN=Configuration(,DC=[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){1,10}$/i
export const containerDn = (configNc: string, c: Container) => `CN=${CONTAINER_CN[c]},CN=Public Key Services,CN=Services,${configNc}`
/** Le nom d'une autorité du DDI ne contient que lettres, chiffres, point, tiret et souligné (CA_NAME_RE) : il peut servir tel quel de RDN. */
export const objectDn = (configNc: string, c: Container, name: string) => `CN=${name},${containerDn(configNc, c)}`
export const containerFor = (kind: string): Container | null => (kind === 'root' || kind === 'extroot' ? 'roots' : kind === 'issuing' ? 'aia' : null)

export const PLACEHOLDER = Buffer.from([0])
export const sha256Hex = (b: Buffer) => createHash('sha256').update(b).digest('hex')
/** Premier certificat d'un fichier PEM, en DER ; null si ce n'est pas un certificat. */
export function pemToDer(pem: Buffer | string): Buffer | null {
  try { return new X509Certificate(pem).raw } catch { return null }
}

// ---- Client LDAP en écriture ----
export interface PkiLdap extends LdapLike {
  add(dn: string, entry: Record<string, unknown>): Promise<unknown>
  replaceBinary(dn: string, attr: string, value: Buffer): Promise<unknown>
  del(dn: string): Promise<unknown>
}
export type PkiLdapFactory = (url: string) => PkiLdap
export function defaultPkiLdapFactory(tls: { tlsRejectUnauthorized: boolean; caPem?: string }): PkiLdapFactory {
  return (url) => {
    const c = new Client({ url, timeout: 8000, connectTimeout: 5000, tlsOptions: { rejectUnauthorized: tls.tlsRejectUnauthorized, ...(tls.caPem ? { ca: tls.caPem } : {}) } })
    return {
      bind: (dn, pw) => c.bind(dn, pw), search: (b, o) => c.search(b, o as any) as any, unbind: () => c.unbind(),
      add: (dn, e) => c.add(dn, e as any),
      replaceBinary: (dn, attr, value) => c.modify(dn, new Change({ operation: 'replace', modification: new Attribute({ type: attr, values: [value] }) })),
      del: (dn) => c.del(dn),
    }
  }
}

// ---- Erreurs ----
export type AdReason = 'bind' | 'tls' | 'unreachable' | 'denied' | 'no_container' | 'conflict' | 'schema' | 'mismatch' | 'bad_cert' | 'config_nc' | 'other'
const text = (e: any) => `${e?.name ?? ''} ${e?.message ?? ''}`
const codeOf = (e: any): number => (typeof e?.code === 'number' ? e.code : -1)
/** Classe une erreur LDAP : de quoi dire à l'administrateur CE QU'IL FAUT CORRIGER (identifiants, certificat du serveur, délégation, conteneur manquant…).
 *  Le code de résultat LDAP (nombre) prime ; le texte ne sert qu'à défaut (erreurs réseau et TLS, qui n'en ont pas). */
export function classifyWrite(e: any): AdReason {
  const n = codeOf(e), t = text(e)
  if (e?.name === 'ConfigNcError') return 'config_nc'
  if (n === 49 || /InvalidCredentials|invalid credentials/i.test(t)) return 'bind'
  if (n === 50 || /InsufficientAccess|insufficient access/i.test(t)) return 'denied'
  if (n === 32 || /NoSuchObject|no such object/i.test(t)) return 'no_container'
  if (n === 68 || /AlreadyExists|already exists/i.test(t)) return 'conflict'
  if ([65, 19, 17, 64, 21].includes(n) || /ObjectClassViolation|ConstraintViolation|UndefinedType|InvalidAttribute|NamingViolation/i.test(t)) return 'schema'
  if (/ECONN|ETIMEDOUT|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|EAI_AGAIN|timeout|timed out/i.test(t)) return 'unreachable'
  if (/cert|tls|ssl|self[- ]signed|unable to verify|hostname|altname/i.test(t)) return 'tls'
  if (/socket|connect|closed/i.test(t)) return 'unreachable'
  return 'other'
}
const noObject = (e: any) => codeOf(e) === 32 || /NoSuchObject|no such object/i.test(text(e))

// ---- Lecture ----
const arr = (x: unknown): unknown[] => (x === undefined || x === null ? [] : Array.isArray(x) ? x : [x])
/** ldapts rend une valeur binaire en Buffer et un texte valide en chaîne : on remet tout en octets. */
const toBuf = (v: unknown): Buffer => (Buffer.isBuffer(v) ? v : Buffer.from(String(v), 'utf8'))
const first = (x: unknown): string => String(arr(x)[0] ?? '')

/** Empreintes SHA-256 des certificats d'un objet ; null si l'objet n'existe pas. */
async function certsAt(c: PkiLdap, dn: string): Promise<string[] | null> {
  let r
  try { r = await c.search(dn, { scope: 'base', filter: '(objectClass=*)', attributes: ['cACertificate'], sizeLimit: 2 }) } catch (e) { if (noObject(e)) return null; throw e }
  const e = r.searchEntries[0]
  return e ? arr(e.cACertificate).map((v) => sha256Hex(toBuf(v))) : null
}

export interface RootDse { configNc: string; defaultNc: string; host: string }
/** Lit le RootDSE (accessible sans compte) : partition Configuration, domaine, nom du contrôleur. */
export async function rootDse(c: PkiLdap): Promise<RootDse | { error: 'config_nc' }> {
  const r = await c.search('', { scope: 'base', filter: '(objectClass=*)', attributes: ['configurationNamingContext', 'defaultNamingContext', 'dnsHostName'], sizeLimit: 1 })
  const e = r.searchEntries[0] ?? {}
  const configNc = first(e.configurationNamingContext)
  if (!CONFIG_NC_RE.test(configNc)) return { error: 'config_nc' }
  return { configNc, defaultNc: first(e.defaultNamingContext), host: first(e.dnsHostName) }
}

export interface ContainerCheck { container: Container; dn: string; exists: boolean; canCreate: boolean }
/** Les deux conteneurs existent-ils, et le compte peut-il y créer un objet « certificationAuthority » ? Lu dans l'attribut calculé allowedChildClassesEffective :
 *  aucune écriture, aucun objet d'essai. Un compte sans délégation obtient une liste vide (canCreate : false). */
export async function checkContainers(c: PkiLdap, configNc: string): Promise<ContainerCheck[]> {
  const out: ContainerCheck[] = []
  for (const container of ['roots', 'aia'] as const) {
    const dn = containerDn(configNc, container)
    try {
      const r = await c.search(dn, { scope: 'base', filter: '(objectClass=*)', attributes: ['allowedChildClassesEffective'], sizeLimit: 1 })
      const e = r.searchEntries[0]
      out.push({ container, dn, exists: !!e, canCreate: !!e && arr(e.allowedChildClassesEffective).map(String).includes('certificationAuthority') })
    } catch (e) { if (!noObject(e)) throw e; out.push({ container, dn, exists: false, canCreate: false }) }
  }
  return out
}

export interface AccountInfo { sam: string; upn: string; sid: string }
/** SID binaire d'Active Directory → « S-1-5-21-… ». */
export function sidToString(b: Buffer): string | null {
  if (b.length < 8 || b[0] !== 1) return null
  const n = b[1]!; if (b.length !== 8 + 4 * n) return null
  let auth = 0n; for (let i = 2; i < 8; i++) auth = (auth << 8n) | BigInt(b[i]!)
  const subs = Array.from({ length: n }, (_, i) => b.readUInt32LE(8 + 4 * i))
  return `S-1-${auth}${subs.map((s) => '-' + s).join('')}`
}
const escFilter = (v: string) => v.replace(/[\\*()\0]/g, (ch) => '\\' + ch.charCodeAt(0).toString(16).padStart(2, '0'))
/** Compte de liaison tel que l'annuaire le connaît (nom, UPN, SID) : sert à écrire la délégation à faire. null si introuvable ou illisible. */
export async function accountInfo(c: PkiLdap, bindDn: string, defaultNc: string): Promise<AccountInfo | null> {
  const attributes = ['sAMAccountName', 'userPrincipalName', 'objectSid']
  try {
    const isDn = /^[A-Za-z][A-Za-z0-9-]*=/.test(bindDn)
    const r = isDn ? await c.search(bindDn, { scope: 'base', filter: '(objectClass=*)', attributes, sizeLimit: 1 })
      : await c.search(defaultNc, { scope: 'sub', filter: `(&(objectClass=user)(|(userPrincipalName=${escFilter(bindDn)})(sAMAccountName=${escFilter(bindDn)})))`, attributes, sizeLimit: 2 })
    if (r.searchEntries.length !== 1) return null
    const e = r.searchEntries[0]!
    const sidRaw = arr(e.objectSid)[0]
    return { sam: first(e.sAMAccountName), upn: first(e.userPrincipalName), sid: Buffer.isBuffer(sidRaw) ? (sidToString(sidRaw) ?? '') : '' }
  } catch { return null }
}

// ---- Écriture ----
export type PublishResult = { ok: true; action: 'added' | 'replaced' | 'unchanged'; sha: string } | { ok: false; reason: AdReason }
/** Publie un certificat d'autorité. `owned` : le DDI a déjà publié à cet endroit (il peut donc remplacer) ; sinon un objet existant qui ne porte pas notre
 *  certificat est un CONFLIT et reste intact. Après toute écriture, l'empreinte est relue : un écart est un échec visible. */
export async function publishCa(c: PkiLdap, o: { dn: string; name: string; der: Buffer; owned: boolean }): Promise<PublishResult> {
  const sha = sha256Hex(o.der)
  try {
    const have = await certsAt(c, o.dn)
    let action: 'added' | 'replaced'
    if (have === null) {
      await c.add(o.dn, { objectClass: ['top', 'certificationAuthority'], cn: o.name, cACertificate: [o.der], certificateRevocationList: [PLACEHOLDER], authorityRevocationList: [PLACEHOLDER] })
      action = 'added'
    } else if (have.includes(sha)) return { ok: true, action: 'unchanged', sha }
    else if (o.owned) { await c.replaceBinary(o.dn, 'cACertificate', o.der); action = 'replaced' }
    else return { ok: false, reason: 'conflict' }
    const after = await certsAt(c, o.dn)
    if (!after || after.length !== 1 || after[0] !== sha) return { ok: false, reason: 'mismatch' }
    return { ok: true, action, sha }
  } catch (e) { return { ok: false, reason: classifyWrite(e) } }
}

export type CheckResult = { ok: true; state: 'ok' | 'missing' | 'different' } | { ok: false; reason: AdReason }
/** Rapprochement : l'objet existe-t-il et porte-t-il notre certificat ? (lecture seule) */
export async function checkCa(c: PkiLdap, dn: string, sha: string): Promise<CheckResult> {
  try {
    const have = await certsAt(c, dn)
    return { ok: true, state: have === null ? 'missing' : have.includes(sha) ? 'ok' : 'different' }
  } catch (e) { return { ok: false, reason: classifyWrite(e) } }
}

export type WithdrawResult = { ok: true; action: 'deleted' | 'absent' } | { ok: false; reason: AdReason }
/** Retrait explicite d'un objet : seulement s'il est le nôtre (porte notre certificat, ou publié par le DDI), puis vérifié. */
export async function withdrawCa(c: PkiLdap, o: { dn: string; sha: string; owned: boolean }): Promise<WithdrawResult> {
  try {
    const have = await certsAt(c, o.dn)
    if (have === null) return { ok: true, action: 'absent' }
    if (!have.includes(o.sha) && !o.owned) return { ok: false, reason: 'conflict' }
    await c.del(o.dn)
    if ((await certsAt(c, o.dn)) !== null) return { ok: false, reason: 'mismatch' }
    return { ok: true, action: 'deleted' }
  } catch (e) { return { ok: false, reason: classifyWrite(e) } }
}

// ---- Ce qu'il faut faire faire à l'annuaire ----
/** Droits du compte de publication : créer / supprimer des objets enfants, lister, lire et écrire les propriétés, supprimer, lire le descripteur. */
export const DELEGATED_RIGHTS = 'CCDCLCLORPWPSDRC'
export interface Delegation { container: Container; cn: string; dn: string; dsacls: string; sddl: string | null; samba: string | null }
/** Commandes à faire exécuter par un administrateur du domaine, une par conteneur. dsacls : forme Microsoft (non validée sur un vrai Windows) ; SDDL et
 *  samba-tool : validés sur Samba AD. Le SID n'est connu qu'après un test de liaison réussi. */
export function delegation(o: { configNc: string; account: string; sid?: string }): Delegation[] {
  return (['roots', 'aia'] as const).map((container) => {
    const dn = containerDn(o.configNc, container)
    const sddl = o.sid ? `(A;CIOI;${DELEGATED_RIGHTS};;;${o.sid})` : null
    return {
      container, cn: CONTAINER_CN[container], dn,
      dsacls: `dsacls "${dn}" /I:T /G "${o.account}:${DELEGATED_RIGHTS}"`,
      sddl, samba: sddl ? `samba-tool dsacl set --objectdn="${dn}" --sddl="${sddl}"` : null,
    }
  })
}

export interface FallbackItem { name: string; container: Container; der: Buffer }
/** Script PowerShell de repli (sans compte délégué) : un administrateur du domaine l'exécute ; les certificats (publics) y sont intégrés et leur empreinte
 *  est contrôlée avant « certutil -dspublish ». Les noms ne contiennent que [A-Za-z0-9._-] : sûrs entre apostrophes. */
export function fallbackScript(items: FallbackItem[]): string {
  const rows = items.map((i) => `    @{ Name = '${i.name}'; Store = '${i.container === 'roots' ? 'RootCA' : 'SubCA'}'; Sha256 = '${sha256Hex(i.der)}'; Cert = '${i.der.toString('base64')}' }`).join(',\n')
  return `# DDI-Buntu — publication manuelle des autorités de la PKI dans l'Active Directory.
# À exécuter par un administrateur du domaine (membre de « Administrateurs de l'entreprise ») sur une machine jointe au domaine.
# Les certificats ci-dessous sont PUBLICS ; l'empreinte de chacun est contrôlée avant la publication.
$ErrorActionPreference = 'Stop'
$items = @(
${rows}
)
$dir = Join-Path $env:TEMP ('ddi-pki-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $dir | Out-Null
try {
  foreach ($i in $items) {
    $file = Join-Path $dir ($i.Name + '.cer')
    [IO.File]::WriteAllBytes($file, [Convert]::FromBase64String($i.Cert))
    if ((Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLower() -ne $i.Sha256) { throw "Empreinte inattendue pour $($i.Name)" }
    certutil -dspublish -f $file $i.Store
    if ($LASTEXITCODE -ne 0) { throw "certutil a échoué pour $($i.Name)" }
    Write-Host "Publiée : $($i.Name) ($($i.Store))"
  }
} finally { Remove-Item -Recurse -Force -Path $dir -ErrorAction SilentlyContinue }
`
}

/** Attente avant la nouvelle tentative d'une publication en échec : 1 min, 2, 4… plafonnée à 1 h. */
export const backoffSeconds = (attempts: number) => Math.min(3600, 60 * 2 ** Math.max(0, Math.min(attempts, 10)))
