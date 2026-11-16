// Aide Kerberos : fabrication du keytab du serveur DNS pour GSS-TSIG.
// Règles : principal « DNS/<nom que les clients résolvent>@DOMAINE » (domaine = royaume Kerberos, en majuscules) ; compte de SERVICE utilisateur
// DÉDIÉ (jamais un compte existant, en particulier pas le compte de liaison AD de la console) ; AES256 (le compte doit l'accepter).
// Deux méthodes : « ktutil » (sur Linux ; testée, ne dépend pas de ktpass) et « ktpass » (sur un contrôleur de domaine).
const REALM = /^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$/
const HOST = /^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$/
const ACCOUNT = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,19}$/
const NETBIOS = /^[A-Za-z0-9][A-Za-z0-9-]{0,14}$/
export const isIpLike = (h: string) => /^[0-9.]+$/.test(h) || h.includes(':')

export interface KtOpts { account?: string; netbios?: string; kvno?: string }
export interface KtNames { realm: string; host: string; account: string; netbios: string; kvno: string }

/** Valeurs nettoyées : toute entrée invalide retombe sur un exemple sûr (rien d'injectable dans les commandes). */
export function ktNames(realmIn: string, hostIn: string, o: KtOpts = {}): KtNames {
  const realm = (REALM.test(realmIn) ? realmIn : 'CORP.LOCAL').toUpperCase()
  const host = HOST.test(hostIn) && !isIpLike(hostIn) && hostIn.includes('.') ? hostIn.toLowerCase() : `ddi1.${realm.toLowerCase()}`
  const account = ACCOUNT.test(o.account ?? '') ? o.account! : 'svc_ddi_dns'
  const netbios = NETBIOS.test(o.netbios ?? '') ? o.netbios!.toUpperCase() : realm.split('.')[0]!.slice(0, 15)
  const kvno = /^\d{1,5}$/.test(o.kvno ?? '') ? o.kvno! : '2'
  return { realm, host, account, netbios, kvno }
}

/** Variante ktpass (une seule ligne : le « ^ » de continuation n'existe que sous cmd.exe, pas sous PowerShell). */
export function ktpassCommand(realmIn: string, hostIn: string, o: KtOpts = {}): string {
  const n = ktNames(realmIn, hostIn, o)
  return `ktpass -princ DNS/${n.host}@${n.realm} -mapuser ${n.netbios}\\${n.account} -pass +rndpass -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -out dns.keytab`
}

/** Méthode ktutil, étape 1 (PowerShell sur un contrôleur de domaine) : compte dédié, SPN, numéro de version de clé. */
export function ktAccountScript(realmIn: string, hostIn: string, o: KtOpts = {}): string {
  const n = ktNames(realmIn, hostIn, o)
  const dom = n.realm.toLowerCase()
  return [
    `$pw = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })`,
    `New-ADUser -Name ${n.account} -SamAccountName ${n.account} -UserPrincipalName ${n.account}@${dom} -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -KerberosEncryptionType AES256`,
    `setspn -S DNS/${n.host} ${n.account}`,
    `(Get-ADUser ${n.account} -Properties msDS-KeyVersionNumber).'msDS-KeyVersionNumber'`,
    `$pw`,
  ].join('\n')
}

/** Méthode ktutil, étape 2 (Linux, par exemple l'appliance) : le mot de passe est tapé à l'invite, jamais écrit dans une commande. */
export function ktutilSteps(realmIn: string, hostIn: string, o: KtOpts = {}): string {
  const n = ktNames(realmIn, hostIn, o)
  return [
    'ktutil',
    `  addent -password -p DNS/${n.host}@${n.realm} -k ${n.kvno} -e aes256-cts-hmac-sha1-96 -s ${n.realm}${n.account}`,
    '  wkt dns.keytab',
    '  q',
    'klist -ket dns.keytab',
  ].join('\n')
}
