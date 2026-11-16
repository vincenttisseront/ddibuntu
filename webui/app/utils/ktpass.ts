// Commande ktpass (à lancer sur un contrôleur de domaine) qui crée le keytab du serveur DNS pour GSS-TSIG.
// Règles : principal « DNS/<nom que les clients résolvent>@DOMAINE » (casse du domaine = royaume Kerberos, en majuscules) ; compte de SERVICE utilisateur
// dédié (pas un compte machine) ; mot de passe aléatoire (+rndpass : personne n'a à le connaître) ; AES256 (le compte doit accepter AES 256 bits).
const REALM = /^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$/
const HOST = /^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$/
export const isIpLike = (h: string) => /^[0-9.]+$/.test(h) || h.includes(':')

export function ktpassCommand(realmIn: string, hostIn: string): string {
  const realm = (REALM.test(realmIn) ? realmIn : 'CORP.LOCAL').toUpperCase()
  const host = HOST.test(hostIn) && !isIpLike(hostIn) && hostIn.includes('.') ? hostIn.toLowerCase() : `ddi1.${realm.toLowerCase()}`
  const netbios = realm.split('.')[0]!
  // une seule ligne : le « ^ » de continuation n'existe que sous cmd.exe, pas sous PowerShell
  return `ktpass -princ DNS/${host}@${realm} -mapuser ${netbios}\\svc-ddi-dns -pass +rndpass -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -out dns.keytab`
}
