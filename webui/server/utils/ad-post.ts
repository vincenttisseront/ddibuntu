// Après la migration (0.12.7) : (1) les enregistrements SRV que les clients Windows utilisent pour trouver un contrôleur de domaine,
// (2) un modèle de configuration BIND pour les mises à jour dynamiques sécurisées (GSS-TSIG) — fourni à titre de gabarit, jamais appliqué.
export const LOCATOR_SRV = [
  '_ldap._tcp', '_kerberos._tcp', '_kerberos._udp', '_kpasswd._tcp', '_kpasswd._udp', '_gc._tcp',
  '_ldap._tcp.dc._msdcs', '_kerberos._tcp.dc._msdcs',
] as const

export interface SrvRec { name: string; rdata: string }
export interface LocatorFinding { name: string; kind: 'missing' | 'target_unresolved' | 'bad_rdata'; detail: string }

const host = (s: string) => s.trim().toLowerCase().replace(/\.$/, '')

/** `srv` : SRV de la zone du domaine ; `hosts` : noms complets (sans point final) qui portent un A ou AAAA dans les zones de la console. */
export function checkLocator(zone: string, srv: SrvRec[], hosts: Set<string>): { findings: LocatorFinding[]; present: number; expected: number } {
  const out: LocatorFinding[] = []; let present = 0
  const by = new Map<string, SrvRec[]>()
  for (const r of srv) by.set(r.name.toLowerCase(), [...(by.get(r.name.toLowerCase()) ?? []), r])
  for (const n of LOCATOR_SRV) {
    const rs = by.get(n)
    if (!rs?.length) { out.push({ name: n, kind: 'missing', detail: '' }); continue }
    present++
    for (const r of rs) {
      const p = r.rdata.trim().split(/\s+/)
      if (p.length !== 4 || p.slice(0, 3).some((x) => !/^\d+$/.test(x))) { out.push({ name: n, kind: 'bad_rdata', detail: r.rdata }); continue }
      const target = host(p[3]!)
      const fq = target.includes('.') ? target : `${target}.${zone}`
      if (!hosts.has(fq)) out.push({ name: n, kind: 'target_unresolved', detail: target })
    }
  }
  return { findings: out, present, expected: LOCATOR_SRV.length }
}

export const validRealm = (s: string) => /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(s) && s.includes('.')

/** Gabarit named.conf pour l'authentification Kerberos des mises à jour dynamiques. À valider par l'administrateur : jamais appliqué par la console. */
export function gssTemplate(zone: string, realm: string, keytab = '/etc/bind/dns.keytab'): string {
  const r = realm.toUpperCase()
  return `# Gabarit — à relire puis à placer dans la configuration BIND (la console ne l'applique pas).
# 1. Sur un contrôleur de domaine, créer le compte du serveur DNS et exporter sa clé :
#      ktpass /princ DNS/ddi.${zone.toLowerCase()}@${r} /mapuser DDI-DNS$ /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /out dns.keytab +rndpass
# 2. Copier dns.keytab vers ${keytab} (propriétaire bind, mode 0400).
options {
    tkey-gssapi-keytab "${keytab}";
};
zone "${zone.toLowerCase()}" {
    type primary;
    file "/var/lib/bind/${zone.toLowerCase()}.zone";
    update-policy {
        grant ${r} ms-self * A AAAA PTR;
        grant ${r} ms-subdomain . A AAAA SRV CNAME PTR;
    };
};`
}
