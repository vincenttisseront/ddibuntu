// Navigation entre les consoles des nœuds d'un cluster : adresse de la console d'un nœud, du nœud principal ou de l'adresse de service.
// Le protocole et le port sont ceux de la page courante (HTTPS sur 443 en production) ; calcul au clic, jamais au rendu (pas de décalage d'hydratation).
export function consoleUrl(host: string): string {
  const l = window.location
  return `${l.protocol}//${host}${l.port ? ':' + l.port : ''}/`
}
export function openConsole(host: string) { window.location.assign(consoleUrl(host)) }
export const hostOf = (cidrOrIp: string) => cidrOrIp.split('/')[0] ?? ''

// Où se trouve le primaire : adresse de service si elle existe, sinon l'adresse du nœud principal.
export function primaryTarget(st: any): { host: string; viaVip: boolean } | null {
  if (!st) return null
  if (st.vip?.address) return { host: hostOf(st.vip.address), viaVip: true }
  const lead = (st.nodes ?? []).find((n: any) => n.name === st.leader)
  return lead?.ip ? { host: lead.ip, viaVip: false } : null
}
