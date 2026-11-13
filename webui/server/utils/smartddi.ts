// « Smart DDI » : l'IPAM pilote DHCP et DNS dans la MÊME transaction que la modification de l'adresse.
// Rien ici n'écrit dans un fichier ni ne parle à un démon : la base reste l'unique source, le déploiement rend ensuite la configuration.
import type { PoolClient } from 'pg'
import { fail } from './router'

type Q = Pick<PoolClient, 'query'>

// ---- Règle de nommage d'un gabarit : motif simple, volontairement PAS une expression régulière ----
// '#' = un chiffre, '?' = un caractère [a-z0-9], '*' = une suite (éventuellement vide) de [a-z0-9-] ; tout le reste est littéral.
// Pas d'expression régulière saisie par un utilisateur : aucun risque d'explosion combinatoire (ReDoS) côté serveur.
export const PATTERN_MAX = 100
export function patternError(p: string): string | null {
  if (p.length === 0 || p.length > PATTERN_MAX) return 'pattern_length'
  if (!/^[A-Za-z0-9#?*._-]+$/.test(p)) return 'pattern_chars'
  if ((p.match(/\*/g) ?? []).length > 3) return 'pattern_stars'
  return null
}
export function patternToRegex(p: string): RegExp {
  const body = [...p].map((c) => (c === '#' ? '[0-9]' : c === '?' ? '[a-z0-9]' : c === '*' ? '[a-z0-9-]*' : c.replace(/[.\-_]/g, '\\$&').toLowerCase())).join('')
  return new RegExp(`^${body}$`)
}
export const hostnameMatches = (pattern: string, hostname: string): boolean => patternToRegex(pattern).test(hostname.toLowerCase())

export interface TemplateRow { id: number; name: string; create_scope: boolean; lease_time: number; dhcp_options: any; dns_zone_id: number | null; hostname_pattern: string | null }
export async function templateOfSubnet(q: Q, subnetId: number): Promise<TemplateRow | null> {
  return (await q.query('select t.id, t.name, t.create_scope, t.lease_time, t.dhcp_options, t.dns_zone_id, t.hostname_pattern from network_templates t join subnets s on s.template_id = t.id where s.id = $1', [subnetId])).rows[0] ?? null
}

export interface Naming { pattern: string | null; format: string | null; source: 'vlan' | 'template' | null; vlan: number | null; site: string | null; cidr: string }
/** Règle et format de nommage d'un réseau : le VLAN du réseau l'emporte sur le gabarit, champ par champ. */
export async function namingOfSubnet(q: Q, subnetId: number): Promise<Naming | null> {
  const r = (await q.query(`select text(s.cidr) as cidr, s.site, v.vlan_id as vlan, v.hostname_pattern as vp, v.name_format as vf, t.hostname_pattern as tp, t.name_format as tf
    from subnets s left join vlans v on v.id = s.vlan_id left join network_templates t on t.id = s.template_id where s.id = $1`, [subnetId])).rows[0]
  if (!r) return null
  const pattern = r.vp || r.tp || null, format = r.vf || r.tf || null
  return { pattern, format, source: r.vp || r.vf ? 'vlan' : r.tp || r.tf ? 'template' : null, vlan: r.vlan ?? null, site: r.site ?? null, cidr: r.cidr }
}

/** Refuse un nom d'hôte qui ne respecte pas la règle du réseau (VLAN, sinon gabarit). */
export async function checkHostnameRule(q: Q, subnetId: number, hostname: string | null | undefined): Promise<void> {
  if (!hostname) return
  const n = await namingOfSubnet(q, subnetId)
  if (n?.pattern && !hostnameMatches(n.pattern, hostname)) fail(400, 'hostname_rule', 'hostname_rule', { pattern: n.pattern })
}

/** Zone DNS à alimenter : choix explicite (null = aucune), sinon celle du gabarit du réseau, sinon aucune. */
export async function resolveDnsZone(q: Q, subnetId: number, requested: number | null | undefined): Promise<number | null> {
  if (requested === null) return null
  if (requested) return requested
  return (await templateOfSubnet(q, subnetId))?.dns_zone_id ?? null
}

export type DhcpSync = 'created' | 'updated' | 'removed' | 'no_mac' | 'no_scope' | 'ipv6' | null
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

/**
 * Aligne la réservation DHCP sur l'adresse IPAM (statut « dhcp » + MAC + étendue sur le réseau) : créée, mise à jour ou retirée.
 * La suppression de l'adresse supprime la réservation (clé étrangère en cascade) : pas de réservation orpheline.
 */
export async function syncReservation(cl: Q, addressId: number): Promise<DhcpSync> {
  const a = (await cl.query(`select a.id, a.status, a.hostname, a.mac::text as mac, host(a.ip) as ip, family(a.ip) as fam, d.id as scope_id
    from addresses a left join dhcp_scopes d on d.subnet_id = a.subnet_id where a.id = $1`, [addressId])).rows[0]
  if (!a) return null
  const existing = (await cl.query('select id from dhcp_reservations where address_id = $1', [addressId])).rows[0]
  const want = a.status === 'dhcp'
  if (!want) {
    if (existing) { await cl.query('delete from dhcp_reservations where id = $1', [existing.id]); return 'removed' }
    return null
  }
  if (a.fam !== 4) return 'ipv6'
  if (!a.scope_id) return 'no_scope'
  if (!a.mac) { if (existing) { await cl.query('delete from dhcp_reservations where id = $1', [existing.id]); return 'removed' } return 'no_mac' }
  const host = a.hostname && LABEL.test(String(a.hostname).split('.')[0]!) ? String(a.hostname).split('.')[0] : null
  if (existing) { await cl.query('update dhcp_reservations set mac = $2, hostname = $3 where id = $1', [existing.id, a.mac, host]); return 'updated' }
  // adopte une réservation saisie à la main sur la même IP avant de tenter d'en créer une
  const adopted = await cl.query('update dhcp_reservations set address_id = $1, mac = $4, hostname = $5 where scope_id = $2 and ip = $3 and address_id is null returning id', [addressId, a.scope_id, a.ip, a.mac, host])
  if (adopted.rowCount) return 'updated'
  await cl.query('insert into dhcp_reservations (scope_id, mac, ip, hostname, address_id) values ($1,$2,$3,$4,$5)', [a.scope_id, a.mac, a.ip, host, addressId])
  return 'created'
}
