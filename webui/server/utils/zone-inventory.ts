// Création des zones à partir de l'inventaire Windows (0.12.3) : une zone vide par zone primaire (à remplir ensuite par fichier ou transfert),
// une zone secondaire avec ses maîtres, une zone de redirection avec ses redirecteurs. Analyse PURE ; l'écriture est dans le gestionnaire.
import { csvObjects } from './ad'
import { isValidDnsName, normIp } from './net'

export type ZoneAction = 'create' | 'exists' | 'skip'
export interface ZonePlanItem {
  name: string; winType: string; type: 'primary' | 'secondary' | 'forward' | null; action: ZoneAction
  reason?: 'stub' | 'no_masters' | 'invalid_name' | 'duplicate'; masters: string[]; forwarders: string[]; adIntegrated: boolean; signed: boolean
}
export interface ZonePlan { items: ZonePlanItem[]; errors: string[] }

const yes = (s: string | undefined) => /^(true|vrai|1|yes|oui)$/i.test((s ?? '').trim())
/** « MasterServers » : adresses séparées par espaces, virgules ou points-virgules ; ne garde que les IPv4/IPv6 valides. */
export const parseServers = (s: string | undefined): string[] => [...new Set((s ?? '').split(/[\s,;]+/).map((x) => normIp(x)).filter((x): x is string => !!x))]

/** `coexist` : adresse du serveur Windows ; les zones primaires deviennent des zones SECONDAIRES de ce serveur (il reste maître jusqu'à la bascule). */
export function planZones(csv: string, existing: Set<string>, coexist: string | null = null): ZonePlan {
  const rows = csvObjects(csv)
  if (!rows.length || !('zonename' in rows[0]!)) return { items: [], errors: ['dns_csv_invalid'] }
  const items: ZonePlanItem[] = [], seen = new Set<string>()
  for (const r of rows) {
    const name = (r.zonename ?? '').trim().toLowerCase().replace(/\.$/, '')
    if (!name || name === '.' || name === 'trustanchors') continue
    const t = (r.zonetype ?? '').toLowerCase(), servers = parseServers(r.masterservers)
    const mirror = !!coexist && t !== 'secondary' && t !== 'forwarder' && t !== 'stub'
    const base = { name, winType: r.zonetype ?? '', masters: [] as string[], forwarders: [] as string[], adIntegrated: yes(r.isdsintegrated), signed: yes(r.issigned) }
    if (!isValidDnsName(name, false)) { items.push({ ...base, type: null, action: 'skip', reason: 'invalid_name' }); continue }
    if (seen.has(name)) { items.push({ ...base, type: null, action: 'skip', reason: 'duplicate' }); continue }
    seen.add(name)
    if (t === 'stub') { items.push({ ...base, type: null, action: 'skip', reason: 'stub' }); continue }
    const type = t === 'secondary' || mirror ? 'secondary' : t === 'forwarder' ? 'forward' : 'primary'
    if (mirror) servers.splice(0, servers.length, coexist!)
    if (type !== 'primary' && !servers.length) { items.push({ ...base, type, action: 'skip', reason: 'no_masters' }); continue }
    items.push({ ...base, type, action: existing.has(name) ? 'exists' : 'create', masters: type === 'secondary' ? servers : [], forwarders: type === 'forward' ? servers : [] })
  }
  return { items, errors: [] }
}
