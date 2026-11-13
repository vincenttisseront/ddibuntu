// Import Active Directory en direct : sites et sous-réseaux lus par LDAP (partition Configuration), zones DNS par transfert AXFR.
import { execFile } from 'node:child_process'
import { cfg } from './config'
import { cidrToString, parseCidr } from './net'
import { byCodeUnit } from './text'
import type { AdSettings, LdapLike } from './ad'

export interface AdSubnet { cidr: string; site: string; description: string; name: string }
export interface AdDiscovery { server: string; configNc: string; sites: string[]; subnets: AdSubnet[] }
const first = (v: unknown): string => String(Array.isArray(v) ? (v[0] ?? '') : (v ?? ''))
/** « CN=Paris,CN=Sites,CN=Configuration,DC=… » -> « Paris » */
const rdnValue = (dn: string): string => (/^[A-Za-z]+=((?:\\.|[^,\\])+)/.exec(dn)?.[1] ?? '').replace(/\\(.)/g, '$1')
/** Partition Configuration déduite du Base DN si le serveur ne l'annonce pas. */
export const configNcFromBaseDn = (baseDn: string): string => `CN=Configuration,${baseDn.split(',').map((s) => s.trim()).filter((s) => /^DC=/i.test(s)).join(',')}`

export class AdImportError extends Error { constructor(public code: string) { super(code) } }

export async function adDiscover(s: AdSettings, bindPassword: string, factory: (url: string) => LdapLike): Promise<AdDiscovery> {
  // une liaison sans mot de passe réussirait « en anonyme » : refusée avant tout
  if (!s.urls.length || !s.bindDn || !bindPassword) throw new AdImportError('ad_incomplete')
  let unreachable = true
  for (const url of s.urls) {
    const cl = factory(url)
    try {
      try { await cl.bind(s.bindDn, bindPassword) } catch { continue }
      unreachable = false
      let configNc = ''
      try {
        const root = await cl.search('', { scope: 'base', filter: '(objectClass=*)', attributes: ['configurationNamingContext'], sizeLimit: 1 })
        configNc = first(root.searchEntries[0]?.configurationNamingContext)
      } catch { /* repli ci-dessous */ }
      if (!configNc) configNc = configNcFromBaseDn(s.baseDn)
      const sitesRes = await cl.search(`CN=Sites,${configNc}`, { scope: 'sub', filter: '(objectClass=site)', attributes: ['cn'], sizeLimit: 5000, paged: true })
      const subRes = await cl.search(`CN=Subnets,CN=Sites,${configNc}`, { scope: 'sub', filter: '(objectClass=subnet)', attributes: ['cn', 'siteObject', 'description', 'location'], sizeLimit: 20000, paged: true })
      const seen = new Set<string>(), subnets: AdSubnet[] = []
      for (const e of subRes.searchEntries) {
        const c = parseCidr(first(e.cn), false)
        if (!c) continue
        const cidr = cidrToString(c)
        if (seen.has(cidr)) continue
        seen.add(cidr)
        const site = rdnValue(first(e.siteObject))
        subnets.push({ cidr, site, description: (first(e.description) || first(e.location)).slice(0, 500), name: site ? `${site} — ${cidr}` : cidr })
      }
      subnets.sort((a, b) => a.cidr.localeCompare(b.cidr, 'en', { numeric: true }))
      return { server: url, configNc, sites: sitesRes.searchEntries.map((e) => first(e.cn)).filter(Boolean).sort(byCodeUnit), subnets }
    } catch (e) {
      if (e instanceof AdImportError) throw e
      /* serveur suivant */
    } finally { await cl.unbind().catch(() => undefined) }
  }
  throw new AdImportError(unreachable ? 'ad_unreachable' : 'ad_search_failed')
}

/** Contrôleurs de domaine autorisés pour un transfert : uniquement ceux des URL LDAPS déjà configurées (jamais un hôte saisi librement). */
export const allowedDcHosts = (s: AdSettings): string[] => s.urls.map((u) => /^ldaps:\/\/([A-Za-z0-9._-]+)/.exec(u)?.[1] ?? '').filter(Boolean)

/** Transfert de zone (AXFR) par « dig » : le serveur doit autoriser l'appliance dans « Zone Transfers » de la zone. */
export function axfrZone(server: string, zone: string, run: typeof execFile = execFile): Promise<string> {
  return new Promise((resolve, reject) => {
    run(cfg().dig, [`@${server}`, zone, 'AXFR', '+noall', '+answer', '+nocomments', '+time=8', '+tries=1'], { timeout: 60000, maxBuffer: 80 * 1024 * 1024 }, (err: any, stdout: any) => {
      if (err && err.code === 'ENOENT') return reject(new AdImportError('axfr_unavailable'))
      const text = String(stdout ?? '')
      // un transfert réussi commence et finit par le SOA ; un refus ou un délai ne produit aucun enregistrement
      const soa = text.split('\n').filter((l) => /\sIN\s+SOA\s/.test(l)).length
      if (soa < 1 || text.split('\n').filter((l) => /\sIN\s/.test(l)).length < 2) return reject(new AdImportError('axfr_failed'))
      resolve(text)
    })
  })
}
