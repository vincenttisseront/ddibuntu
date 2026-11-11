// Active Directory : Kerberos / GSS-TSIG (mises à jour DNS sécurisées) et redirecteurs conditionnels.
// La console ne détient ni le domaine officiel ni le keytab : elle dépose une demande que root (ddibuntu-ad) revalide, puis relit son état publié.
import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { Resolver } from 'node:dns/promises'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { one, query } from '../utils/db'
import { cfg } from '../utils/config'
import { KDC_RE, REALM_RE, depositAdRequest, readAdResult, readAdState, readAdSync } from '../utils/adkrb'
import { isValidDnsName, normIp } from '../utils/net'
import { viewTarget } from '../utils/viewdb'

const bumpGeneration = () => query('update config_generation set generation = generation + 1, changed_at = now() where id = 1')
async function pending(): Promise<boolean> {
  try { await fs.lstat(join(cfg().generatedDir, '.ad-request')); return true } catch { return false }
}
async function deposit(c: any, action: string, req: Parameters<typeof depositAdRequest>[0], keytab?: Buffer, detail?: Record<string, unknown>) {
  if (await pending()) fail(409, 'request_pending')
  const r = await depositAdRequest(req, keytab).catch((e) => { if (e?.message === 'keytab_size') fail(400, 'invalid_input'); throw e })
  await bumpGeneration()   // le rendu BIND dépend de l'état publié par root : la configuration est à redéployer
  await audit(c, `ad.kerberos.${action}`, 'kerberos', undefined, detail)
  return { accepted: true, requestedAt: r.requestedAt }
}

route('GET', '/ad/kerberos', 'operator', async () => {
  const zones = await query<any>("select name, ddns_secure from dns_zones where ddns_secure is not null order by name")
  return { state: await readAdState(), result: await readAdResult(), pending: await pending(), secureZones: zones, sync: await readAdSync() }
})

const Config = z.object({
  realm: z.string().trim().toUpperCase().regex(REALM_RE),
  kdcs: z.array(z.string().trim().regex(KDC_RE)).max(8).default([]),
}).strict()
route('PUT', '/ad/kerberos/config', 'admin', async (c) => {
  const b = await c.body(Config)
  return deposit(c, 'configure', { action: 'configure', realm: b.realm, kdcs: b.kdcs }, undefined, { realm: b.realm, kdcs: b.kdcs.length })
})

// Le keytab est un secret : jamais journalisé, jamais renvoyé. Il passe par un fichier 0600 que root supprime après lecture (même refusé).
const Keytab = z.object({ keytab: z.string().max(90000).regex(/^[A-Za-z0-9+/=\s]+$/) }).strict()
route('PUT', '/ad/kerberos/keytab', 'admin', async (c) => {
  const b = await c.body(Keytab)
  const raw = Buffer.from(b.keytab.replace(/\s+/g, ''), 'base64')
  if (!raw.length || raw.length > 65536 || raw[0] !== 0x05) fail(400, 'invalid_keytab')
  if (!(await readAdState())?.configured) fail(409, 'kerberos_not_configured')
  return deposit(c, 'install-keytab', { action: 'install-keytab' }, raw, { bytes: raw.length })
})
route('POST', '/ad/kerberos/test', 'admin', async (c) => deposit(c, 'test', { action: 'test' }))
route('DELETE', '/ad/kerberos', 'admin', async (c) => deposit(c, 'remove', { action: 'remove' }))

// ---- Redirecteurs conditionnels : vérification (lecture seule) puis création des zones de redirection ----
const ipOk = (v: string) => { const n = normIp(v); return !!n && !/^(0\.|127\.|169\.254\.|22[4-9]\.|23\d\.|24\d\.|25\d\.|::1$|::$|fe80:)/i.test(n) }
const Forwarders = z.object({
  domain: z.string().trim().toLowerCase().transform((v) => v.replace(/\.$/, '')).refine((v) => isValidDnsName(v, false), 'domain'),
  servers: z.array(z.string().trim().refine(ipOk, 'server')).min(1).max(4),
  view_id: z.number().int().positive().nullable().optional(),
}).strict()

async function probe(server: string, domain: string) {
  const r = new Resolver({ timeout: 2000, tries: 1 }); r.setServers([normIp(server)!])
  const t0 = Date.now(), out: any = { server, soa: null, ldap: [], kerberos: [], ms: 0, error: null }
  try { const s = await r.resolveSoa(domain); out.soa = { mname: s.nsname, serial: s.serial } } catch (e: any) { out.error = String(e?.code ?? 'ERROR').slice(0, 24) }
  if (out.soa) {
    try { out.ldap = (await r.resolveSrv(`_ldap._tcp.dc._msdcs.${domain}`)).slice(0, 8).map((x) => x.name) } catch { /* absent : pas un domaine AD */ }
    try { out.kerberos = (await r.resolveSrv(`_kerberos._tcp.${domain}`)).slice(0, 8).map((x) => x.name) } catch { /* idem */ }
  }
  out.ms = Date.now() - t0
  return out
}
route('POST', '/ad/forwarders/check', 'operator', async (c) => {
  const b = await c.body(Forwarders)
  const results = await Promise.all(b.servers.map((s) => probe(s, b.domain)))
  return { domain: b.domain, results, adDetected: results.some((r) => r.ldap.length > 0) }
})

route('POST', '/ad/forwarders/apply', 'operator', async (c) => {
  const b = await c.body(Forwarders)
  const servers = b.servers.map((s) => normIp(s)!)
  const vid = await viewTarget(b.view_id)
  const ex = await one<any>('select id, type from dns_zones where lower(name) = $1 and view_id is not distinct from $2', [b.domain, vid])
  if (ex && ex.type !== 'forward') fail(409, 'zone_exists_not_forward')   // une zone locale du même nom masquerait la redirection
  let id: number
  if (ex) { await query('update dns_zones set forwarders = $2, ad_integrated = true, disabled = false, dirty = true, updated_at = now() where id = $1', [ex.id, servers]); id = ex.id }
  else id = (await one<any>("insert into dns_zones (name, type, forwarders, ad_integrated, view_id) values ($1, 'forward', $2, true, $3) returning id", [b.domain, servers, vid])).id
  await audit(c, ex ? 'ad.forwarder.update' : 'ad.forwarder.create', 'zone', id, { domain: b.domain, servers })
  return { id, created: !ex }
})

export const registered = true
