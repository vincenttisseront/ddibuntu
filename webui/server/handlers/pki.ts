// PKI du DDI (0.14.0) : EJBCA Community dans un conteneur Podman, sur CE nœud. Cette itération installe, démarre, arrête et désinstalle l'instance et
// publie son état ; les autorités, l'émission et la publication dans l'AD viennent aux itérations suivantes (docs/ROADMAP.md, spec du Project).
// Le service est piloté par root (ddibuntu-pki) à partir d'une demande déposée par la console ; voir utils/pki.ts.
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { query, tx } from '../utils/db'
import { logHistory, recSnap } from '../utils/dns-history'
import { toRelativeName } from '../utils/dns'
import { normIp } from '../utils/net'
import {
  applyBody, depositPkiRequest, imageOf, loadPkiSettings, nodeAddresses, pkiRequestPending, PUBLIC_PORT, readPkiResult, readPkiStatus, savePkiSettings, suggestHostname,
} from '../utils/pki'
import type { PkiRequest } from '../utils/pki'

export const registered = true

const strip = (n: string) => n.trim().toLowerCase().replace(/\.$/, '')

/** Enregistrement DNS du nom public : zone primaire du DDI qui le contient, et adresses déjà publiées sous ce nom. */
async function dnsState(hostname: string) {
  const empty = { hostname, zone: null as string | null, zoneId: null as number | null, records: [] as Array<{ id: number; type: string; rdata: string }>, suggested: nodeAddresses() }
  const h = strip(hostname)
  if (!h) return empty
  const zones = await query<{ id: number; name: string }>(`select id, name from dns_zones where type = 'primary'`)
  const z = zones.filter((x) => h.endsWith('.' + strip(x.name))).sort((a, b) => strip(b.name).length - strip(a.name).length)[0]
  if (!z) return empty
  const rel = toRelativeName(h, z.name)
  if (!rel) return { ...empty, zone: z.name, zoneId: z.id }
  const records = await query<{ id: number; type: string; rdata: string }>(
    `select id, type, rdata from dns_records where zone_id = $1 and lower(name) = lower($2) and type in ('A', 'AAAA', 'CNAME') and not disabled order by type, rdata`, [z.id, rel])
  return { ...empty, zone: z.name, zoneId: z.id, records }
}

route('GET', '/pki', 'admin', async () => {
  const [status, result, settings, suggested] = await Promise.all([readPkiStatus(), readPkiResult(), loadPkiSettings(), suggestHostname()])
  // une instance installée impose son nom et sa version ; sinon, les choix enregistrés, puis la proposition
  // des données conservées (désinstallation ou base d'une installation précédente) imposent leur nom public : il est gravé dans leurs certificats
  const fixed = !!(status && !status.installed && status.dataPresent && status.dataHostname)
  const hostname = status?.installed ? status.hostname : fixed ? status.dataHostname : settings.hostname || suggested
  const base = hostname ? `http://${hostname}:${PUBLIC_PORT}/ejbca/publicweb` : null
  return { status, result, requestPending: await pkiRequestPending(), settings, suggestedHostname: suggested, hostname, locked: !!status?.installed, hostnameFixed: fixed, dns: await dnsState(hostname),
    endpoints: { port: PUBLIC_PORT, health: base ? `${base}/healthcheck/ejbcahealth` : null } }
})

async function deposit(c: Parameters<Parameters<typeof route>[3]>[0], req: PkiRequest, detail?: Record<string, unknown>) {
  if (await pkiRequestPending()) fail(409, 'request_pending')
  const r = await depositPkiRequest(req)
  await audit(c, `pki.${req.action}`, 'pki', undefined, detail)
  return { accepted: true, requestedAt: r.requestedAt }
}

// Installer (ou réappliquer les réseaux d'une instance existante). Le nom public et la version d'une instance installée ne changent plus ici :
// le nom est gravé dans les certificats, la version se change par la mise à jour de la PKI (0.14.5).
route('POST', '/pki/apply', 'admin', async (c) => {
  const b = await c.body(applyBody)
  const st = await readPkiStatus()
  if (st?.installed && st.hostname && st.hostname !== b.hostname) fail(409, 'pki_hostname_locked', undefined, { hostname: st.hostname })
  if (st && !st.installed && st.dataPresent && st.dataHostname && st.dataHostname !== b.hostname) fail(409, 'pki_hostname_locked', undefined, { hostname: st.dataHostname })
  if (st?.installed && st.version && st.version !== b.version) fail(409, 'pki_version_locked', undefined, { version: st.version })
  const out = await deposit(c, { action: 'apply', image: imageOf(b.version), hostname: b.hostname, nets: b.nets }, { hostname: b.hostname, version: b.version, nets: b.nets.length })
  await savePkiSettings({ hostname: b.hostname, version: b.version, nets: b.nets })
  return out
})
for (const action of ['start', 'stop', 'restart', 'status'] as const) {
  route('POST', `/pki/${action}`, 'admin', async (c) => {
    const st = await readPkiStatus()
    if (action !== 'status' && !st?.installed) fail(409, 'pki_not_installed')
    return deposit(c, { action })
  })
}
// Désinstaller retire le conteneur et l'unité ; la base, le volume et les secrets restent (les clés des autorités n'en sont pas détruites).
// Confirmation par saisie du nom public, comme une suppression à grande portée : un appel d'API accidentel ne suffit pas.
route('POST', '/pki/uninstall', 'admin', async (c) => {
  const b = await c.body(z.object({ confirm: z.string().trim().toLowerCase() }).strict())
  const st = await readPkiStatus()
  if (!st?.installed) fail(409, 'pki_not_installed')
  if (b.confirm !== strip(st.hostname)) fail(400, 'pki_confirm_mismatch')
  return deposit(c, { action: 'uninstall' }, { hostname: st.hostname })
})

// Enregistrement DNS du nom public dans la zone du DDI qui le contient. Marqué « protégé » : seul un administrateur peut le modifier ou le supprimer
// (ce nom est gravé dans chaque certificat émis).
route('POST', '/pki/dns', 'admin', async (c) => {
  const b = await c.body(z.object({ address: z.string().trim().min(2).max(45) }).strict())
  const address = normIp(b.address)
  if (!address) fail(400, 'pki_dns_address')
  const hostname = (await readPkiStatus())?.hostname || (await loadPkiSettings()).hostname || await suggestHostname()
  if (!hostname) fail(409, 'pki_hostname_missing')
  const d = await dnsState(hostname)
  if (!d.zoneId || !d.zone) fail(409, 'pki_dns_no_zone')
  if (d.records.length) fail(409, 'pki_dns_exists')
  const rel = toRelativeName(strip(hostname), d.zone)!
  const type = address.includes(':') ? 'AAAA' : 'A'
  const id = await tx(async (cl) => {
    const r = (await cl.query(`insert into dns_records (zone_id, name, type, ttl, rdata, comment, protected, disabled) values ($1,$2,$3,null,$4,$5,true,false) returning id`,
      [d.zoneId, rel, type, address, 'PKI DDI-Buntu : nom public gravé dans les certificats'])).rows[0].id as number
    await cl.query('update dns_zones set dirty = true, updated_at = now() where id = $1', [d.zoneId])
    await logHistory(cl, d.zoneId!, r, c.user!.username, 'create', null, recSnap({ name: rel, type, ttl: null, rdata: address, comment: null, protected: true, disabled: false }))
    return r
  })
  await audit(c, 'pki.dns_create', 'record', id, { name: rel, zone: d.zone, type })
  return { id, name: hostname, type, address }
})
