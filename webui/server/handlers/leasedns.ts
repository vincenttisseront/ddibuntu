// Synchronisation bail DHCP → DNS (0.10.0) : réglage (administrateur), état et passage immédiat.
import { z } from 'zod'
import { audit, route } from '../utils/router'
import { one } from '../utils/db'
import { leaseDnsConf, reconcileLeaseDns, saveLeaseDnsConf } from '../utils/lease-dns'

export const registered = true

async function state() {
  const conf = await leaseDnsConf()
  const n = await one<any>("select count(*)::int as n, count(distinct zone_id)::int as zones from dns_records where source = 'dhcp'")
  return { enabled: conf.enabled, records: n?.n ?? 0, zones: n?.zones ?? 0 }
}

route('GET', '/dns/lease-sync', 'viewer', async () => state())

route('PUT', '/dns/lease-sync', 'admin', async (c) => {
  const b = await c.body(z.object({ enabled: z.boolean() }))
  await saveLeaseDnsConf({ enabled: b.enabled })
  const r = await reconcileLeaseDns()
  await audit(c, 'lease_dns_config', 'settings', undefined, { enabled: b.enabled, ...r })
  return { ...(await state()), run: r }
})

// Passage immédiat (sans attendre le prochain tick).
route('POST', '/dns/lease-sync/run', 'operator', async (c) => {
  const r = await reconcileLeaseDns()
  await audit(c, 'lease_dns_run', 'settings', undefined, r)
  return { ...(await state()), run: r }
})
