// Contrôle de cohérence DNS ↔ IPAM (0.10.1) : rapport (lecture) et correction en un clic (opérateur).
import { z } from 'zod'
import { audit, route } from '../utils/router'
import { applyFixes, healthReport } from '../utils/dns-health'

export const registered = true

route('GET', '/dns/health', 'viewer', async () => healthReport())

route('POST', '/dns/health/fix', 'operator', async (c) => {
  const b = await c.body(z.object({ keys: z.array(z.string().max(80)).min(1).max(500) }))
  const r = await applyFixes(b.keys)
  await audit(c, 'dns_health_fix', 'dns_records', undefined, { requested: b.keys.length, ...r })
  return { ...r, report: await healthReport() }
})
