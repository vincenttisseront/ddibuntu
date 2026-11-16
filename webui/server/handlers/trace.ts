// Traçabilité : historique des associations IP / MAC / nom observées sur les baux DHCP.
import { audit, qint, route } from '../utils/router'
import { query } from '../utils/db'
import { reconcileLeaseDns } from '../utils/lease-dns'
import { searchTrace, snapshotLeases } from '../utils/leasetrace'

export const registered = true

route('GET', '/trace', 'viewer', async (c) => {
  const q = String(c.query.q ?? '').trim().slice(0, 100), limit = qint(c, 'limit', 200, 1, 1000)
  const state = ['open', 'closed'].includes(String(c.query.state)) ? (String(c.query.state) as 'open' | 'closed') : 'all'
  const items = await searchTrace(q, limit, state)
  const st = (await query<any>("select count(*)::int as total, count(*) filter (where open)::int as open, min(first_seen) as since from lease_history"))[0]
  return { q, state, items, stats: st }
})

// Passage immédiat (sans attendre le prochain tick) : utile après un changement DHCP et pour les tests.
route('POST', '/trace/collect', 'operator', async (c) => {
  const r = { ...(await snapshotLeases()), dns: await reconcileLeaseDns() }
  await audit(c, 'trace_collect', 'lease_history', undefined, r)
  return r
})
