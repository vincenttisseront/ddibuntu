// Baux actifs de Kea sous forme ip → {mac, nom} (vide si la base de baux n'existe pas encore).
import { one, query } from './db'

export const leaseMap = async () => {
  const out = new Map<string, { mac: string; hostname: string | null }>()
  const t = await one<any>("select to_regclass('public.lease4') is not null as ok")
  if (!t?.ok) return out
  try {
    for (const r of await query<any>(`select ((address >> 24) & 255) || '.' || ((address >> 16) & 255) || '.' || ((address >> 8) & 255) || '.' || (address & 255) as ip, encode(hwaddr, 'hex') as mac, hostname from lease4 where expire > now()`))
      out.set(r.ip, { mac: (r.mac as string).match(/.{2}/g)?.join(':') ?? '', hostname: r.hostname || null })
  } catch { /* table de baux indisponible */ }
  return out
}
