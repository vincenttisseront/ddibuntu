// Options DHCP d'une étendue ou d'un gabarit : schéma de validation et normalisation (partagés).
import { z } from 'zod'
import { isValidDnsName, normIp, parseIp } from './net'

export const ip4 = z.string().trim().refine((v) => parseIp(v)?.v === 4, 'ipv4')
const domain = z.string().trim().toLowerCase().refine((v) => isValidDnsName(v, false), 'domain')
export const optionsS = z.object({
  routers: z.array(ip4).max(8).optional(), dnsServers: z.array(ip4).max(8).optional(), domainName: domain.optional(),
  domainSearch: z.array(domain).max(8).optional(), ntpServers: z.array(ip4).max(8).optional(),
  tftpServer: z.string().trim().max(253).regex(/^[A-Za-z0-9._-]*$/).optional(), bootFile: z.string().trim().max(255).regex(/^[\w./-]*$/).optional(),
  custom: z.array(z.object({ code: z.number().int().min(224).max(254), name: z.string().regex(/^[a-z][a-z0-9-]{0,40}$/), type: z.enum(['string', 'uint8', 'uint16', 'uint32', 'ipv4-address', 'boolean']), value: z.string().max(255).regex(/^[\w .,:/@=-]*$/) })).max(10).optional(),
}).strict()
export const cleanOptions = (o: z.infer<typeof optionsS>) => JSON.parse(JSON.stringify({
  ...o, routers: o.routers?.map((x) => normIp(x)), dnsServers: o.dnsServers?.map((x) => normIp(x)), ntpServers: o.ntpServers?.map((x) => normIp(x)),
}))

