// Connexion par annuaire LDAP générique : réglages (administrateur) et test. Le mot de passe de liaison est chiffré et jamais renvoyé.
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import { getSetting, setSetting } from '../utils/db'
import { decryptSecret, encryptSecret } from '../utils/auth'
import { defaultLdapFactory, escapeFilter } from '../utils/ad'
import type { AdSettings } from '../utils/ad'
import { LDAP_DEFAULTS, validFilter } from '../utils/ldap'
import type { LdapSettings } from '../utils/ldap'

export const registered = true
const ATTR = z.string().trim().regex(/^[A-Za-z][A-Za-z0-9-]{0,40}$/)
const body = z.object({
  enabled: z.boolean(), urls: z.array(z.string().regex(/^ldaps:\/\/[A-Za-z0-9._-]+(:\d{1,5})?$/, 'ldaps')).max(5), baseDn: z.string().trim().max(500), bindDn: z.string().trim().max(500),
  bindPassword: z.string().max(200).optional(), clearPassword: z.boolean().optional(),
  userFilter: z.string().trim().max(500), userAttr: ATTR, displayAttr: ATTR, groupMode: z.enum(['memberOf', 'search']), groupBaseDn: z.string().trim().max(500), groupFilter: z.string().trim().max(500),
  groupMap: z.array(z.object({ groupDn: z.string().trim().min(3).max(500), role: z.enum(['admin', 'operator', 'viewer']), spaceIds: z.array(z.number().int().positive()).max(50).optional() })).max(30),
  tlsRejectUnauthorized: z.boolean(), caPem: z.string().max(20000).regex(/^(|-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----\s*)$/).optional(),
})
const load = async (): Promise<LdapSettings> => ({ ...LDAP_DEFAULTS, ...(await getSetting<LdapSettings>('ldap', LDAP_DEFAULTS)) })

route('GET', '/ldap/settings', 'admin', async () => { const { bindPasswordEnc, ...s } = await load(); return { ...s, bindPasswordSet: !!bindPasswordEnc } })
route('PUT', '/ldap/settings', 'admin', async (c) => {
  const b = await c.body(body)
  if (!validFilter(b.userFilter, ['{u}'])) fail(400, 'ldap_bad_filter')
  if (b.groupMode === 'search' && !validFilter(b.groupFilter, [])) fail(400, 'ldap_bad_filter')
  if (b.groupMode === 'search' && !b.groupFilter.includes('{dn}') && !b.groupFilter.includes('{u}')) fail(400, 'ldap_bad_filter')
  if (b.enabled && (!b.urls.length || !b.baseDn || !b.bindDn)) fail(400, 'ldap_incomplete')
  if (b.enabled && !b.groupMap.length) fail(400, 'ldap_no_mapping')
  const cur = await load()
  const { bindPassword, clearPassword, ...rest } = b
  await setSetting('ldap', { ...cur, ...rest, bindPasswordEnc: bindPassword ? encryptSecret(bindPassword) : clearPassword ? undefined : cur.bindPasswordEnc })
  await audit(c, 'ldap_settings', 'settings', 'ldap', { enabled: b.enabled, passwordChanged: !!bindPassword })
  return { ok: true }
})
// Test : liaison de service puis, si un identifiant est donné, recherche de CET utilisateur (sans connexion ni création de compte).
route('POST', '/ldap/test', 'admin', async (c) => {
  const b = await c.body(z.object({ username: z.string().regex(/^[\w.@\- ]{1,256}$/).optional() }))
  const s = await load()
  if (!s.urls.length || !s.bindDn || !s.baseDn) fail(400, 'ldap_incomplete')
  const factory = defaultLdapFactory(s as unknown as AdSettings)
  for (const url of s.urls) {
    const cl = factory(url)
    try {
      try { await cl.bind(s.bindDn, s.bindPasswordEnc ? decryptSecret(s.bindPasswordEnc) : '') } catch { return { ok: false, step: 'bind', server: url } }
      if (b.username) {
        const r = await cl.search(s.baseDn, { scope: 'sub', filter: s.userFilter.replace(/\{u\}/g, escapeFilter(b.username)), attributes: ['dn'], sizeLimit: 2 })
        return { ok: r.searchEntries.length === 1, step: 'search', server: url, found: r.searchEntries.length }
      }
      return { ok: true, step: 'bind', server: url }
    } catch { /* serveur suivant */ } finally { await cl.unbind().catch(() => undefined) }
  }
  return { ok: false, step: 'connect' }
})
