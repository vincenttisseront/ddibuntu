import http from 'node:http'
import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import { AD_DEFAULTS, authenticateAd, escapeFilter, parseAdSubnets, parseCsv, parseDhcpExport, parseWindowsLease, subtractRanges } from '~~/server/utils/ad'
import type { AdSettings, LdapLike } from '~~/server/utils/ad'
import { fetchList, isPrivateAddress, parseBlocklist } from '~~/server/utils/blocklist'
import { decryptSecret, encryptSecret, hashPassword, passwordPolicyError, verifyPassword } from '~~/server/utils/auth'
import { parseBindLog } from '~~/server/utils/querylog'

process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'; process.env.DDI_ALLOW_PRIVATE_FETCH = '1'

describe('CSV et sous-réseaux AD', () => {
  it('CSV : guillemets, virgules, séparateur ;, BOM', () => {
    expect(parseCsv('\uFEFFa,b\n"x,1","dit ""oui"""\n')).toEqual([['a', 'b'], ['x,1', 'dit "oui"']])
    expect(parseCsv('a;b\r\n1;2')).toEqual([['a', 'b'], ['1', '2']])
  })
  it('Get-ADReplicationSubnet : CIDR, site (nom ou DN), lignes invalides signalées', () => {
    const csv = '"Name","Site","Location"\n"10.1.0.0/16","CN=Paris,CN=Sites,CN=Configuration,DC=corp,DC=local","Siège"\n"10.2.3.4/24","Lyon",""\n"pas-un-reseau","Lyon",""\n'
    const r = parseAdSubnets(csv)
    expect(r.rows).toEqual([{ cidr: '10.1.0.0/16', site: 'Paris', description: 'Siège' }, { cidr: '10.2.3.0/24', site: 'Lyon', description: '' }])
    expect(r.errors).toEqual([{ line: 4, value: 'pas-un-reseau' }])
  })
})

// Export-DhcpServer reconstitué d'après la structure documentée ; à confronter à un vrai export
const DHCP_XML = `<?xml version="1.0" encoding="utf-8"?>
<DHCPServer xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <IPv4>
    <OptionValues><OptionValue><OptionId>15</OptionId><Value>corp.local</Value></OptionValue><OptionValue><OptionId>6</OptionId><Value>10.0.0.10</Value><Value>10.0.0.11</Value></OptionValue></OptionValues>
    <Scopes>
      <Scope><ScopeId>192.168.1.0</ScopeId><Name>LAN Paris</Name><SubnetMask>255.255.255.0</SubnetMask><StartRange>192.168.1.100</StartRange><EndRange>192.168.1.200</EndRange>
        <LeaseDuration>8.00:00:00</LeaseDuration><State>Active</State>
        <ExclusionRanges><IPRange><StartRange>192.168.1.120</StartRange><EndRange>192.168.1.130</EndRange></IPRange></ExclusionRanges>
        <OptionValues><OptionValue><OptionId>3</OptionId><Value>192.168.1.1</Value></OptionValue><OptionValue><OptionId>42</OptionId><Value>192.168.1.2</Value></OptionValue><OptionValue><OptionId>44</OptionId><Value>1.1.1.1</Value></OptionValue></OptionValues>
        <Reservations>
          <Reservation><IPAddress>192.168.1.50</IPAddress><ClientId>AA-BB-CC-DD-EE-01</ClientId><Name>imprimante.corp.local</Name><Description>Compta</Description></Reservation>
          <Reservation><IPAddress>192.168.1.51</IPAddress><ClientId>pas-un-mac</ClientId><Name>x</Name></Reservation>
        </Reservations></Scope>
      <Scope><ScopeId>10.5.0.0</ScopeId><Name>Invités</Name><SubnetMask>255.255.254.0</SubnetMask><StartRange>10.5.0.10</StartRange><EndRange>10.5.1.250</EndRange><LeaseDuration>04:00:00</LeaseDuration><State>InActive</State></Scope>
      <Scope><ScopeId>zzz</ScopeId><SubnetMask>255.255.255.0</SubnetMask></Scope>
    </Scopes>
  </IPv4>
</DHCPServer>`

describe('import DHCP Windows', () => {
  const p = parseDhcpExport(DHCP_XML)
  it('étendues, masque -> CIDR, durée de bail, état', () => {
    expect(p.scopes.map((s) => [s.cidr, s.name, s.leaseTime, s.enabled])).toEqual([['192.168.1.0/24', 'LAN Paris', 691200, true], ['10.5.0.0/23', 'Invités', 14400, false]])
  })
  it('plage moins exclusions -> deux plages', () => {
    expect(p.scopes[0]!.pools).toEqual([{ start: '192.168.1.100', end: '192.168.1.119' }, { start: '192.168.1.131', end: '192.168.1.200' }])
  })
  it('options (globales héritées + propres), option inconnue signalée', () => {
    expect(p.scopes[0]!.options).toEqual({ domainName: 'corp.local', dnsServers: ['10.0.0.10', '10.0.0.11'], routers: ['192.168.1.1'], ntpServers: ['192.168.1.2'] })
    expect(p.warnings).toContainEqual({ scope: '192.168.1.0', code: 'option_unmapped', detail: '44' })
  })
  it('réservations : MAC normalisée, nom d’hôte court, entrée invalide signalée', () => {
    expect(p.scopes[0]!.reservations).toEqual([{ mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.51'.replace('51', '50'), hostname: 'imprimante', description: 'Compta' }])
    expect(p.warnings).toContainEqual({ scope: '192.168.1.0', code: 'reservation_invalid', detail: 'pas-un-mac' })
  })
  it('étendue invalide signalée ; XML invalide et section absente aussi', () => {
    expect(p.warnings).toContainEqual({ scope: 'zzz', code: 'scope_invalid' })
    expect(parseDhcpExport('<x><y></x>').warnings[0]!.code).toBe('xml_invalid')
    expect(parseDhcpExport('<DHCPServer></DHCPServer>').warnings[0]!.code).toBe('no_ipv4_section')
  })
  it('durées et plages', () => {
    expect([parseWindowsLease('8.00:00:00'), parseWindowsLease('01:30:00'), parseWindowsLease('3600'), parseWindowsLease('x')]).toEqual([691200, 5400, 3600, null])
    expect(subtractRanges(1n, 10n, [[3n, 4n], [8n, 20n], [0n, 1n]])).toEqual([[2n, 2n], [5n, 7n]])
  })
})

// ---- Authentification AD avec un annuaire simulé ----
const S: AdSettings = { ...AD_DEFAULTS, enabled: true, urls: ['ldaps://dc1.corp.local'], baseDn: 'DC=corp,DC=local', bindDn: 'CN=svc,DC=corp,DC=local',
  groupMap: [{ groupDn: 'CN=DDI-Viewers,OU=G,DC=corp,DC=local', role: 'viewer' }, { groupDn: 'CN=DDI-Admins,OU=G,DC=corp,DC=local', role: 'admin' }] }
function fakeDirectory(opts: { users: Record<string, { dn: string; pw: string; memberOf: string[]; nested?: string[] }>; svcPw?: string; down?: boolean }) {
  const calls: string[] = []
  const factory = (): LdapLike => {
    let bound: string | null = null
    return {
      async bind(dn, pw) {
        calls.push(`bind:${dn}`)
        if (opts.down) throw new Error('down')
        if (dn === S.bindDn) { if (pw !== (opts.svcPw ?? 'svc-pw')) throw new Error('bad svc'); bound = dn; return }
        const u = Object.values(opts.users).find((x) => x.dn === dn)
        if (!u || u.pw !== pw) throw new Error('bad user')
        bound = dn
      },
      async search(_b, o) {
        calls.push(`search:${o.filter}`)
        const m = o.filter.match(/sAMAccountName=([^)]*)\)/)
        if (o.filter.includes('1.2.840.113556.1.4.1941')) {
          const dn = o.filter.match(/distinguishedName=([^)]*)\)/)![1]!.replace(/\\2c/g, ',')
          const u = Object.values(opts.users).find((x) => x.dn === dn)
          const g = o.filter.match(/:=([^)]*)\)/)![1]!
          return { searchEntries: u?.nested?.some((x) => x.toLowerCase() === g.toLowerCase()) ? [{ dn }] : [] }
        }
        const u = m ? opts.users[m[1]!.replace(/\\[0-9a-f]{2}/g, '')] : undefined
        void bound
        return { searchEntries: u ? [{ dn: u.dn, displayName: 'Jean Dupont', memberOf: u.memberOf, sAMAccountName: m![1] }] : [] }
      },
      async unbind() { /* rien */ },
    }
  }
  return { factory, calls }
}
const U = { jdupont: { dn: 'CN=Jean Dupont,OU=U,DC=corp,DC=local', pw: 'Pa55word!', memberOf: ['CN=DDI-Admins,OU=G,DC=corp,DC=local'] },
  lecteur: { dn: 'CN=Lecteur,OU=U,DC=corp,DC=local', pw: 'Lect-1234', memberOf: ['CN=DDI-Viewers,OU=G,DC=corp,DC=local'] },
  nogroup: { dn: 'CN=Nul,OU=U,DC=corp,DC=local', pw: 'Nul-1234', memberOf: ['CN=Autre,OU=G,DC=corp,DC=local'] },
  imbrique: { dn: 'CN=Imb,OU=U,DC=corp,DC=local', pw: 'Imb-1234', memberOf: [], nested: ['CN=DDI-Admins,OU=G,DC=corp,DC=local'] } }

describe('authentification Active Directory', () => {
  it('administrateur : rôle déduit du groupe', async () => {
    const d = fakeDirectory({ users: U })
    const r = await authenticateAd('jdupont', 'Pa55word!', S, 'svc-pw', d.factory)
    expect(r).toMatchObject({ ok: true, role: 'admin', displayName: 'Jean Dupont' })
  })
  it('le rôle le plus élevé l’emporte ; lecteur = viewer', async () => {
    expect(await authenticateAd('lecteur', 'Lect-1234', S, 'svc-pw', fakeDirectory({ users: U }).factory)).toMatchObject({ ok: true, role: 'viewer' })
  })
  it('groupe imbriqué reconnu (règle de correspondance en chaîne)', async () => {
    expect(await authenticateAd('imbrique', 'Imb-1234', S, 'svc-pw', fakeDirectory({ users: U }).factory)).toMatchObject({ ok: true, role: 'admin' })
    expect(await authenticateAd('imbrique', 'Imb-1234', { ...S, nestedGroups: false }, 'svc-pw', fakeDirectory({ users: U }).factory)).toMatchObject({ ok: false, reason: 'no_group' })
  })
  it('refus : mauvais mot de passe, sans groupe, inconnu, désactivé, annuaire injoignable, compte de service invalide', async () => {
    expect(await authenticateAd('jdupont', 'faux', S, 'svc-pw', fakeDirectory({ users: U }).factory)).toEqual({ ok: false, reason: 'bad_credentials' })
    expect(await authenticateAd('nogroup', 'Nul-1234', S, 'svc-pw', fakeDirectory({ users: U }).factory)).toEqual({ ok: false, reason: 'no_group' })
    expect(await authenticateAd('inconnu', 'x', S, 'svc-pw', fakeDirectory({ users: U }).factory)).toEqual({ ok: false, reason: 'not_found' })
    expect(await authenticateAd('jdupont', 'Pa55word!', { ...S, enabled: false }, 'svc-pw', fakeDirectory({ users: U }).factory)).toEqual({ ok: false, reason: 'disabled' })
    expect(await authenticateAd('jdupont', 'Pa55word!', S, 'svc-pw', fakeDirectory({ users: U, down: true }).factory)).toMatchObject({ ok: false })
    expect(await authenticateAd('jdupont', 'Pa55word!', S, 'mauvais', fakeDirectory({ users: U }).factory)).toEqual({ ok: false, reason: 'service_bind' })
  })
  it('mot de passe vide refusé AVANT toute liaison (liaison anonyme LDAP)', async () => {
    const d = fakeDirectory({ users: U })
    expect(await authenticateAd('jdupont', '', S, 'svc-pw', d.factory)).toEqual({ ok: false, reason: 'empty_password' })
    expect(d.calls).toEqual([])
  })
  it('injection de filtre LDAP : nom d’utilisateur rejeté ou échappé', async () => {
    const d = fakeDirectory({ users: U })
    expect(await authenticateAd('*)(objectClass=*', 'x', S, 'svc-pw', d.factory)).toEqual({ ok: false, reason: 'not_found' })
    expect(d.calls).toEqual([])
    expect(escapeFilter('a*)(\\b\0')).toBe('a\\2a\\29\\28\\5cb\\00')
  })
})

describe('listes de blocage', () => {
  it('formats hosts / domaines / adblock', () => {
    expect(parseBlocklist('# c\n127.0.0.1 localhost\n0.0.0.0 ads.example.com tracker.example.org # x\n0.0.0.0 0.0.0.0\n8.8.8.8 notblocked.com\n', 'hosts').domains).toEqual(['ads.example.com', 'tracker.example.org'])
    expect(parseBlocklist('a.example.com\n*.b.example.com\n# x\nBAD DOMAIN\nA.Example.com.\nlocalhost\n', 'domains').domains).toEqual(['a.example.com', 'b.example.com'])
    expect(parseBlocklist('[Adblock Plus]\n! x\n||ads.example.com^\n@@||ok.example.com^\n||a.com^$third-party\n##.banner\n', 'adblock').domains).toEqual(['ads.example.com'])
  })
  it('plafond d’entrées respecté', () => {
    expect(parseBlocklist(Array.from({ length: 50 }, (_, i) => `d${i}.example.com`).join('\n'), 'domains', 10).domains.length).toBe(10)
  })
  it('adresses privées reconnues (protection SSRF)', () => {
    for (const a of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fc00::1', 'fe80::1', '::ffff:10.0.0.1']) expect(isPrivateAddress(a), a).toBe(true)
    for (const a of ['8.8.8.8', '1.1.1.1', '2606:4700::1111', '172.32.0.1']) expect(isPrivateAddress(a), a).toBe(false)
  })
})

describe('téléchargement protégé', () => {
  let srv: http.Server, port = 0
  beforeAll(async () => {
    srv = http.createServer((req, res) => {
      if (req.url === '/list') { res.end('0.0.0.0 ads.example.com\n'); return }
      if (req.url === '/big') { res.write('a'.repeat(1000)); res.end('b'.repeat(5000)); return }
      if (req.url === '/redir') { res.writeHead(302, { location: '/list' }); res.end(); return }
      if (req.url === '/loop') { res.writeHead(302, { location: '/loop' }); res.end(); return }
      res.writeHead(404); res.end()
    })
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r)); port = (srv.address() as any).port
  })
  afterAll(() => { srv.close() })
  const o = { allowPrivate: true, maxBytes: 4000, timeoutMs: 5000 }
  it('récupère le contenu et son empreinte ; suit une redirection', async () => {
    const r = await fetchList(`http://127.0.0.1:${port}/list`, o)
    expect(r.text).toContain('ads.example.com'); expect(r.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect((await fetchList(`http://127.0.0.1:${port}/redir`, o)).text).toContain('ads.example.com')
  })
  it('refuse : adresse privée par défaut, schéma, identifiants, taille, statut, boucle de redirections', async () => {
    await expect(fetchList(`http://127.0.0.1:${port}/list`, { ...o, allowPrivate: false })).rejects.toMatchObject({ code: 'url_private' })
    await expect(fetchList('file:///etc/passwd', o)).rejects.toMatchObject({ code: 'url_scheme' })
    await expect(fetchList('ftp://x.example/a', o)).rejects.toMatchObject({ code: 'url_scheme' })
    await expect(fetchList('http://user:pw@127.0.0.1/x', o)).rejects.toMatchObject({ code: 'url_credentials' })
    await expect(fetchList(`http://127.0.0.1:${port}/big`, o)).rejects.toMatchObject({ code: 'too_large' })
    await expect(fetchList(`http://127.0.0.1:${port}/absent`, o)).rejects.toMatchObject({ code: 'http_status' })
    await expect(fetchList(`http://127.0.0.1:${port}/loop`, o)).rejects.toMatchObject({ code: 'too_many_redirects' })
    await expect(fetchList('pas une url', o)).rejects.toMatchObject({ code: 'url_invalid' })
  })
})

describe('authentification locale et secrets', () => {
  it('PBKDF2 : vérification, refus d’une empreinte altérée ou mal formée', async () => {
    const h = await hashPassword('Correct-Horse-9')
    expect(h).toMatch(/^pbkdf2\$sha256\$2000\$/)
    expect(await verifyPassword('Correct-Horse-9', h)).toBe(true)
    expect(await verifyPassword('correct-horse-9', h)).toBe(false)
    expect(await verifyPassword('Correct-Horse-9', h.slice(0, -3) + 'AAA')).toBe(false)
    for (const bad of [null, '', 'pbkdf2$sha256$1$x$y', 'md5$x', 'pbkdf2$sha256$999999999$AAAA$AAAA']) expect(await verifyPassword('x', bad as any)).toBe(false)
    expect(await hashPassword('Correct-Horse-9')).not.toBe(h)
  })
  it('politique de mot de passe', () => {
    expect(passwordPolicyError('court', 'u')).toBe('password_short'); expect(passwordPolicyError('xxjdupontxxxxx', 'jdupont')).toBe('password_contains_username'); expect(passwordPolicyError('Correct-Horse-9', 'jdupont')).toBeNull()
  })
  it('chiffrement AES-GCM : aller-retour, altération et mauvaise clé détectées', () => {
    const e = encryptSecret('mot-de-passe-de-liaison')
    expect(e).not.toContain('mot-de-passe'); expect(decryptSecret(e)).toBe('mot-de-passe-de-liaison')
    expect(encryptSecret('x')).not.toBe(encryptSecret('x'))
    const parts = e.split(':'); parts[3] = Buffer.from('altéré').toString('base64')
    expect(() => decryptSecret(parts.join(':'))).toThrow()
    process.env.DDI_SECRET_KEY = 'une-autre-cle-de-test-0123456789abcdef'
    expect(() => decryptSecret(e)).toThrow()
    delete process.env.DDI_SECRET_KEY
  })
})

describe('journaux BIND', () => {
  it('requêtes et réécritures RPZ', () => {
    const log = [
      '2026-11-09T10:15:32.123Z client @0x7f1 10.0.0.5#43210 (example.com): query: example.com IN A + (10.0.0.1)',
      '2026-11-09T10:15:33.000Z rpz: info: client @0x7f1 10.0.0.5#43211 (ads.example.net): rpz QNAME NXDOMAIN rewrite ads.example.net/A/IN via ads.example.net.rpz.ddibuntu.local',
      '2026-11-09T10:15:34.000Z rpz: info: client @0x7f1 10.0.0.5#43212 (ok.example.net): rpz QNAME PASSTHRU rewrite ok.example.net/A/IN via ok.example.net.rpz.ddibuntu.local',
      'ligne sans rapport',
    ].join('\n')
    const e = parseBindLog(log)
    // PASSTHRU = domaine autorisé par une règle : il est désormais conservé (« passthru ») pour le journal du cockpit ; il n'entre jamais dans les statistiques de blocage
    expect(e.map((x) => [x.kind, x.domain, x.client])).toEqual([['query', 'example.com', '10.0.0.5'], ['blocked', 'ads.example.net', '10.0.0.5'], ['passthru', 'ok.example.net', '10.0.0.5']])
    expect(e[0]!.qtype).toBe('A')
    expect(e[0]!.at.toISOString()).toBe('2026-11-09T10:15:32.000Z')
  })
})
