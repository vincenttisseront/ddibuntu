import { spawnSync } from 'node:child_process'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { createSocket } from 'node:dgram'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { clientBody, genSecret, normClientAddress, renderClientsConf, SECRET_RE, selftestSecret } from '../server/utils/radius'
import { buildAccessRequest, radiusProbe, verifyReply } from '../server/utils/radius-proto'
import { encryptSecret } from '../server/utils/auth'

const SCRIPT = join(__dirname, '../../src/rootfs/usr/local/sbin/ddibuntu-radius')
const LIB = join(__dirname, '../../src/rootfs/usr/local/lib/ddibuntu')
process.env.DDI_TEST_MODE = '1'   // clé de chiffrement de test (utils/config.ts) ; lue à l'appel, donc posée avant les describe
let dir = ''
beforeAll(() => { dir = mkdtempSync(join(tmpdir(), 'radius-')) })
afterAll(() => { rmSync(dir, { recursive: true, force: true }) })

describe('adresses des clients', () => {
  it('normalise une adresse ou un réseau', () => {
    expect(normClientAddress('10.10.0.5')).toBe('10.10.0.5/32'); expect(normClientAddress('10.10.0.9/24')).toBe('10.10.0.0/24')
    expect(normClientAddress('2001:db8::1')).toBe('2001:db8::1/128'); expect(normClientAddress('2001:DB8:0:0::/48')).toBe('2001:db8::/48')
  })
  it('refuse réseaux trop larges, bouclage, multicast, lien local, valeurs invalides', () => {
    for (const bad of ['10.0.0.0/15', '0.0.0.0/0', '127.0.0.1', '127.0.0.0/24', '224.0.0.1', '169.254.1.1', '0.1.2.3', '2001:db8::/47', '::1', '::', 'ff02::1', 'fe80::1', 'nimporte quoi', '', '10.0.0.1; drop', '10.0.0/24', '10.0.0.1/33'])
      expect(normClientAddress(bad), bad).toBeNull()
    expect(normClientAddress('10.0.0.0/16')).toBe('10.0.0.0/16')
  })
})

describe('secrets', () => {
  it('le secret généré respecte la règle et varie', () => {
    const a = genSecret(), b = genSecret()
    expect(a).toMatch(SECRET_RE); expect(a).toHaveLength(32); expect(a).not.toBe(b)
  })
  it('règle de forme : 16 à 128 caractères sûrs', () => {
    expect(SECRET_RE.test('abcdefghijklmnop')).toBe(true); expect(SECRET_RE.test('abcdefghijklmno')).toBe(false)
    for (const c of ['"', '\\', '$', '%', '#', ' ', "'", '`', '{', '}', '\n']) expect(SECRET_RE.test(`abcdefghijklmno${c}`), JSON.stringify(c)).toBe(false)
  })
  it('le secret du client d\'essai est stable et propre à la clé', () => {
    expect(selftestSecret()).toMatch(/^[0-9a-f]{32}$/); expect(selftestSecret()).toBe(selftestSecret())
  })
})

describe('corps d\'un client', () => {
  const ok = { name: 'WLC-01', address: '10.10.0.9/24', usage: 'wifi' }
  it('normalise le nom, le réseau, applique les défauts', () => {
    const r = clientBody.parse(ok)
    expect(r).toMatchObject({ name: 'wlc-01', address: '10.10.0.0/24', usage: 'wifi', enabled: true, secret: null, comment: null })
  })
  it('refuse : nom réservé, adresse, secret, champ inconnu, usage', () => {
    for (const b of [{ ...ok, name: 'ddi-selftest' }, { ...ok, name: '1abc' }, { ...ok, address: '127.0.0.1' }, { ...ok, secret: 'court' }, { ...ok, secret: 'a"b'.repeat(8) }, { ...ok, extra: 1 }, { ...ok, usage: 'autre' }])
      expect(clientBody.safeParse(b).success, JSON.stringify(b)).toBe(false)
  })
  it('accepte un secret fourni conforme', () => { expect(clientBody.parse({ ...ok, secret: 'abcdefABCDEF._~+=:@,;()!*-0123' }).secret).toBe('abcdefABCDEF._~+=:@,;()!*-0123') })
})

describe('clients.conf', () => {
  const rows = [
    { name: 'wlc-01', address: '10.10.0.0/24', secret_enc: encryptSecret('abcdefABCDEF0123456789'), enabled: true },
    { name: 'vpn-gw', address: '192.0.2.7/32', secret_enc: encryptSecret('zzzzzzzzzzzzzzzzzzzz'), enabled: true },
    { name: 'off', address: '10.11.0.0/24', secret_enc: encryptSecret('offoffoffoffoffoffoff'), enabled: false },
    { name: 'v6', address: '2001:db8::/48', secret_enc: encryptSecret('v6v6v6v6v6v6v6v6v6v6'), enabled: true },
  ]
  const text = renderClientsConf(rows)
  it('contient le client d\'essai, les clients actifs triés, pas le désactivé', () => {
    expect(text.indexOf('client "ddi-selftest"')).toBe(0)
    expect([...text.matchAll(/^client "([^"]+)"/gm)].map((m) => m[1])).toEqual(['ddi-selftest', 'v6', 'vpn-gw', 'wlc-01'])
    expect(text).toContain('ipaddr = 192.0.2.7\n'); expect(text).toContain('ipaddr = 10.10.0.0/24\n'); expect(text).toContain('ipv6addr = 2001:db8::/48\n')
    expect(text).not.toContain('"off"'); expect(text.match(/require_message_authenticator = yes/g)).toHaveLength(4)
  })
  it('est accepté tel quel par la validation de root (même contrat)', () => {
    const f = join(dir, 'ok.conf'); writeFileSync(f, text)
    const r = spawnSync('bash', [SCRIPT, 'check', f], { env: { ...process.env, DDI_LIBDIR: LIB }, encoding: 'utf8' })
    expect(r.status, r.stderr).toBe(0)
    expect(r.stdout.trim().split('\n').sort()).toEqual(['10.10.0.0/24', '192.0.2.7/32', '2001:db8::/48'])
  })
  it('root refuse ce que la console ne produirait jamais', () => {
    const cases: Record<string, string> = {
      'directive libre': text.replace('nas_type = other', 'nas_type = other\n\texec_wait = yes'),
      'sans client d\'essai': text.replace(/client "ddi-selftest"[\s\S]*?\n}\n\n/, ''),
      'client d\'essai détourné': text.replace('ipaddr = 127.0.0.1', 'ipaddr = 10.0.0.1'),
      'réseau trop large': text.replace('10.10.0.0/24', '10.0.0.0/8'),
      'bouclage': text.replace('ipaddr = 192.0.2.7', 'ipaddr = 127.0.0.2'),
      'secret court': text.replace(/secret = "zzzz[^"]*"/, 'secret = "court"'),
      'secret avec guillemet': text.replace(/secret = "zzzz[^"]*"/, 'secret = "aaaaaaaaaaaaaaaa\\"x"'),
      'include': `$INCLUDE /etc/passwd\n${text}`,
      'doublon': `${text}\n${text.slice(text.indexOf('client "wlc-01"'))}`,
      'bloc non fermé': text.replace(/\}\n$/, ''),
      'shortname différent': text.replace('shortname = wlc-01', 'shortname = autre'),
    }
    for (const [label, body] of Object.entries(cases)) {
      const f = join(dir, 'bad.conf'); writeFileSync(f, body)
      const r = spawnSync('bash', [SCRIPT, 'check', f], { env: { ...process.env, DDI_LIBDIR: LIB }, encoding: 'utf8' })
      expect(r.status, label).toBe(1)
    }
  })
})

describe('protocole RADIUS', () => {
  const secret = 'abcdefghijklmnopqrstuvwxyz012345'
  // serveur de référence indépendant (RFC 2865 / 3579), pour contrôler la sonde sans dépendre d'un démon
  function server(mode: 'reject' | 'accept' | 'badauth' | 'badma' | 'silent' | 'otherid') {
    return new Promise<{ port: number; seen: { ma: boolean; user: string; pass: string }[]; close: () => void }>((resolve) => {
      const s = createSocket('udp4'); const seen: { ma: boolean; user: string; pass: string }[] = []
      s.on('message', (m, r) => {
        // attributs de la requête
        const attrs: Record<number, Buffer> = {}
        for (let o = 20; o < m.length;) { attrs[m[o]!] = m.subarray(o + 2, o + m[o + 1]!); o += m[o + 1]! }
        const tmp = Buffer.from(m); tmp.fill(0, m.length - 16)
        const maOk = createHmac('md5', secret).update(tmp).digest().equals(m.subarray(m.length - 16))
        // User-Password déchiffré
        let pass = Buffer.alloc(0), prev = m.subarray(4, 20)
        for (let i = 0; i < attrs[2]!.length; i += 16) { const b = createHash('md5').update(Buffer.concat([Buffer.from(secret), prev])).digest(); pass = Buffer.concat([pass, Buffer.from(attrs[2]!.subarray(i, i + 16).map((x, j) => x ^ b[j]!))]); prev = attrs[2]!.subarray(i, i + 16) }
        seen.push({ ma: maOk, user: attrs[1]!.toString(), pass: pass.toString().replace(/\0+$/, '') })
        if (mode === 'silent' || !maOk) return   // comme un vrai serveur : secret inconnu ou signature invalide → aucune réponse
        const code = mode === 'accept' ? 2 : 3
        const body = Buffer.concat([Buffer.from([80, 18]), Buffer.alloc(16)])
        const head = Buffer.alloc(20); head[0] = code; head[1] = mode === 'otherid' ? m[1]! ^ 1 : m[1]!; head.writeUInt16BE(20 + body.length, 2); m.subarray(4, 20).copy(head, 4)
        const ma = createHmac('md5', secret).update(Buffer.concat([head, body])).digest(); ma.copy(body, 2)
        if (mode === 'badma') body[2] = body[2]! ^ 0xff
        const pkt = Buffer.concat([head, body])
        const ra = createHash('md5').update(Buffer.concat([pkt.subarray(0, 4), m.subarray(4, 20), pkt.subarray(20), Buffer.from(secret)])).digest()
        if (mode === 'badauth') ra[0] = ra[0]! ^ 1
        ra.copy(pkt, 4); s.send(pkt, r.port, r.address)
      })
      s.bind(0, '127.0.0.1', () => resolve({ port: s.address().port, seen, close: () => s.close() }))
    })
  }
  it('requête bien formée : Message-Authenticator valide, mot de passe PAP déchiffrable', async () => {
    const srv = await server('reject'); const r = await radiusProbe({ port: srv.port, secret, timeoutMs: 1500 }); srv.close()
    expect(r).toMatchObject({ ok: true, reply: 'reject' }); expect(srv.seen[0]).toMatchObject({ ma: true, user: 'ddi-selftest' }); expect(srv.seen[0]!.pass).toMatch(/^[0-9a-f]{24}$/)
  })
  it('distingue accept et refus', async () => { const s = await server('accept'); expect((await radiusProbe({ port: s.port, secret })).reply).toBe('accept'); s.close() })
  it('rejette une réponse falsifiée (authentificateur, Message-Authenticator, identifiant)', async () => {
    for (const m of ['badauth', 'badma', 'otherid'] as const) { const s = await server(m); expect(await radiusProbe({ port: s.port, secret, timeoutMs: 800 }), m).toMatchObject({ ok: false }); s.close() }
  })
  it('mauvais secret ou serveur muet : pas de réponse', async () => {
    const s = await server('reject'); expect(await radiusProbe({ port: s.port, secret: 'x'.repeat(32), timeoutMs: 600 })).toMatchObject({ ok: false, error: 'timeout' }); s.close()
    const m = await server('silent'); expect(await radiusProbe({ port: m.port, secret, timeoutMs: 400 })).toMatchObject({ ok: false, error: 'timeout' }); m.close()
  })
  it('verifyReply : paquets tronqués ou aberrants refusés', () => {
    const { packet, auth } = buildAccessRequest(secret, 'u', 'p', 7)
    for (const bad of [Buffer.alloc(0), Buffer.alloc(19), randomBytes(40), packet.subarray(0, 25)]) expect(verifyReply(secret, 7, auth, bad)).toBeNull()
  })
})
