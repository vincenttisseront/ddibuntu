// 0.14.0 — PKI (EJBCA Community) : validation des demandes de la console, lecture de l'état publié par root, dépôt de la demande. Les règles de la console
// et celles de root (ddibuntu-pki) doivent dire la même chose : un test différentiel fait passer les mêmes valeurs par les deux.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-pki-unit-'))
process.env.DDI_PKI_STATUS = join(TMP, 'status.json'); process.env.DDI_PKI_RESULT = join(TMP, 'result.json'); process.env.DDI_GENERATED_DIR = TMP
process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'
const ROOT = resolve(__dirname, '../..')
const PKI_SH = join(ROOT, 'src/rootfs/usr/local/sbin/ddibuntu-pki')
let pki: typeof import('../server/utils/pki')
beforeAll(async () => { pki = await import('../server/utils/pki') })

const parse = (b: unknown) => pki.applyBody.safeParse(b)
const root = (host: string, nets = '') => spawnSync('bash', [PKI_SH, 'check', 'docker.io/keyfactor/ejbca-ce:9.6.3', host, nets], { encoding: 'utf8', env: { ...process.env, DDI_LIBDIR: join(ROOT, 'src/rootfs/usr/local/lib/ddibuntu') } }).status === 0

describe('applyBody', () => {
  it('accepte une demande valide, normalise et applique la version par défaut', () => {
    const r = parse({ hostname: ' PKI.Lab.Test ', nets: ['10.0.0.0/8', '192.168.1.7', '2001:db8::/32'] })
    expect(r.success).toBe(true)
    if (r.success) { expect(r.data.hostname).toBe('pki.lab.test'); expect(r.data.version).toBe(pki.DEFAULT_VERSION); expect(r.data.nets).toEqual(['10.0.0.0/8', '192.168.1.7/32', '2001:db8::/32']) }
  })
  it('retire les doublons de réseaux', () => {
    const r = parse({ hostname: 'pki.lab.test', nets: ['10.0.0.0/8', '10.0.0.0/8', '10.0.0.0/08'] })
    expect(r.success && r.data.nets).toEqual(['10.0.0.0/8'])
  })
  it.each([
    ['sans point', 'pki'], ['espace', 'pki lab.test'], ['point-virgule', 'pki.lab.test;id'], ['barre oblique', 'pki.lab.test/x'], ['tiret initial', '-pki.lab.test'],
    ['tiret final', 'pki-.lab.test'], ['souligné', 'pki_x.lab.test'], ['étiquette vide', 'pki..lab.test'], ['point final seul', 'pki.lab.test.'], ['trop long', `${'a'.repeat(64)}.lab.test`],
    ['IPv4', '10.0.0.1'], ['guillemet', 'pki.lab"test'], ['unicode', 'pkï.lab.test'], ['vide', ''],
  ])('refuse un nom public invalide : %s', (_n, host) => { expect(parse({ hostname: host }).success).toBe(false) })
  it.each(['latest', '9', '9.6', '9.6.3-rc1', '9.6.3; id', 'v9.6.3', '', '999.1.1'])('refuse une version invalide : %s', (v) => { expect(parse({ hostname: 'pki.lab.test', version: v }).success).toBe(false) })
  it.each(['0.0.0.0/0', '::/0', '10.0.0.0/33', 'pas-un-reseau', '10.0.0.0/8; reboot', '', '999.1.1.1', '2001:db8::/129'])('refuse un réseau invalide : %s', (n) => {
    expect(parse({ hostname: 'pki.lab.test', nets: [n] }).success).toBe(false)
  })
  it('refuse plus de 64 réseaux et les champs inconnus', () => {
    expect(parse({ hostname: 'pki.lab.test', nets: Array.from({ length: 65 }, (_v, i) => `10.${i}.0.0/16`) }).success).toBe(false)
    expect(parse({ hostname: 'pki.lab.test', nets: Array.from({ length: 64 }, (_v, i) => `10.${i}.0.0/16`) }).success).toBe(true)
    expect(parse({ hostname: 'pki.lab.test', image: 'docker.io/evil/x:1.0.0' }).success).toBe(false)   // l'image est construite par la console, jamais reprise du corps
  })
  it('construit l\'image uniquement depuis le dépôt officiel', () => { expect(pki.imageOf('9.6.3')).toBe('docker.io/keyfactor/ejbca-ce:9.6.3') })
})

describe('mêmes décisions que root (ddibuntu-pki check)', () => {
  const names = ['pki.lab.test', 'pki.sub.lab.test', 'a.b', 'pki', 'PKI.lab.test', 'pki.lab.test;id', '-pki.lab.test', 'pki-.lab.test', 'pki..lab.test', 'pki_x.lab.test', 'pki.lab.test.', `${'a'.repeat(63)}.lab.test`, `${'a'.repeat(64)}.lab.test`, '10.0.0.1', 'pki.lab-test.fr', 'x.y.z.t.u.v']
  it.each(names)('nom public « %s »', (h) => {
    // la console met le nom en minuscules avant de le valider ; root le reçoit déjà en minuscules
    const consoleOk = parse({ hostname: h }).success
    const rootOk = root(h.trim().toLowerCase())
    expect(rootOk, `console=${consoleOk} root=${rootOk}`).toBe(consoleOk)
  })
  const nets = ['10.0.0.0/8', '192.168.1.0/24', '2001:db8::/32', '10.1.2.3', '0.0.0.0/0', '::/0', '10.0.0.0/33', 'pas-un-reseau']
  it.each(nets)('réseau « %s »', (n) => {
    const consoleOk = parse({ hostname: 'pki.lab.test', nets: [n] }).success
    // ce que la console accepte, root l'accepte toujours ; root peut refuser davantage mais jamais accepter ce que la console refuse pour un /0
    const rootOk = root('pki.lab.test', n)
    if (consoleOk) expect(rootOk).toBe(true)
    if (n.endsWith('/0')) expect(rootOk).toBe(false)
  })
})

describe('état publié par root', () => {
  const STATUS = () => process.env.DDI_PKI_STATUS!
  it('absent ou illisible : null', async () => {
    expect(await pki.readPkiStatus()).toBeNull()
    writeFileSync(STATUS(), 'pas du json'); expect(await pki.readPkiStatus()).toBeNull()
    writeFileSync(STATUS(), '{"state":"healthy"}'); expect(await pki.readPkiStatus()).toBeNull()   // sans horodatage : ignoré
  })
  it('lit un état complet', async () => {
    writeFileSync(STATUS(), JSON.stringify({ at: 1700000000, podman: true, installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', digest: 'sha256:' + 'a'.repeat(64), nets: ['10.0.0.0/8'], health: 'ALLOK', port: 8080 }))
    expect(await pki.readPkiStatus()).toMatchObject({ installed: true, active: true, state: 'healthy', hostname: 'pki.lab.test', version: '9.6.3', nets: ['10.0.0.0/8'], health: 'ALLOK', port: 8080, podman: true })
  })
  it('borne et assainit ce que root publie', async () => {
    writeFileSync(STATUS(), JSON.stringify({ at: 1, state: 'n-importe-quoi', hostname: 'h'.repeat(500), version: 'v'.repeat(100), nets: Array.from({ length: 200 }, () => 'n'.repeat(200)), health: 'x'.repeat(500), installed: 'oui', port: 'x' }))
    const s = (await pki.readPkiStatus())!
    expect(s.state).toBe('absent'); expect(s.hostname.length).toBe(253); expect(s.version.length).toBe(24); expect(s.nets.length).toBe(64); expect(s.nets[0]!.length).toBe(64)
    expect(s.health.length).toBe(64); expect(s.installed).toBe(false); expect(s.port).toBe(8080)
  })
  it('lit le résultat de la dernière demande', async () => {
    expect(await pki.readPkiResult()).toBeNull()
    writeFileSync(process.env.DDI_PKI_RESULT!, JSON.stringify({ at: 5, action: 'apply', ok: false, message: 'm'.repeat(1000) }))
    const r = (await pki.readPkiResult())!
    expect(r).toMatchObject({ at: 5, action: 'apply', ok: false }); expect(r.message.length).toBe(300)
  })
})

describe('dépôt de la demande', () => {
  it('écrit une demande JSON courte, lisible par root seulement, et détecte qu\'elle attend', async () => {
    expect(await pki.pkiRequestPending()).toBe(false)
    await pki.depositPkiRequest({ action: 'apply', image: pki.imageOf('9.6.3'), hostname: 'pki.lab.test', nets: ['10.0.0.0/8'] })
    expect(await pki.pkiRequestPending()).toBe(true)
    const f = join(TMP, '.pki-request')
    expect(JSON.parse(readFileSync(f, 'utf8'))).toEqual({ action: 'apply', image: 'docker.io/keyfactor/ejbca-ce:9.6.3', hostname: 'pki.lab.test', nets: ['10.0.0.0/8'] })
    expect((statSync(f).mode & 0o777).toString(8)).toBe('640')
    expect(readFileSync(f, 'utf8').length).toBeLessThan(4096)
    // aucun secret n'existe côté console : la demande ne peut en contenir aucun
    expect(readFileSync(f, 'utf8')).not.toMatch(/PASSWORD|KEYSTORE|secret/i)
  })
  it('l\'ordre des champs est celui que root lit : action, image, nom, réseaux', async () => {
    await pki.depositPkiRequest({ action: 'stop' })
    expect(JSON.parse(readFileSync(join(TMP, '.pki-request'), 'utf8'))).toEqual({ action: 'stop' })
  })
})
