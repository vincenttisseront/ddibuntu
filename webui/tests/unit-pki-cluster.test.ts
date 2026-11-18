// 0.14.9 — la PKI dans le cluster : lecture bornée de ce que root publie (bloc « ejbca » du statut du cluster, pki-cluster.json de ce nœud), nœuds inconnus ignorés,
// valeurs piégées écartées, aucun contenu chiffré ni secret relayé. Les deux formats sont aussi relus tels que les scripts de root les produisent (test différentiel
// avec ddibuntu-cluster et ddibuntu-pki : voir tests/b40-pki-cluster-live.sh, qui lit les mêmes champs).
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'ddi-pki-cl-'))
process.env.DDI_PKI_CLUSTER = join(TMP, 'pki-cluster.json'); process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'
let cl: typeof import('../server/utils/cluster'), pki: typeof import('../server/utils/pki')
beforeAll(async () => { cl = await import('../server/utils/cluster'); pki = await import('../server/utils/pki') })
afterAll(() => rmSync(TMP, { recursive: true, force: true }))

const NOW = 1_800_000_000
const SHA = 'a1b2c3d4e5f6'
const nodes = [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }]
const ready = (over: Record<string, unknown> = {}) => ({ role: 'replica', installed: true, unit: 'inactive', image: 'ready', version: '9.6.3', desired: 'running', synced: SHA, blocked: null, at: NOW - 20, ...over })
const ej = (over: Record<string, unknown> = {}) => ({ enabled: true, state: { sha: SHA, by: 'n1', at: NOW - 60 }, nodes: { n1: ready({ role: 'leader', unit: 'active' }), n2: ready() },
  mark: null, sync: { at: NOW - 10, state: 'synced', message: 'à jour', hash: SHA }, ...over })
const parse = (j: unknown) => cl.parseEjbca(j, nodes)!

describe('bloc « ejbca » du statut du cluster', () => {
  it('lit un état complet', () => {
    const e = parse(ej())
    expect(e.enabled).toBe(true); expect(e.state).toEqual({ sha: SHA, by: 'n1', at: NOW - 60 })
    expect(Object.keys(e.nodes)).toEqual(['n1', 'n2']); expect(e.nodes.n2).toMatchObject({ role: 'replica', unit: 'inactive', image: 'ready', synced: SHA, desired: 'running', blocked: null })
    expect(e.mark).toBeNull(); expect(e.sync).toMatchObject({ state: 'synced', hash: SHA })
  })
  it.each([null, 'texte', 12, [], undefined])('un bloc illisible est ignoré : %j', (v) => { expect(cl.parseEjbca(v, nodes)).toBeNull() })
  it('désactivé tant qu\'aucune PKI n\'est répliquée (état « none » ou absent)', () => {
    expect(parse(ej({ state: { sha: 'none', by: 'n1', at: 1 } })).enabled).toBe(false)
    expect(parse(ej({ state: null })).enabled).toBe(false)
    expect(parse(ej({ enabled: false })).enabled).toBe(false)
  })
  it('un nœud inconnu du registre ou l\'arbitre ne se fait pas passer pour un nœud de données', () => {
    const e = parse(ej({ nodes: { n1: ready(), n3: ready(), evil: ready(), '../x': ready(), n2: ready() } }))
    expect(Object.keys(e.nodes).sort()).toEqual(['n1', 'n2'])
  })
  it('valeurs piégées écartées, jamais recopiées', () => {
    const e = parse(ej({
      state: { sha: SHA, by: '<img src=x>', at: 'x' },
      nodes: { n1: ready({ role: '<script>', unit: 'rm -rf', image: 'x', version: '9.6.3; id', desired: 'x', synced: 'zz', blocked: 'a b' }) },
      mark: { node: 'n1; id', at: 1, from: '9.6.3', to: '9.6.4' }, sync: { at: 1, state: 'pwned', message: 'x', hash: 'y' },
      blob: 'SECRET', secret: 'topsecret' }))
    expect(e.state!.by).toBeNull(); expect(e.state!.at).toBeNull()
    expect(e.nodes.n1).toMatchObject({ role: 'unknown', unit: 'inactive', image: 'none', version: '', desired: 'running', synced: '', blocked: null })
    expect(e.mark).toBeNull(); expect(e.sync).toBeNull()
    expect(JSON.stringify(e)).not.toMatch(/SECRET|topsecret|blob/i)
  })
  it('marque « mise à jour en cours » : nœud, version de départ et d\'arrivée assainis ; marque illisible = nœud « inconnu » (elle bloque quand même)', () => {
    const e = parse(ej({ mark: { node: 'n1', at: NOW - 30, from: '9.6.3', to: 'docker.io/x@sha256:ab<' } }))
    expect(e.mark).toEqual({ node: 'n1', at: NOW - 30, from: '9.6.3', to: 'docker.io/x@sha256:ab' })
    expect(parse(ej({ mark: { node: 'inconnu', at: 0, from: '', to: '' } })).mark).toMatchObject({ node: 'inconnu' })
  })
  it('au plus 16 nœuds lus, message de synchronisation borné', () => {
    const many: Record<string, unknown> = {}; for (let i = 0; i < 40; i++) many['n' + i] = ready()
    const big = cl.parseEjbca(ej({ nodes: many, sync: { at: 1, state: 'failed', message: 'x'.repeat(5000), hash: '' } }), Array.from({ length: 40 }, (_, i) => ({ name: 'n' + i, ip: '10.0.0.' + i, role: 'data' })))!
    expect(Object.keys(big.nodes).length).toBeLessThanOrEqual(16); expect(big.sync!.message.length).toBeLessThanOrEqual(200)
  })
})

describe('statut complet du cluster', () => {
  const doc = (e: unknown) => JSON.stringify({ cluster: 'lab', node: 'n2', role: 'data', local_role: 'replica', at: NOW - 30, etcd: { healthy: true, members: 3 }, peers: nodes,
    patroni: { members: [{ name: 'n1', role: 'leader', state: 'running' }, { name: 'n2', role: 'replica', state: 'streaming' }] }, ejbca: e })
  it('reprend le bloc ejbca', () => {
    const s = cl.parseClusterState(doc(ej()), NOW)!
    expect(s.leader).toBe('n1'); expect(s.ejbca?.enabled).toBe(true); expect(s.ejbca?.nodes.n1!.unit).toBe('active')
  })
  it('un statut sans bloc ejbca (nœud sans PKI, arbitre, ancienne version) donne null', () => {
    expect(cl.parseClusterState(doc(undefined), NOW)!.ejbca).toBeNull()
    expect(cl.parseClusterState(doc(null), NOW)!.ejbca).toBeNull()
  })
})

describe('pki-cluster.json de ce nœud', () => {
  const local = (over: Record<string, unknown> = {}) => ({ at: NOW - 20, role: 'replica', installed: true, unit: 'inactive', image: 'ready', desired: 'running', version: '9.6.3', blocked: null, ...over })
  it('lit l\'état local et le juge périmé au-delà de 3 minutes', () => {
    const r = pki.parsePkiClusterLocal(JSON.stringify(local()), NOW)!
    expect(r).toMatchObject({ role: 'replica', installed: true, unit: 'inactive', image: 'ready', desired: 'running', version: '9.6.3', blocked: null, stale: false, ageSeconds: 20 })
    expect(pki.parsePkiClusterLocal(JSON.stringify(local({ at: NOW - 400 })), NOW)!.stale).toBe(true)
  })
  it('blocage : mise à jour interrompue, etcd injoignable ; raison inconnue ignorée', () => {
    const b = pki.parsePkiClusterLocal(JSON.stringify(local({ role: 'leader', blocked: { reason: 'update-interrupted', node: 'n1', at: 5, from: '9.6.3', to: '9.6.4' } })), NOW)!
    expect(b.blocked).toEqual({ reason: 'update-interrupted', node: 'n1', at: 5, from: '9.6.3', to: '9.6.4' })
    expect(pki.parsePkiClusterLocal(JSON.stringify(local({ blocked: { reason: 'cluster-unreachable' } })), NOW)!.blocked).toEqual({ reason: 'cluster-unreachable' })
    expect(pki.parsePkiClusterLocal(JSON.stringify(local({ blocked: { reason: 'x; id' } })), NOW)!.blocked).toBeNull()
  })
  it.each(['pas du json', '[]', '{}', '{"at":"x"}', 'null'])('document illisible refusé : %s', (raw) => { expect(pki.parsePkiClusterLocal(raw, NOW)).toBeNull() })
  it('valeurs piégées ramenées aux valeurs sûres', () => {
    const r = pki.parsePkiClusterLocal(JSON.stringify(local({ role: '<x>', unit: 'x', image: 'x', desired: 'x', version: '9.6.3<script>', blocked: { reason: 'update-interrupted', node: 'n 1', from: '9.6.3;rm', to: 'a b' } })), NOW)!
    expect(r).toMatchObject({ role: 'unknown', unit: 'inactive', image: 'none', desired: 'running', version: '' })
    expect(r.blocked).toEqual({ reason: 'update-interrupted', from: '9.6.3rm', to: 'ab' })
  })
  it('lecture du fichier : absent = null, fichier réel relu', async () => {
    expect(await pki.readPkiClusterLocal()).toBeNull()
    writeFileSync(process.env.DDI_PKI_CLUSTER!, JSON.stringify(local({ at: Math.floor(Date.now() / 1000) })))
    expect(await pki.readPkiClusterLocal()).toMatchObject({ role: 'replica', stale: false })
    writeFileSync(process.env.DDI_PKI_CLUSTER!, 'x'.repeat(20000))
    expect(await pki.readPkiClusterLocal()).toBeNull()
  })
})
