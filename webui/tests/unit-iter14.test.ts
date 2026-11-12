// 0.9.11 — nœud préféré du primaire (lecture bornée, refus préalables) ; sessions signées d'un secondaire (jeton, révocation, anti-force brute).
import { describe, expect, it } from 'vitest'
import { actionRefusal, parseClusterState, parsePreferred } from '../server/utils/cluster'
import { credentialStamp, parseReplicaToken, replicaLoginBlocked, replicaRecordAttempt, signReplicaSession } from '../server/utils/auth'

process.env.DDI_TEST_MODE = '1'
const NOW = 1_800_000_000
const base = {
  cluster: 'lab', node: 'n1', role: 'data', local_role: 'leader', at: NOW - 30, bind: 'primary',
  etcd: { healthy: true, members: 3, quorum: { voters: 3, needed: 2, healthy: 3, hasQuorum: true, tolerance: 1, leader: 'n1', members: [], unknownToEtcd: [] } },
  peers: [{ name: 'n1', ip: '10.9.0.1', role: 'data' }, { name: 'n2', ip: '10.9.0.2', role: 'data' }, { name: 'n3', ip: '10.9.0.3', role: 'witness' }],
  patroni: { members: [{ name: 'n1', role: 'leader', state: 'running' }, { name: 'n2', role: 'replica', state: 'streaming', lag: 0 }] },
}
const mk = (over: Record<string, unknown> = {}) => parseClusterState(JSON.stringify({ ...base, ...over }), NOW)!

describe('nœud préféré dans l\'état publié', () => {
  it('lu quand c\'est un nœud de données du registre', () => {
    expect(mk({ preferred: { node: 'n2', at: 1700000000, by: 'n1' } }).preferred).toEqual({ node: 'n2', at: 1700000000, by: 'n1' })
  })
  it('absent (ancien nœud), arbitre, inconnu ou valeur piégée : null, jamais d\'erreur', () => {
    expect(mk().preferred).toBeNull()
    for (const v of [{ node: 'n3', at: 1, by: 'n1' }, { node: 'zz', at: 1, by: 'n1' }, { node: 7 }, 'n2', [], null]) expect(mk({ preferred: v }).preferred, JSON.stringify(v)).toBeNull()
    expect(parsePreferred({ node: 'n1', at: 'x', by: 'y'.repeat(500) }, mk().nodes)).toEqual({ node: 'n1', at: 0, by: 'y'.repeat(31) })
  })
})

describe('refus préalables du nœud préféré', () => {
  const R = (a: any, over: Record<string, unknown> = {}) => actionRefusal(mk(over), a)
  const set = { action: 'set-preferred', node: 'n2', confirm: 'lab' }
  it('confirmation = nom du cluster ; nœud de données connu uniquement', () => {
    expect(R(set)).toBeNull()
    expect(R({ ...set, confirm: 'autre' })).toBe('confirm_mismatch')
    expect(R({ ...set, node: 'n3' })).toBe('invalid_node')    // l'arbitre ne porte jamais le primaire
    expect(R({ ...set, node: 'inconnu' })).toBe('invalid_node')
  })
  it('quorum exigé, état périmé refusé, nœud d\'arbitre refusé', () => {
    const lost = { etcd: { healthy: false, members: 3, quorum: { ...base.etcd.quorum, hasQuorum: false, healthy: 1 } } }
    expect(R(set, lost)).toBe('quorum_required')
    expect(R(set, { at: NOW - 900 })).toBe('quorum_required')
    expect(R(set, { role: 'witness' })).toBe('action_data_node_only')
  })
  it('retrait : seulement s\'il y a une consigne', () => {
    const clr = { action: 'clear-preferred', confirm: 'lab' }
    expect(R(clr)).toBe('no_preferred')
    expect(R(clr, { preferred: { node: 'n2', at: 1, by: 'n1' } })).toBeNull()
    expect(R({ ...clr, confirm: 'x' }, { preferred: { node: 'n2', at: 1, by: 'n1' } })).toBe('confirm_mismatch')
  })
})

describe('session signée d\'un secondaire', () => {
  const user = { id: 7, password_hash: 'pbkdf2$sha256$600000$AAAA$BBBB', source: 'local' }
  it('jeton valide : utilisateur, empreinte et jeton CSRF reconstitués', () => {
    const s = signReplicaSession(user, 1_000_000)
    const p = parseReplicaToken(s.token, 1_000_000 + 1000)!
    expect(p.uid).toBe(7); expect(p.stamp).toBe(credentialStamp(user)); expect(p.csrf).toBe(s.csrf)
    expect(s.maxAge).toBeLessThanOrEqual(4 * 3600)
  })
  it('échéance respectée', () => {
    const s = signReplicaSession(user, 1_000_000)
    expect(parseReplicaToken(s.token, 1_000_000 + 4 * 3600 * 1000 + 2000)).toBeNull()
  })
  it('jeton altéré, tronqué, d\'un autre format ou signé autrement : refusé', () => {
    const s = signReplicaSession(user, 1_000_000)
    const [pre, payload, sig] = [s.token.slice(0, 3), s.token.slice(3).split('.')[0]!, s.token.slice(3).split('.')[1]!]
    const forged = Buffer.from(JSON.stringify({ u: 1, e: 9_999_999_999, n: 'x', v: credentialStamp(user) })).toString('base64url')
    for (const bad of [`${pre}${forged}.${sig}`, `${pre}${payload}.${sig.slice(0, -2)}AA`, `${pre}${payload}`, `${pre}${payload}.${sig}.x`, 'r1.', 'x1.a.b', '', 'r1.' + 'a'.repeat(700)]) expect(parseReplicaToken(bad, 1_000_000), bad.slice(0, 30)).toBeNull()
  })
  it('l\'empreinte change avec le mot de passe (le jeton est alors révoqué à la lecture de l\'utilisateur)', () => {
    expect(credentialStamp(user)).not.toBe(credentialStamp({ ...user, password_hash: 'autre' }))
    expect(credentialStamp(user)).toBe(credentialStamp({ ...user }))
    expect(credentialStamp(user)).not.toContain('pbkdf2')
  })
  it('anti-force brute en mémoire : 5 échecs par identifiant, 30 par adresse, réussite = remise à zéro, fenêtre de 15 minutes', () => {
    const t0 = 5_000_000
    for (let i = 0; i < 4; i++) replicaRecordAttempt('alice', '203.0.113.5', false, t0 + i)
    expect(replicaLoginBlocked('alice', '203.0.113.5', t0 + 10)).toBe(false)
    replicaRecordAttempt('alice', '203.0.113.5', false, t0 + 5)
    expect(replicaLoginBlocked('ALICE', '203.0.113.9', t0 + 10)).toBe(true)          // insensible à la casse
    expect(replicaLoginBlocked('alice', '203.0.113.5', t0 + 16 * 60_000)).toBe(false)  // fenêtre écoulée
    replicaRecordAttempt('bob', null, false, t0); replicaRecordAttempt('bob', null, true, t0 + 1)
    expect(replicaLoginBlocked('bob', null, t0 + 2)).toBe(false)
    for (let i = 0; i < 30; i++) replicaRecordAttempt('u' + i, '198.51.100.7', false, t0)
    expect(replicaLoginBlocked('nouveau', '198.51.100.7', t0 + 1)).toBe(true)         // 30 échecs depuis la même adresse
  })
})

import { readFileSync } from 'node:fs'
describe('découverte : tout sélectionner', () => {
  it('la case « tout sélectionner » coche l\'ensemble des sous-réseaux IPv4 (état partiel géré)', () => {
    const src = readFileSync(new URL('../app/components/DiscoveryWizard.vue', import.meta.url), 'utf8')
    expect(src).toContain("t('disc.select_all')")
    expect(src).toMatch(/toggleAll = \(on: boolean\) => \{ for \(const s of v4\.value\) pick\[s\.id\] = on \}/)
    expect(src).toContain("'indeterminate'")
  })
})

import { parseUpdate, versionSpread } from '../server/utils/cluster'
describe('mise à jour du cluster : état publié et refus préalables', () => {
  const upd = (o: Record<string, unknown> = {}) => ({ order: null, versions: { n1: '0.9.12', n2: '0.9.12', n3: '0.9.12' }, states: {}, ...o })
  it('lecture bornée : nœuds inconnus, versions et états invalides écartés', () => {
    const s = mk({ update: { order: { target: '0.9.13', at: 5, by: 'n1' }, versions: { n1: '0.9.12', n2: 'x', zz: '1.0.0', n3: ['0.9.12'] }, states: { n1: { state: 'done', at: 1, msg: 'ok' }, n2: { state: 'rm -rf', at: 1 }, zz: { state: 'done' } } } })
    expect(s.update).toEqual({ order: { target: '0.9.13', at: 5, by: 'n1' }, versions: { n1: '0.9.12' }, states: { n1: { state: 'done', at: 1, msg: 'ok' } } })
    expect(mk().update).toBeNull()
    expect(parseUpdate('x', mk().nodes)).toBeNull()
    expect(mk({ update: { order: { target: 'latest' }, versions: {}, states: {} } }).update!.order).toBeNull()
  })
  it('homogénéité : une seule version connue pour tous les nœuds', () => {
    expect(versionSpread(mk({ update: upd() }))).toEqual({ homogeneous: true, versions: ['0.9.12'] })
    expect(versionSpread(mk({ update: upd({ versions: { n1: '0.9.12', n2: '0.9.9', n3: '0.9.12' } }) }))).toEqual({ homogeneous: false, versions: ['0.9.9', '0.9.12'] })
    expect(versionSpread(mk({ update: upd({ versions: { n1: '0.9.12' } }) })).homogeneous).toBe(false)
    expect(versionSpread(mk()).homogeneous).toBe(false)
  })
  const R = (a: any, over: Record<string, unknown> = {}) => actionRefusal(mk(over), a)
  const start = { action: 'update-start', version: '0.9.13', confirm: 'lab' }
  it('démarrage : confirmation, quorum, versions connues, pas de nœud plus récent, un seul ordre à la fois', () => {
    const ok = { update: upd({ versions: { n1: '0.9.12', n2: '0.9.12', n3: '0.9.12' } }) }
    expect(R(start, ok)).toBeNull()
    expect(R({ ...start, confirm: 'x' }, ok)).toBe('confirm_mismatch')
    expect(R(start, { update: upd({ versions: { n1: '0.9.12' } }) })).toBe('versions_unknown')
    expect(R(start)).toBe('versions_unknown')
    expect(R({ ...start, version: '0.9.12' }, ok)).toBe('already_at_target')
    expect(R({ ...start, version: '0.9.10' }, ok)).toBe('node_newer')
    expect(R(start, { update: upd({ order: { target: '0.9.13', at: 1, by: 'n1' } }) })).toBe('update_running')
    expect(R(start, { ...ok, etcd: { healthy: false, members: 3, quorum: { ...base.etcd.quorum, hasQuorum: false, healthy: 1 } } })).toBe('quorum_required')
    expect(R(start, { ...ok, role: 'witness' })).toBe('action_data_node_only')
  })
  it('annulation : seulement avec un ordre en cours', () => {
    const c = { action: 'update-cancel', confirm: 'lab' }
    expect(R(c, { update: upd() })).toBe('no_update')
    expect(R(c, { update: upd({ order: { target: '0.9.13', at: 1, by: 'n1' } }) })).toBeNull()
  })
})

// 0.9.14 — réglages de session communs : relecture stricte de la valeur enregistrée.
import { envSessionDefaults, parseSessionSetting, SESSION_LIMITS } from '../server/utils/session-settings'
describe('réglages de session communs', () => {
  const d = { hours: 8, idleMinutes: 30 }
  it('valeur valide conservée', () => expect(parseSessionSetting({ hours: 12, idleMinutes: 60 }, d)).toEqual({ hours: 12, idleMinutes: 60 }))
  it('hors bornes, texte, flottant, absent : défaut du nœud champ par champ', () => {
    expect(parseSessionSetting({ hours: 0, idleMinutes: 5 }, d)).toEqual({ hours: 8, idleMinutes: 5 })
    expect(parseSessionSetting({ hours: SESSION_LIMITS.hours.max + 1, idleMinutes: 'x' }, d)).toEqual(d)
    expect(parseSessionSetting({ hours: 1.5, idleMinutes: 99999 }, d)).toEqual(d)
    expect(parseSessionSetting(null, d)).toEqual(d)
    expect(parseSessionSetting([1, 2], d)).toEqual(d)
    expect(parseSessionSetting('abc', d)).toEqual(d)
  })
  it('défauts du nœud toujours dans les bornes', () => {
    const e = envSessionDefaults()
    expect(e.hours).toBeGreaterThanOrEqual(SESSION_LIMITS.hours.min); expect(e.hours).toBeLessThanOrEqual(SESSION_LIMITS.hours.max)
    expect(e.idleMinutes).toBeGreaterThanOrEqual(SESSION_LIMITS.idle.min); expect(e.idleMinutes).toBeLessThanOrEqual(SESSION_LIMITS.idle.max)
  })
  it('jeton signé : durée donnée, plafonnée à 4 h', () => {
    const u = { id: 1, password_hash: 'h', source: 'local' }
    expect(signReplicaSession(u, 1_000_000, 2).maxAge).toBe(7200)
    expect(signReplicaSession(u, 1_000_000, 30).maxAge).toBe(4 * 3600)
  })
})

import { missingClusterTools } from '../server/utils/cluster'
describe('composants du cluster (0.9.14)', () => {
  it('liste ce qui manque, selon les dossiers fournis', () => {
    const have = new Set(['/usr/bin/etcd', '/usr/bin/etcdctl'])
    expect(missingClusterTools(['/usr/bin', '', '/opt'], (p) => have.has(p))).toEqual(['patroni', 'patronictl'])
    expect(missingClusterTools(['/usr/bin'], () => true)).toEqual([])
    expect(missingClusterTools([], () => true)).toHaveLength(4)
  })
})

// 0.9.15+ — tâche en cours : lecture assainie des fichiers de demande.
import { mkdtempSync, rmSync, writeFileSync, utimesSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join as pjoin } from 'node:path'
import { cancelPending, readPending } from '../server/utils/cluster'
describe('tâche du cluster en attente', () => {
  const mk = () => mkdtempSync(pjoin(tmpdir(), 'pend-'))
  it('aucune demande : null', async () => { const d = mk(); expect(await readPending(d)).toBeNull(); rmSync(d, { recursive: true }) })
  it('action et nœud lus, contenu inattendu écarté', async () => {
    const d = mk()
    writeFileSync(pjoin(d, '.cluster-action'), JSON.stringify({ action: 'bundle', node: 'vmtools-ddi02', pass: 'secret' }))
    const p = await readPending(d); expect(p).toMatchObject({ kind: 'action', action: 'bundle', node: 'vmtools-ddi02' }); expect(JSON.stringify(p)).not.toContain('secret')
    writeFileSync(pjoin(d, '.cluster-action'), JSON.stringify({ action: '../../etc', node: 'X;rm' }))
    expect(await readPending(d)).toMatchObject({ action: 'other' }); expect((await readPending(d))?.node).toBeUndefined()
    writeFileSync(pjoin(d, '.cluster-action'), 'pas du json'); expect((await readPending(d))?.action).toBe('other')
    rmSync(d, { recursive: true })
  })
  it('création du cluster, bascule et lot de rattachement reconnus ; ancienneté', async () => {
    const d = mk(); writeFileSync(pjoin(d, '.cluster-setup'), JSON.stringify({ action: 'init', name: 'n1' }))
    const old = new Date(Date.now() - 600_000); utimesSync(pjoin(d, '.cluster-setup'), old, old)
    const p = await readPending(d); expect(p).toMatchObject({ kind: 'setup', action: 'init' }); expect(Date.now() / 1000 - p!.since).toBeGreaterThan(590)
    expect(await cancelPending(d)).toBe(1); expect(await readPending(d)).toBeNull()
    writeFileSync(pjoin(d, '.cluster-switchover'), 'vmtools-ddi02\n'); expect(await readPending(d)).toMatchObject({ kind: 'switchover', action: 'switchover', node: 'vmtools-ddi02' })
    rmSync(pjoin(d, '.cluster-switchover')); writeFileSync(pjoin(d, 'cluster-join.bundle'), 'x'); expect(await readPending(d)).toMatchObject({ kind: 'join', action: 'join' })
    rmSync(d, { recursive: true })
  })
})
