// RADIUS actif / passif (0.15.0) : instantané chiffré du dernier déploiement, validation à la relecture, avancement avec la réponse de root, et décision de reprise
// par le nouveau leader. Logique pure : aucune base, aucun disque (l'orchestration est exercée par b28 pour le côté root et par e2e-iter59 pour la console).
import { describe, expect, it } from 'vitest'
import { decryptSecret, encryptSecret } from '../server/utils/auth'
import type { ClusterState } from '../server/utils/cluster'
import type { RadiusStatus } from '../server/utils/radius'
import { BUSY_S, EMPTY_SNAPSHOT, PENDING_TIMEOUT_S, RETRY_AFTER_S, followDecision, openApply, parseSnapshot, reconcile, resultKey, sealApply, snapshotBusy } from '../server/utils/radius-snapshot'
import type { ApplyRequest, SnapshotState } from '../server/utils/radius-snapshot'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'

const REQ: ApplyRequest = { action: 'apply', clients: 'client "a" {\n}\n', pki: { checkCrl: true, ca: 'CA', server: 'SRV', key: 'PRIVATE-KEY-PEM', crls: { 'x.pem': 'CRL' } }, authz: { rules: '[]', ldap: '{"password":"bind-secret"}', caPem: 'LDAPCA' } }
const cluster = (o: Partial<ClusterState> = {}) => ({ nodeRole: 'data', localRole: 'leader', ...o }) as ClusterState
const status = (o: Partial<RadiusStatus> = {}) => ({ installed: true, active: false, ...o }) as RadiusStatus
const state = (o: Partial<SnapshotState> = {}): SnapshotState => ({ ...EMPTY_SNAPSHOT, deployed: sealApply(REQ), ...o })
const base = { cluster: cluster(), recovery: false, state: state(), status: status(), requestPending: false, now: 10_000 }

describe('instantané du dernier déploiement', () => {
  it('relu à l\'identique après chiffrement', () => {
    expect(openApply(sealApply(REQ))).toEqual(REQ)
  })
  it('chiffré : ni la clé privée ni le mot de passe de liaison ne sont lisibles dans la valeur stockée', () => {
    const enc = sealApply(REQ)
    expect(enc).not.toContain('PRIVATE-KEY-PEM'); expect(enc).not.toContain('bind-secret'); expect(enc.startsWith('v1:')).toBe(true)
  })
  it('sans PKI ni règles : seulement les clients', () => {
    const r: ApplyRequest = { action: 'apply', clients: 'x' }
    expect(openApply(sealApply(r))).toEqual(r)
  })
  it('valeur absente, illisible, falsifiée ou de forme inattendue : null (jamais rejouée)', () => {
    expect(openApply(null)).toBeNull(); expect(openApply('')).toBeNull(); expect(openApply('v1:aaaa:bbbb:cccc')).toBeNull(); expect(openApply('pas chiffré')).toBeNull()
    const bad = (o: unknown) => openApply(encryptSecret(JSON.stringify(o)))
    expect(bad({ action: 'stop' })).toBeNull()
    expect(bad({ action: 'apply' })).toBeNull()
    expect(bad({ action: 'apply', clients: 1 })).toBeNull()
    expect(bad({ action: 'apply', clients: 'x', pki: { checkCrl: 'oui', ca: 'a', server: 'b', key: 'c' } })).toBeNull()
    expect(bad({ action: 'apply', clients: 'x', authz: { rules: '[]', ldap: '{}' } })).toBeNull()   // des règles sans PKI n'existent pas
    expect(bad({ action: 'apply', clients: 'x'.repeat(1_048_577) })).toBeNull()
  })
  it('noms de CRL hors format écartés (ils deviennent des noms de fichier chez root)', () => {
    const r = openApply(encryptSecret(JSON.stringify({ action: 'apply', clients: 'x', pki: { checkCrl: false, ca: 'a', server: 'b', key: 'c', crls: { '../etc/passwd': 'x', 'ok.pem': 'y', 'a/b.pem': 'z' } } })))
    expect(Object.keys(r!.pki!.crls)).toEqual(['ok.pem'])
  })
  it('chiffrement réversible avec la clé du cluster seulement', () => {
    const enc = encryptSecret('x')
    expect(decryptSecret(enc)).toBe('x')
    const keep = process.env.DDI_SECRET_KEY
    process.env.DDI_SECRET_KEY = 'une-autre-cle-de-test-0123456789abcdef'
    expect(openApply(sealApply(REQ))).toEqual(REQ)   // la clé change pour tous ensemble
    const enc2 = sealApply(REQ)
    process.env.DDI_SECRET_KEY = keep
    expect(openApply(enc2)).toBeNull()               // une autre clé ne lit pas la valeur
  })
})

describe('lecture de l\'état stocké', () => {
  it('valeur vide ou étrangère : état vide', () => {
    for (const v of [null, undefined, 3, 'x', []]) expect(parseSnapshot(v)).toEqual(EMPTY_SNAPSHOT)
  })
  it('champs inattendus ignorés, valeurs bornées', () => {
    expect(parseSnapshot({ pending: { kind: 'apply', at: 5, prev: 'x'.repeat(999) } }).pending!.prev.length).toBe(400)
    const s = parseSnapshot({ deployed: 'v1:a:b:c', pending: { kind: 'rm -rf', at: 5 }, follow: { at: 7, ok: 'oui', message: 'm'.repeat(999) }, extra: 1 })
    expect(s.pending).toBeNull(); expect(s.follow!.ok).toBeNull(); expect(s.follow!.message.length).toBe(300); expect(Object.keys(s)).toEqual(['deployed', 'pending', 'follow'])
  })
})

describe('avancement avec la réponse de root', () => {
  const pend = (o: object = {}) => state({ deployed: 'ancien', pending: { kind: 'apply', enc: 'nouveau', at: 100, auto: false, prev: '', ...o } })
  const res = (o: object = {}) => ({ at: 101, action: 'apply', ok: true, message: 'Service RADIUS démarré', ...o })
  it('rien en attente : inchangé', () => { const s = state(); expect(reconcile(s, res(), 200)).toBe(s) })
  it('déploiement accepté : devient « le déploiement »', () => {
    const s = reconcile(pend(), res(), 200)
    expect(s.deployed).toBe('nouveau'); expect(s.pending).toBeNull()
  })
  it('déploiement refusé : l\'ancien reste, la demande est retirée', () => {
    const s = reconcile(pend(), res({ ok: false, message: 'refusé' }), 200)
    expect(s.deployed).toBe('ancien'); expect(s.pending).toBeNull()
  })
  it('réponse plus ancienne que la demande ou d\'une autre action : on attend', () => {
    expect(reconcile(pend(), res({ at: 99 }), 200).pending).not.toBeNull()
    expect(reconcile(pend(), res({ action: 'stop' }), 200).pending).not.toBeNull()
    expect(reconcile(pend(), null, 200).pending).not.toBeNull()
  })
  it('l\'ancien résultat de root, même daté de la même seconde, n\'est jamais pris pour la réponse à la nouvelle demande', () => {
    const old = res({ at: 100, message: 'ancien' })
    const p = pend({ prev: resultKey(old) })
    expect(reconcile(p, old, 100).pending).not.toBeNull()                              // toujours en attente
    expect(reconcile(p, res({ at: 100, message: 'nouveau' }), 100).deployed).toBe('nouveau')   // une vraie réponse, même seconde
  })
  it('un dépôt est refusé tant que root n\'a pas répondu (90 s au plus)', () => {
    expect(snapshotBusy(pend(), 100 + BUSY_S - 1)).toBe(true)
    expect(snapshotBusy(pend(), 100 + BUSY_S)).toBe(false)
    expect(snapshotBusy(state(), 100)).toBe(false)
  })
  it('sans réponse de root au bout du délai : demande abandonnée, ancien déploiement conservé', () => {
    const s = reconcile(pend(), null, 100 + PENDING_TIMEOUT_S + 1)
    expect(s.pending).toBeNull(); expect(s.deployed).toBe('ancien')
  })
  it('arrêt accepté : plus rien à rejouer (aucun leader ne redémarre un service arrêté volontairement)', () => {
    const s = reconcile(state({ deployed: 'ancien', pending: { kind: 'stop', at: 100, auto: false, prev: '' } }), res({ action: 'stop', message: 'arrêté' }), 200)
    expect(s.deployed).toBeNull()
  })
  it('arrêt refusé : le déploiement reste', () => {
    expect(reconcile(state({ deployed: 'ancien', pending: { kind: 'stop', at: 100, auto: false, prev: '' } }), res({ action: 'stop', ok: false }), 200).deployed).toBe('ancien')
  })
  it('reprise automatique : le résultat est retenu pour l\'écran', () => {
    const ok = reconcile(pend({ auto: true }), res(), 200)
    expect(ok.follow).toEqual({ at: 100, ok: true, message: 'Service RADIUS démarré' })
    const ko = reconcile(pend({ auto: true }), res({ ok: false, message: 'config refusée' }), 200)
    expect(ko.follow).toEqual({ at: 100, ok: false, message: 'config refusée' })
    expect(reconcile(pend({ auto: true }), null, 100 + PENDING_TIMEOUT_S + 1).follow!.ok).toBe(false)
  })
  it('déploiement manuel : la dernière reprise automatique n\'est pas écrasée', () => {
    const f = { at: 50, ok: true as const, message: 'avant' }
    expect(reconcile({ ...pend(), follow: f }, res(), 200).follow).toEqual(f)
  })
})

describe('le nouveau leader rejoue-t-il le déploiement ?', () => {
  it('leader, déploiement connu, service arrêté : oui', () => {
    expect(followDecision(base)).toEqual({ act: true, reason: expect.any(String) })
  })
  it.each([
    ['hors cluster', { cluster: null }],
    ['arbitre', { cluster: cluster({ nodeRole: 'witness' }) }],
    ['secondaire (rôle Patroni)', { cluster: cluster({ localRole: 'replica' }) }],
    ['secondaire (base en lecture seule)', { recovery: true }],
    ['rôle inconnu', { cluster: cluster({ localRole: 'unknown' }) }],
    ['rien de déployé', { state: state({ deployed: null }) }],
    ['demande déjà en attente chez root', { requestPending: true }],
    ['demande déjà suivie par la console', { state: state({ pending: { kind: 'apply', at: 9_999, auto: true, prev: '' } }) }],
    ['état du service inconnu', { status: null }],
    ['freeradius absent de ce nœud', { status: status({ installed: false }) }],
    ['le service tourne déjà', { status: status({ active: true }) }],
  ])('non : %s', (_n, o) => { expect(followDecision({ ...base, ...o } as any).act).toBe(false) })
  it('au plus une reprise toutes les 5 minutes, même quand la précédente a réussi', () => {
    const f = (ago: number, ok: boolean) => state({ follow: { at: base.now - ago, ok, message: '' } })
    expect(followDecision({ ...base, state: f(RETRY_AFTER_S - 1, false) }).act).toBe(false)
    expect(followDecision({ ...base, state: f(RETRY_AFTER_S - 1, true) }).act).toBe(false)
    expect(followDecision({ ...base, state: f(RETRY_AFTER_S, false) }).act).toBe(true)
  })
})
