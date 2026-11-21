// 0.21.0 — certificat HTTPS de la console, automatique et commun à tous les nœuds : décisions, noms voulus, dépôt sur le nœud, boucle d'émission.
// L'émission réelle par la PKI (EJBCA) n'est pas rejouée ici : elle est injectée.
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { consoleTlsTick, certNames, EMPTY_TLS, firstCert, installDecision, issueDecision, parseTls, RENEW_DAYS, tlsBody, wantedNames, writeFiles } from '../server/utils/console-tls'
import type { Deps, TlsState } from '../server/utils/console-tls'
import { decryptSecret, encryptSecret } from '../server/utils/auth'

const TMP = mkdtempSync(join(tmpdir(), 'ctls-'))
function mk(name: string, san: string, days = 400): { cert: string; key: string } {
  const k = join(TMP, `${name}.key`), c = join(TMP, `${name}.crt`)
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', String(days), '-subj', `/CN=${name}`, '-addext', `subjectAltName=${san}`, '-keyout', k, '-out', c], { stdio: 'ignore' })
  return { cert: readFileSync(c, 'utf8'), key: readFileSync(k, 'utf8') }
}
let A: { cert: string; key: string }, B: { cert: string; key: string }, SHORT: { cert: string; key: string }
beforeAll(() => {
  A = mk('a', 'DNS:console.lab.test,DNS:n1.lab.test,DNS:n1,DNS:n2.lab.test,DNS:n2,IP:10.0.0.10,IP:10.0.0.11,IP:10.0.0.12')
  B = mk('b', 'DNS:console.lab.test,DNS:n1.lab.test,DNS:n2.lab.test,IP:10.0.0.10,IP:10.0.0.11')
  SHORT = mk('s', 'DNS:console.lab.test,IP:10.0.0.10', 5)
})
afterAll(() => rmSync(TMP, { recursive: true, force: true }))

const NOW = Math.floor(Date.now() / 1000)
const NODES = [{ name: 'n1', ip: '10.0.0.11', host: 'n1.lab.test' }, { name: 'n2', ip: '10.0.0.12', host: 'n2.lab.test' }]
const cert = (x: { cert: string; key: string }, over: Record<string, unknown> = {}) => {
  const n = certNames(x.cert)!
  return { pem: x.cert, chain: '', keyEnc: encryptSecret(x.key), serial: '01', notAfter: n.notAfter, dns: n.dns, ip: n.ip, at: NOW, ...over }
}
const S = (o: Partial<TlsState> = {}): TlsState => ({ ...EMPTY_TLS, auto: true, ca: 'Lab-Sub', names: ['console.lab.test'], ...o })

describe('lecture et noms voulus', () => {
  it('un état abîmé donne l\'état vide, jamais une exception', () => {
    expect(parseTls(null)).toEqual(EMPTY_TLS); expect(parseTls('x')).toEqual(EMPTY_TLS)
    expect(parseTls({ auto: 'oui', ca: 5, names: [1, 'a.b'], cert: { pem: 1 } })).toMatchObject({ auto: false, ca: '', names: ['a.b'], cert: null })
  })
  it('les noms de l\'administrateur d\'abord, puis la console des postes, puis les nœuds ; adresse virtuelle d\'abord ; sans doublon', () => {
    const w = wantedNames({ names: ['Console.lab.test'] }, 'console.lab.test', NODES, '10.0.0.10')
    expect(w.dns).toEqual(['console.lab.test', 'n1.lab.test', 'n1', 'n2.lab.test', 'n2']); expect(w.ip).toEqual(['10.0.0.10', '10.0.0.11', '10.0.0.12']); expect(w.truncated).toBe(false)
  })
  it('plafonnés comme le profil serveur (8 noms, 4 adresses) et signalés', () => {
    const many = Array.from({ length: 6 }, (_, i) => ({ name: `nd${i}`, ip: `10.0.1.${i}`, host: `nd${i}.lab.test` }))
    const w = wantedNames({ names: ['c.lab.test'] }, '', many, '10.0.0.1')
    expect(w.dns).toHaveLength(8); expect(w.ip).toHaveLength(4); expect(w.truncated).toBe(true)
  })
  it('un nom invalide est ignoré', () => { expect(wantedNames({ names: ['pas valide!'] }, 'a b', [], null).dns).toEqual([]) })
  it('le corps des réglages est strict', () => {
    expect(tlsBody.safeParse({ auto: true, ca: 'X', names: ['A.b.c'] }).data).toEqual({ auto: true, ca: 'X', names: ['a.b.c'] })
    for (const bad of [{ auto: true, ca: 'X', names: ['a b'] }, { auto: true, ca: 'X', names: Array(9).fill('a.b') }, { auto: 1, ca: 'X', names: [] }, { auto: true, ca: 'X', names: [], x: 1 }]) expect(tlsBody.safeParse(bad).success).toBe(false)
  })
})

describe('décisions', () => {
  const want = (dns: string[], ip: string[] = []) => ({ dns, ip, truncated: false })
  it('rien sans réglage, sans autorité ou sans nom', () => {
    expect(issueDecision(S({ auto: false }), want(['a.b']), NOW)).toEqual({ act: false, reason: 'disabled' })
    expect(issueDecision(S({ ca: '' }), want(['a.b']), NOW)).toEqual({ act: false, reason: 'no_ca' })
    expect(issueDecision(S(), want([]), NOW)).toEqual({ act: false, reason: 'no_names' })
  })
  it('premier certificat, nouveaux noms, échéance proche ; sinon rien', () => {
    expect(issueDecision(S(), want(['console.lab.test']), NOW)).toEqual({ act: true, reason: 'first' })
    const ok = S({ cert: cert(A) })
    expect(issueDecision(ok, want(['console.lab.test', 'n1.lab.test'], ['10.0.0.10']), NOW)).toEqual({ act: false, reason: 'current' })
    expect(issueDecision(ok, want(['console.lab.test', 'n3.lab.test']), NOW)).toEqual({ act: true, reason: 'names' })
    expect(issueDecision(ok, want(['console.lab.test'], ['10.0.0.99']), NOW)).toEqual({ act: true, reason: 'names' })
    expect(issueDecision(S({ cert: cert(SHORT) }), want(['console.lab.test']), NOW)).toEqual({ act: true, reason: 'expiry' })
    expect(RENEW_DAYS).toBe(30)
  })
  it('après un échec, on attend avant de réessayer', () => {
    const failed = S({ last: { at: NOW - 60, ok: false, message: 'x' } })
    expect(issueDecision(failed, want(['a.b']), NOW)).toEqual({ act: false, reason: 'wait' })
    expect(issueDecision(S({ last: { at: NOW - 3600, ok: false, message: 'x' } }), want(['a.b']), NOW)).toEqual({ act: true, reason: 'first' })
  })
  it('installation : rien / déjà servi / à installer / expiré', () => {
    expect(installDecision(S(), A.cert, NOW)).toBe('none')
    expect(installDecision(S({ cert: cert(A) }), A.cert, NOW)).toBe('current')
    expect(installDecision(S({ cert: cert(A) }), B.cert, NOW)).toBe('install')
    expect(installDecision(S({ cert: cert(A) }), '', NOW)).toBe('install')
    expect(installDecision(S({ cert: cert(A) }), A.cert, NOW + 800 * 86400)).toBe('invalid')
  })
  it('lit le SAN, l\'échéance et le caractère auto-signé', () => {
    const n = certNames(A.cert)!
    expect(n.dns).toEqual(['console.lab.test', 'n1.lab.test', 'n1', 'n2.lab.test', 'n2']); expect(n.ip).toEqual(['10.0.0.10', '10.0.0.11', '10.0.0.12']); expect(n.selfSigned).toBe(true)
    expect(certNames('rien')).toBeNull(); expect(firstCert(A.cert + B.cert)).toBe(A.cert)
  })
})

describe('dépôt sur le nœud', () => {
  it('écrit la clé en 0600 et le certificat avec sa chaîne ; refuse une clé qui ne correspond pas', async () => {
    const dir = join(TMP, 'dep'), d = { dir, decrypt: decryptSecret }
    await writeFiles(d, cert(A, { chain: B.cert }) as any)
    expect(statSync(join(dir, 'console.key')).mode & 0o777).toBe(0o600); expect(readFileSync(join(dir, 'console.crt'), 'utf8')).toBe(A.cert.trim() + '\n' + B.cert.trim() + '\n')
    expect(readFileSync(join(dir, '.installed'), 'utf8').trim()).toBe(certNames(A.cert)!.fingerprint)
    await expect(writeFiles({ dir: join(TMP, 'dep2'), decrypt: decryptSecret }, cert(A, { keyEnc: encryptSecret(B.key) }) as any)).rejects.toThrow(/correspondent pas/)
    expect(existsSync(join(TMP, 'dep2', 'console.key'))).toBe(false)
  })
})

describe('boucle d\'émission et d\'installation', () => {
  function deps(o: { leader: boolean; state?: TlsState; served?: string; issue?: Deps['issue'] }) {
    const calls = { issued: 0, restarts: 0, logs: [] as string[] }
    const box = { state: o.state ?? S() }
    const d: Deps = {
      now: () => NOW, inRecovery: async () => !o.leader, load: async () => box.state, save: async (s) => { box.state = s },
      cluster: async () => ({ nodes: NODES, vip: '10.0.0.10' }), enrollHost: async () => 'console.lab.test',
      issue: o.issue ?? (async (_ca, _cn, dns) => { calls.issued++; expect(dns[0]).toBe('console.lab.test'); return { certPem: A.cert, chainPem: '', keyPem: A.key, serial: 'AB' } }),
      encrypt: encryptSecret, decrypt: decryptSecret, servedPem: () => o.served ?? B.cert, dir: join(TMP, 'run-' + Math.random().toString(36).slice(2)),
      restart: () => { calls.restarts++ }, log: (m) => calls.logs.push(m),
    }
    return { d, calls, box }
  }
  it('le leader émet, enregistre (clé chiffrée), dépose et relance ; la passe suivante ne fait plus rien', async () => {
    const { d, calls, box } = deps({ leader: true })
    expect(await consoleTlsTick(d)).toBe('installed')
    expect(calls).toMatchObject({ issued: 1, restarts: 1 }); expect(box.state.cert!.keyEnc).not.toContain('PRIVATE'); expect(box.state.cert!.dns).toContain('n1.lab.test')
    expect(existsSync(join(d.dir, 'console.key'))).toBe(true)
    const after = deps({ leader: true, state: box.state, served: A.cert }); expect(await consoleTlsTick(after.d)).toBe('current'); expect(after.calls).toMatchObject({ issued: 0, restarts: 0 })
  })
  it('un secondaire n\'émet jamais mais installe le certificat de la base', async () => {
    const { d, calls } = deps({ leader: false, state: S({ cert: cert(A) }) })
    expect(await consoleTlsTick(d)).toBe('installed'); expect(calls).toMatchObject({ issued: 0, restarts: 1 })
  })
  it('un certificat déposé mais refusé au démarrage n\'entraîne pas de relances en boucle', async () => {
    const { d, calls } = deps({ leader: false, state: S({ cert: cert(A) }) })
    expect(await consoleTlsTick(d)).toBe('installed'); expect(await consoleTlsTick(d)).toBe('refused'); expect(calls.restarts).toBe(1)
  })
  it('échec de l\'émission : motif retenu, ancien certificat conservé, nouvelle tentative différée', async () => {
    const { d, box, calls } = deps({ leader: true, state: S({ cert: cert(A), names: ['console.lab.test', 'autre.lab.test'] }), served: A.cert, issue: async () => { throw new Error('la PKI refuse') } })
    expect(await consoleTlsTick(d)).toBe('current')
    expect(box.state.last).toMatchObject({ ok: false, message: 'la PKI refuse' }); expect(box.state.cert!.serial).toBe('01'); expect(calls.restarts).toBe(0)
    let n = 0; const again = { ...d, issue: async () => { n++; throw new Error('x') } }
    await consoleTlsTick(again); expect(n).toBe(0)   // dans le délai de repos
  })
  it('un certificat reçu qui ne correspond pas à la clé est refusé', async () => {
    const { d, box } = deps({ leader: true, issue: async () => ({ certPem: A.cert, chainPem: '', keyPem: B.key, serial: '1' }) })
    expect(await consoleTlsTick(d)).toBe('none'); expect(box.state.cert).toBeNull(); expect(box.state.last).toMatchObject({ ok: false })
  })
  it('désactivé : aucune émission ni installation', async () => {
    const { d, calls } = deps({ leader: true, state: S({ auto: false }) })
    expect(await consoleTlsTick(d)).toBe('none'); expect(calls.issued).toBe(0)
  })
})

import { createServer } from 'node:tls'
import { X509Certificate } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import { createServer as createHttps } from 'node:https'
import { probeChain, probeRole, trustVerdict } from '../server/utils/enroll-trust'

describe('les postes font-ils confiance à la console ?', () => {
  const x = (c: string) => new X509Certificate(c)
  it('feuille auto-signée approuvée et nom couvert : tout va bien', () => {
    const v = trustVerdict('console.lab.test', [x(A.cert)], [x(A.cert)])
    expect(v).toMatchObject({ reachable: true, nameOk: true, trusted: true, selfSigned: true, reasons: [] }); expect(v.names).toContain('n1.lab.test')
  })
  it('un autre certificat auto-signé que celui de la GPO : non approuvé (le cas de deux nœuds)', () => {
    expect(trustVerdict('console.lab.test', [x(B.cert)], [x(A.cert)]).reasons).toEqual(['untrusted'])
  })
  it('un nom absent du certificat : refusé même si l\'autorité est approuvée (SAN sans le nom complet)', () => {
    const v = trustVerdict('console.ar.fr', [x(A.cert)], [x(A.cert)]); expect(v).toMatchObject({ nameOk: false, trusted: true, reasons: ['name'] })
  })
  it('expiré', () => { expect(trustVerdict('console.lab.test', [x(A.cert)], [x(A.cert)], Date.now() + 900 * 86400_000).reasons).toEqual(['expired']) })
  it('injoignable : aucune raison inventée', () => { expect(trustVerdict('x.y', null, [x(A.cert)])).toMatchObject({ reachable: false, reasons: [] }) })
  it('sonde réelle d\'un serveur TLS local, sans valider son certificat', async () => {
    const own = mk('srv', 'DNS:localhost')
    const srv = createServer({ cert: own.cert, key: own.key }, (s) => s.end()); await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r))
    try {
      const port = (srv.address() as AddressInfo).port
      const chain = await probeChain('127.0.0.1', port, 3000); expect(chain).toHaveLength(1)
      expect(trustVerdict('localhost', chain, [x(own.cert)])).toMatchObject({ nameOk: true, trusted: true })
      expect(trustVerdict('localhost', chain, [x(A.cert)]).trusted).toBe(false)
    } finally { srv.close() }
    expect(await probeChain('127.0.0.1', 1, 1500)).toBeNull()
  })
})

describe('le nom d\'enrôlement mène-t-il à un nœud secondaire ? (0.21.2)', () => {
  const serve = async (status: number, body: string) => {
    const own = mk('srv', 'DNS:localhost')
    const srv = createHttps({ cert: own.cert, key: own.key }, (_rq, rs) => { rs.statusCode = status; rs.setHeader('content-type', 'application/json'); rs.end(body) })
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r))
    return { srv, port: (srv.address() as AddressInfo).port }
  }
  it('503 « replica » : nœud secondaire', async () => {
    const { srv, port } = await serve(503, '{"error":true,"statusCode":503,"data":{"code":"replica"}}')
    try { expect(await probeRole('127.0.0.1', port, 3000)).toBe('replica') } finally { srv.close() }
  })
  it('401 (leader, sans ticket) ou 404 (service éteint) : pas un secondaire', async () => {
    for (const [st, body] of [[401, '{"data":{"code":"enroll_negotiate"}}'], [404, '{"data":{"code":"not_found"}}']] as const) {
      const { srv, port } = await serve(st, body)
      try { expect(await probeRole('127.0.0.1', port, 3000)).toBe('leader') } finally { srv.close() }
    }
  })
  it('un autre 503 (annuaire, keytab) n\'est pas pris pour un secondaire', async () => {
    const { srv, port } = await serve(503, '{"data":{"code":"enroll_directory"}}')
    try { expect(await probeRole('127.0.0.1', port, 3000)).toBe('leader') } finally { srv.close() }
  })
  it('injoignable : pas de réponse exploitable', async () => { expect(await probeRole('127.0.0.1', 1, 1500)).toBeNull() })
})
