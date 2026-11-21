// Les postes font-ils confiance à la console ? (0.21.0) Le script d'enrôlement appelle https://<nom de la console>/ : si le certificat présenté sous ce nom ne couvre pas ce nom
// ou n'est validé par aucune des autorités que la GPO installe sur les postes, Windows refuse la connexion (« relation de confiance pour le canal sécurisé ») et rien n'est jamais
// enregistré côté console. La console se connecte donc elle-même à ce nom et compare ; l'écran l'affiche avant qu'un poste ne bute dessus.
import { connect } from 'node:tls'
import { request } from 'node:https'
import { isIP } from 'node:net'
import { X509Certificate } from 'node:crypto'

export type TrustReason = 'name' | 'untrusted' | 'expired'
export interface TrustVerdict {
  reachable: boolean
  host: string
  subject: string
  fingerprint: string
  selfSigned: boolean
  names: string[]
  notAfter: number
  nameOk: boolean
  trusted: boolean
  reasons: TrustReason[]
}

/** Chaîne présentée par un serveur (feuille d'abord), sans valider quoi que ce soit : c'est justement ce qu'on veut examiner. */
export function probeChain(host: string, port = 443, timeoutMs = 5000): Promise<X509Certificate[] | null> {
  return new Promise((resolve) => {
    let done = false
    const finish = (v: X509Certificate[] | null) => { if (!done) { done = true; try { s.destroy() } catch { /* déjà fermé */ } resolve(v) } }
    const s = connect({ host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      try {
        const out: X509Certificate[] = []
        let p: any = s.getPeerCertificate(true)
        const seen = new Set<string>()
        while (p && p.raw && out.length < 8) {
          const x = new X509Certificate(p.raw)
          if (seen.has(x.fingerprint256)) break
          seen.add(x.fingerprint256); out.push(x)
          p = p.issuerCertificate
        }
        finish(out.length ? out : null)
      } catch { finish(null) }
    })
    s.on('error', () => finish(null)); s.on('timeout', () => finish(null))
  })
}

const validates = (c: X509Certificate, a: X509Certificate) => c.fingerprint256 === a.fingerprint256 || (c.checkIssued(a) && c.verify(a.publicKey))

/** Verdict pour une chaîne présentée et les autorités que les postes recevront. */
export function trustVerdict(host: string, chain: X509Certificate[] | null, anchors: X509Certificate[], now = Date.now()): TrustVerdict {
  if (!chain || !chain.length) return { reachable: false, host, subject: '', fingerprint: '', selfSigned: false, names: [], notAfter: 0, nameOk: false, trusted: false, reasons: [] }
  const leaf = chain[0]!
  const nameOk = leaf.checkHost(host) !== undefined
  const trusted = chain.some((c) => anchors.some((a) => { try { return validates(c, a) } catch { return false } }))
  const notAfter = Date.parse(leaf.validTo)
  const names = (leaf.subjectAltName ?? '').split(/,\s*/).map((p) => /^DNS:(.+)$/.exec(p.trim())?.[1]).filter((x): x is string => !!x)
  const reasons: TrustReason[] = []
  if (!nameOk) reasons.push('name')
  if (!trusted) reasons.push('untrusted')
  if (notAfter <= now) reasons.push('expired')
  return { reachable: true, host, subject: leaf.subject.replace(/\n/g, ', ').slice(0, 200), fingerprint: leaf.fingerprint256.replace(/:/g, '').toLowerCase(), selfSigned: leaf.subject === leaf.issuer, names, notAfter, nameOk, trusted, reasons }
}

/** Le nom d'enrôlement mène-t-il à un nœud secondaire ? (0.21.2) Seul le leader écrit : un secondaire répond « 503 replica » à toute requête qui écrit, donc l'enrôlement échoue
 *  en silence sur le poste. Requête sans ticket (jamais de secret) ; la réponse d'un leader est 401 (ou 404 si le service est éteint). null = pas de réponse exploitable. */
export function probeRole(host: string, port = 443, timeoutMs = 5000): Promise<'replica' | 'leader' | null> {
  return new Promise((resolve) => {
    let done = false
    const finish = (v: 'replica' | 'leader' | null) => { if (!done) { done = true; resolve(v) } }
    const req = request({ host, port, servername: isIP(host) ? undefined : host, path: '/api/enroll/v1/machine', method: 'POST', rejectUnauthorized: false, timeout: timeoutMs, headers: { 'Content-Length': '0' } }, (res) => {
      let body = ''
      res.on('data', (d) => { if (body.length < 2000) body += d })
      res.on('end', () => finish(res.statusCode === 503 && /"code"\s*:\s*"replica"/.test(body) ? 'replica' : 'leader'))
      res.on('error', () => finish(null))
    })
    req.on('error', () => finish(null)); req.on('timeout', () => { req.destroy(); finish(null) })
    req.end()
  })
}
