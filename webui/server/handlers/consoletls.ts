// Certificat HTTPS de la console, automatique et commun à tous les nœuds (0.21.0) : voir utils/console-tls.ts.
//   GET  /system/console-tls          : état (réglages, certificat, noms voulus, ce que ce nœud sert)
//   PUT  /system/console-tls          : réglages (automatique, autorité émettrice, noms supplémentaires)
//   POST /system/console-tls/issue    : lance une passe tout de suite (force = renouveler même si le certificat est bon)
import { join } from 'node:path'
import { z } from 'zod'
import { audit, fail, route } from '../utils/router'
import type { Ctx } from '../utils/router'
import { cfg } from '../utils/config'
import { getSetting, inRecovery, setSetting } from '../utils/db'
import { readClusterState } from '../utils/cluster'
import { decryptSecret, encryptSecret } from '../utils/auth'
import { readPkiCas } from '../utils/pki-ca'
import { newKeyAndCsr } from '../utils/pki-certs'
import { loadEnroll } from '../utils/enroll'
import { certNames, consoleTlsTick, EMPTY_TLS, firstCert, issueAndSave, parseTls, TLS_KEY, tlsBody, wantedNames } from '../utils/console-tls'
import type { Deps, TlsState } from '../utils/console-tls'
import { issueCert } from './pkicert'

export const registered = true

// l'émission n'est pas demandée par une personne : la trace porte « système » (pas d'utilisateur, pas d'adresse)
const systemCtx = (): Ctx => ({ event: undefined as never, params: {}, query: {}, user: null, ip: null, body: async () => { throw new Error('pas de corps') } })

export const loadTls = async (): Promise<TlsState> => parseTls(await getSetting<unknown>(TLS_KEY, EMPTY_TLS))
const issuers = async () => ((await readPkiCas())?.cas ?? []).filter((x) => x.kind === 'issuing' && x.state === 'active' && x.managed).map((x) => x.name)

export function realDeps(): Deps {
  return {
    now: () => Math.floor(Date.now() / 1000),
    inRecovery: () => inRecovery(),
    load: loadTls,
    save: (s) => setSetting(TLS_KEY, s),
    cluster: async () => { const s = await readClusterState(); return s ? { nodes: s.nodes.map((n) => ({ name: n.name, ip: n.ip, host: n.host })), vip: s.vip?.address ?? null } : null },
    enrollHost: async () => (await loadEnroll()).host,
    issue: async (ca, cn, dns, ip) => {
      const { keyPem, csrPem } = await newKeyAndCsr('ecp256', cn)
      const x = await issueCert(systemCtx(), { ca, profile: 'server', cn, dns, ip, mail: [], upn: [] }, Buffer.from(csrPem, 'utf8'))
      return { certPem: x.certPem, chainPem: x.chainPem, keyPem, serial: x.serial }
    },
    encrypt: encryptSecret, decrypt: decryptSecret,
    servedPem: () => process.env.NITRO_SSL_CERT || process.env.DDI_TLS_CERT_PEM || '',
    dir: process.env.DDI_TLS_GEN_DIR || join(cfg().generatedDir, 'console-tls'),
    restart: () => { if (process.env.DDI_CONSOLE_TLS_NO_RESTART !== '1') setTimeout(() => process.exit(1), 1000).unref() },   // systemd (Restart=on-failure) relance la console, qui lit alors le nouveau certificat
    log: (m) => console.log(`[console-tls] ${m}`),
  }
}

async function view() {
  const st = await loadTls()
  const cl = await readClusterState()
  const want = wantedNames(st, (await loadEnroll()).host, cl?.nodes.map((n) => ({ name: n.name, ip: n.ip, host: n.host })) ?? [], cl?.vip?.address ?? null)
  const served = certNames(firstCert(process.env.NITRO_SSL_CERT || process.env.DDI_TLS_CERT_PEM || ''))
  const dbc = st.cert ? certNames(firstCert(st.cert.pem)) : null
  return {
    auto: st.auto, ca: st.ca, names: st.names, want, last: st.last, issuers: await issuers(), leader: !(await inRecovery()),
    cert: st.cert && dbc ? { serial: st.cert.serial, notAfter: dbc.notAfter, dns: dbc.dns, ip: dbc.ip, at: st.cert.at, fingerprint: dbc.fingerprint } : null,
    served: served ? { subject: served.subject, selfSigned: served.selfSigned, notAfter: served.notAfter, dns: served.dns, ip: served.ip, fingerprint: served.fingerprint } : null,
    // la base porte un certificat que ce nœud ne sert pas encore (dépôt et relance en cours, ou refusé au démarrage)
    pending: !!(st.cert && dbc && served && dbc.fingerprint !== served.fingerprint),
  }
}

route('GET', '/system/console-tls', 'admin', async () => view())

route('PUT', '/system/console-tls', 'admin', async (c) => {
  const b = await c.body(tlsBody)
  if (b.auto) {
    if (!b.ca) fail(400, 'console_tls_ca_required')
    if (!(await issuers()).includes(b.ca)) fail(409, 'pki_ca_not_issuing')
  }
  const st = await loadTls()
  // changer d'autorité ou de noms ne jette pas le certificat en place : la prochaine passe en fait émettre un autre si les noms voulus ne sont plus couverts
  await setSetting(TLS_KEY, { ...st, auto: b.auto, ca: b.ca, names: b.names, last: null })
  await audit(c, 'system.console_tls', 'settings', TLS_KEY, { auto: b.auto, ca: b.ca, names: b.names })
  return view()
})

route('POST', '/system/console-tls/issue', 'admin', async (c) => {
  const body = await c.body(z.object({ force: z.boolean().default(false) }).strict())
  if (await inRecovery()) fail(409, 'console_tls_not_leader')
  let st = await loadTls()
  if (!st.auto || !st.ca) fail(409, 'console_tls_disabled')
  if (!(await issuers()).includes(st.ca)) fail(409, 'pki_ca_not_issuing')
  const d = realDeps()
  if (body.force) {
    const cl = await d.cluster()
    st = await issueAndSave(d, st, wantedNames(st, await d.enrollHost(), cl?.nodes ?? [], cl?.vip ?? null))
    if (!st.last?.ok) fail(502, 'console_tls_issue_failed', undefined, { detail: st.last?.message })
  } else await setSetting(TLS_KEY, { ...st, last: null })
  await audit(c, 'system.console_tls_issue', 'settings', TLS_KEY, { force: body.force })
  await consoleTlsTick(d)
  return view()
})
