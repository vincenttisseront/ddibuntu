// Clé de récupération de la PKI (0.14.5). Les clés des autorités sont dans la base « ejbca » (sauvegardée avec PostgreSQL) mais ne s'y lisent qu'avec les secrets d'ejbca.env :
// chaque sauvegarde reçoit donc un lot chiffré de ces secrets, que SEUL le détenteur de la clé privée de récupération peut ouvrir. L'appliance ne garde que le certificat PUBLIC.
//
// Ici, la console fabrique la paire de clés (RSA 4096) dans la mémoire de CE processus ; seul le certificat part vers root (dépôt pki-in/recovery.pem + demande « recovery_set »).
// La clé privée est RENDUE UNE SEULE FOIS à l'administrateur, dans la réponse à sa demande, jamais écrite sur le disque (hors fichier de /dev/shm effacé aussitôt, pour openssl),
// jamais journalisée, jamais dans l'audit, jamais envoyée à root. Perdre cette clé = secrets sauvegardés irrécupérables : c'est le contrat, et l'écran le dit.
// Un administrateur qui préfère fabriquer la clé ailleurs (HSM, PKI interne) n'a qu'à enregistrer le certificat avec « ddibuntu-pki recovery-set CERT.pem ».
import { generateKeyPair, X509Certificate } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { z } from 'zod'
import { cfg } from './config'
import { openssl, withTmp } from './openssl'
import { readPkiResult } from './pki'

export const RECOVERY_BITS = 4096
export const RECOVERY_DAYS = 36500
/** Phrase secrète facultative (fortement conseillée) qui protège le fichier de la clé privée : 10 à 128 caractères, sans caractère de contrôle. */
export const recoveryBody = z.object({
  passphrase: z.string().min(10).max(128).refine((p) => !/[\x00-\x1f\x7f]/.test(p)).optional(),
  replace: z.boolean().optional(),
}).strict()
export type RecoveryBody = z.infer<typeof recoveryBody>

const genKeyPair = promisify(generateKeyPair) as (t: any, o: any) => Promise<{ privateKey: KeyObject; publicKey: KeyObject }>
const safeHost = () => os.hostname().replace(/[^A-Za-z0-9.-]/g, '').slice(0, 63) || 'ddi'

export interface RecoveryKey { keyPem: string; certPem: string; fingerprint: string; encrypted: boolean }
/** Paire de clés RSA 4096, certificat auto-signé (100 ans : il ne sert qu'à désigner la clé), clé privée en PKCS#8 (chiffrée AES-256 si une phrase est donnée). */
export async function newRecoveryKey(passphrase?: string, now = new Date()): Promise<RecoveryKey> {
  const { privateKey } = await genKeyPair('rsa', { modulusLength: RECOVERY_BITS })
  const plain = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  const cn = `DDI-Buntu PKI recovery ${safeHost()} ${now.toISOString().slice(0, 10)}`
  return withTmp(async (_d, put) => {
    const k = await put('k.pem', plain)
    const c = await openssl(['req', '-new', '-x509', '-key', k, '-sha256', '-days', String(RECOVERY_DAYS), '-subj', `/CN=${cn}`,
      '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,keyEncipherment,dataEncipherment'], { timeoutMs: 30_000 })
    if (c.code !== 0 || !c.stdout.includes('BEGIN CERTIFICATE')) throw new Error('recovery_cert_failed')
    const certPem = c.stdout.trim() + '\n'
    let keyPem = plain
    if (passphrase) {
      // chiffrement du fichier par openssl : PBES2, AES-256-CBC, PBKDF2-SHA256 avec 600 000 itérations ; la phrase passe par l'environnement, jamais par la ligne de commande
      const e = await openssl(['pkcs8', '-topk8', '-in', k, '-v2', 'aes-256-cbc', '-v2prf', 'hmacWithSHA256', '-iter', '600000', '-passout', 'env:DDI_RECPW'], { env: { DDI_RECPW: passphrase }, timeoutMs: 60_000 })
      if (e.code !== 0 || !e.stdout.includes('BEGIN ENCRYPTED PRIVATE KEY')) throw new Error('recovery_key_failed')
      keyPem = e.stdout.trim() + '\n'
    }
    const fingerprint = new X509Certificate(certPem).fingerprint256.replace(/:/g, '').toLowerCase()
    return { keyPem, certPem, fingerprint, encrypted: !!passphrase }
  }, { ram: true })
}

const inDir = () => join(cfg().generatedDir, 'pki-in')
/** Dépose le certificat PUBLIC pour root (0640) ; l'éventuel ancien dépôt est supprimé avant, pour ne jamais écrire à travers un lien. */
export async function putRecoveryDeposit(certPem: string): Promise<void> {
  await fs.mkdir(inDir(), { recursive: true, mode: 0o750 })
  const p = join(inDir(), 'recovery.pem')
  await fs.rm(p, { force: true })
  await fs.writeFile(p, certPem, { mode: 0o640, flag: 'wx' })
}
export const dropRecoveryDeposit = () => fs.rm(join(inDir(), 'recovery.pem'), { force: true }).catch(() => {})

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
export type RecoveryOutcome = { ok: true } | { ok: false; code: 'refused' | 'timeout'; message: string }
/** Attend le résultat de root pour CETTE demande : action « recovery_set », postérieur au dépôt ; en cas de succès, son message cite le début de l'empreinte. */
export async function awaitRecovery(fingerprint: string, startedAt: number, opts: { timeoutMs?: number; pollMs?: number } = {}): Promise<RecoveryOutcome> {
  const end = Date.now() + (opts.timeoutMs ?? (Number(process.env.DDI_PKI_RECOVERY_WAIT_MS) || 60_000)), poll = opts.pollMs ?? 400
  for (;;) {
    const r = await readPkiResult()
    if (r && r.action === 'recovery_set' && r.at >= startedAt) {
      if (r.ok && r.message.includes(fingerprint.slice(0, 16))) return { ok: true }
      if (!r.ok) return { ok: false, code: 'refused', message: r.message }
    }
    if (Date.now() >= end) return { ok: false, code: 'timeout', message: '' }
    await sleep(poll)
  }
}
