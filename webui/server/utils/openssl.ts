// Appels au binaire openssl (EAP-TLS, 0.13.2) : génération de demandes de certificat, lecture de CRL, import PKCS#12, vérification d'une chaîne.
// Jamais de shell (arguments en tableau), délai et taille de sortie bornés, fichiers temporaires dans un dossier privé effacé ensuite.
// Les secrets passent par l'entrée standard ou une variable d'environnement, jamais par la ligne de commande ; seule la demande de certificat (req -key)
// exige un fichier : dossier privé 0700, fichier 0600, effacé dans tous les cas (withTmp). Ne pas utiliser /dev/stdin : un tube Node est un socket, openssl ne peut pas l'ouvrir.
import { spawn } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export interface SslResult { code: number; stdout: string; stderr: string }
const BIN = () => process.env.DDI_OPENSSL || 'openssl'

export function openssl(args: string[], opts: { input?: string | Buffer; timeoutMs?: number; env?: Record<string, string>; maxBytes?: number } = {}): Promise<SslResult> {
  return new Promise((resolve, reject) => {
    const max = opts.maxBytes ?? 32 * 1024 * 1024
    const p = spawn(BIN(), args, { env: { PATH: process.env.PATH ?? '/usr/bin:/bin', LC_ALL: 'C', ...opts.env }, stdio: ['pipe', 'pipe', 'pipe'] })
    const out: Buffer[] = [], err: Buffer[] = []; let size = 0, done = false
    const finish = (fn: () => void) => { if (!done) { done = true; clearTimeout(timer); fn() } }
    const timer = setTimeout(() => { p.kill('SIGKILL'); finish(() => reject(new Error('openssl_timeout'))) }, opts.timeoutMs ?? 30_000)
    p.stdout.on('data', (d: Buffer) => { size += d.length; if (size > max) { p.kill('SIGKILL'); finish(() => reject(new Error('openssl_output_too_large'))) } else out.push(d) })
    p.stderr.on('data', (d: Buffer) => { if (err.length < 64) err.push(d) })
    p.on('error', () => finish(() => reject(new Error('openssl_unavailable'))))
    p.on('close', (code) => finish(() => resolve({ code: code ?? 1, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8').slice(0, 4000) })))
    p.stdin.on('error', () => { /* le processus s'est arrêté avant d'avoir tout lu */ })
    p.stdin.end(opts.input)
  })
}

/** Dossier temporaire privé (0700) pour les commandes qui exigent des fichiers ; supprimé dans tous les cas. */
export async function withTmp<T>(fn: (dir: string, put: (name: string, data: string | Buffer) => Promise<string>) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'ddi-ssl-'))
  try { return await fn(dir, async (name, data) => { const f = join(dir, name); await writeFile(f, data, { mode: 0o600 }); return f }) }
  finally { await rm(dir, { recursive: true, force: true }) }
}
