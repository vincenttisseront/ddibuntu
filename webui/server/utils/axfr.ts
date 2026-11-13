// Transfert de zone (AXFR) depuis un serveur DNS existant, typiquement Windows (0.12.3). Passe par « dig » (jamais par un shell) ; la sortie
// est du texte de zone que l'import habituel sait lire. Le serveur doit autoriser le transfert vers l'adresse de cette console.
import { execFile } from 'node:child_process'
import { isValidDnsName, parseIp } from './net'

export const validServer = (s: string): boolean => !!parseIp(s) || (isValidDnsName(s, false) && !s.startsWith('-'))
export const axfrArgs = (zone: string, server: string): string[] => ['+noall', '+answer', '+nocomments', '+time=10', '+tries=1', '+tcp', `@${server}`, zone, 'AXFR']

export function axfr(zone: string, server: string): Promise<{ ok: boolean; text: string; error?: 'axfr_refused' | 'axfr_failed' | 'dig_missing' }> {
  const bin = process.env.DDI_DIG || 'dig'
  return new Promise((resolve) => {
    execFile(bin, axfrArgs(zone, server), { timeout: 60_000, maxBuffer: 64 * 1024 * 1024 }, (err: any, stdout, stderr) => {
      if (err?.code === 'ENOENT') return resolve({ ok: false, text: '', error: 'dig_missing' })
      const text = String(stdout ?? '')
      const all = `${text}${stderr ?? ''}`
      if (/transfer failed|refused|REFUSED/i.test(all) && !/\sSOA\s/.test(text)) return resolve({ ok: false, text: '', error: 'axfr_refused' })
      if (err || !/\sSOA\s/.test(text)) return resolve({ ok: false, text: '', error: 'axfr_failed' })
      resolve({ ok: true, text })
    })
  })
}
