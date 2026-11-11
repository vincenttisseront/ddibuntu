// Client SMTP minimal (envoi d'un message texte), sans dépendance : connexion simple, STARTTLS ou TLS implicite, AUTH PLAIN / LOGIN.
// Les identifiants ne partent JAMAIS en clair : une authentification sans chiffrement est refusée.
import net from 'node:net'
import tls from 'node:tls'
import { randomBytes } from 'node:crypto'

export interface SmtpOptions {
  host: string; port: number; security: 'none' | 'starttls' | 'tls'; verifyCert: boolean
  user?: string; pass?: string; from: string; to: string[]; subject: string; text: string
  heloName?: string; timeoutMs?: number
}
export const ADDRESS_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/
const b64 = (s: string | Buffer) => Buffer.from(s).toString('base64')
const wrap = (s: string) => s.replace(/(.{76})/g, '$1\r\n')

export function buildMessage(o: Pick<SmtpOptions, 'from' | 'to' | 'subject' | 'text'>, now = new Date(), host = 'ddibuntu'): string {
  const subj = o.subject.replace(/[\r\n]+/g, ' ').slice(0, 200)
  const encSubj = /^[\x20-\x7e]*$/.test(subj) ? subj : `=?UTF-8?B?${b64(subj)}?=`
  const headers = [
    `From: ${o.from}`, `To: ${o.to.join(', ')}`, `Subject: ${encSubj}`, `Date: ${now.toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: <${randomBytes(12).toString('hex')}@${host.replace(/[^A-Za-z0-9.-]/g, '') || 'ddibuntu'}>`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', 'Auto-Submitted: auto-generated',
  ]
  return headers.join('\r\n') + '\r\n\r\n' + wrap(b64(o.text)) + '\r\n'
}

class Session {
  private buf = ''
  private waiters: Array<(l: string) => void> = []
  private lines: string[] = []
  private err: Error | null = null
  constructor(public sock: net.Socket) { this.attach(sock) }
  attach(sock: net.Socket) {
    this.sock = sock
    sock.setEncoding('utf8')
    sock.on('data', (d: string) => {
      this.buf += d
      let i
      while ((i = this.buf.indexOf('\n')) >= 0) { const l = this.buf.slice(0, i).replace(/\r$/, ''); this.buf = this.buf.slice(i + 1); this.lines.push(l); this.flush() }
      if (this.buf.length > 65536) sock.destroy(new Error('reply_too_long'))
    })
    sock.on('error', (e) => { this.err = e; this.flush() })
    sock.on('close', () => { this.err ??= new Error('connection_closed'); this.flush() })
  }
  private flush() { while (this.waiters.length && (this.lines.length || this.err)) { const w = this.waiters.shift()!; w(this.lines.shift() ?? '') } }
  private line(): Promise<string> { return new Promise((res, rej) => { this.waiters.push((l) => { if (!l && this.err && !this.lines.length) rej(this.err); else res(l) }); this.flush() }) }
  // une réponse = une ou plusieurs lignes « 250-… » puis « 250 … »
  async reply(): Promise<{ code: number; lines: string[] }> {
    const lines: string[] = []
    for (let n = 0; n < 100; n++) {
      const l = await this.line()
      lines.push(l.slice(4))
      if (!/^\d{3}$/.test(l.slice(0, 3))) throw new Error('bad_reply')
      if (l[3] !== '-') return { code: Number(l.slice(0, 3)), lines }
    }
    throw new Error('reply_too_long')
  }
  write(s: string) { this.sock.write(s) }
  async cmd(s: string, ...ok: number[]): Promise<{ code: number; lines: string[] }> {
    this.write(s + '\r\n')
    const r = await this.reply()
    if (!ok.includes(r.code)) throw new Error(`smtp_${r.code}`)
    return r
  }
}

export async function sendMail(o: SmtpOptions): Promise<void> {
  if (!o.to.length || !ADDRESS_RE.test(o.from) || !o.to.every((a) => ADDRESS_RE.test(a))) throw new Error('bad_address')
  if (o.user && o.security === 'none') throw new Error('auth_requires_tls')
  const timeout = o.timeoutMs ?? 15000
  const helo = (o.heloName ?? 'ddibuntu').replace(/[^A-Za-z0-9.-]/g, '') || 'ddibuntu'
  const sock: net.Socket = await new Promise((res, rej) => {
    const s = o.security === 'tls' ? tls.connect({ host: o.host, port: o.port, servername: net.isIP(o.host) ? undefined : o.host, rejectUnauthorized: o.verifyCert }, () => res(s)) : net.connect({ host: o.host, port: o.port }, () => res(s))
    s.once('error', rej)
  })
  sock.setTimeout(timeout, () => sock.destroy(new Error('timeout')))
  let ses = new Session(sock), ok = false
  try {
    const hello = await ses.reply(); if (hello.code !== 220) throw new Error(`smtp_${hello.code}`)
    let caps = (await ses.cmd(`EHLO ${helo}`, 250)).lines.map((l) => l.toUpperCase())
    if (o.security === 'starttls') {
      if (!caps.some((c) => c === 'STARTTLS')) throw new Error('starttls_unsupported')
      await ses.cmd('STARTTLS', 220)
      ses.sock.removeAllListeners('data')   // la couche TLS reprend la lecture de la connexion
      const upgraded: tls.TLSSocket = await new Promise((res, rej) => {
        const t = tls.connect({ socket: ses.sock, servername: net.isIP(o.host) ? undefined : o.host, rejectUnauthorized: o.verifyCert }, () => res(t))
        t.once('error', rej)
      })
      upgraded.setTimeout(timeout, () => upgraded.destroy(new Error('timeout')))
      ses = new Session(upgraded)
      caps = (await ses.cmd(`EHLO ${helo}`, 250)).lines.map((l) => l.toUpperCase())
    }
    if (o.user) {
      const mech = caps.find((c) => c.startsWith('AUTH ')) ?? ''
      if (/\bPLAIN\b/.test(mech)) await ses.cmd(`AUTH PLAIN ${b64(`\0${o.user}\0${o.pass ?? ''}`)}`, 235)
      else if (/\bLOGIN\b/.test(mech)) { await ses.cmd('AUTH LOGIN', 334); await ses.cmd(b64(o.user), 334); await ses.cmd(b64(o.pass ?? ''), 235) }
      else throw new Error('auth_unsupported')
    }
    await ses.cmd(`MAIL FROM:<${o.from}>`, 250)
    for (const a of o.to) await ses.cmd(`RCPT TO:<${a}>`, 250, 251)
    await ses.cmd('DATA', 354)
    ses.write(buildMessage(o, new Date(), helo).replace(/^\./gm, '..') + '.\r\n')
    const end = await ses.reply(); if (end.code !== 250) throw new Error(`smtp_${end.code}`)
    ses.write('QUIT\r\n'); ses.sock.end(); ok = true
  } finally { if (!ok) { ses.sock.destroy(); sock.destroy() } }
}
