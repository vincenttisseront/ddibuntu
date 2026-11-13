// Faux serveur SMTP pour les tests : enregistre les messages, gère STARTTLS, TLS implicite, AUTH PLAIN / LOGIN (certificat auto-signé généré par openssl).
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync } from 'node:fs'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import tls from 'node:tls'

export interface Mail { from: string; to: string[]; raw: string; auth: string | null; secure: boolean }
export interface FakeOptions { starttls?: boolean; implicitTls?: boolean; auth?: { user: string; pass: string }; plainAuthWithoutTls?: boolean; refuseRcpt?: string; refuseData?: boolean }

let pem: { key: string; cert: string } | null = null
export function selfSigned(): { key: string; cert: string } {
  if (pem) return pem
  const d = mkdtempSync(join(tmpdir(), 'ddi-smtp-'))
  execFileSync('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(d, 'k.pem'), '-out', join(d, 'c.pem'), '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' })
  return (pem = { key: readFileSync(join(d, 'k.pem'), 'utf8'), cert: readFileSync(join(d, 'c.pem'), 'utf8') })
}

export async function startFakeSmtp(o: FakeOptions = {}) {
  const mails: Mail[] = [], commands: string[] = []
  const cert = o.starttls || o.implicitTls ? selfSigned() : null
  const session = (sock: net.Socket, secure: boolean, greet = true) => {
    let state: 'cmd' | 'data' | 'user' | 'pass' = 'cmd', buf = '', from = '', to: string[] = [], data: string[] = [], auth: string | null = null, user = ''
    const send = (s: string) => sock.write(s + '\r\n')
    sock.setEncoding('utf8')
    const checkAuth = (u: string, p: string) => { if (o.auth && u === o.auth.user && p === o.auth.pass) { auth = `${u}:${p}`; return true } return false }
    const line = (l: string) => {
      if (state === 'data') {
        if (l === '.') { mails.push({ from, to, raw: data.join('\r\n'), auth, secure }); data = []; state = 'cmd'; send(o.refuseData ? '554 refused' : '250 queued'); return }
        data.push(l.startsWith('..') ? l.slice(1) : l); return
      }
      if (state === 'user') { user = Buffer.from(l, 'base64').toString(); state = 'pass'; send('334 UGFzc3dvcmQ6'); return }
      if (state === 'pass') { state = 'cmd'; send(checkAuth(user, Buffer.from(l, 'base64').toString()) ? '235 ok' : '535 bad credentials'); return }
      commands.push(secure ? `(tls) ${l.replace(/^AUTH PLAIN .*/, 'AUTH PLAIN ***')}` : l.replace(/^AUTH PLAIN .*/, 'AUTH PLAIN ***'))
      const u = l.toUpperCase()
      if (u.startsWith('EHLO') || u.startsWith('HELO')) {
        const caps = ['localhost']; if (o.starttls && !secure) caps.push('STARTTLS')
        if (o.auth && (secure || o.plainAuthWithoutTls || o.implicitTls)) caps.push('AUTH PLAIN LOGIN')
        caps.push('8BITMIME'); caps.forEach((c, i) => send(`250${i === caps.length - 1 ? ' ' : '-'}${c}`)); return
      }
      if (u === 'STARTTLS') {
        if (!o.starttls || secure) return send('502 not available')
        send('220 go ahead'); sock.removeAllListeners('data')
        const t = new tls.TLSSocket(sock, { isServer: true, key: cert!.key, cert: cert!.cert }); t.on('error', () => undefined); session(t, true, false); return
      }
      if (u.startsWith('AUTH PLAIN ')) { const p = Buffer.from(l.slice(11), 'base64').toString().split('\0'); return send(checkAuth(p[1] ?? '', p[2] ?? '') ? '235 ok' : '535 bad credentials') }
      if (u === 'AUTH LOGIN') { state = 'user'; return send('334 VXNlcm5hbWU6') }
      if (u.startsWith('MAIL FROM:')) { from = l.slice(10).replace(/[<>]/g, '').trim(); to = []; return send(o.auth && !auth ? '530 authentication required' : '250 ok') }
      if (u.startsWith('RCPT TO:')) { const a = l.slice(8).replace(/[<>]/g, '').trim(); if (o.refuseRcpt && a === o.refuseRcpt) return send('550 no such user'); to.push(a); return send('250 ok') }
      if (u === 'DATA') { state = 'data'; return send('354 end with <CRLF>.<CRLF>') }
      if (u === 'QUIT') { send('221 bye'); sock.end(); return }
      send('500 unknown')
    }
    sock.on('data', (d: string) => { buf += d; let i; while ((i = buf.indexOf('\r\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 2); line(l) } })
    sock.on('error', () => undefined)
    if (greet) send('220 localhost fake-smtp')
  }
  const server: net.Server = o.implicitTls
    ? tls.createServer({ key: cert!.key, cert: cert!.cert }, (s) => { s.on('error', () => undefined); session(s, true) })
    : net.createServer((s) => session(s, false))
  server.on('tlsClientError', () => undefined)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  return { port: (server.address() as net.AddressInfo).port, mails, commands, close: () => new Promise<void>((r) => server.close(() => r())) }
}

// En-têtes et corps décodé (Content-Transfer-Encoding: base64) d'un message reçu.
export function decode(m: Mail): { headers: Record<string, string>; body: string } {
  const [h, ...rest] = m.raw.split('\r\n\r\n')
  const headers: Record<string, string> = {}
  for (const l of h!.split('\r\n')) { const i = l.indexOf(':'); if (i > 0) headers[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim() }
  return { headers, body: Buffer.from(rest.join('\r\n\r\n').replace(/\r\n/g, ''), 'base64').toString('utf8') }
}
export const subjectOf = (m: Mail) => { const s = decode(m).headers.subject ?? ''; const x = /^=\?UTF-8\?B\?(.+)\?=$/.exec(s); return x ? Buffer.from(x[1]!, 'base64').toString('utf8') : s }
