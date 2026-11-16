// Sonde RADIUS (RFC 2865 / 3579) : un Access-Request PAP signé (Message-Authenticator) envoyé au service local, réponse vérifiée.
// Aucune dépendance : ce fichier est aussi chargé tel quel par la batterie shell b28 contre un vrai FreeRADIUS.
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { createSocket } from 'node:dgram'

export const CODE = { accessRequest: 1, accessAccept: 2, accessReject: 3, accessChallenge: 11 } as const
const ATTR = { userName: 1, userPassword: 2, nasIpAddress: 4, messageAuthenticator: 80 } as const
export type ProbeReply = 'accept' | 'reject' | 'challenge'
export interface ProbeResult { ok: boolean; reply?: ProbeReply; ms: number; error?: 'timeout' | 'bad_reply' | 'socket' }

const md5 = (...b: Buffer[]) => createHash('md5').update(Buffer.concat(b)).digest()
const attr = (type: number, value: Buffer) => Buffer.concat([Buffer.from([type, value.length + 2]), value])

/** Access-Request PAP : User-Name, User-Password (RFC 2865 §5.2), NAS-IP-Address, Message-Authenticator (HMAC-MD5 de tout le paquet). */
export function buildAccessRequest(secret: string, username: string, password: string, id = randomBytes(1)[0]!, auth = randomBytes(16)): { packet: Buffer; auth: Buffer } {
  const pw = Buffer.alloc(Math.max(16, Math.ceil(Buffer.byteLength(password) / 16) * 16)); pw.write(password)
  const enc = Buffer.alloc(pw.length)
  let prev = auth
  for (let i = 0; i < pw.length; i += 16) {
    const b = md5(Buffer.from(secret), prev)
    for (let j = 0; j < 16; j++) enc[i + j] = pw[i + j]! ^ b[j]!
    prev = enc.subarray(i, i + 16)
  }
  const attrs = Buffer.concat([attr(ATTR.userName, Buffer.from(username)), attr(ATTR.userPassword, enc), attr(ATTR.nasIpAddress, Buffer.from([127, 0, 0, 1])), attr(ATTR.messageAuthenticator, Buffer.alloc(16))])
  const head = Buffer.alloc(20); head[0] = CODE.accessRequest; head[1] = id; head.writeUInt16BE(20 + attrs.length, 2); auth.copy(head, 4)
  const packet = Buffer.concat([head, attrs])
  const ma = createHmac('md5', secret).update(packet).digest()
  ma.copy(packet, packet.length - 16)   // le Message-Authenticator est le dernier attribut
  return { packet, auth }
}

/** Vérifie une réponse : longueur, identifiant, authentificateur de réponse (RFC 2865 §3) et Message-Authenticator s'il est présent. */
export function verifyReply(secret: string, requestId: number, requestAuth: Buffer, reply: Buffer): ProbeReply | null {
  if (reply.length < 20 || reply.length > 4096) return null
  const len = reply.readUInt16BE(2)
  if (len < 20 || len > reply.length || reply[1] !== requestId) return null
  const pkt = reply.subarray(0, len)
  const code = pkt[0]
  const expected = md5(pkt.subarray(0, 4), requestAuth, pkt.subarray(20), Buffer.from(secret))
  if (!expected.equals(pkt.subarray(4, 20))) return null
  // attributs : bornes strictes, puis Message-Authenticator recalculé avec l'authentificateur de la REQUÊTE
  let off = 20, maAt = -1
  while (off < pkt.length) {
    if (off + 2 > pkt.length) return null
    const t = pkt[off]!, l = pkt[off + 1]!
    if (l < 2 || off + l > pkt.length) return null
    if (t === ATTR.messageAuthenticator) { if (l !== 18) return null; maAt = off + 2 }
    off += l
  }
  if (maAt >= 0) {
    const tmp = Buffer.from(pkt); requestAuth.copy(tmp, 4); tmp.fill(0, maAt, maAt + 16)
    if (!createHmac('md5', secret).update(tmp).digest().equals(pkt.subarray(maAt, maAt + 16))) return null
  }
  return code === CODE.accessAccept ? 'accept' : code === CODE.accessReject ? 'reject' : code === CODE.accessChallenge ? 'challenge' : null
}

/** Envoie la requête et attend la réponse. Un secret inconnu ou un client non déclaré ne reçoit AUCUNE réponse : « timeout ». */
export function radiusProbe(opts: { host?: string; port: number; secret: string; timeoutMs?: number; username?: string }): Promise<ProbeResult> {
  const t0 = Date.now()
  const { packet, auth } = buildAccessRequest(opts.secret, opts.username ?? 'ddi-selftest', randomBytes(12).toString('hex'))
  const id = packet[1]!
  return new Promise((resolve) => {
    const sock = createSocket('udp4')
    let done = false
    const finish = (r: Omit<ProbeResult, 'ms'>) => { if (done) return; done = true; clearTimeout(timer); try { sock.close() } catch { /* déjà fermé */ } resolve({ ...r, ms: Date.now() - t0 }) }
    const timer = setTimeout(() => finish({ ok: false, error: 'timeout' }), opts.timeoutMs ?? 2500)
    sock.on('error', () => finish({ ok: false, error: 'socket' }))
    sock.on('message', (msg) => { const r = verifyReply(opts.secret, id, auth, msg); finish(r ? { ok: true, reply: r } : { ok: false, error: 'bad_reply' }) })
    sock.send(packet, opts.port, opts.host ?? '127.0.0.1', (e) => { if (e) finish({ ok: false, error: 'socket' }) })
  })
}
