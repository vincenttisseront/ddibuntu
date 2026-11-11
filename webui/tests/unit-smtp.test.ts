import { afterAll, describe, expect, it } from 'vitest'
import { sendMail } from '../server/utils/smtp'
import type { SmtpOptions } from '../server/utils/smtp'
import { decode, startFakeSmtp, subjectOf } from './helpers/fake-smtp'

const base = (port: number, over: Partial<SmtpOptions> = {}): SmtpOptions => ({ host: '127.0.0.1', port, security: 'none', verifyCert: true, from: 'ddibuntu@example.com', to: ['ops@example.com'], subject: 'Test', text: 'Bonjour', timeoutMs: 5000, ...over })
const servers: Array<{ close: () => Promise<void> }> = []
afterAll(async () => { for (const s of servers) await s.close() })
const start = async (o?: Parameters<typeof startFakeSmtp>[0]) => { const s = await startFakeSmtp(o); servers.push(s); return s }

describe('client SMTP', () => {
  it('connexion simple sans authentification : message remis, corps et objet décodés (UTF-8)', async () => {
    const s = await start()
    await sendMail(base(s.port, { subject: '[CRITIQUE] lab — quorum perdu é', text: 'Quorum etcd PERDU.\r\n.ligne commençant par un point\r\nFin', to: ['a@example.com', 'b@example.com'] }))
    expect(s.mails).toHaveLength(1)
    const m = s.mails[0]!
    expect(m.from).toBe('ddibuntu@example.com'); expect(m.to).toEqual(['a@example.com', 'b@example.com']); expect(m.secure).toBe(false); expect(m.auth).toBeNull()
    expect(subjectOf(m)).toBe('[CRITIQUE] lab — quorum perdu é')
    expect(decode(m).body).toBe('Quorum etcd PERDU.\r\n.ligne commençant par un point\r\nFin')
    expect(decode(m).headers['content-type']).toContain('utf-8'); expect(decode(m).headers['auto-submitted']).toBe('auto-generated')
  })
  it('STARTTLS (certificat auto-signé accepté sur demande) + AUTH PLAIN : le mot de passe ne circule qu’après chiffrement', async () => {
    const s = await start({ starttls: true, auth: { user: 'robot', pass: 'S3cret!pw' } })
    await sendMail(base(s.port, { security: 'starttls', verifyCert: false, user: 'robot', pass: 'S3cret!pw' }))
    expect(s.mails[0]).toMatchObject({ secure: true, auth: 'robot:S3cret!pw' })
    expect(s.commands.filter((c) => !c.startsWith('(tls)')).join(' ')).not.toContain('AUTH')   // jamais d'AUTH avant le chiffrement
    expect(s.commands.some((c) => c.startsWith('(tls) AUTH PLAIN'))).toBe(true)
  })
  it('certificat auto-signé REFUSÉ par défaut (vérification activée) : rien n’est envoyé', async () => {
    const s = await start({ starttls: true })
    await expect(sendMail(base(s.port, { security: 'starttls', verifyCert: true }))).rejects.toThrow()
    expect(s.mails).toHaveLength(0)
  })
  it('TLS implicite', async () => {
    const s = await start({ implicitTls: true, auth: { user: 'robot', pass: 'pw-0123456789' } })
    await sendMail(base(s.port, { security: 'tls', verifyCert: false, user: 'robot', pass: 'pw-0123456789' }))
    expect(s.mails[0]).toMatchObject({ secure: true, auth: 'robot:pw-0123456789' })
  })
  it('mauvais mot de passe : refus, aucun message', async () => {
    const s = await start({ starttls: true, auth: { user: 'robot', pass: 'bon' } })
    await expect(sendMail(base(s.port, { security: 'starttls', verifyCert: false, user: 'robot', pass: 'mauvais' }))).rejects.toThrow(/smtp_535/)
    expect(s.mails).toHaveLength(0)
  })
  it('identifiants sans chiffrement : refusés AVANT toute connexion', async () => {
    const s = await start({ plainAuthWithoutTls: true, auth: { user: 'robot', pass: 'pw' } })
    await expect(sendMail(base(s.port, { security: 'none', user: 'robot', pass: 'pw' }))).rejects.toThrow('auth_requires_tls')
    expect(s.commands).toHaveLength(0)
  })
  it('STARTTLS demandé mais non proposé par le serveur : échec, jamais de repli en clair', async () => {
    const s = await start({})
    await expect(sendMail(base(s.port, { security: 'starttls', verifyCert: false }))).rejects.toThrow('starttls_unsupported')
    expect(s.mails).toHaveLength(0)
  })
  it('destinataire refusé par le serveur : erreur explicite', async () => {
    const s = await start({ refuseRcpt: 'ops@example.com' })
    await expect(sendMail(base(s.port))).rejects.toThrow(/smtp_550/)
  })
  it('adresses invalides ou piégées (injection d’en-tête) : refusées sans connexion', async () => {
    const s = await start()
    for (const bad of ['a@b.c\r\nBcc: x@y.z', 'pas-une-adresse', 'a b@example.com', '<a@example.com>', '']) {
      await expect(sendMail(base(s.port, { to: [bad] }))).rejects.toThrow('bad_address')
      await expect(sendMail(base(s.port, { from: bad }))).rejects.toThrow('bad_address')
    }
    await expect(sendMail(base(s.port, { to: [] }))).rejects.toThrow('bad_address')
    expect(s.commands).toHaveLength(0)
  })
  it('objet avec retours à la ligne : aplati, aucun en-tête ajouté', async () => {
    const s = await start()
    await sendMail(base(s.port, { subject: 'Objet\r\nBcc: pirate@example.com' }))
    const d = decode(s.mails[0]!)
    expect(d.headers.bcc).toBeUndefined(); expect(subjectOf(s.mails[0]!)).toBe('Objet Bcc: pirate@example.com')
  })
  it('serveur injoignable : erreur claire, pas de blocage', async () => {
    await expect(sendMail(base(1, { timeoutMs: 2000 }))).rejects.toThrow()
  })
})
