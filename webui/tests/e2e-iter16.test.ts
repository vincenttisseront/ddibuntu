// Bout en bout (serveur CONSTRUIT, PostgreSQL réel) : 0.9.28 — traçabilité des baux (historique IP / MAC / nom).
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import pg from 'pg'
import { createServer, type Server } from 'node:http'
import { createHash } from 'node:crypto'
import { SignJWT, exportJWK, generateKeyPair } from 'jose'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

process.env.DDI_SECRET_KEY = 'cle-secrete-de-test-0123456789abcdefghij'; process.env.DDI_TEST_MODE = '1'; process.env.DDI_PBKDF2_ITERATIONS = '2000'

const PORT = 3416, BASE = `http://127.0.0.1:${PORT}`
const DBURL = 'postgresql://ddi:ddi-test-pw@127.0.0.1:5432/ddibuntu_test'
const SETUP_TOKEN = 'jeton-de-test-0123456789abcdef', PW = 'Correct-Horse-Battery-9'
const TMP = mkdtempSync(join(tmpdir(), 'ddi-s16-')); mkdirSync(join(TMP, 'gen'))
let srv: ChildProcess, db: pg.Client, srvLog = ''

class Client {
  cookie = ''; csrf = ''
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = { cookie: this.cookie }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
    for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
    const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* HTML */ }
    return { status: r.status, json, text }
  }
  get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b); delete = (p: string) => this.req('DELETE', p)
  async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
}
const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
const admin = new Client(), viewer = new Client(), anon = new Client()
const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }

beforeAll(async () => {
  db = new pg.Client({ connectionString: DBURL }); await db.connect()
  await db.query('drop schema public cascade; create schema public')
  srv = spawn('node', ['.output/server/index.mjs'], { env: { ...process.env, NODE_ENV: 'production', PORT: String(PORT), NITRO_HOST: '127.0.0.1', DDI_TEST_MODE: '1', DDI_COOKIE_SECURE: 'false', DDI_DATABASE_URL: DBURL,
    DDI_SECRET_KEY: 'cle-secrete-de-test-0123456789abcdefghij', DDI_SETUP_TOKEN: SETUP_TOKEN, DDI_PBKDF2_ITERATIONS: '2000', DDI_GENERATED_DIR: join(TMP, 'gen'), DDI_RELOAD_STATUS: join(TMP, 'rs'), DDI_CLUSTER_STATUS: join(TMP, 'cl.json'), DDI_AD_STATUS: join(TMP, 'ad.json'), DDI_OIDC_ALLOW_HTTP: '1' } })
  srv.stdout!.on('data', (d) => { srvLog += d }); srv.stderr!.on('data', (d) => { srvLog += d })
  await until(async () => (await fetch(BASE + '/api/health')).status === 200)
  const su = await anon.post('/api/setup/admin', { token: SETUP_TOKEN, username: 'admin', password: PW })
  expect(su.status, `setup : ${su.text}\n${srvLog.slice(-1500)}`).toBe(200)
  expect((await admin.login('admin', PW)).status).toBe(200)
  expect((await admin.post('/api/users', { username: 'lect', role: 'viewer', password: PW })).status).toBe(200)
  expect((await viewer.login('lect', PW)).status).toBe(200)
}, 120000)
afterAll(async () => { srv?.kill('SIGTERM'); await db?.end() })



// ---- Fournisseur d'identité simulé : découverte, JWKS, autorisation, jeton (PKCE vérifié, code à usage unique), userinfo ----
const IDP_PORT = 3417, IDP = `http://127.0.0.1:${IDP_PORT}`, CLIENT = 'ddi-console', SECRET = 'secret-client-de-test'
let idp: Server, key: any, other: any
const codes = new Map<string, { nonce: string; challenge: string; redirect: string; claims: any }>()
const knob: { claims: any; badSig?: boolean; aud?: string; iss?: string; expired?: boolean; nonce?: string; userinfoGroups?: string[]; deny?: boolean } = { claims: {} }
beforeAll(async () => {
  key = await generateKeyPair('RS256'); other = await generateKeyPair('RS256')
  const jwk = { ...(await exportJWK(key.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }
  idp = createServer(async (req, res) => {
    const u = new URL(req.url!, IDP); const send = (st: number, o: unknown, h: Record<string, string> = {}) => { res.writeHead(st, { 'content-type': 'application/json', ...h }); res.end(JSON.stringify(o)) }
    if (u.pathname === '/.well-known/openid-configuration') return send(200, { issuer: IDP, authorization_endpoint: `${IDP}/authorize`, token_endpoint: `${IDP}/token`, jwks_uri: `${IDP}/jwks`, userinfo_endpoint: `${IDP}/userinfo` })
    if (u.pathname === '/jwks') return send(200, { keys: [jwk] })
    if (u.pathname === '/authorize') {
      const q = u.searchParams
      if (q.get('client_id') !== CLIENT || q.get('code_challenge_method') !== 'S256' || !q.get('code_challenge') || q.get('response_type') !== 'code' || !q.get('nonce') || !q.get('state')) return send(400, { error: 'invalid_request' })
      const back = new URL(q.get('redirect_uri')!)
      if (knob.deny) { back.searchParams.set('error', 'access_denied'); back.searchParams.set('state', q.get('state')!); res.writeHead(302, { location: back.toString() }); return res.end() }
      const code = 'c' + Math.random().toString(36).slice(2); codes.set(code, { nonce: q.get('nonce')!, challenge: q.get('code_challenge')!, redirect: q.get('redirect_uri')!, claims: knob.claims })
      back.searchParams.set('code', code); back.searchParams.set('state', q.get('state')!); res.writeHead(302, { location: back.toString() }); return res.end()
    }
    if (u.pathname === '/token') {
      let raw = ''; for await (const c of req) raw += c; const p = new URLSearchParams(raw)
      const auth = Buffer.from((req.headers.authorization ?? '').replace('Basic ', ''), 'base64').toString()
      if (auth !== `${CLIENT}:${SECRET}`) return send(401, { error: 'invalid_client' })
      const c = codes.get(p.get('code') ?? ''); codes.delete(p.get('code') ?? '')       // usage unique
      if (!c || c.redirect !== p.get('redirect_uri') || createHash('sha256').update(p.get('code_verifier') ?? '').digest('base64url') !== c.challenge) return send(400, { error: 'invalid_grant' })
      const now = Math.floor(Date.now() / 1000)
      const jwt = await new SignJWT({ ...c.claims, nonce: knob.nonce ?? c.nonce }).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(knob.iss ?? IDP).setAudience(knob.aud ?? CLIENT).setSubject(String(c.claims.sub ?? 'x')).setIssuedAt(now - 10).setExpirationTime(knob.expired ? now - 3600 : now + 300).sign(knob.badSig ? other.privateKey : key.privateKey)
      return send(200, { id_token: jwt, access_token: 'at-' + Math.random(), token_type: 'Bearer' })
    }
    if (u.pathname === '/userinfo') return send(200, { groups: knob.userinfoGroups ?? [] })
    send(404, {})
  })
  await new Promise<void>((r) => idp.listen(IDP_PORT, '127.0.0.1', r))
})
afterAll(async () => { idp?.close() })

/** Parcours navigateur complet : start → IdP → callback ; renvoie l'adresse finale et le cookie de session éventuel. */
async function sso(claims: any, tweak: Partial<typeof knob> = {}, mutate?: (cb: URL, ck: string) => { url: URL; cookie: string }) {
  Object.keys(knob).forEach((k) => delete (knob as any)[k]); Object.assign(knob, { claims }, tweak)
  const r1 = await fetch(BASE + '/api/auth/oidc/start', { redirect: 'manual' })
  const loc1 = r1.headers.get('location')!; const ck = (r1.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]!).find((c) => c.startsWith('ddi_oidc=')) ?? ''
  if (!loc1.startsWith(IDP)) return { loc: loc1, cookie: '', startStatus: r1.status }
  const r2 = await fetch(loc1, { redirect: 'manual' }); const cb = new URL(r2.headers.get('location')!)
  const m = mutate ? mutate(cb, ck) : { url: cb, cookie: ck }
  const r3 = await fetch(m.url.toString().replace(`http://127.0.0.1:${PORT}`, BASE), { redirect: 'manual', headers: { cookie: m.cookie } })
  const session = (r3.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0]!).find((c) => c.startsWith('ddi_session=')) ?? ''
  return { loc: r3.headers.get('location') ?? '', cookie: session, startStatus: r1.status }
}
const me = async (cookie: string) => { const r = await fetch(BASE + '/api/auth/me', { headers: { cookie } }); return (await r.json()).user }
const errOf = (loc: string) => new URL(loc, BASE).searchParams.get('sso_error')

describe('SSO OpenID Connect', () => {
  const settings = (over: any = {}) => ({ enabled: true, issuer: IDP, clientId: CLIENT, clientSecret: SECRET, publicUrl: '', scopes: 'openid profile email', usernameClaim: 'preferred_username', groupsClaim: 'groups',
    groupMap: [{ group: 'DDI-Admins', role: 'admin' }, { group: 'DDI-Paris', role: 'operator', spaceIds: [2] }, { group: 'DDI-Lyon', role: 'operator', spaceIds: [3] }, { group: 'DDI-Lecteurs', role: 'viewer' }], defaultRole: null, buttonLabel: 'Entreprise SSO', ...over })

  it('réglages : réservés à l\'administrateur, validés, secret jamais relu', async () => {
    code(await viewer.get('/api/sso/settings'), 403, 'forbidden'); code(await viewer.put('/api/sso/settings', settings()), 403, 'forbidden')
    code(await admin.put('/api/sso/settings', settings({ issuer: '' })), 400, 'sso_incomplete')
    code(await admin.put('/api/sso/settings', settings({ groupMap: [] })), 400, 'sso_no_mapping')
    expect((await admin.put('/api/sso/settings', settings({ scopes: 'openid <script>' }))).status).toBe(400)
    expect((await admin.put('/api/sso/settings', settings({ publicUrl: 'ftp://x' }))).status).toBe(400)
    expect((await admin.put('/api/sso/settings', settings({ enabled: false }))).status).toBe(200)
    expect((await anon.get('/api/auth/providers')).json.oidc).toBeNull()
    const ok = await admin.put('/api/sso/settings', settings()); expect(ok.status, ok.text).toBe(200)
    const g = await admin.get('/api/sso/settings'); expect(g.json).toMatchObject({ enabled: true, clientSecretSet: true, issuer: IDP }); expect(JSON.stringify(g.json)).not.toContain(SECRET)
    expect(g.json.callbackUrl).toBe(`${BASE}/api/auth/oidc/callback`)
    expect((await db.query("select value::text v from settings where key = 'oidc'")).rows[0].v).not.toContain(SECRET)       // chiffré au repos
    expect((await anon.get('/api/auth/providers')).json.oidc).toEqual({ label: 'Entreprise SSO', url: '/api/auth/oidc/start' })
    const t = await admin.post('/api/sso/test'); expect(t.status, t.text).toBe(200); expect(t.json).toMatchObject({ ok: true, issuer: IDP, keys: 1 })
  })
  it('connexion réussie : compte créé avec le rôle du groupe, session valide, aucune connexion locale possible', async () => {
    const r = await sso({ sub: 'u1', preferred_username: 'alice', name: 'Alice Martin', groups: ['DDI-Admins', 'Autre'] })
    expect(r.loc).toBe('/'); expect(r.cookie).toMatch(/^ddi_session=/)
    expect(await me(r.cookie)).toMatchObject({ username: 'alice', role: 'admin', source: 'oidc', displayName: 'Alice Martin', spaceIds: null })
    expect((await db.query("select source, password_hash, last_login is not null as l from users where username = 'alice'")).rows[0]).toEqual({ source: 'oidc', password_hash: null, l: true })
    code(await anon.post('/api/auth/login', { username: 'alice', password: PW }), 401, 'bad_credentials')
    expect((await db.query("select count(*)::int n from audit_log where action = 'login' and detail::text like '%oidc%'")).rows[0].n).toBe(1)
  })
  it('rôle le plus élevé et périmètre issus des groupes ; mise à jour à chaque connexion', async () => {
    let r = await sso({ sub: 'u2', preferred_username: 'paul', groups: ['ddi-paris', 'DDI-LYON', 'DDI-Lecteurs'] })       // insensible à la casse
    expect(await me(r.cookie)).toMatchObject({ role: 'operator', spaceIds: [2, 3] })
    r = await sso({ sub: 'u2', preferred_username: 'paul', groups: ['DDI-Lecteurs'] }); expect(await me(r.cookie)).toMatchObject({ role: 'viewer', spaceIds: null })
    r = await sso({ sub: 'u2', preferred_username: 'paul', groups: ['DDI-Paris'] }); expect(await me(r.cookie)).toMatchObject({ role: 'operator', spaceIds: [2] })
  })
  it('groupes absents du jeton : repris de userinfo', async () => {
    const r = await sso({ sub: 'u3', preferred_username: 'ugo' }, { userinfoGroups: ['DDI-Lecteurs'] }); expect(r.loc).toBe('/'); expect((await me(r.cookie)).role).toBe('viewer')
  })
  it('aucun groupe correspondant : refus, sauf rôle par défaut ; identifiant assaini ; repli sur e-mail', async () => {
    let r = await sso({ sub: 'u4', preferred_username: 'zoe', groups: ['Inconnu'] }); expect(errOf(r.loc)).toBe('no_group'); expect(r.cookie).toBe('')
    expect((await db.query("select 1 from users where username = 'zoe'")).rowCount).toBe(0)
    expect((await admin.put('/api/sso/settings', settings({ defaultRole: 'viewer' }))).status).toBe(200)
    r = await sso({ sub: 'u4', preferred_username: 'zoe de la Tour!', groups: [] }); expect(r.loc).toBe('/'); expect((await me(r.cookie))).toMatchObject({ username: 'zoe_de_la_Tour_', role: 'viewer' })
    r = await sso({ sub: 'u5', email: 'marc@exemple.fr' }); expect((await me(r.cookie)).username).toBe('marc@exemple.fr')
    expect((await admin.put('/api/sso/settings', settings())).status).toBe(200)
  })
  it('jamais de reprise d\'un compte local ni d\'un compte désactivé', async () => {
    let r = await sso({ sub: 'u6', preferred_username: 'admin', groups: ['DDI-Admins'] }); expect(errOf(r.loc)).toBe('conflict'); expect(r.cookie).toBe('')
    expect((await db.query("select source from users where username = 'admin'")).rows[0].source).toBe('local')
    await db.query("update users set disabled = true where username = 'alice'")
    r = await sso({ sub: 'u1', preferred_username: 'alice', groups: ['DDI-Admins'] }); expect(errOf(r.loc)).toBe('disabled_user'); expect(r.cookie).toBe('')
    await db.query("update users set disabled = false where username = 'alice'")
  })
  it('attaques : état falsifié, cookie absent, code rejoué, retour du fournisseur en erreur', async () => {
    let r = await sso({ sub: 'u7', preferred_username: 'eve', groups: ['DDI-Admins'] }, {}, (cb, ck) => { cb.searchParams.set('state', 'autre-etat'); return { url: cb, cookie: ck } }); expect(errOf(r.loc)).toBe('state')
    r = await sso({ sub: 'u7', preferred_username: 'eve', groups: ['DDI-Admins'] }, {}, (cb) => ({ url: cb, cookie: '' })); expect(errOf(r.loc)).toBe('state')
    r = await sso({ sub: 'u7', preferred_username: 'eve', groups: ['DDI-Admins'] }, {}, (cb) => ({ url: cb, cookie: 'ddi_oidc=n-importe-quoi' })); expect(errOf(r.loc)).toBe('state')
    // rejeu : le même retour utilisé deux fois
    let saved: { url: URL; cookie: string } | null = null
    r = await sso({ sub: 'u7', preferred_username: 'eve', groups: ['DDI-Admins'] }, {}, (cb, ck) => (saved = { url: cb, cookie: ck })); expect(r.loc).toBe('/')
    const again = await fetch(saved!.url.toString(), { redirect: 'manual', headers: { cookie: saved!.cookie } }); expect(errOf(again.headers.get('location')!)).toBe('token')
    r = await sso({ sub: 'u7' }, { deny: true }); expect(errOf(r.loc)).toBe('idp_error')
    expect((await db.query("select count(*)::int n from audit_log where action = 'login_failed' and detail::text like '%sso%'")).rows[0].n).toBeGreaterThanOrEqual(6)
  })
  it('id_token invalide : mauvaise signature, audience, émetteur, expiré, nonce', async () => {
    const c = { sub: 'u8', preferred_username: 'mallory', groups: ['DDI-Admins'] }
    for (const tweak of [{ badSig: true }, { aud: 'autre-client' }, { iss: 'http://evil.example' }, { expired: true }, { nonce: 'rejoue' }]) {
      const r = await sso(c, tweak); expect([JSON.stringify(tweak), errOf(r.loc), r.cookie]).toEqual([JSON.stringify(tweak), 'token', ''])
    }
    expect((await db.query("select 1 from users where username = 'mallory'")).rowCount).toBe(0)
  })
  it('désactivé : plus de bouton, démarrage refusé ; secondaire : refus propre', async () => {
    expect((await admin.put('/api/sso/settings', settings({ enabled: false }))).status).toBe(200)
    expect((await anon.get('/api/auth/providers')).json.oidc).toBeNull()
    const r = await sso({ sub: 'u9' }); expect(errOf(r.loc)).toBe('disabled')
  })
})
