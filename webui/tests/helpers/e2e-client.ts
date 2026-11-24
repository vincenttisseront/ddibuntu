// Assistants des tests de bout en bout : client HTTP à cookie de session et jeton CSRF, attente d'une condition.
import { expect } from 'vitest'

export function clientClass(base: string) {
  return class Client {
    cookie = ''; csrf = ''
    async req(method: string, path: string, body?: unknown) {
      const headers: Record<string, string> = { cookie: this.cookie }
      if (body !== undefined) headers['content-type'] = 'application/json'
      if (method !== 'GET' && this.csrf) headers['x-csrf-token'] = this.csrf
      const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
      for (const c of r.headers.getSetCookie?.() ?? []) { const kv = c.split(';')[0]!; if (kv.startsWith('ddi_session=')) this.cookie = kv }
      const text = await r.text(); let json: any = null; try { json = JSON.parse(text) } catch { /* HTML */ }
      return { status: r.status, json, text, headers: r.headers }
    }
    get = (p: string) => this.req('GET', p); post = (p: string, b: unknown = {}) => this.req('POST', p, b); put = (p: string, b: unknown) => this.req('PUT', p, b); delete = (p: string) => this.req('DELETE', p)
    async login(u: string, p: string) { const r = await this.post('/api/auth/login', { username: u, password: p }); if (r.status === 200) this.csrf = r.json.csrf; return r }
  }
}

export const code = (r: { status: number; json: any }, status: number, c: string) => expect([r.status, r.json?.data?.code]).toEqual([status, c])
export const until = async (fn: () => Promise<boolean>, ms = 30000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await fn()) return } catch { /* pas encore */ } await new Promise((r) => setTimeout(r, 300)) } throw new Error('délai dépassé') }
