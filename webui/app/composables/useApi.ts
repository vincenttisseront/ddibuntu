// Appels d'API : jeton CSRF, redirection si la session a expiré, erreurs traduites.
import { isSessionExpired } from '../utils/session'
export interface ApiErrorInfo { status: number; code: string; message: string; issues: Array<{ path: string; message: string }>; upstream?: { status: number; detail: string } }

export function useApi() {
  const csrf = useState<string>('csrf', () => '')
  const { t } = useT()

  function describe(e: any): ApiErrorInfo {
    const status = e?.statusCode ?? e?.response?.status ?? 0
    const body = e?.data ?? {}
    const code: string = body?.data?.code ?? body?.statusMessage ?? (status ? 'internal' : 'network')
    const key = `err.${code}`
    const msg = t(key)
    const up = body?.data?.upstream
    return { status, code, message: msg === key ? t('err.internal') : msg, issues: body?.data?.issues ?? [], ...(up && typeof up.status === 'number' ? { upstream: { status: up.status, detail: String(up.detail ?? '') } } : {}) }
  }

  async function call<T = any>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, body?: unknown, opts: { silent?: boolean; busy?: boolean } = {}): Promise<T> {
    // indicateur d'attente global : toute écriture (POST/PUT/DELETE) ou appel marqué « busy » ; il n'apparaît qu'au-delà de 400 ms (voir BusyIndicator)
    const track = method !== 'GET' || opts.busy === true
    const busy = useState<number>('busy', () => 0)
    if (track) busy.value++
    try {
      return await $fetch<T>('/api' + url, { method, body: body as any, headers: method === 'GET' ? {} : { 'x-csrf-token': csrf.value } })
    } catch (e: any) {
      const info = describe(e)
      if (isSessionExpired(info.status, info.code) && !opts.silent) { useState<any>('user').value = null; await navigateTo('/login') }
      throw Object.assign(new Error(info.code), { info })
    } finally {
      if (track) busy.value = Math.max(0, busy.value - 1)
    }
  }
  return { call, describe, csrf }
}
