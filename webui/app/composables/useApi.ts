// Appels d'API : jeton CSRF, redirection si la session a expiré, erreurs traduites.
export interface ApiErrorInfo { status: number; code: string; message: string; issues: Array<{ path: string; message: string }> }

export function useApi() {
  const csrf = useState<string>('csrf', () => '')
  const { t } = useT()

  function describe(e: any): ApiErrorInfo {
    const status = e?.statusCode ?? e?.response?.status ?? 0
    const body = e?.data ?? {}
    const code: string = body?.data?.code ?? body?.statusMessage ?? (status ? 'internal' : 'network')
    const key = `err.${code}`
    const msg = t(key)
    return { status, code, message: msg === key ? t('err.internal') : msg, issues: body?.data?.issues ?? [] }
  }

  async function call<T = any>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, body?: unknown, opts: { silent?: boolean } = {}): Promise<T> {
    try {
      return await $fetch<T>('/api' + url, { method, body: body as any, headers: method === 'GET' ? {} : { 'x-csrf-token': csrf.value } })
    } catch (e: any) {
      const info = describe(e)
      if (info.status === 401 && !opts.silent) { useState<any>('user').value = null; await navigateTo('/login') }
      throw Object.assign(new Error(info.code), { info })
    }
  }
  return { call, describe, csrf }
}
