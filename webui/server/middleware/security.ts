// En-têtes de sécurité sur toutes les réponses.
import { cfg } from '../utils/config'

export default defineEventHandler((event) => {
  const h = (k: string, v: string) => setResponseHeader(event, k, v)
  // 'unsafe-inline' : Nuxt injecte un script d'amorçage en ligne ; passage à un nonce prévu (nuxt-security)
  h('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
  h('X-Content-Type-Options', 'nosniff')
  h('X-Frame-Options', 'DENY')
  h('Referrer-Policy', 'no-referrer')
  h('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
  h('Cross-Origin-Opener-Policy', 'same-origin')
  h('Cross-Origin-Resource-Policy', 'same-origin')
  if (cfg().cookieSecure) h('Strict-Transport-Security', 'max-age=31536000')
})
