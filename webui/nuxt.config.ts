export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  modules: ['@nuxt/ui'],
  css: ['~/assets/css/main.css'],
  // Appliance hors ligne : aucune police ni icône téléchargée (polices Fira embarquées, icônes Lucide locales)
  ui: { fonts: false },
  icon: { provider: 'server', fallbackToApi: false, serverBundle: { collections: ['lucide'] }, clientBundle: { scan: true } },
  devtools: { enabled: false },
  telemetry: false,
  typescript: { strict: true },
  nitro: { preset: 'node-server' },
  app: {
    head: {
      title: 'DDI-Buntu',
      htmlAttrs: { lang: 'fr' },
      link: [{ rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
      meta: [{ name: 'viewport', content: 'width=device-width, initial-scale=1' }, { name: 'color-scheme', content: 'light dark' }],
    },
  },
})
