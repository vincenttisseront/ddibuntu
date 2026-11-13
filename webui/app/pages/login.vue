<script setup lang="ts">
definePageMeta({ layout: 'login' })
const { t, lang, setLang } = useT()
const api = useApi()
const colorMode = useColorMode()
const { data: setup } = await useFetch<{ needed: boolean }>('/api/setup/status')
const { data: prov } = await useFetch<{ version: string | null; oidc: { label: string | null; url: string } | null }>('/api/auth/providers', { default: () => ({ version: null, oidc: null }) })
const route = useRoute()
const ssoErr = computed(() => (route.query.sso_error ? t(`err.sso_${String(route.query.sso_error)}`) : ''))
const username = ref(''), password = ref(''), error = ref(''), busy = ref(false), showPw = ref(false), caps = ref(false)
// seconde étape (MFA)
const challenge = ref(''), code = ref(''), recovery = ref(false)
const done = async (r: any) => { useState<any>('user').value = r.user; api.csrf.value = r.csrf; await navigateTo('/') }
async function submit() {
  busy.value = true; error.value = ''
  try {
    const r: any = await api.call('POST', '/auth/login', { username: username.value, password: password.value }, { silent: true })
    if (r.mfa) { challenge.value = r.challenge; code.value = ''; recovery.value = false; password.value = ''; return }
    await done(r)
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal'); password.value = '' } finally { busy.value = false }
}
async function submitCode() {
  busy.value = true; error.value = ''
  try { await done(await api.call('POST', '/auth/login/mfa', { challenge: challenge.value, code: code.value }, { silent: true })) }
  catch (e: any) {
    error.value = e.info?.message ?? t('err.internal'); code.value = ''
    if (e.info?.code === 'mfa_expired') { challenge.value = ''; password.value = '' }
  } finally { busy.value = false }
}
const digits = computed({ get: () => code.value.split('').slice(0, 6), set: (v: string[]) => { code.value = v.join('') } })
watch(code, (c) => { if (!recovery.value && /^\d{6}$/.test(c) && !busy.value) submitCode() })
function back() { challenge.value = ''; code.value = ''; error.value = ''; recovery.value = false }
const onKey = (e: KeyboardEvent) => { caps.value = e.getModifierState?.('CapsLock') ?? false }
</script>

<template>
  <div class="min-h-screen w-full grid lg:grid-cols-[minmax(0,5fr)_minmax(0,4fr)]">
    <!-- Bandeau de marque (masqué sur mobile) -->
    <aside class="relative hidden lg:flex flex-col justify-between overflow-hidden p-12 text-white bg-gradient-to-br from-brand-900 via-brand-800 to-brand-600" aria-hidden="true">
      <svg class="absolute inset-0 size-full opacity-[0.14]" xmlns="http://www.w3.org/2000/svg"><defs><pattern id="g" width="48" height="48" patternUnits="userSpaceOnUse"><path d="M48 0H0V48" fill="none" stroke="currentColor" stroke-width="1" /></pattern></defs><rect width="100%" height="100%" fill="url(#g)" /></svg>
      <svg class="absolute -right-24 -bottom-24 size-[30rem] opacity-20" viewBox="0 0 200 200" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="100" cy="100" r="30" /><circle cx="100" cy="100" r="60" /><circle cx="100" cy="100" r="90" /><path d="M100 10V190M10 100H190M36 36l128 128M164 36L36 164" /><circle cx="100" cy="100" r="6" fill="currentColor" /><circle cx="160" cy="100" r="5" fill="currentColor" /><circle cx="52" cy="58" r="5" fill="currentColor" /><circle cx="70" cy="160" r="5" fill="currentColor" /></svg>
      <div class="relative flex items-center gap-3"><UIcon name="i-lucide-network" class="size-8" /><span class="font-mono text-2xl font-semibold tracking-tight">DDI-Buntu</span></div>
      <div class="relative max-w-md">
        <h2 class="text-4xl font-semibold leading-tight">{{ t('login.tagline') }}</h2>
        <ul class="mt-8 flex flex-col gap-4 text-brand-50/90">
          <li class="flex items-start gap-3"><UIcon name="i-lucide-globe" class="size-5 mt-0.5 shrink-0" /><span><b class="font-semibold text-white">DNS</b> · {{ t('login.f_dns') }}</span></li>
          <li class="flex items-start gap-3"><UIcon name="i-lucide-server" class="size-5 mt-0.5 shrink-0" /><span><b class="font-semibold text-white">DHCP</b> · {{ t('login.f_dhcp') }}</span></li>
          <li class="flex items-start gap-3"><UIcon name="i-lucide-layout-grid" class="size-5 mt-0.5 shrink-0" /><span><b class="font-semibold text-white">IPAM</b> · {{ t('login.f_ipam') }}</span></li>
          <li class="flex items-start gap-3"><UIcon name="i-lucide-shield-check" class="size-5 mt-0.5 shrink-0" /><span><b class="font-semibold text-white">{{ t('login.f_ha_t') }}</b> · {{ t('login.f_ha') }}</span></li>
        </ul>
      </div>
      <p class="relative font-mono text-xs text-brand-100/70">{{ prov?.version ? `v${prov.version}` : '' }}</p>
    </aside>

    <!-- Formulaire -->
    <main class="relative flex flex-col items-center justify-center px-6 py-12 bg-default">
      <div class="absolute top-4 end-4 flex items-center gap-1">
        <UButton color="neutral" variant="ghost" size="sm" :icon="colorMode.value === 'dark' ? 'i-lucide-sun' : 'i-lucide-moon'" :aria-label="t('nav.theme')" @click="colorMode.preference = colorMode.value === 'dark' ? 'light' : 'dark'" />
        <UButton color="neutral" variant="ghost" size="sm" :label="lang === 'fr' ? 'EN' : 'FR'" :aria-label="t('nav.language')" @click="setLang(lang === 'fr' ? 'en' : 'fr')" />
      </div>
      <div class="w-full max-w-sm">
        <div class="lg:hidden flex items-center gap-2 mb-8"><UIcon name="i-lucide-network" class="size-7 text-primary" /><span class="font-mono text-xl font-semibold">DDI-Buntu</span></div>

        <!-- Étape 1 : identifiants -->
        <form v-if="!challenge" class="flex flex-col gap-5" @submit.prevent="submit">
          <div><h1 class="text-2xl font-semibold">{{ t('login.title') }}</h1><p class="mt-1 text-sm text-muted">{{ t('login.intro') }}</p></div>
          <UAlert v-if="error || ssoErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error || ssoErr" role="alert" />
          <UFormField :label="t('login.username')" required><UInput v-model="username" icon="i-lucide-user" autocomplete="username" autofocus size="lg" class="w-full" /></UFormField>
          <UFormField :label="t('login.password')" required :help="caps ? t('login.caps') : undefined">
            <UInput v-model="password" :type="showPw ? 'text' : 'password'" icon="i-lucide-lock" autocomplete="current-password" size="lg" class="w-full" @keydown="onKey" @keyup="onKey">
              <template #trailing><UButton color="neutral" variant="link" size="sm" :icon="showPw ? 'i-lucide-eye-off' : 'i-lucide-eye'" :aria-label="showPw ? t('login.hide') : t('login.show')" :aria-pressed="showPw" @click="showPw = !showPw" /></template>
            </UInput>
          </UFormField>
          <UButton type="submit" block size="lg" :loading="busy" :label="t('login.submit')" :disabled="!username || !password" />
          <template v-if="prov?.oidc">
            <div class="flex items-center gap-3 text-xs text-muted"><span class="h-px flex-1 bg-border" />{{ t('login.or') }}<span class="h-px flex-1 bg-border" /></div>
            <UButton block size="lg" color="neutral" variant="outline" icon="i-lucide-log-in" :href="prov.oidc.url" external :label="prov.oidc.label || t('sso.button_default')" />
          </template>
          <NuxtLink v-if="setup?.needed" to="/setup" class="text-xs text-muted text-center underline">{{ t('login.first_setup') }}</NuxtLink>
        </form>

        <!-- Étape 2 : second facteur -->
        <form v-else class="flex flex-col gap-5" @submit.prevent="submitCode">
          <div><div class="mb-3 grid place-items-center size-12 rounded-full bg-primary/10 text-primary"><UIcon name="i-lucide-shield-check" class="size-6" /></div>
            <h1 class="text-2xl font-semibold">{{ t('login.mfa_title') }}</h1><p class="mt-1 text-sm text-muted">{{ recovery ? t('login.mfa_recovery_intro') : t('login.mfa_intro') }}</p></div>
          <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" />
          <div v-if="!recovery" class="flex justify-center"><UPinInput v-model="digits" :length="6" type="number" otp size="xl" autofocus :disabled="busy" :aria-label="t('login.mfa_code')" /></div>
          <UInput v-else v-model="code" size="lg" class="w-full font-mono" placeholder="xxxxx-xxxxx" autocomplete="off" autofocus :aria-label="t('login.mfa_recovery_code')" />
          <UButton type="submit" block size="lg" :loading="busy" :label="t('login.mfa_verify')" :disabled="recovery ? code.trim().length < 11 : code.length !== 6" />
          <div class="flex items-center justify-between text-sm">
            <UButton color="neutral" variant="link" size="sm" icon="i-lucide-arrow-left" :label="t('login.back')" @click="back" />
            <UButton color="neutral" variant="link" size="sm" :label="recovery ? t('login.mfa_use_app') : t('login.mfa_use_recovery')" @click="recovery = !recovery; code = ''; error = ''" />
          </div>
        </form>
      </div>
      <p class="absolute bottom-4 text-xs text-muted lg:hidden font-mono">{{ prov?.version ? `v${prov.version}` : '' }}</p>
    </main>
  </div>
</template>
