<script setup lang="ts">
definePageMeta({ layout: 'blank' })
const { t, lang, setLang } = useT()
const api = useApi()
const username = ref(''), password = ref(''), error = ref(''), busy = ref(false)
async function submit() {
  busy.value = true; error.value = ''
  try {
    const r: any = await api.call('POST', '/auth/login', { username: username.value, password: password.value }, { silent: true })
    useState<any>('user').value = r.user; api.csrf.value = r.csrf
    await navigateTo('/')
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal'); password.value = '' } finally { busy.value = false }
}
</script>

<template>
  <UCard class="w-full max-w-sm">
    <template #header>
      <div class="flex items-center gap-2"><UIcon name="i-lucide-network" class="size-6 text-primary" /><h1 class="font-mono font-semibold text-lg">DDI-Buntu</h1><div class="flex-1" />
        <UButton color="neutral" variant="ghost" size="sm" :label="lang === 'fr' ? 'EN' : 'FR'" :aria-label="t('nav.language')" @click="setLang(lang === 'fr' ? 'en' : 'fr')" /></div>
    </template>
    <form class="flex flex-col gap-4" @submit.prevent="submit">
      <p class="text-sm text-muted">{{ t('login.intro') }}</p>
      <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" />
      <UFormField :label="t('login.username')" required><UInput v-model="username" autocomplete="username" autofocus class="w-full" /></UFormField>
      <UFormField :label="t('login.password')" required><UInput v-model="password" type="password" autocomplete="current-password" class="w-full" /></UFormField>
      <UButton type="submit" block :loading="busy" :label="t('login.submit')" :disabled="!username || !password" />
      <NuxtLink to="/setup" class="text-xs text-muted text-center underline">{{ t('login.first_setup') }}</NuxtLink>
    </form>
  </UCard>
</template>
