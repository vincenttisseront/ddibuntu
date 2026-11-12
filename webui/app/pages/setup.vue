<script setup lang="ts">
definePageMeta({ layout: 'blank' })
const { t } = useT(); const api = useApi()
// appliance déjà initialisée : plus rien à faire ici
const { data: status } = await useFetch<{ needed: boolean }>('/api/setup/status')
if (!status.value?.needed) await navigateTo('/login', { replace: true })
const token = ref(''), username = ref('admin'), password = ref(''), error = ref(''), done = ref(false)
async function submit() {
  error.value = ''
  try { await api.call('POST', '/setup/admin', { token: token.value, username: username.value, password: password.value }, { silent: true }); done.value = true }
  catch (e: any) { error.value = e.info?.message ?? t('err.internal') }
}
</script>

<template>
  <UCard class="w-full max-w-sm">
    <template #header><h1 class="font-semibold">{{ t('setup.title') }}</h1></template>
    <div v-if="done" class="flex flex-col gap-3"><UAlert color="success" variant="subtle" icon="i-lucide-check" :title="t('setup.done')" /><UButton to="/login" block :label="t('login.submit')" /></div>
    <form v-else class="flex flex-col gap-4" @submit.prevent="submit">
      <p class="text-sm text-muted">{{ t('setup.intro') }}</p>
      <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" />
      <UFormField :label="t('setup.token')" required><UInput v-model="token" type="password" autocomplete="off" class="w-full" /></UFormField>
      <UFormField :label="t('login.username')" required><UInput v-model="username" autocomplete="username" class="w-full" /></UFormField>
      <UFormField :label="t('login.password')" :help="t('login.policy')" required><UInput v-model="password" type="password" autocomplete="new-password" class="w-full" /></UFormField>
      <UButton type="submit" block :label="t('setup.submit')" :disabled="!token || !username || !password" />
    </form>
  </UCard>
</template>
