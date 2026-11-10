<script setup lang="ts">
const open = defineModel<boolean>('open', { default: false })
const { t } = useT(); const api = useApi(); const toast = useToast()
const cur = ref(''), next = ref(''), again = ref(''), error = ref(''), busy = ref(false)
watch(open, (o) => { if (o) { cur.value = next.value = again.value = error.value = '' } })
async function submit() {
  error.value = ''
  if (next.value !== again.value) { error.value = t('login.mismatch'); return }
  busy.value = true
  try { await api.call('POST', '/auth/password', { current: cur.value, next: next.value }); open.value = false; toast.add({ title: t('login.changed'), color: 'success', icon: 'i-lucide-check' }) }
  catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
</script>

<template>
  <UModal v-model:open="open" :title="t('login.change_password')" :description="t('login.policy')">
    <template #body>
      <form class="flex flex-col gap-3" @submit.prevent="submit">
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" />
        <UFormField :label="t('login.current')" required><UInput v-model="cur" type="password" autocomplete="current-password" class="w-full" /></UFormField>
        <UFormField :label="t('login.new')" required><UInput v-model="next" type="password" autocomplete="new-password" class="w-full" /></UFormField>
        <UFormField :label="t('login.confirm')" required><UInput v-model="again" type="password" autocomplete="new-password" class="w-full" /></UFormField>
        <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="open = false" /><UButton type="submit" :loading="busy" :label="t('common.save')" /></div>
      </form>
    </template>
  </UModal>
</template>
