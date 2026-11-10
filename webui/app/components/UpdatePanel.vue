<script setup lang="ts">
// Mises à jour en ligne : version installée / disponible, notes, installation sur clic. Rien n'est installé automatiquement.
// La console ne fait que demander ; l'installation (signature vérifiée, sauvegarde, retour arrière) est faite par un service root.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const data = ref<any>(null), loading = ref(true), error = ref(''), waitingRestart = ref(false)
let timer: ReturnType<typeof setInterval> | undefined, wasBusy = false

async function load(silent = false) {
  try { data.value = await api.call('GET', '/system/update', undefined, { silent }); error.value = ''; waitingRestart.value = false }
  catch (e: any) { if (!silent) error.value = e.info?.message ?? t('err.internal'); else waitingRestart.value = true }
  finally { loading.value = false }
  const busy = !!data.value?.busy
  if (busy) { wasBusy = true; startPolling() }
  else { stopPolling(); if (wasBusy) { wasBusy = false; finished() } }
}
function startPolling() { if (!timer) timer = setInterval(() => load(true), 3000) }
function stopPolling() { if (timer) { clearInterval(timer); timer = undefined } }
function finished() {
  const st = data.value?.status
  if (st?.state === 'done') { toast.add({ title: t('update.done', { v: st.current }), color: 'success', icon: 'i-lucide-check' }); setTimeout(() => location.reload(), 2500) }
  else if (st?.state === 'failed') toast.add({ title: t('update.failed'), description: st.error, color: 'error' })
}
onMounted(() => load())
onBeforeUnmount(stopPolling)

const st = computed(() => data.value?.status ?? null)
const busy = computed(() => !!data.value?.busy || waitingRestart.value)
const when = (s: number) => (s ? new Date(s * 1000).toLocaleString() : t('update.never'))
async function check() {
  error.value = ''
  try { await api.call('POST', '/system/update/check'); wasBusy = true; await new Promise((r) => setTimeout(r, 1500)); await load(true); startPolling() }
  catch (e: any) { error.value = e.info?.message ?? t('err.internal') }
}
async function install() {
  const v = st.value?.latest
  if (!v || !(await ask(t('update.confirm_title', { v }), t('update.confirm_body'), false))) return
  error.value = ''
  try { await api.call('POST', '/system/update/apply', { version: v }); wasBusy = true; await new Promise((r) => setTimeout(r, 1500)); await load(true); startPolling() }
  catch (e: any) { error.value = e.info?.message ?? t('err.internal') }
}
</script>

<template>
  <div class="flex flex-col gap-4 max-w-3xl">
    <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" />
    <UCard>
      <template #header><span class="font-medium">{{ t('update.title') }}</span></template>
      <p class="text-sm text-muted mb-3">{{ t('update.desc') }}</p>
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm mb-4">
        <dt class="text-muted">{{ t('update.installed') }}</dt><dd class="font-mono">{{ data?.version || st?.current || '—' }}</dd>
        <dt class="text-muted">{{ t('update.latest') }}</dt><dd class="font-mono">{{ st?.latest || '—' }}</dd>
        <dt class="text-muted">{{ t('update.checked') }}</dt><dd>{{ when(st?.checkedAt ?? 0) }}</dd>
      </dl>
      <UAlert v-if="st && st.state === 'failed'" class="mb-3" color="error" variant="subtle" icon="i-lucide-circle-x" :title="t('update.failed')" :description="st.error" />
      <UAlert v-else-if="st && st.error && !busy" class="mb-3" color="warning" variant="subtle" icon="i-lucide-wifi-off" :title="t('update.check_error')" :description="st.error" />
      <UAlert v-if="busy" class="mb-3" color="info" variant="subtle" icon="i-lucide-loader" :title="waitingRestart ? t('update.state.restarting') : t(`update.state.${st?.state ?? 'checking'}`)" :description="t('update.busy_hint')" />
      <UAlert v-else-if="st && !st.available && st.latest && !st.error" class="mb-3" color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('update.up_to_date')" />
      <div class="flex gap-2">
        <UButton icon="i-lucide-refresh-cw" color="neutral" variant="outline" :loading="busy" :disabled="busy" :label="t('update.check')" @click="check" />
        <UButton v-if="st?.available && !busy" icon="i-lucide-download" :label="t('update.install', { v: st.latest })" @click="install" />
      </div>
    </UCard>

    <UCard v-if="st?.available && !busy">
      <template #header><div class="flex items-center gap-2"><UBadge color="primary" variant="subtle" :label="t('update.available')" /><span class="font-medium">{{ st.latest }}</span>
        <a v-if="st.url" :href="st.url" target="_blank" rel="noopener noreferrer" class="text-sm text-primary underline ms-auto">{{ t('update.release_page') }}</a></div></template>
      <h3 class="text-sm font-medium mb-1">{{ t('update.notes') }}</h3>
      <pre class="text-sm whitespace-pre-wrap font-sans max-h-72 overflow-auto">{{ st.notes || t('common.empty') }}</pre>
    </UCard>
  </div>
</template>
