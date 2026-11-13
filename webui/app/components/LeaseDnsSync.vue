<script setup lang="ts">
// Synchronisation bail DHCP → DNS (0.10.0) : A et PTR créés avec le bail, retirés à son expiration, sans jamais toucher un enregistrement saisi.
const { t } = useT(); const api = useApi(); const toast = useToast()
const { isAdmin } = useRole()
const st = ref<any>(null), busy = ref(false), err = ref('')
async function load() { try { st.value = await api.call('GET', '/dns/lease-sync', undefined, { silent: true }) } catch (e: any) { err.value = e?.info?.message ?? '' } }
async function toggle(v: boolean) {
  busy.value = true; err.value = ''
  try { st.value = await api.call('PUT', '/dns/lease-sync', { enabled: v }); toast.add({ title: t(v ? 'leasedns.on' : 'leasedns.off'), color: 'success' }) }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal'); await load() } finally { busy.value = false }
}
async function run() {
  busy.value = true; err.value = ''
  try { const r = await api.call('POST', '/dns/lease-sync/run'); st.value = r; toast.add({ title: t('leasedns.ran', { a: r.run.added, d: r.run.removed }), color: 'success' }) }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
await load()
</script>

<template>
  <UCard>
    <template #header><span class="font-medium">{{ t('leasedns.title') }}</span></template>
    <p class="text-sm text-muted mb-3">{{ t('leasedns.hint') }}</p>
    <div v-if="st" class="flex flex-wrap items-center gap-4">
      <div class="flex items-center gap-2"><USwitch :model-value="st.enabled" :disabled="!isAdmin || busy" :aria-label="t('leasedns.title')" data-test="leasedns-switch" @update:model-value="(v: any) => toggle(!!v)" /><span>{{ t(st.enabled ? 'leasedns.enabled' : 'leasedns.disabled') }}</span></div>
      <UBadge color="neutral" variant="subtle" :label="t('leasedns.count', { n: st.records, z: st.zones })" />
      <UButton v-if="st.enabled" color="neutral" variant="outline" icon="i-lucide-refresh-cw" :label="t('leasedns.run')" :loading="busy" @click="run" />
    </div>
    <p class="text-xs text-dimmed mt-2">{{ t('leasedns.scope') }}</p>
    <p v-if="err" class="text-sm text-error mt-2" role="alert">{{ err }}</p>
  </UCard>
</template>
