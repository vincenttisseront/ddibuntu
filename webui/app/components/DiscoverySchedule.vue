<script setup lang="ts">
// Découverte planifiée : scan périodique ; ne crée aucune adresse, met à jour « vu le » et alimente les alertes d'hygiène.
const { t } = useT(); const api = useApi(); const toast = useToast()
const { isAdmin } = useRole()
const { data, refresh } = await useFetch<any>('/api/discovery/schedule')
const { data: subnets } = await useFetch<any>('/api/ipam/subnets')
const f = reactive<any>({ enabled: false, intervalHours: 24, subnetIds: [], methods: { tcp: false, icmp: true, arp: true, reverse: true, leases: true }, autoGhost: false, ghostDays: 30 })
watch(data, (d) => { if (d?.schedule) Object.assign(f, JSON.parse(JSON.stringify(d.schedule))) }, { immediate: true })
const options = computed(() => (subnets.value?.items ?? []).filter((s: any) => s.family === 4 && s.kind === 'network').map((s: any) => ({ label: `${s.cidr} — ${s.name}`, value: s.id })))
const intervals = [1, 6, 12, 24, 48, 168].map((h) => ({ label: h < 24 ? t('dsch.every_h', { n: h }) : h === 24 ? t('dsch.daily') : h === 168 ? t('dsch.weekly') : t('dsch.every_d', { n: h / 24 }), value: h }))
const saving = ref(false), running = ref(false)
const fmt = (s: number) => new Date(s * 1000).toLocaleString()
async function save() {
  saving.value = true
  try { await api.call('PUT', '/discovery/schedule', { enabled: f.enabled, intervalHours: f.intervalHours, subnetIds: f.subnetIds, methods: f.methods, autoGhost: f.autoGhost, ghostDays: Number(f.ghostDays) }, { busy: true }); toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await refresh() }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) } finally { saving.value = false }
}
async function runNow() {
  running.value = true
  try {
    await api.call('POST', '/discovery/schedule/run', {})
    for (let i = 0; i < 90; i++) { await new Promise((r) => setTimeout(r, 2000)); await refresh(); if (!data.value?.running) break }
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) } finally { running.value = false }
}
</script>

<template>
  <UCard>
    <template #header><span class="font-medium">{{ t('dsch.title') }}</span></template>
    <p class="text-sm text-muted mb-3">{{ t('dsch.intro') }}</p>
    <div class="flex flex-col gap-3 max-w-xl">
      <USwitch v-model="f.enabled" :label="t('dsch.enabled')" :disabled="!isAdmin" />
      <UFormField :label="t('dsch.interval')"><USelect v-model="f.intervalHours" :items="intervals" class="w-56" :disabled="!isAdmin" /></UFormField>
      <UFormField :label="t('dsch.subnets')" :hint="t('dsch.subnets_hint')"><USelectMenu v-model="f.subnetIds" :items="options" value-key="value" multiple class="w-full" :disabled="!isAdmin" :placeholder="t('dsch.all')" /></UFormField>
      <div class="flex flex-wrap gap-4">
        <USwitch v-model="f.methods.icmp" :label="t('disc.m_icmp')" :disabled="!isAdmin" />
        <USwitch v-model="f.methods.arp" label="ARP" :disabled="!isAdmin" />
        <USwitch v-model="f.methods.reverse" :label="t('dsch.m_reverse')" :disabled="!isAdmin" />
        <USwitch v-model="f.methods.leases" :label="t('dsch.m_leases')" :disabled="!isAdmin" />
        <USwitch v-model="f.methods.tcp" label="TCP" :disabled="!isAdmin" />
      </div>
      <div class="flex flex-col gap-2 border-t border-default pt-3">
        <USwitch v-model="f.autoGhost" :label="t('dsch.auto_ghost')" :disabled="!isAdmin" data-test="dsch-autoghost" />
        <UFormField :label="t('dsch.ghost_days')" :hint="t('dsch.ghost_hint')"><UInput v-model.number="f.ghostDays" type="number" min="1" max="3650" class="w-32" :disabled="!isAdmin" data-test="dsch-ghostdays" /></UFormField>
      </div>
      <div class="flex gap-2">
        <UButton v-if="isAdmin" icon="i-lucide-save" :label="t('common.save')" :loading="saving" @click="save" />
        <UButton icon="i-lucide-play" color="neutral" variant="outline" :label="t('dsch.run_now')" :loading="running || data?.running" @click="runNow" />
      </div>
      <UAlert v-if="data?.last" :color="data.last.ok ? 'success' : 'error'" variant="subtle" :icon="data.last.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'" data-test="dsch-last"
        :title="t('dsch.last', { at: fmt(data.last.at) })" :description="data.last.ok ? t('dsch.last_ok', { scanned: data.last.scanned, alive: data.last.alive, known: data.last.known, unknown: data.last.unknown, mac: data.last.macChanged, down: data.last.unreachable ?? 0 }) : t(`err.${data.last.error}`)" />
      <p v-else class="text-xs text-muted">{{ t('dsch.never') }}</p>
    </div>
  </UCard>
</template>
