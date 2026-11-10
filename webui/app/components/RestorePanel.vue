<script setup lang="ts">
// Points de restauration des données et historique des déploiements : aperçu de ce qui changera, restauration (avec redéploiement en option).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { data: snaps, refresh: rs } = useFetch<any>('/api/snapshots', { server: false })
const { data: deps, refresh: rd } = useFetch<any>('/api/system/deployments', { server: false })
const { data: status } = useFetch<any>('/api/system/reload-status', { server: false })
const label = ref(''), busy = ref(false), open = ref(false), target = ref<any>(null), diff = ref<any>(null), redeploy = ref(false), error = ref('')
const fail = (e: any) => { error.value = e.info?.message ?? t('err.internal'); toast.add({ title: error.value, color: 'error' }) }
async function create() { busy.value = true; try { await api.call('POST', '/snapshots', { label: label.value }); label.value = ''; await rs(); toast.add({ title: t('restore.created'), color: 'success', icon: 'i-lucide-check' }) } catch (e: any) { fail(e) } finally { busy.value = false } }
async function preview(id: number) {
  error.value = ''; diff.value = null; redeploy.value = false
  try { const r: any = await api.call('GET', `/snapshots/${id}/diff`); target.value = r.snapshot; diff.value = r.diff; open.value = true } catch (e: any) { fail(e) }
}
async function restore() {
  busy.value = true; error.value = ''
  try {
    const r: any = await api.call('POST', `/snapshots/${target.value.id}/restore`, { deploy: redeploy.value })
    open.value = false; toast.add({ title: t('restore.done_pre', { id: r.preSnapshot }), color: 'success', icon: 'i-lucide-check' }); await Promise.all([rs(), rd()])
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function pin(s: any) { try { await api.call('PUT', `/snapshots/${s.id}`, { pinned: !s.pinned }); await rs() } catch (e: any) { fail(e) } }
async function remove(s: any) { if (!(await ask(t('common.delete'), t('restore.delete_confirm', { id: s.id }), true))) return; try { await api.call('DELETE', `/snapshots/${s.id}`); await rs() } catch (e: any) { fail(e) } }
const when = (s: string) => new Date(s).toLocaleString()
const total = (c: any) => Object.values(c ?? {}).reduce((n: number, v: any) => n + Number(v), 0)
const empty = computed(() => !diff.value || !Object.keys(diff.value).length)
</script>

<template>
  <div class="flex flex-col gap-4">
    <UAlert v-if="status?.status" :color="status.status.ok ? 'success' : 'error'" variant="subtle" :icon="status.status.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'" :title="status.status.ok ? t('restore.reload_ok') : t('restore.reload_ko')" :description="`${new Date(status.status.at * 1000).toLocaleString()} — ${status.status.message}`" />
    <UCard><template #header><span class="font-medium">{{ t('restore.title') }}</span></template>
      <p class="text-sm text-muted mb-3">{{ t('restore.desc') }}</p>
      <form class="flex gap-2 mb-3" @submit.prevent="create"><UInput v-model="label" :placeholder="t('restore.label_ph')" :aria-label="t('restore.label_ph')" class="flex-1" /><UButton type="submit" icon="i-lucide-camera" :loading="busy" :label="t('restore.create')" /></form>
      <div class="overflow-auto max-h-96"><table class="w-full text-sm"><caption class="sr-only">{{ t('restore.title') }}</caption>
        <thead><tr class="text-muted"><th scope="col" class="text-start p-1">#</th><th scope="col" class="text-start p-1">{{ t('common.date') }}</th><th scope="col" class="text-start p-1">{{ t('common.type') }}</th><th scope="col" class="text-start p-1">{{ t('restore.label') }}</th><th scope="col" class="text-start p-1">{{ t('system.user') }}</th><th scope="col" class="p-1">{{ t('restore.objects') }}</th><th scope="col" class="p-1"><span class="sr-only">{{ t('common.actions') }}</span></th></tr></thead>
        <tbody><tr v-for="s in snaps?.items ?? []" :key="s.id" class="border-t border-default">
          <td class="p-1 num">{{ s.id }}</td><td class="p-1 whitespace-nowrap">{{ when(s.at) }}</td><td class="p-1"><UBadge color="neutral" variant="subtle" :label="t(`restore.kind.${s.kind}`)" /></td><td class="p-1">{{ s.label }}</td><td class="p-1">{{ s.username }}</td><td class="p-1 num text-center">{{ total(s.counts) }}</td>
          <td class="p-1 text-end whitespace-nowrap"><UButton size="xs" icon="i-lucide-history" color="neutral" variant="outline" :label="t('restore.preview')" @click="preview(s.id)" />
            <UButton size="xs" :icon="s.pinned ? 'i-lucide-pin-off' : 'i-lucide-pin'" color="neutral" variant="ghost" :aria-label="s.pinned ? t('restore.unpin') : t('restore.pin')" @click="pin(s)" />
            <UButton size="xs" icon="i-lucide-trash-2" color="error" variant="ghost" :aria-label="t('common.delete')" @click="remove(s)" /></td></tr></tbody></table></div>
      <p v-if="!(snaps?.items ?? []).length" class="text-sm text-muted">{{ t('common.empty') }}</p></UCard>

    <UCard><template #header><span class="font-medium">{{ t('system.deployments') }}</span></template>
      <ul class="text-sm flex flex-col gap-2 max-h-80 overflow-auto"><li v-for="d in deps?.items ?? []" :key="d.id" class="flex flex-wrap items-center gap-2">
        <UIcon :name="d.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'" :class="d.ok ? 'text-success' : 'text-error'" /><span class="whitespace-nowrap">{{ when(d.at) }}</span><span class="text-muted">{{ d.username }}</span>
        <UBadge v-if="d.applied === true" color="success" variant="subtle" :label="t('restore.applied')" /><UBadge v-else-if="d.applied === false" color="error" variant="subtle" :label="t('restore.rolled_back')" :title="d.apply_message" /><UBadge v-else-if="d.ok" color="neutral" variant="subtle" :label="t('restore.pending')" />
        <span class="flex-1" /><UButton v-if="d.snapshot_id" size="xs" color="neutral" variant="outline" icon="i-lucide-history" :label="t('restore.back_to')" @click="preview(d.snapshot_id)" /></li></ul>
      <p v-if="!(deps?.items ?? []).length" class="text-sm text-muted">{{ t('common.empty') }}</p></UCard>

    <UModal v-model:open="open" :title="t('restore.confirm_title', { id: target?.id ?? '' })" :description="target ? `${when(target.at)} — ${target.label}` : ''">
      <template #body>
        <div class="flex flex-col gap-3 text-sm">
          <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" />
          <p v-if="empty" class="text-muted">{{ t('restore.no_change') }}</p>
          <table v-else class="w-full"><caption class="sr-only">{{ t('restore.will') }}</caption>
            <thead><tr class="text-muted"><th scope="col" class="text-start p-1">{{ t('restore.object') }}</th><th scope="col" class="p-1">{{ t('restore.will_remove') }}</th><th scope="col" class="p-1">{{ t('restore.will_restore') }}</th><th scope="col" class="p-1">{{ t('restore.will_change') }}</th></tr></thead>
            <tbody><tr v-for="(d, k) in diff" :key="k" class="border-t border-default align-top"><th scope="row" class="text-start p-1">{{ t(`restore.t.${k}`) }}</th>
              <td class="p-1 text-center num text-error" :title="d.samples.removed.join(', ')">{{ d.removed }}</td><td class="p-1 text-center num text-success" :title="d.samples.restored.join(', ')">{{ d.restored }}</td><td class="p-1 text-center num text-warning" :title="d.samples.changed.join(', ')">{{ d.changed }}</td></tr></tbody></table>
          <USwitch v-model="redeploy" :label="t('restore.redeploy')" />
          <p class="text-xs text-muted">{{ t('restore.reversible') }}</p>
        </div>
      </template>
      <template #footer><div class="flex justify-end gap-2 w-full"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="open = false" /><UButton color="warning" icon="i-lucide-history" :loading="busy" :label="t('restore.restore')" @click="restore" /></div></template>
    </UModal>
  </div>
</template>
