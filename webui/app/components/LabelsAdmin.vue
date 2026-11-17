<script setup lang="ts">
// Catalogue des labels IPAM : couleur, description, usage ; renommage et suppression sont propagés à tous les objets
const props = defineProps<{ canWrite: boolean }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { items, refresh, colorOf } = useLabels()
const cols = computed(() => [
  { key: 'name', label: t('label.name'), kind: 'text' as const }, { key: 'description', label: t('common.description') },
  { key: 'subnets', label: t('ipam.networks'), kind: 'num' as const }, { key: 'addresses', label: t('ipam.addresses'), kind: 'num' as const },
  { key: 'vlans', label: t('ipam.vlans'), kind: 'num' as const }, { key: 'spaces', label: t('ipam.spaces'), kind: 'num' as const }, { key: 'total', label: t('label.total'), kind: 'num' as const },
])
const dlg = reactive({ open: false, id: 0, name: '', color: '#2563eb', auto: true, description: '', busy: false, err: '' })
function edit(row: any | null) {
  Object.assign(dlg, { open: true, id: row?.id ?? 0, name: row?.name ?? '', color: row?.color || colorOf(row?.name ?? ''), auto: !row?.color, description: row?.description ?? '', busy: false, err: '' })
}
async function save() {
  dlg.busy = true; dlg.err = ''
  const body: any = { name: dlg.name, color: dlg.auto ? null : dlg.color, description: dlg.description.trim() || null }
  try {
    if (dlg.id) await api.call('PUT', `/ipam/labels/${dlg.id}`, body, { silent: true }); else await api.call('POST', '/ipam/labels', body, { silent: true })
    dlg.open = false; toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await refresh()
  } catch (e: any) { dlg.err = e.info?.message ?? t('err.internal') } finally { dlg.busy = false }
}
async function remove(row: any) {
  if (!row.id) { dlg.err = ''; return }
  if (!(await ask(t('common.delete'), t('label.delete_confirm', { name: row.name, n: row.total }), true))) return
  try { await api.call('DELETE', `/ipam/labels/${row.id}`); await refresh() } catch { /* message déjà affiché */ }
}
const known = (row: any) => !!row.id
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('label.intro') }}</p>
    <DenseTable :rows="items" :columns="cols" export-name="ipam-labels">
      <template #toolbar>
        <UButton v-if="props.canWrite" icon="i-lucide-plus" size="sm" :label="t('label.add_new')" @click="edit(null)" />
      </template>
      <template #cell-name="{ row }"><LabelBadges :labels="[row.name]" /></template>
      <template #actions="{ row }">
        <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-list-ordered" :aria-label="t('label.show_addresses')" :title="t('label.show_addresses')" :to="`/ipam?label=${encodeURIComponent(row.name)}#addresses`" />
        <UButton v-if="props.canWrite && known(row)" size="xs" color="neutral" variant="ghost" icon="i-lucide-pencil" :aria-label="t('common.edit')" @click="edit(row)" />
        <UButton v-if="props.canWrite && known(row)" size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" @click="remove(row)" />
        <UButton v-else-if="props.canWrite" size="xs" color="neutral" variant="ghost" icon="i-lucide-book-plus" :aria-label="t('label.catalog_add')" :title="t('label.catalog_add')" @click="edit({ name: row.name })" />
      </template>
    </DenseTable>
    <UModal v-model:open="dlg.open" :title="dlg.id ? t('label.edit') : t('label.add_new')" :description="t('common.form_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="save">
          <UAlert v-if="dlg.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="dlg.err" />
          <UFormField :label="t('label.name')" :help="dlg.id ? t('label.rename_hint') : t('label.name_hint')" required><UInput v-model="dlg.name" class="w-full" autocomplete="off" /></UFormField>
          <UFormField :label="t('label.color')">
            <div class="flex items-center gap-3">
              <input v-model="dlg.color" type="color" class="h-8 w-12 cursor-pointer rounded border border-default bg-transparent" :disabled="dlg.auto" :aria-label="t('label.color')">
              <UCheckbox v-model="dlg.auto" :label="t('label.color_auto')" />
              <LabelBadges :labels="dlg.name ? [dlg.name] : []" :color="dlg.auto ? undefined : dlg.color" class="ml-auto" />
            </div>
          </UFormField>
          <UFormField :label="t('common.description')"><UInput v-model="dlg.description" class="w-full" autocomplete="off" /></UFormField>
          <div class="flex justify-end gap-2 pt-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="dlg.open = false" />
            <UButton type="submit" :loading="dlg.busy" :label="t('common.save')" />
          </div>
        </form>
      </template>
    </UModal>
  </div>
</template>
