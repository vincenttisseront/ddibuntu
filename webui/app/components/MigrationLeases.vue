<script setup lang="ts">
// Reprise des baux actifs Windows (0.12.2) : CSV de Get-DhcpServerv4Lease → base de baux de Kea. Analyse d'abord, puis confirmation.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const props = defineProps<{ push?: { at: string | null; imported: number; total: number } | null }>()
const emit = defineEmits<{ done: [] }>()
const csv = ref(''), name = ref(''), pre = ref<any>(null), busy = ref(false), err = ref('')
async function pick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]; if (!f) return
  if (f.size > 25 * 1024 * 1024) { err.value = t('err.too_large'); return }
  csv.value = await f.text(); name.value = f.name; pre.value = null; err.value = ''
  busy.value = true
  try { pre.value = await api.call('POST', '/migration/leases/preview', { content: csv.value, filename: name.value }, { silent: true }) }
  catch (x: any) { err.value = x?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function commit() {
  if (!(await ask(t('mil.confirm_title'), t('mil.confirm_msg', { n: pre.value.toImport }), false))) return
  busy.value = true; err.value = ''
  try {
    const r = await api.call('POST', '/migration/leases/commit', { content: csv.value, filename: name.value }, { silent: true })
    toast.add({ title: t('mil.done', { n: r.imported, e: r.existing }), color: 'success', icon: 'i-lucide-check' }); pre.value = null; csv.value = ''; emit('done')
  } catch (x: any) { err.value = x?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
</script>

<template>
  <div class="flex flex-col gap-2 rounded-md bg-elevated/50 p-3">
    <span class="text-sm font-medium">{{ t('mil.title') }}</span>
    <p class="text-xs text-muted">{{ t('mil.hint') }}</p>
    <p v-if="props.push?.at" class="text-xs text-success" data-test="mil-push">{{ t('mil.push', { n: props.push.total, d: new Date(props.push.at).toLocaleString() }) }}</p>
    <p class="text-xs text-dimmed">{{ t('mil.push_hint') }}</p>
    <input type="file" accept=".csv,text/csv,text/plain" class="block w-full text-sm" :aria-label="t('mil.title')" data-test="mil-file" @change="pick">
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <div v-if="busy && !pre" class="flex items-center gap-2 text-muted"><UIcon name="i-lucide-loader-circle" class="size-4 animate-spin" />{{ t('common.loading') }}</div>
    <template v-if="pre">
      <UAlert v-if="pre.errors.length" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('mil.e_csv')" role="alert" />
      <UAlert v-else-if="!pre.available" color="warning" variant="subtle" icon="i-lucide-database" :title="t('mil.no_db')" />
      <div v-else class="flex flex-wrap items-center gap-2 text-sm" data-test="mil-summary">
        <UBadge color="success" variant="subtle" :label="t('mil.to_import', { n: pre.toImport })" />
        <UBadge color="neutral" variant="outline" :label="t('mil.skipped', { a: pre.skipped.not_active, b: pre.skipped.expired, c: pre.skipped.no_scope, d: pre.skipped.invalid })" />
        <UButton icon="i-lucide-download" :label="t('mil.go')" :loading="busy" :disabled="!pre.toImport" data-test="mil-go" @click="commit" />
      </div>
    </template>
  </div>
</template>
