<script setup lang="ts">
// Domaines importés depuis les listes de blocage (lecture seule) : filtre par liste, recherche, pagination
const { t } = useT(); const api = useApi()
const PAGE = 50
const lists = ref<any[]>([]), items = ref<any[]>([]), total = ref(0), offset = ref(0), loading = ref(false)
const list = ref('0'), q = ref('')
const options = computed(() => [{ label: t('filter.all_lists'), value: '0' }, ...lists.value.map((l) => ({ label: `${l.name} (${l.entries})`, value: String(l.id) }))])
let timer: ReturnType<typeof setTimeout> | undefined
async function load() {
  loading.value = true
  try {
    const r: any = await api.call('GET', `/filter/entries?list=${list.value}&q=${encodeURIComponent(q.value.trim())}&limit=${PAGE}&offset=${offset.value}`)
    items.value = r.items; total.value = r.total
  } finally { loading.value = false }
}
async function loadLists() { try { lists.value = ((await api.call('GET', '/filter/lists')) as any).items } catch { lists.value = [] } }
watch([list, q], () => { offset.value = 0; clearTimeout(timer); timer = setTimeout(load, 250) })
onMounted(async () => { await loadLists(); await load() })
onBeforeUnmount(() => clearTimeout(timer))
const from = computed(() => (total.value ? offset.value + 1 : 0)), to = computed(() => Math.min(total.value, offset.value + PAGE))
function go(d: number) { offset.value = Math.max(0, offset.value + d * PAGE); load() }
defineExpose({ refresh: async () => { await loadLists(); await load() } })
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex flex-wrap items-center gap-2">
        <span class="font-medium">{{ t('filter.list_domains') }}</span>
        <span class="text-sm text-muted">{{ t('filter.list_domains_hint') }}</span>
        <div class="ml-auto flex flex-wrap items-center gap-2">
          <USelect v-model="list" :items="options" class="w-56" :aria-label="t('filter.lists')" />
          <UInput v-model="q" icon="i-lucide-search" :placeholder="t('filter.search_domain')" class="w-56" />
        </div>
      </div>
    </template>
    <div v-if="!loading && !items.length" class="py-4 text-center text-sm text-muted">{{ t('filter.no_entries') }}</div>
    <table v-else class="w-full text-sm">
      <thead><tr class="text-left text-muted"><th class="py-1">{{ t('filter.domain') }}</th><th>{{ t('filter.list') }}</th><th>{{ t('filter.category') }}</th><th>{{ t('filter.action') }}</th></tr></thead>
      <tbody>
        <tr v-for="r in items" :key="`${r.list_id}-${r.domain}`" class="border-t border-default">
          <td class="py-1 font-mono">{{ r.domain }}</td>
          <td>{{ r.list_name }}</td>
          <td><UBadge color="neutral" variant="subtle" size="sm">{{ t(`filter.cat.${r.category}`) }}</UBadge></td>
          <td><UBadge :color="r.enabled ? 'error' : 'neutral'" variant="subtle" size="sm">{{ r.enabled ? t('filter.act.block') : t('filter.list_disabled') }}</UBadge></td>
        </tr>
      </tbody>
    </table>
    <div class="mt-3 flex items-center justify-end gap-2 text-sm text-muted">
      <span>{{ t('filter.entries_range', { from, to, total }) }}</span>
      <UButton icon="i-lucide-chevron-left" size="xs" color="neutral" variant="outline" :disabled="offset === 0 || loading" :aria-label="t('common.previous')" @click="go(-1)" />
      <UButton icon="i-lucide-chevron-right" size="xs" color="neutral" variant="outline" :disabled="offset + PAGE >= total || loading" :aria-label="t('common.next')" @click="go(1)" />
    </div>
  </UCard>
</template>
