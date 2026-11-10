<script setup lang="ts">
// Recherche globale (Ctrl+K) : réseaux, adresses, zones, enregistrements, DHCP, VLAN, filtrage. Modale du design de la console.
const open = defineModel<boolean>('open', { default: false })
const { t } = useT(); const api = useApi()
const q = ref(''), loading = ref(false), failed = ref(false), active = ref(0)
const groups = ref<Array<{ kind: string; items: Array<{ id: number; title: string; subtitle: string; to: string }>; more: boolean }>>([])
const ICON: Record<string, string> = { network: 'i-lucide-network', address: 'i-lucide-map-pin', zone: 'i-lucide-folder-tree', record: 'i-lucide-file-text', scope: 'i-lucide-server', reservation: 'i-lucide-bookmark', vlan: 'i-lucide-split', filter: 'i-lucide-shield-ban' }
const flat = computed(() => groups.value.flatMap((g) => g.items.map((i) => ({ ...i, kind: g.kind }))))
let timer: ReturnType<typeof setTimeout> | undefined, seq = 0
watch(q, (v) => {
  clearTimeout(timer); active.value = 0
  const s = v.trim()
  if (s.length < 2) { seq++; groups.value = []; loading.value = false; failed.value = false; return }
  loading.value = true
  timer = setTimeout(async () => {
    const my = ++seq
    try { const r = await api.call('GET', `/search?q=${encodeURIComponent(s)}`, undefined, { silent: true }); if (my === seq) { groups.value = r.groups ?? []; failed.value = false } }
    catch { if (my === seq) { groups.value = []; failed.value = true } }
    finally { if (my === seq) loading.value = false }
  }, 200)
})
watch(open, (o) => { if (o) { q.value = ''; groups.value = []; failed.value = false; active.value = 0 } else { clearTimeout(timer); seq++ } })
onBeforeUnmount(() => clearTimeout(timer))
async function go(i: { to: string }) { open.value = false; await navigateTo(i.to) }
function key(e: KeyboardEvent) {
  if (e.key === 'ArrowDown') { e.preventDefault(); if (flat.value.length) active.value = (active.value + 1) % flat.value.length }
  else if (e.key === 'ArrowUp') { e.preventDefault(); if (flat.value.length) active.value = (active.value - 1 + flat.value.length) % flat.value.length }
  else if (e.key === 'Enter' && flat.value[active.value]) { e.preventDefault(); void go(flat.value[active.value]!) }
}
watch(active, () => nextTick(() => document.getElementById('gs-active')?.scrollIntoView({ block: 'nearest' })))
const idx = (kind: string, id: number) => flat.value.findIndex((f) => f.kind === kind && f.id === id)
</script>

<template>
  <UModal v-model:open="open" :title="t('search.title')" :description="t('search.desc')" :ui="{ content: 'max-w-2xl' }">
    <template #body>
      <div class="flex flex-col gap-3">
        <UInput v-model="q" icon="i-lucide-search" size="lg" class="w-full" autofocus :loading="loading" :placeholder="t('search.placeholder')" :aria-label="t('common.search')" @keydown="key" />
        <p v-if="q.trim().length < 2" class="text-sm text-muted">{{ t('search.hint') }}</p>
        <UAlert v-else-if="failed" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('err.internal')" />
        <p v-else-if="!loading && !groups.length" class="text-sm text-muted">{{ t('search.none') }}</p>
        <div v-if="groups.length" class="flex flex-col gap-3 max-h-[26rem] overflow-auto" role="listbox" :aria-label="t('search.results')">
          <section v-for="g in groups" :key="g.kind">
            <h3 class="text-xs font-medium uppercase tracking-wide text-muted mb-1">{{ t(`search.kind.${g.kind}`) }}<span v-if="g.more"> · {{ t('search.more') }}</span></h3>
            <ul class="flex flex-col">
              <li v-for="i in g.items" :id="idx(g.kind, i.id) === active ? 'gs-active' : undefined" :key="g.kind + i.id" role="option" :aria-selected="idx(g.kind, i.id) === active">
                <button type="button" class="w-full flex items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-elevated" :class="idx(g.kind, i.id) === active ? 'bg-elevated' : ''" @mousemove="active = idx(g.kind, i.id)" @click="go(i)">
                  <UIcon :name="ICON[g.kind] ?? 'i-lucide-search'" class="size-4 shrink-0 text-muted" />
                  <span class="font-mono truncate">{{ i.title }}</span>
                  <span class="text-xs text-muted truncate">{{ i.subtitle }}</span>
                </button>
              </li>
            </ul>
          </section>
        </div>
      </div>
    </template>
  </UModal>
</template>
