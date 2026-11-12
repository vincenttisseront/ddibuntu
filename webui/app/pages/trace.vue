<script setup lang="ts">
// Traçabilité : « qui avait cette adresse, quand ? » — recherche par IP, MAC ou nom dans l'historique des baux DHCP.
import type { DCol } from '~/components/DenseTable.vue'
const { t } = useT(); const api = useApi(); const toast = useToast()
const { canWrite } = useRole()
const route = useRoute()
const q = ref(String(route.query.q ?? '')), term = ref(q.value)
const { data, pending, refresh } = await useFetch<any>('/api/trace', { query: computed(() => ({ q: term.value })), watch: [term] })
const collecting = ref(false)
const fmtDate = (v: string) => (v ? new Date(v).toLocaleString() : '')
const cols = computed<DCol[]>(() => [
  { key: 'ip', label: 'IP', kind: 'mono' }, { key: 'mac', label: 'MAC', kind: 'mono' }, { key: 'hostname', label: t('ipam.hostname') },
  { key: 'first_seen', label: t('trace.first'), fmt: fmtDate }, { key: 'last_seen', label: t('trace.last'), fmt: fmtDate },
  { key: 'open', label: t('trace.state'), fmt: (v: boolean) => (v ? t('trace.active') : t('trace.ended')) },
  { key: 'ipam_hostname', label: t('trace.ipam') },
])
const search = () => { term.value = q.value.trim() }
async function collect() {
  collecting.value = true
  try {
    const r: any = await api.call('POST', '/trace/collect', {})
    toast.add({ title: r.skipped ? t('trace.skipped') : t('trace.collected', { n: r.active }), color: r.skipped ? 'neutral' : 'success', icon: 'i-lucide-check' })
    await refresh()
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) } finally { collecting.value = false }
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <UAlert color="neutral" variant="subtle" icon="i-lucide-history" :description="t('trace.intro')" />
    <form class="flex gap-2" @submit.prevent="search">
      <UInput v-model="q" class="flex-1" icon="i-lucide-search" :placeholder="t('trace.placeholder')" :aria-label="t('trace.placeholder')" data-test="trace-q" />
      <UButton type="submit" :label="t('common.search')" :loading="pending" />
      <UButton v-if="canWrite" icon="i-lucide-refresh-cw" color="neutral" variant="outline" :label="t('trace.collect')" :loading="collecting" @click="collect" />
    </form>
    <p class="text-xs text-muted" data-test="trace-stats">{{ t('trace.stats', { n: data?.stats?.total ?? 0, o: data?.stats?.open ?? 0 }) }}</p>
    <DenseTable v-if="term" :rows="data?.items ?? []" :columns="cols" :loading="pending" export-name="tracabilite" />
  </div>
</template>
