<script setup lang="ts">
// Cockpit de filtrage (à la Pi-hole) : indicateurs, courbe autorisées/bloquées, domaines et clients les plus actifs, pause du blocage.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { canWrite, isAdmin } = useRole(); const { ask } = useConfirm()
const emit = defineEmits<{ changed: [] }>()
const range = ref('24h'), busy = ref(false)
const { data: s, refresh } = useFetch<any>(() => `/api/cockpit/summary?range=${range.value}`, { server: false, watch: [range] })
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => { timer = setInterval(() => { if (!document.hidden) refresh() }, 15000) })
onBeforeUnmount(() => clearInterval(timer))
defineExpose({ refresh })
const filter = useState<{ client: string }>('cockpit-filter', () => ({ client: '' }))
const BIN: Record<string, number> = { '1 minute': 60_000, '5 minutes': 300_000, '15 minutes': 900_000, '1 hour': 3_600_000 }
const MINS: Record<string, number> = { '15m': 15, '1h': 60, '6h': 360, '24h': 1440, '7d': 10080 }
const chart = computed(() => {
  const bin = BIN[s.value?.bin ?? '1 hour'] ?? 3_600_000, to = Math.ceil(Date.now() / bin) * bin, from = to - (MINS[range.value] ?? 1440) * 60_000
  const pts = (st: string) => (s.value?.series ?? []).filter((r: any) => r.status === st).map((r: any) => ({ t: Date.parse(r.t), v: r.n }))
  return { bin, to, from, series: [{ name: t('cockpit.s_allowed'), color: '#16a34a', points: pts('allowed') }, { name: t('cockpit.s_blocked'), color: '#dc2626', points: pts('blocked') }] }
})
const tiles = computed(() => [
  { k: 'total', icon: 'i-lucide-activity', v: s.value?.total ?? 0 }, { k: 'blocked', icon: 'i-lucide-shield-ban', v: `${s.value?.blocked ?? 0} (${s.value?.percent ?? 0} %)` },
  { k: 'lists', icon: 'i-lucide-list-x', v: Number(s.value?.blocklist?.domains ?? 0).toLocaleString() }, { k: 'clients', icon: 'i-lucide-monitor-smartphone', v: s.value?.uniqueClients ?? 0 },
])
const types = computed(() => (s.value?.byType ?? []).map((x: any) => ({ label: x.qtype, value: x.n })))
const reasons = computed(() => (s.value?.byReason ?? []).map((x: any) => ({ label: x.reason.startsWith('list:') ? x.reason.slice(5) : t(`cockpit.reason.${x.reason}`), value: x.n })))
async function act(domain: string, action: 'allow' | 'block') {
  try { await api.call('POST', '/cockpit/action', { domain, action }); toast.add({ title: t(action === 'allow' ? 'cockpit.allowed_done' : 'cockpit.blocked_done', { d: domain }), color: 'success', icon: 'i-lucide-check' }); await refresh(); emit('changed') }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) }
}
async function pause(minutes: number) {
  if (minutes > 0 && !(await ask(t('cockpit.pause'), t('cockpit.pause_confirm', { m: minutes }), false))) return
  busy.value = true
  try { await api.call('POST', '/cockpit/pause', { minutes }); toast.add({ title: t(minutes ? 'cockpit.paused' : 'cockpit.resumed'), color: 'success', icon: 'i-lucide-check' }); await refresh() }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { busy.value = false }
}
async function enable() {
  busy.value = true
  try { const cur: any = await api.call('GET', '/filter/settings'); await api.call('PUT', '/filter/settings', { rpzEnabled: true, rpzAction: cur.rpzAction, sinkhole4: cur.sinkhole4, sinkhole6: cur.sinkhole6 }); await api.call('POST', '/system/apply', { deploy: true }); await refresh() }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { busy.value = false }
}
async function deploy() {
  if (!(await ask(t('apply.deploy'), t('apply.deploy_confirm'), false))) return
  busy.value = true
  try { const r: any = await api.call('POST', '/system/apply', { deploy: true }); toast.add({ title: r.deployed ? t('apply.deployed') : t('apply.invalid'), color: r.deployed ? 'success' : 'error' }); await refresh() }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { busy.value = false }
}
const until = computed(() => (s.value?.blocking?.pausedUntil ? new Date(s.value.blocking.pausedUntil).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''))
</script>

<template>
  <div class="flex flex-col gap-4">
    <UAlert v-if="s && !s.blocking.enabled && !s.blocking.pausedUntil" color="warning" variant="subtle" icon="i-lucide-shield-off" :title="t('cockpit.off')" :description="t('cockpit.off_desc')">
      <template #actions><UButton v-if="isAdmin" size="xs" color="warning" variant="outline" :loading="busy" :label="t('cockpit.enable')" @click="enable" /></template>
    </UAlert>
    <UAlert v-if="s?.blocking.pausedUntil" color="warning" variant="subtle" icon="i-lucide-pause" :title="t('cockpit.paused_until', { h: until })">
      <template #actions><UButton v-if="isAdmin" size="xs" color="warning" variant="outline" :loading="busy" :label="t('cockpit.resume')" @click="pause(0)" /></template>
    </UAlert>
    <UAlert v-if="s && s.pending > 0" color="info" variant="subtle" icon="i-lucide-rocket" :title="t('cockpit.pending', { n: s.pending })" :description="s.autoDeploy ? t('cockpit.auto_on') : t('cockpit.auto_off')">
      <template #actions><UButton v-if="isAdmin && !s.autoDeploy" size="xs" :loading="busy" :label="t('apply.deploy')" @click="deploy" /></template>
    </UAlert>

    <div class="flex flex-wrap items-center gap-2">
      <div role="group" :aria-label="t('filter.range')" class="flex gap-1"><UButton v-for="r in ['15m', '1h', '6h', '24h', '7d']" :key="r" size="xs" :color="range === r ? 'primary' : 'neutral'" :variant="range === r ? 'solid' : 'outline'" :label="r" :aria-pressed="range === r" @click="range = r" /></div>
      <div class="flex-1" />
      <template v-if="isAdmin && s?.blocking.enabled">
        <span class="text-sm text-muted">{{ t('cockpit.pause') }}</span>
        <UButton v-for="m in [5, 30, 60, 480]" :key="m" size="xs" color="neutral" variant="outline" icon="i-lucide-pause" :label="m < 60 ? `${m} min` : `${m / 60} h`" :loading="busy" @click="pause(m)" />
      </template>
    </div>

    <ul class="grid grid-cols-2 md:grid-cols-4 gap-3" :aria-label="t('dash.kpi')">
      <li v-for="x in tiles" :key="x.k" class="flex items-center gap-3 rounded-lg border border-default p-3">
        <UIcon :name="x.icon" class="size-5 text-primary shrink-0" />
        <div class="min-w-0"><div class="text-2xl font-semibold num leading-none">{{ x.v }}</div><div class="text-xs text-muted truncate">{{ t(`cockpit.k.${x.k}`) }}</div></div>
      </li>
    </ul>

    <UCard><template #header><span class="font-medium">{{ t('cockpit.over_time') }}</span></template>
      <LineChart :series="chart.series" :bin-ms="chart.bin" :from="chart.from" :to="chart.to" :label="t('cockpit.over_time')" />
      <p v-if="s && !s.total" class="text-sm text-muted mt-2">{{ t('cockpit.no_data', { d: s.retentionDays }) }}</p></UCard>

    <div class="grid gap-4 lg:grid-cols-3">
      <UCard><template #header><span class="font-medium">{{ t('cockpit.top_blocked') }}</span></template>
        <ul class="text-sm flex flex-col gap-1"><li v-for="d in s?.topBlocked ?? []" :key="d.domain" class="flex items-center gap-2"><span class="font-mono truncate flex-1" :title="d.domain">{{ d.domain }}</span><span class="num text-muted">{{ d.n }}</span>
          <UButton v-if="canWrite" size="xs" color="success" variant="ghost" icon="i-lucide-check" :aria-label="`${t('cockpit.allow')} ${d.domain}`" @click="act(d.domain, 'allow')" /></li></ul>
        <p v-if="!(s?.topBlocked ?? []).length" class="text-sm text-muted">{{ t('common.empty') }}</p></UCard>
      <UCard><template #header><span class="font-medium">{{ t('cockpit.top_allowed') }}</span></template>
        <ul class="text-sm flex flex-col gap-1"><li v-for="d in s?.topAllowed ?? []" :key="d.domain" class="flex items-center gap-2"><span class="font-mono truncate flex-1" :title="d.domain">{{ d.domain }}</span><span class="num text-muted">{{ d.n }}</span>
          <UButton v-if="canWrite" size="xs" color="error" variant="ghost" icon="i-lucide-ban" :aria-label="`${t('cockpit.block')} ${d.domain}`" @click="act(d.domain, 'block')" /></li></ul>
        <p v-if="!(s?.topAllowed ?? []).length" class="text-sm text-muted">{{ t('common.empty') }}</p></UCard>
      <UCard><template #header><span class="font-medium">{{ t('cockpit.top_clients') }}</span></template>
        <ul class="text-sm flex flex-col gap-1"><li v-for="c in s?.topClients ?? []" :key="c.client" class="flex items-center gap-2"><button type="button" class="font-mono truncate flex-1 text-start hover:underline" :title="t('cockpit.filter_client')" @click="filter = { client: c.client }">{{ c.client }}</button><span class="num text-muted">{{ c.total }}</span><span class="num text-error">{{ c.blocked }}</span></li></ul>
        <p v-if="!(s?.topClients ?? []).length" class="text-sm text-muted">{{ t('common.empty') }}</p></UCard>
    </div>
    <div class="grid gap-4 lg:grid-cols-2">
      <UCard><template #header><span class="font-medium">{{ t('cockpit.by_reason') }}</span></template><BarChart v-if="reasons.length" :items="reasons" :label="t('cockpit.by_reason')" /><p v-else class="text-sm text-muted">{{ t('common.empty') }}</p></UCard>
      <UCard><template #header><span class="font-medium">{{ t('cockpit.by_type') }}</span></template><BarChart v-if="types.length" :items="types" :label="t('cockpit.by_type')" /><p v-else class="text-sm text-muted">{{ t('common.empty') }}</p></UCard>
    </div>
  </div>
</template>
