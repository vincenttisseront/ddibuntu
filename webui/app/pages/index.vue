<script setup lang="ts">
const { t } = useT()
const { data } = await useFetch<any>('/api/dashboard')
const c = computed(() => data.value?.counts ?? {})
const sys = computed(() => data.value?.system ?? null)
const tiles = computed(() => [
  { k: 'subnets', icon: 'i-lucide-network', to: '/ipam#subnets' }, { k: 'addresses', icon: 'i-lucide-list-ordered', to: '/ipam#addresses' },
  { k: 'zones', icon: 'i-lucide-globe', to: '/dns#zones' }, { k: 'records', icon: 'i-lucide-file-text', to: '/dns#records' },
  { k: 'scopes', icon: 'i-lucide-server', to: '/dhcp#scopes' }, { k: 'reservations', icon: 'i-lucide-bookmark', to: '/dhcp#ranges' },
  { k: 'lists', icon: 'i-lucide-shield-ban', to: '/filtering#lists' }, { k: 'blocked_domains', icon: 'i-lucide-ban', to: '/filtering#lists' },
])
const util = computed(() => (data.value?.top ?? []).map((s: any) => ({ label: s.cidr, value: s.percent, display: `${s.percent}% · ${s.used}/${s.capacity}`, warn: s.percent >= 80 })))
const types = computed(() => (data.value?.byType ?? []).slice(0, 8).map((r: any) => ({ label: r.type, value: r.n })))
const day = (k: string) => Number((data.value?.day ?? []).find((d: any) => d.kind === k)?.n ?? 0)
const blockedPct = computed(() => { const q = day('query'); return q > 0 ? Math.round((day('blocked') / q) * 1000) / 10 : 0 })
function uptime(s: number) {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60)
  return d > 0 ? t('dash.uptime_dh', { d, h }) : h > 0 ? t('dash.uptime_hm', { h, m }) : t('dash.uptime_m', { m })
}
const gauge = (v: number | null | undefined) => ({ value: v ?? 0, display: v == null ? '—' : `${v}%`, warn: (v ?? 0) >= 85 })
const resources = computed(() => {
  const h = sys.value?.host; if (!h) return []
  return [
    { label: t('dash.memory'), ...gauge(h.memPercent) },
    { label: t('dash.disk'), ...gauge(h.diskPercent), display: h.diskPercent == null ? '—' : `${h.diskPercent}% · ${t('dash.free', { g: h.diskFreeGb })}` },
    { label: t('dash.load'), value: Math.min(100, Math.round((h.load1 / h.cpus) * 100)), display: `${h.load1} / ${h.cpus} CPU`, warn: h.load1 / h.cpus >= 1 },
  ]
})
const when = (s: number) => new Date(s * 1000).toLocaleString()
</script>

<template>
  <div class="flex flex-col gap-4">
    <UAlert v-if="sys?.update?.available && !sys.update.busy" color="primary" variant="subtle" icon="i-lucide-circle-arrow-up" :title="t('dash.update_available', { v: sys.update.latest, cur: sys.version })">
      <template #actions><UButton to="/system#updates" size="xs" color="primary" variant="outline" :label="t('dash.update_go')" /></template>
    </UAlert>
    <UAlert v-if="sys?.update?.busy" color="info" variant="subtle" icon="i-lucide-loader" :title="t('dash.update_running')">
      <template #actions><UButton to="/system#updates" size="xs" color="info" variant="outline" :label="t('dash.update_follow')" /></template>
    </UAlert>
    <UAlert v-if="c.dirty_zones > 0" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('dash.dirty', { n: c.dirty_zones })">
      <template #actions><UButton to="/dns#deploy" size="xs" color="warning" variant="outline" :label="t('dash.deploy_now')" /></template>
    </UAlert>

    <ul class="grid grid-cols-2 md:grid-cols-4 gap-3" :aria-label="t('dash.kpi')">
      <li v-for="x in tiles" :key="x.k">
        <NuxtLink :to="x.to" class="flex items-center gap-3 rounded-lg border border-default p-3 hover:bg-elevated transition-colors">
          <UIcon :name="x.icon" class="size-5 text-primary shrink-0" />
          <div class="min-w-0"><div class="text-2xl font-semibold num leading-none">{{ c[x.k] ?? 0 }}</div><div class="text-xs text-muted truncate">{{ t(`dash.${x.k}`) }}</div></div>
        </NuxtLink>
      </li>
    </ul>

    <div class="grid gap-4 lg:grid-cols-3">
      <UCard class="lg:col-span-1"><template #header><span class="font-medium">{{ t('dash.system') }}</span></template>
        <dl v-if="sys" class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm mb-3">
          <dt class="text-muted">{{ t('system.version') }}</dt><dd class="font-mono">{{ sys.version || '—' }}</dd>
          <dt class="text-muted">{{ t('dash.host') }}</dt><dd class="font-mono truncate" :title="sys.host.hostname">{{ sys.host.hostname }}</dd>
          <dt class="text-muted">{{ t('dash.uptime') }}</dt><dd>{{ uptime(sys.host.uptimeSeconds) }}</dd>
        </dl>
        <BarChart v-if="resources.length" :items="resources" :max="100" :label="t('dash.system')" />
        <div v-if="sys?.lastApply" class="mt-3 flex items-start gap-2 text-sm">
          <UIcon :name="sys.lastApply.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'" class="size-4 mt-0.5 shrink-0" :class="sys.lastApply.ok ? 'text-success' : 'text-error'" />
          <div class="min-w-0"><div>{{ sys.lastApply.ok ? t('dash.apply_ok') : t('dash.apply_ko') }}</div><div class="text-xs text-muted">{{ when(sys.lastApply.at) }}</div></div>
        </div>
        <p v-else-if="sys" class="mt-3 text-xs text-muted">{{ t('dash.apply_none') }}</p>
      </UCard>
      <UCard class="lg:col-span-1"><template #header><span class="font-medium">{{ t('dash.utilization') }}</span></template>
        <BarChart v-if="util.length" :items="util" :max="100" :label="t('dash.utilization')" />
        <p v-else class="text-sm text-muted">{{ t('common.empty') }}</p>
        <p class="text-xs text-muted mt-2">{{ t('dash.threshold') }}</p></UCard>
      <UCard class="lg:col-span-1"><template #header><span class="font-medium">{{ t('dash.types') }}</span></template>
        <BarChart v-if="types.length" :items="types" :label="t('dash.types')" />
        <p v-else class="text-sm text-muted">{{ t('common.empty') }}</p>
        <p class="text-xs text-muted mt-2">{{ t('dash.queries_24h', { q: day('query'), b: day('blocked') }) }}<template v-if="day('query') > 0"> ({{ blockedPct }} %)</template></p></UCard>
    </div>
  </div>
</template>
