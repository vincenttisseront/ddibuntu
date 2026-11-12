<script setup lang="ts">
const { t } = useT()
const { isAdmin } = useRole()
const { dateTime, time } = useFmt()
const { data, refresh } = await useFetch<any>('/api/dashboard')
// le tableau de bord se tient à jour seul (état des services, quorum, alertes) ; l'heure de la dernière mise à jour est affichée
const updatedAt = ref(Date.now())
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => { timer = setInterval(() => { refresh().then(() => { updatedAt.value = Date.now() }).catch(() => {}) }, 30000) })
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
const c = computed(() => data.value?.counts ?? {})
const sys = computed(() => data.value?.system ?? null)
const cfgState = computed(() => data.value?.config ?? null)
const tiles = computed(() => [
  { k: 'subnets', icon: 'i-lucide-network', to: '/ipam#subnets' }, { k: 'addresses', icon: 'i-lucide-list-ordered', to: '/ipam#addresses' },
  { k: 'zones', icon: 'i-lucide-globe', to: '/dns#zones' }, { k: 'records', icon: 'i-lucide-file-text', to: '/dns#records' },
  { k: 'scopes', icon: 'i-lucide-server', to: '/dhcp#scopes' }, { k: 'reservations', icon: 'i-lucide-bookmark', to: '/dhcp#ranges' },
  { k: 'lists', icon: 'i-lucide-shield-ban', to: '/filtering#lists' }, { k: 'blocked_domains', icon: 'i-lucide-ban', to: '/filtering#lists' },
])
const subnetWarn = computed(() => data.value?.alerts?.thresholds?.subnetWarn ?? 90)
const util = computed(() => (data.value?.top ?? []).map((s: any) => ({ label: s.cidr, value: s.percent, display: `${s.percent}% · ${s.used}/${s.capacity}`, warn: s.percent >= subnetWarn.value })))
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
const when = (s: number) => dateTime(s * 1000)

// ---- supervision : alertes, services du nœud, cluster, sauvegardes
const alerts = computed(() => data.value?.alerts ?? null)
const nAlerts = computed(() => (alerts.value ? alerts.value.summary.critical + alerts.value.summary.warning + alerts.value.summary.info : 0))
const worst = computed<'error' | 'warning' | 'info'>(() => (alerts.value?.summary.critical ? 'error' : alerts.value?.summary.warning ? 'warning' : 'info'))
const sevIcon = (s: string) => (s === 'critical' ? 'i-lucide-octagon-alert' : s === 'warning' ? 'i-lucide-triangle-alert' : 'i-lucide-info')
const sevClass = (s: string) => (s === 'critical' ? 'text-error' : s === 'warning' ? 'text-warning' : 'text-info')
const ruleText = (a: any) => t(`alerts.rule.${a.rule}`, { node: a.node || '?', subject: a.subject || '', ...(a.params ?? {}) })
const alertCounts = computed(() => { const m = alerts.value?.summary; if (!m) return ''
  return [m.critical && t('dash.alerts.crit', { n: m.critical }), m.warning && t('dash.alerts.warn', { n: m.warning }), m.info && t('dash.alerts.info', { n: m.info }), m.silenced && t('dash.alerts.silenced', { n: m.silenced })].filter(Boolean).join(' · ') })
const node = computed(() => data.value?.node ?? null)
const cl = computed(() => data.value?.cluster ?? null)
const bk = computed(() => data.value?.backup ?? null)
const age = (s: number) => (s < 120 ? `${s} s` : s < 7200 ? `${Math.round(s / 60)} min` : `${Math.round(s / 3600)} h`)
const svcOk = (x: any) => x.state === 'active'
const svcColor = (x: any) => (x.state === 'active' ? 'text-success' : ['activating', 'reloading'].includes(x.state) ? 'text-info' : x.expected ? 'text-error' : 'text-muted')
const svcIcon = (x: any) => (x.state === 'active' ? 'i-lucide-circle-check' : ['activating', 'reloading'].includes(x.state) ? 'i-lucide-loader-circle' : x.expected ? 'i-lucide-circle-x' : 'i-lucide-circle-minus')
const stateText = (s: string) => { const k = `dash.state.${s}`; const v = t(k); return v === k ? s : v }
const svcName = (n: string) => { const k = `dash.svc.${n}`; const v = t(k); return v === k ? n : v }
const certName = (n: string) => { const k = `dash.cert.${n}`; const v = t(k); return v === k ? n : v }
const bytes = (n: number | null | undefined) => (n == null ? '—' : n < 1048576 ? `${Math.round(n / 1024)} Kio` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} Mio` : `${(n / 1073741824).toFixed(2)} Gio`)
const quorumOk = computed(() => cl.value?.quorum?.hasQuorum === true)
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

    <section :aria-label="t('alerts.title')" data-testid="dash-alerts">
      <UAlert v-if="nAlerts > 0" :color="worst" variant="subtle" :icon="sevIcon(worst === 'error' ? 'critical' : worst)" :title="t('dash.alerts.some', { n: nAlerts })">
        <template #description>
          <p class="text-xs mb-1">{{ alertCounts }}</p>
          <ul class="text-sm flex flex-col gap-1">
            <li v-for="a in alerts.top" :key="a.id" class="flex items-start gap-2"><UIcon :name="sevIcon(a.severity)" class="size-4 mt-0.5 shrink-0" :class="sevClass(a.severity)" /><span class="text-default">{{ ruleText(a) }}</span></li>
          </ul>
        </template>
        <template v-if="isAdmin" #actions><UButton to="/system#alerts" size="xs" :color="worst" variant="outline" :label="t('dash.alerts.go')" /></template>
      </UAlert>
      <p v-else-if="alerts" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-circle-check" class="size-4 text-success" />{{ t('dash.alerts.ok') }}<span v-if="alerts.summary.silenced"> ({{ t('dash.alerts.silenced', { n: alerts.summary.silenced }) }})</span></p>
    </section>

    <div class="grid gap-4 lg:grid-cols-3" data-testid="dash-health">
      <UCard><template #header><span class="font-medium">{{ t('dash.services') }}</span></template>
        <template v-if="node">
          <p v-if="node.stale" class="text-xs text-warning mb-2">{{ t('dash.services.stale', { age: age(node.ageSeconds) }) }}</p>
          <ul class="flex flex-col gap-1 text-sm">
            <li v-for="x in node.services" :key="x.name" class="flex items-center gap-2" :data-svc="x.name" :data-state="x.state">
              <UIcon :name="svcIcon(x)" class="size-4 shrink-0" :class="[svcColor(x), x.state === 'activating' ? 'animate-spin' : '']" />
              <span class="flex-1">{{ svcName(x.name) }}</span><span class="text-xs" :class="svcOk(x) ? 'text-muted' : svcColor(x)">{{ stateText(x.state) }}</span>
            </li>
            <li v-if="node.postgres === false" class="flex items-center gap-2 text-error"><UIcon name="i-lucide-circle-x" class="size-4" />{{ t('dash.postgres_down') }}</li>
            <li v-if="node.timeSynced === false" class="flex items-center gap-2 text-warning"><UIcon name="i-lucide-clock-alert" class="size-4" />{{ t('dash.time_unsynced') }}</li>
          </ul>
          <ul v-if="node.certs.length" class="mt-3 pt-2 border-t border-default flex flex-col gap-1 text-xs">
            <li v-for="c in node.certs" :key="c.name" class="flex items-center gap-2"><UIcon name="i-lucide-badge-check" class="size-3.5 shrink-0" :class="c.days <= 7 ? 'text-error' : c.days <= 30 ? 'text-warning' : 'text-muted'" />
              <span class="flex-1">{{ t('dash.cert', { name: certName(c.name) }) }}</span><span :class="c.days <= 7 ? 'text-error' : c.days <= 30 ? 'text-warning' : 'text-muted'">{{ c.days < 0 ? t('dash.cert_expired') : t('dash.cert_days', { d: c.days }) }}</span></li>
          </ul>
        </template>
        <p v-else class="text-sm text-muted flex items-center gap-2"><UIcon name="i-lucide-loader-circle" class="size-4 animate-spin" />{{ t('dash.services.collecting') }}</p>
      </UCard>

      <UCard><template #header><div class="flex items-center gap-2"><span class="font-medium">{{ t('dash.cluster.title') }}</span><span v-if="cl" class="text-xs text-muted font-mono">{{ cl.name }}</span><span class="flex-1" />
          <UButton v-if="cl || isAdmin" to="/cluster" size="xs" color="neutral" variant="ghost" trailing-icon="i-lucide-arrow-right" :label="t('dash.cluster.go')" /></div></template>
        <template v-if="cl">
          <p v-if="cl.stale" class="text-xs text-warning mb-2">{{ t('dash.cluster.stale', { age: cl.ageSeconds }) }}</p>
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm mb-3">
            <dt class="text-muted">{{ t('dash.cluster.leader') }}</dt><dd class="font-mono" :class="cl.leader ? '' : 'text-error'">{{ cl.leader ?? t('dash.cluster.no_leader') }}</dd>
            <template v-if="cl.quorum"><dt class="text-muted">{{ t('dash.cluster.quorum') }}</dt>
              <dd :class="quorumOk ? (cl.quorum.tolerance === 0 ? 'text-warning' : '') : 'text-error font-medium'" data-testid="dash-quorum">{{ quorumOk ? t('dash.cluster.quorum_ok', { h: cl.quorum.healthy, v: cl.quorum.voters, n: cl.quorum.needed, t: cl.quorum.tolerance }) : t('dash.cluster.quorum_lost', { h: cl.quorum.healthy, v: cl.quorum.voters, n: cl.quorum.needed }) }}</dd></template>
            <template v-if="cl.vip"><dt class="text-muted">{{ t('dash.cluster.vip') }}</dt><dd><span class="font-mono text-xs">{{ cl.vip.address }}</span> <span class="text-xs text-muted">{{ cl.vip.held ? t('dash.cluster.vip_here') : t('dash.cluster.vip_other') }}</span></dd></template>
          </dl>
          <ul class="flex flex-col gap-1.5 text-sm">
            <li v-for="n in cl.nodes" :key="n.name" class="flex flex-wrap items-center gap-2" :data-node="n.name">
              <UIcon :name="!n.health || n.health.stale ? 'i-lucide-circle-help' : n.health.servicesDown ? 'i-lucide-triangle-alert' : 'i-lucide-circle-check'" class="size-4 shrink-0"
                :class="!n.health ? 'text-muted' : n.health.stale ? 'text-error' : n.health.servicesDown ? 'text-warning' : 'text-success'" />
              <span class="font-mono">{{ n.name }}</span>
              <UBadge size="sm" color="neutral" variant="subtle" :label="t(`dash.cluster.role.${n.role}`)" />
              <UBadge v-if="n.isLeader" size="sm" color="primary" variant="subtle" :label="t('dash.cluster.leader_tag')" />
              <span v-if="n.health?.stale" class="text-xs text-error">{{ t('dash.cluster.silent') }}</span>
              <span v-else-if="n.health?.servicesDown" class="text-xs text-warning">{{ t('dash.cluster.svc_down', { n: n.health.servicesDown }) }}</span>
              <span v-else-if="n.state && !n.isLeader" class="text-xs text-muted">{{ n.state }}<template v-if="n.lagBytes"> · {{ t('dash.cluster.lag', { n: bytes(n.lagBytes) }) }}</template></span>
            </li>
          </ul>
        </template>
        <p v-else class="text-sm text-muted">{{ t('dash.cluster.none') }}</p>
      </UCard>

      <UCard><template #header><div class="flex items-center gap-2"><span class="font-medium">{{ t('dash.backup.title') }}</span><span class="flex-1" />
          <UButton v-if="isAdmin" to="/system#backup" size="xs" color="neutral" variant="ghost" trailing-icon="i-lucide-arrow-right" :label="t('dash.backup.go')" /></div></template>
        <template v-if="bk">
          <p v-if="bk.stale" class="text-xs text-warning mb-2">{{ t('dash.backup.stale') }}</p>
          <p v-if="bk.archiverFailing" class="text-xs text-error mb-2 flex items-start gap-2"><UIcon name="i-lucide-triangle-alert" class="size-4 shrink-0" />{{ t('dash.backup.failing') }}</p>
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt class="text-muted">{{ t('dash.backup.last') }}</dt><dd class="num">{{ bk.lastAt ? when(bk.lastAt) : t('dash.backup.never') }}</dd>
            <dt class="text-muted">{{ t('dash.backup.count') }}</dt><dd class="num">{{ bk.count }}</dd>
            <template v-if="bk.pitrFrom"><dt class="text-muted">{{ t('dash.backup.window') }}</dt><dd class="num">{{ when(bk.pitrFrom) }}</dd></template>
          </dl>
        </template>
        <p v-else class="text-sm text-muted">{{ t('dash.backup.off') }}</p>
      </UCard>
    </div>

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
          <template v-if="cfgState"><dt class="text-muted">{{ t('dash.config_gen') }}</dt>
            <dd class="flex items-center gap-2"><span class="font-mono">#{{ cfgState.generation }}</span><UBadge size="sm" variant="subtle" :color="cfgState.pending ? 'warning' : 'success'" :label="cfgState.pending ? t('dash.config_pending') : t('dash.config_applied')" /><UButton v-if="cfgState.pending && isAdmin" to="/dns#deploy" size="xs" color="warning" variant="outline" icon="i-lucide-rocket" :label="t('dash.deploy_now')" data-test="dash-deploy" /></dd></template>
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
        <p class="text-xs text-muted mt-2">{{ t('dash.threshold', { n: subnetWarn }) }}</p></UCard>
      <UCard class="lg:col-span-1"><template #header><span class="font-medium">{{ t('dash.types') }}</span></template>
        <BarChart v-if="types.length" :items="types" :label="t('dash.types')" />
        <p v-else class="text-sm text-muted">{{ t('common.empty') }}</p>
        <p class="text-xs text-muted mt-2">{{ t('dash.queries_24h', { q: day('query'), b: day('blocked') }) }}<template v-if="day('query') > 0"> ({{ blockedPct }} %)</template></p></UCard>
    </div>
      <p class="text-xs text-muted text-end">{{ t('dash.updated', { at: time(updatedAt) }) }}</p>
  </div>
</template>
