<script setup lang="ts">
// Page « Cluster » : état publié par root (lecture seule) et bascule contrôlée. La console ne pilote rien directement :
// elle dépose une demande que root valide de nouveau (voir docs/ARCHITECTURE-CLUSTER.md).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const { isAdmin } = useRole()
const data = ref<any>(null), loading = ref(true), error = ref(''), switching = ref('')
let timer: ReturnType<typeof setInterval> | undefined
async function load(silent = false) {
  try { data.value = await api.call('GET', '/cluster/status', undefined, { silent }); error.value = '' }
  catch (e: any) { if (!silent) error.value = e.info?.message ?? t('err.internal') }
  finally { loading.value = false }
}
onMounted(() => { load(); timer = setInterval(() => load(true), 5000) })
onBeforeUnmount(() => { if (timer) clearInterval(timer) })

const st = computed(() => data.value?.state ?? null)
const isLeader = computed(() => st.value?.localRole === 'leader')
const canSwitch = computed(() => isAdmin.value && isLeader.value && !data.value?.replica && !switching.value)
const when = (s: number) => (s ? new Date(s * 1000).toLocaleString() : '—')
const roleColor = (r: string) => (r === 'leader' ? 'success' : r === 'replica' ? 'info' : 'neutral') as any
const stateColor = (s?: string) => (['running', 'streaming'].includes(s ?? '') ? 'success' : s ? 'warning' : 'neutral') as any
const nodeKind = (n: any) => (n.role === 'witness' ? t('cluster.witness') : t(`cluster.pg.${n.patroniRole || 'unknown'}`))
const lag = (n: any) => (n.lagBytes === null || n.lagBytes === undefined ? '—' : n.lagBytes < 1024 ? `${n.lagBytes} B` : `${Math.round(n.lagBytes / 1024)} KiB`)
const kea = computed(() => st.value?.kea)

async function switchover(node: string) {
  if (!(await ask(t('cluster.switch_title', { n: node }), t('cluster.switch_body', { n: node }), true))) return
  error.value = ''; switching.value = node
  const before = data.value?.result?.at ?? 0
  try {
    await api.call('POST', '/cluster/switchover', { candidate: node }, { busy: true })
    // root traite la demande de façon asynchrone : on attend son résultat (la bascule dure en général moins d'une minute)
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 2000)); await load(true)
      const r = data.value?.result
      if (r && r.at > before) {
        toast.add({ title: r.ok ? t('cluster.switch_done', { n: node }) : t('cluster.switch_failed'), description: r.ok ? undefined : r.message, color: r.ok ? 'success' : 'error', icon: r.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
        break
      }
    }
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal') }
  finally { switching.value = ''; load(true) }
}
</script>

<template>
  <div class="flex flex-col gap-4 max-w-5xl">
    <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" />
    <div v-if="loading" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader" class="animate-spin" />{{ t('cluster.loading') }}</div>
    <UAlert v-else-if="!data?.clustered" color="neutral" variant="subtle" icon="i-lucide-info" :title="t('cluster.none_title')" :description="t('cluster.none_desc')" />
    <template v-else-if="st">
      <UAlert v-if="st.stale" color="warning" variant="subtle" icon="i-lucide-clock-alert" :title="t('cluster.stale')" :description="t('cluster.stale_desc', { d: when(st.at) })" />
      <UAlert v-if="data.replica" color="info" variant="subtle" icon="i-lucide-copy" :title="t('cluster.replica_title')" :description="t('cluster.replica_desc')" />
      <div class="grid gap-4 lg:grid-cols-2">
        <UCard>
          <template #header><span class="font-medium">{{ t('cluster.this_node') }}</span></template>
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt class="text-muted">{{ t('cluster.name') }}</dt><dd class="font-mono">{{ st.cluster }} / {{ st.node }}</dd>
            <dt class="text-muted">{{ t('cluster.pg_role') }}</dt><dd><UBadge :color="roleColor(st.localRole)" variant="subtle" :label="t(`cluster.pg.${st.localRole === 'unknown' ? 'unknown' : st.localRole}`)" /></dd>
            <dt class="text-muted">{{ t('cluster.dns_role') }}</dt><dd><UBadge :color="st.bind === 'primary' ? 'success' : 'neutral'" variant="subtle" :label="st.bind ? t(`cluster.bind.${st.bind}`) : '—'" /></dd>
            <dt class="text-muted">{{ t('cluster.quorum') }}</dt><dd><UBadge :color="st.etcd.healthy ? 'success' : 'error'" variant="subtle" :label="st.etcd.healthy ? t('cluster.quorum_ok', { n: st.etcd.members }) : t('cluster.quorum_lost')" /></dd>
            <dt class="text-muted">{{ t('cluster.vip') }}</dt>
            <dd v-if="st.vip"><span class="font-mono">{{ st.vip.address }}</span> <UBadge :color="st.vip.held ? 'success' : 'neutral'" variant="subtle" :label="st.vip.held ? t('cluster.vip_held') : t('cluster.vip_not_held')" /></dd>
            <dd v-else class="text-muted">{{ t('cluster.vip_none') }}</dd>
            <dt class="text-muted">{{ t('cluster.updated') }}</dt><dd>{{ when(st.at) }}</dd>
          </dl>
        </UCard>
        <UCard>
          <template #header><span class="font-medium">{{ t('cluster.dhcp') }}</span></template>
          <p v-if="!kea" class="text-sm text-muted">{{ t('cluster.kea_off') }}</p>
          <p v-else-if="!kea.ha" class="text-sm text-muted">{{ t('cluster.kea_no_ha') }}</p>
          <dl v-else class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt class="text-muted">{{ t('cluster.ha_mode') }}</dt><dd class="font-mono">{{ kea.mode }}</dd>
            <dt class="text-muted">{{ t('cluster.ha_local') }}</dt><dd><UBadge :color="kea.local?.state === 'load-balancing' ? 'success' : 'warning'" variant="subtle" :label="kea.local?.state || '—'" /></dd>
            <dt class="text-muted">{{ t('cluster.ha_partner') }}</dt><dd><UBadge :color="kea.partner?.state === 'load-balancing' ? 'success' : 'warning'" variant="subtle" :label="kea.partner?.state || '—'" /> <span v-if="kea.partner?.interrupted" class="text-warning text-xs">{{ t('cluster.ha_interrupted') }}</span></dd>
          </dl>
        </UCard>
      </div>
      <UCard>
        <template #header><div class="flex items-center justify-between"><span class="font-medium">{{ t('cluster.nodes') }}</span><span v-if="switching" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader" class="animate-spin" />{{ t('cluster.switching', { n: switching }) }}</span></div></template>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead><tr class="text-left text-muted"><th class="py-1 pr-4">{{ t('cluster.name') }}</th><th class="pr-4">{{ t('cluster.address') }}</th><th class="pr-4">{{ t('cluster.kind') }}</th><th class="pr-4">{{ t('cluster.state') }}</th><th class="pr-4">{{ t('cluster.lag') }}</th><th /></tr></thead>
            <tbody>
              <tr v-for="n in st.nodes" :key="n.name" class="border-t border-default">
                <td class="py-1.5 pr-4 font-mono">{{ n.name }}<UBadge v-if="n.name === st.node" class="ml-2" size="sm" color="neutral" variant="outline" :label="t('cluster.me')" /></td>
                <td class="pr-4 font-mono">{{ n.ip }}</td>
                <td class="pr-4"><UBadge :color="roleColor(n.patroniRole || '')" variant="subtle" :label="nodeKind(n)" /></td>
                <td class="pr-4"><UBadge v-if="n.role === 'data'" :color="stateColor(n.state)" variant="subtle" :label="n.state || t('cluster.pg.unknown')" /><span v-else class="text-muted">—</span></td>
                <td class="pr-4 font-mono">{{ n.role === 'data' && n.patroniRole !== 'leader' ? lag(n) : '—' }}</td>
                <td class="text-right"><UButton v-if="canSwitch && (data.candidates ?? []).includes(n.name)" size="xs" color="neutral" variant="outline" icon="i-lucide-arrow-left-right" :loading="switching === n.name" :label="t('cluster.make_leader')" @click="switchover(n.name)" /></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="text-xs text-muted mt-3">{{ t('cluster.vip_hint') }}</p>
      </UCard>
    </template>
  </div>
</template>
