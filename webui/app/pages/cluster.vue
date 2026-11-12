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
// Actualisation « en direct » : l'état est relu toutes les 5 s ; un opérateur demande en plus à root de republier (sondes etcd fraîches) toutes les 15 s.
let ticks = 0
const { canWrite } = useRole()
onMounted(() => {
  load()
  timer = setInterval(() => {
    if (document.hidden) return
    if (canWrite.value && data.value?.clustered && !data.value?.replica && ticks++ % 3 === 0) api.call('POST', '/cluster/refresh', undefined, { silent: true }).catch(() => {})
    nowS.value = Math.floor(Date.now() / 1000); load(true)
  }, 5000)
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })

const st = computed(() => data.value?.state ?? null)
// tâche déposée par la console et pas encore prise en charge par root : laquelle, depuis quand, et possibilité de l'annuler si elle semble bloquée
const pending = computed(() => data.value?.pending ?? null)
const nowS = ref(Math.floor(Date.now() / 1000))
const pendingAge = computed(() => (pending.value ? Math.max(0, nowS.value - pending.value.since) : 0))
const pendingStuck = computed(() => pendingAge.value > 120)
const ageText = (s: number) => (s < 90 ? `${s} s` : `${Math.round(s / 60)} min`)
async function cancelPending() {
  if (!(await ask(t('cluster.pending.cancel_title'), t('cluster.pending.cancel_body'), true))) return
  try { await api.call('DELETE', '/cluster/pending'); toast.add({ title: t('cluster.pending.cancelled'), color: 'success' }); await load(true) } catch (e: any) { error.value = e?.info?.message ?? t('err.internal') }
}
const wiz = ref<any>(null)
const canAdd = computed(() => isAdmin.value && st.value?.nodeRole === 'data' && st.value?.ca?.node === true && !data.value?.replica)
const isLeader = computed(() => st.value?.localRole === 'leader')
const canSwitch = computed(() => isAdmin.value && isLeader.value && !data.value?.replica && !switching.value)
const fmt = useFmt()
const when = (s: number) => (s ? fmt.dateTime(s * 1000) : '—')
const roleColor = (r: string) => (r === 'leader' ? 'success' : r === 'replica' ? 'info' : 'neutral') as any
const stateColor = (s?: string) => (['running', 'streaming'].includes(s ?? '') ? 'success' : s ? 'warning' : 'neutral') as any
const nodeKind = (n: any) => (n.role === 'witness' ? t('cluster.witness') : t(`cluster.pg.${n.patroniRole || 'unknown'}`))
const lag = (n: any) => (n.lagBytes === null || n.lagBytes === undefined ? '—' : n.lagBytes < 1024 ? `${n.lagBytes} B` : `${Math.round(n.lagBytes / 1024)} KiB`)
const kea = computed(() => st.value?.kea)
const member = (name: string) => st.value?.etcd?.quorum?.members?.find((m: any) => m.name === name) ?? null
const etcdLabel = (m: any) => (!m.reachable ? t('cluster.etcd.down') : m.learner ? t('cluster.etcd.learner') : m.isLeader ? t('cluster.etcd.leader') : t('cluster.etcd.voter'))
// écart avec le nœud préféré : le primaire n'est pas là où la consigne le veut (jamais corrigé automatiquement)
const drift = computed(() => (st.value?.preferred && st.value.leader && st.value.preferred.node !== st.value.leader ? st.value.preferred : null))
const canReturn = computed(() => !!drift.value && canSwitch.value && (data.value?.candidates ?? []).includes(drift.value.node))

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
    <ClusterWizards ref="wiz" :st="st" :setup="data?.setup" :result="data?.result" @reload="load(true)" />
    <UAlert v-if="pending" :color="pendingStuck ? 'warning' : 'info'" variant="subtle" icon="i-lucide-loader" :title="t('cluster.pending.title', { task: pendingLabel(t, pending) })" data-test="pending-task">
      <template #description>
        <span>{{ t('cluster.pending.since', { s: ageText(pendingAge) }) }} — {{ pendingStuck ? t('cluster.pending.stuck') : t('cluster.pending.wait') }}</span>
        <div v-if="isAdmin && pendingStuck" class="mt-2"><UButton size="xs" color="warning" variant="outline" :label="t('cluster.pending.cancel')" @click="cancelPending" /></div>
      </template>
    </UAlert>
    <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" />
    <div v-if="loading" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader" class="animate-spin" />{{ t('cluster.loading') }}</div>
    <template v-else-if="!data?.clustered">
      <UAlert color="neutral" variant="subtle" icon="i-lucide-info" :title="t('cluster.none_title')" :description="t('cluster.none_desc')" />
      <div v-if="isAdmin" class="grid gap-4 lg:grid-cols-2">
        <UCard><template #header><span class="font-medium">{{ t('cluster.w.create_card') }}</span></template>
          <p class="text-sm text-muted mb-3">{{ t('cluster.w.create_card_desc') }}</p><UButton icon="i-lucide-server-cog" :label="t('cluster.w.create_btn')" @click="wiz?.begin('init')" /></UCard>
        <UCard><template #header><span class="font-medium">{{ t('cluster.w.join_card') }}</span></template>
          <p class="text-sm text-muted mb-3">{{ t('cluster.w.join_card_desc') }}</p><UButton color="neutral" variant="outline" icon="i-lucide-log-in" :label="t('cluster.w.join_btn')" @click="wiz?.begin('join')" /></UCard>
      </div>
    </template>
    <template v-else-if="st">
      <UAlert v-if="st.stale" color="warning" variant="subtle" icon="i-lucide-clock-alert" :title="t('cluster.stale')" :description="t('cluster.stale_desc', { d: when(st.at) })" />
      <UAlert v-if="data.replica" color="info" variant="subtle" icon="i-lucide-copy" :title="t('cluster.replica_title')" :description="t('cluster.replica_desc')"
        :actions="primaryTarget(st) ? [{ label: primaryTarget(st)!.viaVip ? t('cluster.replica_go_vip') : t('cluster.replica_go'), icon: 'i-lucide-external-link', color: 'neutral', variant: 'outline', onClick: () => openConsole(primaryTarget(st)!.host) }] : []" />
      <UAlert v-if="drift" color="warning" variant="subtle" icon="i-lucide-star" :title="t('cluster.pref.drift_title')"
        :description="[t('cluster.pref.drift_desc', { l: st.leader, p: drift.node }), canReturn ? '' : t('cluster.pref.drift_elsewhere')].filter(Boolean).join(' ')"
        :actions="canReturn ? [{ label: t('cluster.pref.drift_go', { n: drift.node }), icon: 'i-lucide-arrow-left-right', color: 'warning', variant: 'outline', loading: switching === drift.node, onClick: () => switchover(drift!.node) }] : []" />
      <div class="grid gap-4 lg:grid-cols-2">
        <UCard>
          <template #header><span class="font-medium">{{ t('cluster.this_node') }}</span></template>
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt class="text-muted">{{ t('cluster.name') }}</dt><dd class="font-mono">{{ st.cluster }} / {{ st.node }}</dd>
            <dt class="text-muted">{{ t('cluster.pg_role') }}</dt><dd><UBadge :color="roleColor(st.localRole)" variant="subtle" :label="t(`cluster.pg.${st.localRole === 'unknown' ? 'unknown' : st.localRole}`)" /></dd>
            <dt class="text-muted">{{ t('cluster.dns_role') }}</dt><dd><UBadge :color="st.bind === 'primary' ? 'success' : 'neutral'" variant="subtle" :label="st.bind ? t(`cluster.bind.${st.bind}`) : '—'" /></dd>
            <dt class="text-muted">{{ t('cluster.quorum') }}</dt><dd><UBadge :color="(st.etcd.quorum ? st.etcd.quorum.hasQuorum && st.etcd.quorum.tolerance >= 1 : st.etcd.healthy) ? 'success' : st.etcd.quorum?.hasQuorum ? 'warning' : 'error'" variant="subtle" :label="st.etcd.quorum ? (st.etcd.quorum.hasQuorum ? t('cluster.quorum_live', { h: st.etcd.quorum.healthy, v: st.etcd.quorum.voters }) : t('cluster.quorum_lost')) : (st.etcd.healthy ? t('cluster.quorum_ok', { n: st.etcd.members }) : t('cluster.quorum_lost'))" /></dd>
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
      <ClusterUpdate :st="st" :result="data.result" :replica="!!data.replica" @reload="load(true)" />
      <ClusterOps :st="st" :result="data.result" @reload="load(true)" />
      <ClusterDrill :st="st" :result="data.result" :replica="!!data.replica" @reload="load(true)" />
      <ClusterSettings :st="st" :result="data.result" :local="data.local" @reload="load(true)" />
      <UCard>
        <template #header><div class="flex items-center justify-between"><span class="font-medium">{{ t('cluster.nodes') }}</span><UButton v-if="canAdd" size="xs" icon="i-lucide-user-plus" :label="t('cluster.w.add_btn')" @click="wiz?.begin('add')" /><span v-if="switching" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader" class="animate-spin" />{{ t('cluster.switching', { n: switching }) }}</span></div></template>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead><tr class="text-left text-muted"><th class="py-1 pr-4">{{ t('cluster.name') }}</th><th class="pr-4">{{ t('cluster.address') }}</th><th class="pr-4">{{ t('cluster.kind') }}</th><th class="pr-4">{{ t('cluster.state') }}</th><th class="pr-4">{{ t('cluster.lag') }}</th><th class="pr-4">{{ t('cluster.col.etcd') }}</th><th class="pr-4">{{ t('cluster.col.dns') }}</th><th class="pr-4">{{ t('cluster.col.console') }}</th><th /></tr></thead>
            <tbody>
              <tr v-for="n in st.nodes" :key="n.name" class="border-t border-default">
                <td class="py-1.5 pr-4 font-mono">{{ n.name }}<UBadge v-if="n.name === st.node" class="ml-2" size="sm" color="neutral" variant="outline" :label="t('cluster.me')" />
                  <UIcon v-if="st.preferred?.node === n.name" name="i-lucide-star" class="ml-2 size-4 text-warning align-text-bottom" :title="t('cluster.pref.star')" />
                  <div v-if="st.vip && st.leader === n.name" class="text-xs text-muted font-sans">{{ t('cluster.vip_on_node') }} · {{ st.vip.address }}</div></td>
                <td class="pr-4 font-mono">{{ n.ip }}</td>
                <td class="pr-4"><UBadge :color="roleColor(n.patroniRole || '')" variant="subtle" :label="nodeKind(n)" /></td>
                <td class="pr-4"><UBadge v-if="n.role === 'data'" :color="stateColor(n.state)" variant="subtle" :label="n.state || t('cluster.pg.unknown')" /><span v-else class="text-muted">—</span></td>
                <td class="pr-4 font-mono">{{ n.role === 'data' && n.patroniRole !== 'leader' ? lag(n) : '—' }}</td>
                <td class="pr-4">
                  <template v-if="member(n.name)"><UBadge :color="!member(n.name).reachable ? 'error' : member(n.name).healthy ? 'success' : 'warning'" variant="subtle" :label="etcdLabel(member(n.name))" />
                    <div class="text-xs text-muted">{{ member(n.name).raftTerm !== null ? t('cluster.etcd.term', { n: member(n.name).raftTerm }) : '' }}{{ member(n.name).latencyMs !== null ? ` · ${member(n.name).latencyMs} ms` : '' }}</div></template>
                  <span v-else class="text-muted">—</span>
                </td>
                <td class="pr-4"><UBadge v-if="n.role === 'data' && n.patroniRole" :color="n.patroniRole === 'leader' ? 'success' : 'neutral'" variant="subtle" :label="t(`cluster.bind.${n.patroniRole === 'leader' ? 'primary' : 'secondary'}`)" /><span v-else class="text-muted">—</span></td>
                <td class="pr-4"><UButton v-if="n.role === 'data' && n.name !== st.node" size="xs" color="neutral" variant="ghost" icon="i-lucide-external-link" :label="t('cluster.open')" @click="openConsole(n.ip)" /><span v-else class="text-muted">—</span></td>
                <td class="text-right"><UButton v-if="canSwitch && (data.candidates ?? []).includes(n.name)" size="xs" color="neutral" variant="outline" icon="i-lucide-arrow-left-right" :loading="switching === n.name" :label="t('cluster.make_leader')" @click="switchover(n.name)" /></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="text-xs text-muted mt-3">{{ t('cluster.vip_hint') }}</p>
        <p v-if="isAdmin && st.ca && !st.ca.node && st.ca.owner" class="text-xs text-muted mt-1">{{ t('cluster.w.add_hint_other', { n: st.ca.owner }) }}</p>
      </UCard>
    </template>
  </div>
</template>
