<script setup lang="ts">
// PKI et cluster (0.14.9). EJBCA ne tourne que sur le LEADER PostgreSQL : sa base est dans le PostgreSQL du cluster (répliquée par Patroni), et ses secrets, ses autorités
// et son volume sont répliqués par etcd (chiffrés). Cette carte ne fait que MONTRER ce que root publie : où la PKI tourne, si le secondaire est prêt à la reprendre
// (état synchronisé, image tirée), et ce qui la bloque (mise à jour interrompue, etcd injoignable). Aucune action n'est déposée d'ici.
const props = defineProps<{ cluster: any; status: any }>()
const { t } = useT(); const fmt = useFmt()
const c = computed(() => props.cluster)
const ej = computed(() => c.value?.ejbca ?? null)
const local = computed(() => c.value?.local ?? null)
const names = computed(() => Object.keys(ej.value?.nodes ?? {}).sort((x, y) => x.localeCompare(y)))
const iAmLeader = computed(() => !!c.value?.leader && c.value.leader === c.value.node)
const stateSha = computed(() => ej.value?.state?.sha ?? '')
const rows = computed(() => names.value.map((n) => {
  const v = ej.value.nodes[n]
  const synced = !!stateSha.value && v.synced === stateSha.value
  const ready = v.installed && v.image === 'ready' && synced && !v.blocked
  return { name: n, leader: n === c.value.leader, v, synced, ready, age: v.at ? Math.max(0, Math.round(Date.now() / 1000 - v.at)) : null }
}))
// secondaire(s) prêts à reprendre : chaque nœud de données qui n'est pas le leader doit être prêt
const standby = computed(() => rows.value.filter((r) => !r.leader))
const allReady = computed(() => standby.value.length > 0 && standby.value.every((r) => r.ready))
const sync = computed(() => ej.value?.sync ?? null)
const syncBad = computed(() => !!sync.value && (sync.value.state === 'failed' || sync.value.state === 'conflict'))
const blocked = computed(() => local.value?.blocked ?? null)
const mark = computed(() => ej.value?.mark ?? null)
const reason = (r: any) => (r.v.blocked ? t(`pki.cl.blocked.${r.v.blocked}`) : !r.v.installed ? t('pki.cl.why_not_installed') : r.v.image !== 'ready' ? t('pki.cl.why_image') : !r.synced ? t('pki.cl.why_sync') : '')
</script>

<template>
  <UCard v-if="c?.clustered" data-test="pki-cluster">
    <template #header>
      <div class="flex items-center justify-between gap-2">
        <span class="font-medium">{{ t('pki.cl.title') }}</span>
        <UBadge v-if="c.stale" color="warning" variant="subtle" :label="t('pki.cl.stale')" data-test="pki-cl-stale" />
        <UBadge v-else-if="c.nodeRole !== 'data'" color="neutral" variant="subtle" :label="t('pki.cl.witness')" data-test="pki-cl-role" />
        <UBadge v-else-if="iAmLeader" color="success" variant="subtle" :label="t('pki.cl.leader')" data-test="pki-cl-role" />
        <UBadge v-else color="neutral" variant="subtle" :label="t('pki.cl.replica')" data-test="pki-cl-role" />
      </div>
    </template>
    <div class="flex flex-col gap-3 text-sm">
      <p class="text-muted" data-test="pki-cl-where">
        <template v-if="c.stale">{{ t('pki.cl.stale_body') }}</template>
        <template v-else-if="c.nodeRole !== 'data'">{{ t('pki.cl.witness_body') }}</template>
        <template v-else-if="!ej?.enabled">{{ iAmLeader ? t('pki.cl.here_none') : t('pki.cl.elsewhere_none', { node: c.leader ?? '?' }) }}</template>
        <template v-else-if="iAmLeader">{{ t('pki.cl.here') }}</template>
        <template v-else>{{ t('pki.cl.elsewhere', { node: c.leader ?? '?' }) }}</template>
      </p>

      <UAlert v-if="blocked?.reason === 'update-interrupted'" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.cl.blocked_title')"
        :description="t('pki.cl.blocked_body', { node: blocked.node || mark?.node || '?', from: blocked.from || mark?.from || '?', to: blocked.to || mark?.to || '?' })" data-test="pki-cl-blocked" />
      <UAlert v-else-if="blocked?.reason === 'cluster-unreachable'" color="warning" variant="subtle" icon="i-lucide-unplug" :title="t('pki.cl.unreachable_title')" :description="t('pki.cl.unreachable_body')" data-test="pki-cl-unreachable" />
      <UAlert v-else-if="mark" color="info" variant="subtle" icon="i-lucide-refresh-cw" :title="t('pki.cl.mark_title', { node: mark.node })"
        :description="t('pki.cl.mark_body', { from: mark.from || '?', to: mark.to || '?', at: mark.at ? fmt.dateTime(mark.at * 1000) : '—' })" data-test="pki-cl-mark" />
      <UAlert v-if="syncBad" :color="sync.state === 'conflict' ? 'error' : 'warning'" variant="subtle" icon="i-lucide-cloud-off" :title="t(`pki.cl.sync.${sync.state}`)" :description="sync.message" data-test="pki-cl-sync-bad" />

      <template v-if="ej?.enabled">
        <table class="w-full text-left" data-test="pki-cl-nodes">
          <thead class="text-muted"><tr><th class="py-1 pr-3 font-normal">{{ t('pki.cl.node') }}</th><th class="pr-3 font-normal">{{ t('pki.cl.col_role') }}</th><th class="pr-3 font-normal">{{ t('pki.cl.col_unit') }}</th>
            <th class="pr-3 font-normal">{{ t('pki.cl.col_image') }}</th><th class="pr-3 font-normal">{{ t('pki.cl.col_state') }}</th><th class="font-normal">{{ t('pki.cl.col_ready') }}</th></tr></thead>
          <tbody>
            <tr v-for="r in rows" :key="r.name" :data-test="`pki-cl-row-${r.name}`">
              <td class="py-1 pr-3 font-mono">{{ r.name }}<span v-if="r.name === c.node" class="text-dimmed"> ({{ t('pki.cl.this') }})</span></td>
              <td class="pr-3">{{ r.leader ? t('pki.cl.leader') : t('pki.cl.replica') }}</td>
              <td class="pr-3">{{ r.v.unit === 'active' ? t('pki.cl.unit_active') : t('pki.cl.unit_idle') }}<span v-if="r.v.desired === 'stopped'" class="text-warning"> · {{ t('pki.cl.stopped_by_admin') }}</span></td>
              <td class="pr-3">{{ t(`pki.cl.image.${r.v.image}`) }}</td>
              <td class="pr-3"><UIcon :name="r.synced ? 'i-lucide-circle-check' : 'i-lucide-circle-x'" :class="r.synced ? 'text-success' : 'text-error'" class="align-text-bottom" /> {{ r.synced ? t('pki.cl.synced') : t('pki.cl.not_synced') }}</td>
              <td>
                <template v-if="r.leader">—</template>
                <UBadge v-else-if="r.ready" color="success" variant="subtle" :label="t('pki.cl.ready')" />
                <UBadge v-else color="warning" variant="subtle" :label="reason(r) || t('pki.cl.not_ready')" />
              </td>
            </tr>
          </tbody>
        </table>
        <p v-if="allReady" class="text-xs text-muted" role="status" data-test="pki-cl-ready">{{ t('pki.cl.all_ready') }}</p>
        <p v-else-if="standby.length" class="text-xs text-warning" role="status" data-test="pki-cl-notready">{{ t('pki.cl.not_all_ready') }}</p>
        <p v-if="ej.state?.at" class="text-xs text-dimmed">{{ t('pki.cl.state_at', { by: ej.state.by ?? '?', at: fmt.dateTime(ej.state.at * 1000), sha: ej.state.sha }) }}</p>
      </template>
      <p v-else-if="c.nodeRole === 'data' && !c.stale" class="text-muted" data-test="pki-cl-none">{{ t('pki.cl.none') }}</p>

      <p v-if="c.vip?.address" class="text-xs text-dimmed" data-test="pki-cl-vip">{{ t('pki.cl.vip_hint', { vip: c.vip.address }) }}</p>
      <p class="text-xs text-dimmed">{{ t('pki.cl.limits') }}</p>
    </div>
  </UCard>
</template>
