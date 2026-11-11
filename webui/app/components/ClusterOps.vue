<script setup lang="ts">
// Santé du quorum en direct (sondes root) et opérations de reprise : retrait d'un nœud perdu, reprise de l'autorité de certification,
// reconstruction après perte du quorum. Chaque opération exige de retaper un nom (boîte maison, jamais système) et affiche un spinner.
const props = defineProps<{ st: any; result: any }>()
const emit = defineEmits<{ (e: 'reload'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { isAdmin } = useRole()

const q = computed(() => props.st?.etcd?.quorum ?? null)
const ca = computed(() => props.st?.ca ?? null)
const isData = computed(() => props.st?.nodeRole === 'data')
const members = computed(() => [...(q.value?.members ?? [])].sort((a: any, b: any) => a.name.localeCompare(b.name)))
const tone = computed(() => (!q.value ? 'neutral' : !q.value.hasQuorum ? 'error' : q.value.tolerance < 1 ? 'warning' : 'success') as any)
const headline = computed(() => (!q.value ? t('cluster.q.unknown') : !q.value.hasQuorum ? t('cluster.q.lost') : q.value.tolerance < 1 ? t('cluster.q.fragile') : t('cluster.q.ok', { n: q.value.tolerance })))
const bytes = (n: number | null) => (n === null ? '—' : n < 1048576 ? `${Math.round(n / 1024)} KiB` : `${(n / 1048576).toFixed(1)} MiB`)
const mstate = (m: any) => (!m.reachable ? 'down' : !m.healthy ? 'unhealthy' : 'ok')
const mcolor = (m: any) => ({ ok: 'success', unhealthy: 'warning', down: 'error' } as any)[mstate(m)]

type Op = { kind: 'remove-node' | 'take-ca' | 'recover'; node?: string; expect: string }
const op = ref<Op | null>(null), typed = ref(''), busy = ref(false), err = ref('')
const open = computed({ get: () => op.value !== null, set: (v: boolean) => { if (!v && !busy.value) op.value = null } })
function begin(kind: Op['kind'], node?: string) {
  typed.value = ''; err.value = ''
  op.value = { kind, node, expect: kind === 'remove-node' ? node! : kind === 'take-ca' ? props.st.node : props.st.cluster }
}
const canGo = computed(() => op.value !== null && typed.value === op.value.expect && !busy.value)
async function go() {
  const o = op.value; if (!o || typed.value !== o.expect) return
  busy.value = true; err.value = ''
  const before = props.result?.at ?? 0
  try {
    await api.call('POST', '/cluster/action', o.kind === 'remove-node' ? { action: o.kind, node: o.node, confirm: typed.value } : { action: o.kind, confirm: typed.value }, { busy: true })
    // root traite la demande en tâche de fond (reconstruction : jusqu'à ~1 minute) : on attend son résultat
    for (let i = 0; i < 150; i++) {
      await new Promise((r) => setTimeout(r, 2000)); emit('reload'); await new Promise((r) => setTimeout(r, 1000))
      const r = props.result
      if (r && r.at > before && r.action === o.kind) {
        toast.add({ title: r.ok ? t(`cluster.op.${o.kind}.done`) : t('cluster.op.failed'), description: r.message, color: r.ok ? 'success' : 'error', icon: r.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
        op.value = null; return
      }
    }
    err.value = t('cluster.op.timeout')
  } catch (e: any) { err.value = e.info?.message ?? t('err.internal') }
  finally { busy.value = false; emit('reload') }
}
defineExpose({ begin })
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex items-center justify-between gap-2">
        <span class="font-medium">{{ t('cluster.q.title') }}</span>
        <UBadge :color="tone" variant="subtle" :label="headline" />
      </div>
    </template>
    <p v-if="!q" class="text-sm text-muted">{{ t('cluster.q.none') }}</p>
    <template v-else>
      <p class="text-sm mb-3">{{ t('cluster.q.summary', { h: q.healthy, v: q.voters, n: q.needed }) }}</p>
      <UAlert v-if="!q.hasQuorum" class="mb-3" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('cluster.q.lost_title')" :description="t('cluster.q.lost_desc')" />
      <UAlert v-else-if="q.unknownToEtcd.length" class="mb-3" color="warning" variant="subtle" icon="i-lucide-circle-help" :title="t('cluster.q.unknown_nodes', { n: q.unknownToEtcd.join(', ') })" />
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead><tr class="text-left text-muted"><th class="py-1 pr-4">{{ t('cluster.name') }}</th><th class="pr-4">{{ t('cluster.q.etcd') }}</th><th class="pr-4">{{ t('cluster.q.latency') }}</th><th class="pr-4">{{ t('cluster.q.raft') }}</th><th class="pr-4">{{ t('cluster.q.db') }}</th><th class="pr-4">{{ t('cluster.q.version') }}</th><th /></tr></thead>
          <tbody>
            <tr v-for="m in members" :key="m.name" class="border-t border-default">
              <td class="py-1.5 pr-4 font-mono">{{ m.name }}<UBadge v-if="m.isLeader" class="ml-2" size="sm" color="primary" variant="subtle" :label="t('cluster.q.leader')" /></td>
              <td class="pr-4"><UBadge :color="mcolor(m)" variant="subtle" :label="t(`cluster.q.s.${mstate(m)}`)" /></td>
              <td class="pr-4 font-mono">{{ m.latencyMs === null ? '—' : `${m.latencyMs} ms` }}</td>
              <td class="pr-4 font-mono">{{ m.raftIndex ?? '—' }}<span class="text-muted"> / {{ m.raftTerm ?? '—' }}</span></td>
              <td class="pr-4 font-mono">{{ bytes(m.dbSize) }}</td>
              <td class="pr-4 font-mono">{{ m.version || '—' }}</td>
              <td class="text-right"><UButton v-if="isAdmin && isData && m.name !== st.node" size="xs" color="error" variant="outline" icon="i-lucide-user-minus" :label="t('cluster.op.remove')" :disabled="!q.hasQuorum" @click="begin('remove-node', m.name)" /></td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </UCard>

  <UCard v-if="ca">
    <template #header><span class="font-medium">{{ t('cluster.ca.title') }}</span></template>
    <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
      <dt class="text-muted">{{ t('cluster.ca.holder') }}</dt><dd class="font-mono">{{ ca.node ? st.node : (ca.owner || '—') }}</dd>
      <dt class="text-muted">{{ t('cluster.ca.escrow') }}</dt><dd><UBadge :color="ca.escrow || !isData ? 'success' : 'warning'" variant="subtle" :label="ca.escrow ? t('cluster.ca.escrow_yes') : t('cluster.ca.escrow_no')" /></dd>
    </dl>
    <p class="text-xs text-muted mt-2">{{ t('cluster.ca.hint') }}</p>
    <div v-if="isAdmin && isData && !ca.node && ca.escrow" class="mt-3">
      <UButton color="warning" variant="outline" icon="i-lucide-key-round" :label="t('cluster.ca.take')" @click="begin('take-ca')" />
    </div>
  </UCard>

  <UCard v-if="isAdmin && isData && q && !q.hasQuorum" :ui="{ root: 'ring-error' }">
    <template #header><span class="font-medium text-error">{{ t('cluster.rec.title') }}</span></template>
    <p class="text-sm">{{ t('cluster.rec.desc') }}</p>
    <ul class="list-disc pl-5 mt-2 text-sm text-muted">
      <li>{{ t('cluster.rec.w1') }}</li><li>{{ t('cluster.rec.w2') }}</li><li>{{ t('cluster.rec.w3') }}</li>
    </ul>
    <div class="mt-3"><UButton color="error" icon="i-lucide-life-buoy" :label="t('cluster.rec.go')" @click="begin('recover')" /></div>
  </UCard>

  <UModal v-model:open="open" :title="op ? t(`cluster.op.${op.kind}.title`, { n: op.node ?? '' }) : ''" :description="op ? t(`cluster.op.${op.kind}.body`, { n: op.node ?? '' }) : ''" :dismissible="!busy">
    <template #body>
      <div v-if="op" class="flex flex-col gap-3">
        <UAlert v-if="op.kind === 'recover'" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('cluster.rec.loss_title')" :description="t('cluster.rec.loss_desc')" />
        <UAlert v-if="op.kind === 'remove-node'" color="warning" variant="subtle" icon="i-lucide-info" :title="t('cluster.op.remove.note')" />
        <label class="text-sm">{{ t('cluster.op.type', { v: op.expect }) }}
          <UInput v-model="typed" class="w-full mt-1" autocomplete="off" :disabled="busy" @keyup.enter="go" />
        </label>
        <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" />
        <div v-if="busy" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader" class="animate-spin" />{{ t('cluster.op.running') }}</div>
      </div>
    </template>
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton color="neutral" variant="outline" :label="t('common.cancel')" :disabled="busy" @click="op = null" />
        <UButton color="error" :label="t('common.confirm')" :disabled="!canGo" :loading="busy" @click="go" />
      </div>
    </template>
  </UModal>
</template>
