<script setup lang="ts">
// Mise à jour du cluster, nœud par nœud : un ordre commun (version cible) que chaque nœud applique à son tour — arbitre, secondaires, primaire en dernier.
// La console ne fait que déposer la demande (root la revalide) ; l'installation est celle de la page Système (signature, sauvegarde, retour arrière).
const props = defineProps<{ st: any; result: any; replica: boolean }>()
const emit = defineEmits<{ (e: 'reload'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const { isAdmin } = useRole(); const fmt = useFmt()

const upd = computed(() => props.st?.update ?? null)
const order = computed(() => upd.value?.order ?? null)
const versions = computed<Record<string, string>>(() => upd.value?.versions ?? {})
const spread = computed(() => { const vs = (props.st?.nodes ?? []).map((n: any) => versions.value[n.name] ?? ''); const set = [...new Set(vs.filter(Boolean))].sort((a: any, b: any) => a.localeCompare(b, undefined, { numeric: true })); return { ok: set.length === 1 && vs.every(Boolean), set: set as string[] } })
const local = ref<any>(null), busy = ref(false), checking = ref(false), err = ref('')
async function loadLocal() { try { local.value = await api.call('GET', '/system/update', undefined, { silent: true }) } catch { local.value = null } }
onMounted(() => { if (isAdmin.value) loadLocal() })
watch(() => props.st?.at, () => { if (isAdmin.value && !busy.value) loadLocal() })
const latest = computed<string>(() => local.value?.status?.available ? local.value.status.latest : '')
const canAct = computed(() => isAdmin.value && props.st?.nodeRole === 'data' && !props.replica && !props.st?.stale)
const canStart = computed(() => canAct.value && !order.value && !!latest.value && versionsBelow(latest.value))
function versionsBelow(v: string) { return (props.st?.nodes ?? []).some((n: any) => (versions.value[n.name] ?? '').localeCompare(v, undefined, { numeric: true }) < 0) }
const stateColor = (s: string) => (s === 'done' ? 'success' : s === 'failed' ? 'error' : s === 'updating' || s === 'requested' ? 'info' : 'neutral') as any
const rowState = (n: any) => {
  const s = upd.value?.states?.[n.name]
  if (!order.value) return null
  if (versions.value[n.name] === order.value.target) return { state: 'done', msg: '' }
  return s ?? { state: 'waiting', msg: '' }
}
async function waitResult(action: string, before: number): Promise<any> {
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 2000)); emit('reload'); await new Promise((r) => setTimeout(r, 1000))
    const r = props.result; if (r && r.at > before && r.action === action) return r
  }
  return null
}
async function send(action: string, body: Record<string, unknown>, okKey: string) {
  busy.value = true; err.value = ''
  const before = props.result?.at ?? 0
  try {
    await api.call('POST', '/cluster/action', body, { busy: true })
    const r = await waitResult(action, before)
    if (!r) { toast.add({ title: t('cluster.op.timeout'), color: 'warning', icon: 'i-lucide-clock-alert' }); return }
    toast.add({ title: r.ok ? t(okKey) : t('cluster.op.failed'), description: r.message, color: r.ok ? 'success' : 'error', icon: r.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
  } catch (e: any) { err.value = e.info?.message ?? t('err.internal') }
  finally { busy.value = false; emit('reload') }
}
async function start() {
  if (!(await ask(t('cluster.upd.start_title', { v: latest.value }), t('cluster.upd.start_body', { v: latest.value }), false))) return
  await send('update-start', { action: 'update-start', version: latest.value, confirm: props.st.cluster }, 'cluster.upd.started')
}
async function cancel() {
  if (!(await ask(t('cluster.upd.cancel_title'), t('cluster.upd.cancel_body'), true))) return
  await send('update-cancel', { action: 'update-cancel', confirm: props.st.cluster }, 'cluster.upd.cancelled')
}
async function check() {
  checking.value = true; err.value = ''
  try {
    await api.call('POST', '/system/update/check', {}, { busy: true })
    for (let i = 0; i < 20; i++) { await new Promise((r) => setTimeout(r, 2000)); await loadLocal(); if (local.value && !local.value.busy) break }
  } catch (e: any) { err.value = e.info?.message ?? t('err.internal') } finally { checking.value = false }
}
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex items-center justify-between gap-2">
        <span class="font-medium">{{ t('cluster.upd.title') }}</span>
        <UBadge :color="spread.ok ? 'success' : spread.set.length ? 'warning' : 'neutral'" variant="subtle"
          :label="spread.ok ? t('cluster.upd.homogeneous', { v: spread.set[0] }) : spread.set.length ? t('cluster.upd.mixed', { v: spread.set.join(' / ') }) : t('cluster.upd.unknown')" />
      </div>
    </template>
    <UAlert v-if="err" class="mb-3" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" />
    <UAlert v-if="order" class="mb-3" color="info" variant="subtle" icon="i-lucide-refresh-cw" :title="t('cluster.upd.running', { v: order.target })"
      :description="t('cluster.upd.running_desc', { by: order.by, d: order.at ? fmt.dateTime(order.at * 1000) : '—' })" />
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead><tr class="text-left text-muted"><th class="py-1 pr-4">{{ t('cluster.name') }}</th><th class="pr-4">{{ t('cluster.upd.version') }}</th><th>{{ t('cluster.upd.progress') }}</th></tr></thead>
        <tbody>
          <tr v-for="n in st.nodes" :key="n.name" class="border-t border-default">
            <td class="py-1.5 pr-4 font-mono">{{ n.name }}<UBadge v-if="n.name === st.node" class="ml-2" size="sm" color="neutral" variant="outline" :label="t('cluster.me')" /></td>
            <td class="pr-4 font-mono">{{ versions[n.name] || '—' }}</td>
            <td>
              <template v-if="rowState(n)"><UBadge :color="stateColor(rowState(n)!.state)" variant="subtle" :label="t(`cluster.upd.st.${rowState(n)!.state}`)" /> <span class="text-xs text-muted">{{ rowState(n)!.msg }}</span></template>
              <span v-else class="text-muted">—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="text-xs text-muted mt-3">{{ t('cluster.upd.hint') }}</p>
    <div v-if="isAdmin" class="flex flex-wrap items-center gap-2 mt-3">
      <UButton v-if="canStart" size="sm" icon="i-lucide-rocket" :label="t('cluster.upd.start', { v: latest })" :loading="busy" :disabled="busy" @click="start" />
      <UButton v-if="order && canAct" size="sm" color="error" variant="outline" icon="i-lucide-octagon-x" :label="t('cluster.upd.cancel')" :loading="busy" :disabled="busy" @click="cancel" />
      <UButton v-if="canAct && !order" size="sm" color="neutral" variant="outline" icon="i-lucide-search" :label="t('cluster.upd.check')" :loading="checking" :disabled="checking || busy" @click="check" />
      <span v-if="canAct && !order && !latest && local?.status?.checkedAt" class="text-xs text-muted">{{ t('cluster.upd.none_available') }}</span>
    </div>
  </UCard>
</template>
