<script setup lang="ts">
// Plan de bascule (0.12.6) : check-list ordonnée, point de restauration au démarrage, bascule finale refusée tant que tout n'est pas fait, retour arrière.
import { PS_CUTOVER_ROLLBACK, PS_CUTOVER_STOP, PS_CUTOVER_TTL } from '~/utils/migration-scripts'
const { t } = useT(); const api = useApi(); const { isAdmin, canWrite } = useRole(); const { ask } = useConfirm()
const emit = defineEmits<{ done: [] }>()
const st = ref<any>(null), busy = ref(''), err = ref(''), shown = ref('')
async function load() { try { st.value = await api.call('GET', '/migration/cutover', undefined, { silent: true }) } catch { /* lecture seule */ } }
await load()
const TXT = computed<Record<string, { label: string; hint: string }>>(() => ({
  ttl: { label: t('mc.i_ttl'), hint: t('mc.i_ttl_h') }, verify: { label: t('mc.i_verify'), hint: t('mc.i_verify_h') }, leases: { label: t('mc.i_leases'), hint: t('mc.i_leases_h') },
  relay: { label: t('mc.i_relay'), hint: t('mc.i_relay_h') }, stop_windows: { label: t('mc.i_stop'), hint: t('mc.i_stop_h') }, promote: { label: t('mc.i_promote'), hint: t('mc.i_promote_h') },
  clients_dns: { label: t('mc.i_clients'), hint: t('mc.i_clients_h') },
}))
const SCRIPTS = computed<Record<string, { title: string; code: string }>>(() => ({
  ttl: { title: t('mc.s_ttl'), code: PS_CUTOVER_TTL }, stop_windows: { title: t('mc.s_stop'), code: PS_CUTOVER_STOP }, rollback: { title: t('mc.s_rollback'), code: PS_CUTOVER_ROLLBACK },
}))
async function call(m: string, p: string, b?: unknown, k = p) {
  busy.value = k; err.value = ''
  try { st.value = { ...st.value, ...(await api.call(m, p, b, { silent: true })) }; emit('done') } catch (e: any) { err.value = e?.info?.message ?? t('err.internal'); await load() } finally { busy.value = '' }
}
async function act(k: 'start' | 'finish' | 'rollback') {
  const T = { start: [t('mc.ask_start'), t('mc.ask_start_b'), false], finish: [t('mc.ask_finish'), t('mc.ask_finish_b'), false], rollback: [t('mc.ask_rollback'), t('mc.ask_rollback_b'), true] }[k]
  if (await ask(T[0] as string, T[1] as string, T[2] as boolean)) await call('POST', `/migration/cutover/${k}`)
}
const tick = (id: string, done: boolean) => call('PUT', '/migration/cutover/item', { id, done }, id)
</script>

<template>
  <div v-if="st" class="flex flex-col gap-3 rounded-md bg-elevated/50 p-3" data-test="mc-root">
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <div v-if="st.finishedAt" data-test="mc-finished"><UAlert color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('mc.finished')" /></div>
    <template v-if="!st.started">
      <p class="text-sm text-muted">{{ t('mc.intro') }}</p>
      <div v-if="isAdmin"><UButton icon="i-lucide-flag" :label="t('mc.start')" :loading="busy === '/migration/cutover/start'" data-test="mc-start" @click="act('start')" /></div>
    </template>
    <template v-else>
      <p class="text-sm text-muted" data-test="mc-started">{{ t('mc.started', { id: st.started.snapshotId, at: new Date(st.started.at).toLocaleString() }) }}</p>
      <ol class="flex flex-col gap-2" data-test="mc-items">
        <li v-for="(i, n) in st.items" :key="i.id" class="flex gap-3 rounded-md border border-default p-3" :data-item="i.id" :data-done="i.done">
          <UIcon :name="i.done ? 'i-lucide-circle-check' : 'i-lucide-circle'" class="size-5 mt-0.5 shrink-0" :class="i.done ? 'text-success' : 'text-muted'" />
          <div class="text-sm flex-1"><div class="font-medium">{{ n + 1 }}. {{ TXT[i.id]?.label }} <UBadge v-if="i.auto" color="neutral" variant="outline" :label="t('mc.auto')" /></div><div class="text-muted">{{ TXT[i.id]?.hint }}</div></div>
          <UCheckbox v-if="!i.auto && canWrite && !st.finishedAt" :model-value="i.done" :label="t('mig.done')" :disabled="busy === i.id" :data-test="`mc-tick-${i.id}`" @update:model-value="(v: any) => tick(i.id, !!v)" />
        </li>
      </ol>
      <div class="flex flex-wrap gap-2"><UButton v-for="(sc, k) in SCRIPTS" :key="k" size="xs" :color="shown === k ? 'primary' : 'neutral'" variant="outline" icon="i-lucide-file-code" :label="sc.title" @click="shown = shown === k ? '' : String(k)" /></div>
      <pre v-if="shown" class="text-xs font-mono bg-elevated rounded-md p-3 overflow-x-auto" data-test="mc-script">{{ SCRIPTS[shown]!.code }}</pre>
      <div v-if="isAdmin" class="flex flex-wrap gap-2">
        <UButton v-if="!st.finishedAt" icon="i-lucide-check-check" :label="t('mc.finish')" :disabled="st.pending.length > 0" :loading="busy === '/migration/cutover/finish'" data-test="mc-finish" @click="act('finish')" />
        <UButton color="error" variant="outline" icon="i-lucide-undo-2" :label="t('mc.rollback')" :loading="busy === '/migration/cutover/rollback'" data-test="mc-rollback" @click="act('rollback')" />
      </div>
    </template>
  </div>
</template>
