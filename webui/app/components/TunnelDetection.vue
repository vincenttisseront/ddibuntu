<script setup lang="ts">
// Détection de tunnels / exfiltration DNS : heuristique sur le journal des requêtes. Bloquer ou ignorer = créer une règle de filtrage.
import type { DCol } from '~/components/DenseTable.vue'
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { canWrite } = useRole()
const hours = ref(24)
const hourItems = [1, 6, 24, 72, 168].map((h) => ({ label: t('tunnel.hours_n', { n: h }), value: h }))
const { data, pending, refresh } = await useFetch<any>('/api/filter/tunnel', { query: computed(() => ({ hours: hours.value })), watch: [hours] })
const acting = ref(false)

const cols = computed<DCol[]>(() => [
  { key: 'severity', label: t('tunnel.severity'), kind: 'badge', trans: 'tunnel.sev' }, { key: 'score', label: t('tunnel.score'), kind: 'num' },
  { key: 'client', label: t('cockpit.client'), kind: 'mono' }, { key: 'domain', label: t('filter.domain'), kind: 'mono' },
  { key: 'queries', label: t('tunnel.queries'), kind: 'num' }, { key: 'subs', label: t('tunnel.subs'), kind: 'num' }, { key: 'avgLen', label: t('tunnel.avg_len'), kind: 'num' },
  { key: 'entropy', label: t('tunnel.entropy'), kind: 'num' },
  { key: 'reasons', label: t('tunnel.reasons'), nosort: true, fmt: (v: string[]) => (v ?? []).map((r) => t(`tunnel.why.${r}`)).join(', ') },
])
async function act(row: any, action: 'block' | 'allow') {
  const key = action === 'block' ? 'tunnel.block_confirm' : 'tunnel.allow_confirm'
  if (!(await ask(t(action === 'block' ? 'tunnel.block' : 'tunnel.allow'), t(key, { domain: row.domain }), action === 'block'))) return
  acting.value = true
  try {
    await api.call('POST', '/filter/rules', { domain: row.domain, action, comment: t('tunnel.rule_comment') })
    toast.add({ title: t('tunnel.rule_done', { domain: row.domain }), color: 'success', icon: 'i-lucide-check' })
    await refresh()
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) } finally { acting.value = false }
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <UAlert color="neutral" variant="subtle" icon="i-lucide-shield-alert" :description="t('tunnel.intro')" />
    <DenseTable :rows="(data?.items ?? []).map((r: any, i: number) => ({ ...r, id: i + 1 }))" :columns="cols" :loading="pending" export-name="dns-tunnels">
      <template #toolbar>
        <USelect v-model="hours" :items="hourItems" class="w-40" :aria-label="t('tunnel.window')" />
        <span class="text-xs text-muted" data-test="tunnel-count">{{ t('tunnel.count', { n: data?.items?.length ?? 0 }) }}</span>
      </template>
      <template #actions="{ row }">
        <UButton v-if="canWrite" size="xs" color="error" variant="ghost" icon="i-lucide-ban" :aria-label="t('tunnel.block')" :disabled="acting" @click="act(row, 'block')" />
        <UButton v-if="canWrite" size="xs" color="neutral" variant="ghost" icon="i-lucide-circle-check" :aria-label="t('tunnel.allow')" :disabled="acting" @click="act(row, 'allow')" />
      </template>
    </DenseTable>
  </div>
</template>
