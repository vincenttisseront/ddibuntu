<script setup lang="ts">
// Adresses fantômes : allouées dans l'IPAM, vues autrefois par une découverte, silencieuses depuis N jours.
// La libération passe par une boîte de dialogue maison ; le serveur revérifie le critère avant de supprimer.
import type { DCol } from '~/components/DenseTable.vue'
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { canWrite } = useRole()
const days = ref(30)
const dayItems = [7, 14, 30, 60, 90, 180, 365].map((d) => ({ label: t('ghost.days_n', { n: d }), value: d }))
const { data, pending, refresh } = await useFetch<any>('/api/ipam/ghosts', { query: computed(() => ({ days: days.value })), watch: [days] })
const selected = ref<number[]>([])
const releasing = ref(false)
watch(data, () => { const ids = new Set((data.value?.items ?? []).map((r: any) => r.id)); selected.value = selected.value.filter((i) => ids.has(i)) })

const cols = computed<DCol[]>(() => [
  { key: 'ip', label: 'IP', kind: 'mono' }, { key: 'cidr', label: t('ipam.network'), kind: 'mono' },
  { key: 'status', label: t('common.status'), kind: 'badge', trans: 'ipam.status' }, { key: 'hostname', label: t('ipam.hostname') }, { key: 'mac', label: 'MAC', kind: 'mono' },
  { key: 'last_seen', label: t('ghost.last_seen'), fmt: (v: string) => (v ? new Date(v).toLocaleString() : '') },
  { key: 'silent_days', label: t('ghost.silent'), kind: 'num' },
])

async function release() {
  const n = selected.value.length
  if (!n) return
  if (!(await ask(t('ghost.release'), t('ghost.release_confirm', { n, d: days.value })))) return
  releasing.value = true
  try {
    const r: any = await api.call('POST', '/ipam/ghosts/release', { ids: selected.value, days: days.value })
    toast.add({ title: t('ghost.released', { n: r.released, s: r.skipped }), color: 'success', icon: 'i-lucide-check' })
    selected.value = []
    await refresh()
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) } finally { releasing.value = false }
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <UAlert color="neutral" variant="subtle" icon="i-lucide-ghost" :description="t('ghost.intro')" />
    <DenseTable v-model:selected="selected" :rows="data?.items ?? []" :columns="cols" :selectable="canWrite" :loading="pending" export-name="ipam-fantomes">
      <template #toolbar>
        <USelect v-model="days" :items="dayItems" class="w-40" :aria-label="t('ghost.silent_for')" />
        <span class="text-xs text-muted" data-test="ghost-count">{{ t('ghost.count', { n: data?.total ?? 0 }) }}<template v-if="data && data.total > data.shown"> · {{ t('ghost.truncated', { n: data.shown }) }}</template></span>
        <UButton v-if="canWrite" icon="i-lucide-trash-2" color="error" size="sm" :label="t('ghost.release_n', { n: selected.length })" :disabled="!selected.length" :loading="releasing" @click="release" />
      </template>
    </DenseTable>
  </div>
</template>
