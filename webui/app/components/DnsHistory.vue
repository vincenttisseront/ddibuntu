<script setup lang="ts">
// Historique des enregistrements d'une zone (retour arrière d'un changement) et aperçu de la zone avant déploiement (named-checkzone + différences).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const { canWrite } = useRole()
const { data: zones } = await useFetch<any>('/api/dns/zones', { server: false })
const zid = ref<number | null>(null), hist = ref<any[]>([]), prev = ref<any>(null), err = ref(''), busy = ref('')
const primaries = computed(() => (zones.value?.items ?? []).filter((z: any) => z.type === 'primary').map((z: any) => ({ label: z.view ? `${z.name} (${z.view})` : z.name, value: z.id })))
async function load() {
  if (!zid.value) return
  busy.value = 'load'; err.value = ''; prev.value = null
  try {
    hist.value = ((await api.call('GET', `/dns/zones/${zid.value}/history`, undefined, { silent: true })) as any).items
    prev.value = await api.call('GET', `/dns/zones/${zid.value}/preview`, undefined, { silent: true })
  } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
watch(zid, load)
const ACTION = computed<Record<string, string>>(() => ({ create: t('dnh.a_create'), update: t('dnh.a_update'), delete: t('dnh.a_delete'), revert: t('dnh.a_revert') }))
const fmt = (r: any) => (r ? `${r.name} ${r.type} ${r.rdata}${r.ttl ? ` (${r.ttl}s)` : ''}${r.disabled ? ` [${t('dnh.disabled')}]` : ''}` : '')
async function revert(h: any) {
  if (!(await ask(t('dnh.confirm_title'), t('dnh.confirm_msg', { a: ACTION.value[h.action] ?? h.action, r: fmt(h.after ?? h.before) }), false))) return
  busy.value = `r${h.id}`; err.value = ''
  try { await api.call('POST', `/dns/history/${h.id}/revert`, {}, { silent: true }); toast.add({ title: t('dnh.reverted'), color: 'success', icon: 'i-lucide-check' }); await load() }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
</script>

<template>
  <div class="flex flex-col gap-4" data-test="dnh-root">
    <p class="text-sm text-muted">{{ t('dnh.help') }}</p>
    <USelect v-model="zid" :items="primaries" :placeholder="t('dnh.zone')" class="max-w-sm" data-test="dnh-zone" />
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <template v-if="zid && prev">
      <div class="flex flex-col gap-2 rounded-md bg-elevated/50 p-3" data-test="dnh-preview">
        <div class="font-medium text-sm">{{ t('dnh.preview') }}</div>
        <div class="flex flex-wrap gap-2">
          <UBadge v-for="c in prev.checks" :key="c.name" :color="c.ok === null ? 'neutral' : c.ok ? 'success' : 'error'" variant="subtle" :label="`${c.name} : ${c.ok === null ? t('dnh.check_na') : c.ok ? 'OK' : t('dnh.check_ko')}`" />
          <UBadge :color="prev.dirty ? 'warning' : 'neutral'" variant="outline" :label="prev.dirty ? t('dnh.dirty') : t('dnh.clean')" />
        </div>
        <pre v-for="c in prev.checks.filter((x: any) => x.ok === false)" :key="c.name" class="text-xs font-mono text-error whitespace-pre-wrap">{{ c.output }}</pre>
        <p v-if="!prev.deployed" class="text-sm text-muted">{{ t('dnh.not_deployed') }}</p>
        <p v-else-if="!prev.diff.added.length && !prev.diff.removed.length" class="text-sm text-muted" data-test="dnh-nodiff">{{ t('dnh.no_diff') }}</p>
        <div v-else class="font-mono text-xs flex flex-col" data-test="dnh-diff">
          <div v-for="(l, i) in prev.diff.removed" :key="`r${i}`" class="text-error">- {{ l }}</div>
          <div v-for="(l, i) in prev.diff.added" :key="`a${i}`" class="text-success">+ {{ l }}</div>
        </div>
      </div>
      <div class="flex flex-col gap-2">
        <div class="font-medium text-sm">{{ t('dnh.history') }}</div>
        <p v-if="!hist.length" class="text-sm text-muted">{{ t('dnh.empty') }}</p>
        <ul class="flex flex-col gap-2" data-test="dnh-list">
          <li v-for="h in hist" :key="h.id" class="flex flex-wrap items-center gap-3 rounded-md border border-default p-3 text-sm">
            <UBadge color="neutral" variant="subtle" :label="ACTION[h.action] ?? h.action" />
            <div class="flex-1 min-w-64 font-mono text-xs"><div v-if="h.before" class="text-error">- {{ fmt(h.before) }}</div><div v-if="h.after" class="text-success">+ {{ fmt(h.after) }}</div></div>
            <span class="text-muted text-xs">{{ h.username }} · {{ new Date(h.at).toLocaleString() }}</span>
            <UButton v-if="canWrite && h.action !== 'revert'" size="xs" color="neutral" variant="outline" icon="i-lucide-undo-2" :label="t('dnh.revert')" :loading="busy === `r${h.id}`" :data-test="`dnh-revert-${h.id}`" @click="revert(h)" />
          </li>
        </ul>
      </div>
    </template>
  </div>
</template>
