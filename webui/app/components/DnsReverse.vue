<script setup lang="ts">
// Zones inverses automatiques (0.10.4) : sous-réseaux dont la zone inverse manque, création en un clic (délégation classless RFC 2317 pour les /25 à /32).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const { canWrite } = useRole()
const { data: zones } = await useFetch<any>('/api/dns/zones', { server: false })
const { data: views } = await useFetch<any>('/api/dns/views', { server: false })
const viewId = ref<number | null>(null), model = ref<number | null>(null), items = ref<any[]>([]), err = ref(''), busy = ref('')
const hasViews = computed(() => (views.value?.items ?? []).length > 0)
const viewItems = computed(() => (views.value?.items ?? []).map((v: any) => ({ label: v.name, value: v.id })))
const modelItems = computed(() => (zones.value?.items ?? []).filter((z: any) => z.type === 'primary' && (viewId.value ? z.view_id === viewId.value : true)).map((z: any) => ({ label: z.view ? `${z.name} (${z.view})` : z.name, value: z.id })))
async function load() {
  busy.value = 'load'; err.value = ''
  try { items.value = ((await api.call('GET', `/dns/reverse/missing${viewId.value ? `?view_id=${viewId.value}` : ''}`, undefined, { silent: true })) as any).items }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
watch(viewId, load, { immediate: true })
async function create(s: any) {
  if (!(await ask(t('dnr.confirm_title', { c: s.cidr }), t('dnr.confirm_msg', { z: s.missing.join(', ') }), false))) return
  busy.value = `c${s.id}`; err.value = ''
  try {
    const r = await api.call('POST', '/dns/reverse/create', { subnet_id: s.id, view_id: viewId.value, from_zone_id: model.value }, { silent: true }) as any
    toast.add({ title: t('dnr.done', { z: r.zones, c: r.cnames }), color: 'success', icon: 'i-lucide-check' }); await load()
  } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
</script>

<template>
  <div class="flex flex-col gap-3" data-test="dnr-root">
    <p class="text-sm text-muted">{{ t('dnr.help') }}</p>
    <div class="flex flex-wrap gap-3">
      <USelect v-if="hasViews" v-model="viewId" :items="viewItems" :placeholder="t('dnr.view')" class="min-w-56" data-test="dnr-view" />
      <UFormField :label="t('dnr.model')" :help="t('dnr.model_h')"><USelect v-model="model" :items="modelItems" :placeholder="t('dnr.none')" class="min-w-64" data-test="dnr-model" /></UFormField>
    </div>
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <UAlert v-if="!items.length && busy !== 'load'" color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('dnr.all_ok')" data-test="dnr-ok" />
    <ul class="flex flex-col gap-2" data-test="dnr-list">
      <li v-for="s in items" :key="s.id" class="flex flex-wrap items-center gap-3 rounded-md border border-default p-3 text-sm">
        <span class="font-mono">{{ s.cidr }}</span><span class="text-muted">{{ s.name }}</span>
        <span class="flex-1 font-mono text-xs text-muted">{{ s.missing.join(' · ') }}</span>
        <UButton v-if="canWrite" size="xs" icon="i-lucide-wand-sparkles" :label="t('dnr.create')" :loading="busy === `c${s.id}`" :data-test="`dnr-create-${s.id}`" @click="create(s)" />
      </li>
    </ul>
  </div>
</template>
