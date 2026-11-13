<script setup lang="ts">
// Journal des requêtes DNS : filtres, affichage en direct, « autoriser » / « bloquer » en un clic. Les nouveautés arrivent par after_id.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { canWrite } = useRole()
const emit = defineEmits<{ changed: [] }>()
const filter = useState<{ client: string }>('cockpit-filter', () => ({ client: '' }))
const f = reactive({ status: '', client: '', domain: '', qtype: '' })
const items = ref<any[]>([]), next = ref<number | null>(null), live = ref(true), busy = ref(false), error = ref('')
const qs = (extra: Record<string, string | number> = {}) => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries({ ...f, ...extra })) if (v !== '' && v !== undefined) p.set(k, String(v))
  return p.toString()
}
async function load(more = false) {
  busy.value = true; error.value = ''
  try {
    const r: any = await api.call('GET', `/cockpit/queries?${qs({ limit: 100, ...(more && next.value ? { before_id: next.value } : {}) })}`, undefined, { silent: true })
    items.value = more ? [...items.value, ...r.items] : r.items; next.value = r.nextBefore
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function poll() {
  if (!live.value || busy.value || !items.value.length || document.hidden) return
  try {
    const r: any = await api.call('GET', `/cockpit/queries?${qs({ limit: 100, after_id: items.value[0].id })}`, undefined, { silent: true })
    if (r.items.length) items.value = [...r.items, ...items.value].slice(0, 1000)
  } catch { /* nouvelle tentative au prochain passage */ }
}
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => { void load(); timer = setInterval(poll, 3000) })
onBeforeUnmount(() => clearInterval(timer))
let deb: ReturnType<typeof setTimeout> | undefined
watch(f, () => { clearTimeout(deb); deb = setTimeout(() => load(), 350) })
watch(() => filter.value.client, (c) => { f.client = c })
const time = (s: string) => new Date(s).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const why = (r: any) => (r.reason?.startsWith('list:') ? t('cockpit.reason.list', { name: r.reason.slice(5) }) : r.reason ? t(`cockpit.reason.${r.reason}`) : '')
async function act(r: any, action: 'allow' | 'block') {
  try { await api.call('POST', '/cockpit/action', { domain: r.domain, action }); toast.add({ title: t(action === 'allow' ? 'cockpit.allowed_done' : 'cockpit.blocked_done', { d: r.domain }), color: 'success', icon: 'i-lucide-check' }); emit('changed') }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) }
}
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex flex-wrap items-end gap-2">
        <span class="font-medium me-2">{{ t('cockpit.log') }}</span>
        <USelect v-model="f.status" :items="[{ label: t('cockpit.all'), value: '' }, { label: t('cockpit.s_allowed'), value: 'allowed' }, { label: t('cockpit.s_blocked'), value: 'blocked' }]" :aria-label="t('cockpit.status')" class="w-36" />
        <UInput v-model="f.client" :placeholder="t('cockpit.client')" :aria-label="t('cockpit.client')" class="w-36 font-mono" />
        <UInput v-model="f.domain" :placeholder="t('cockpit.domain')" :aria-label="t('cockpit.domain')" class="w-48 font-mono" icon="i-lucide-search" />
        <UInput v-model="f.qtype" :placeholder="t('cockpit.type')" :aria-label="t('cockpit.type')" class="w-24 font-mono" />
        <div class="flex-1" />
        <USwitch v-model="live" :label="t('cockpit.live')" />
        <UButton color="neutral" variant="outline" icon="i-lucide-refresh-cw" :aria-label="t('common.refresh')" :loading="busy" @click="load()" />
      </div>
    </template>
    <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" class="mb-2" />
    <p v-if="!items.length && !busy" class="text-sm text-muted">{{ t('cockpit.empty') }}</p>
    <div v-else class="overflow-auto max-h-[28rem]">
      <table class="w-full text-sm">
        <caption class="sr-only">{{ t('cockpit.log') }}</caption>
        <thead class="sticky top-0 bg-default"><tr class="text-start text-muted"><th scope="col" class="text-start p-1">{{ t('common.date') }}</th><th scope="col" class="text-start p-1">{{ t('cockpit.client') }}</th><th scope="col" class="text-start p-1">{{ t('cockpit.domain') }}</th><th scope="col" class="p-1">{{ t('cockpit.type') }}</th><th scope="col" class="text-start p-1">{{ t('cockpit.status') }}</th><th scope="col" class="text-start p-1">{{ t('cockpit.why') }}</th><th v-if="canWrite" scope="col" class="p-1"><span class="sr-only">{{ t('common.actions') }}</span></th></tr></thead>
        <tbody>
          <tr v-for="r in items" :key="r.id" class="border-t border-default">
            <td class="p-1 num whitespace-nowrap">{{ time(r.at) }}</td><td class="p-1 font-mono">{{ r.client }}</td><td class="p-1 font-mono break-all">{{ r.domain }}</td><td class="p-1 text-center font-mono">{{ r.qtype }}</td>
            <td class="p-1"><UBadge :color="r.status === 'blocked' ? 'error' : 'success'" variant="subtle" :label="t(`cockpit.s_${r.status}`)" /></td>
            <td class="p-1 text-muted">{{ why(r) }}</td>
            <td v-if="canWrite" class="p-1 text-end whitespace-nowrap">
              <UButton v-if="r.status === 'blocked'" size="xs" color="success" variant="outline" icon="i-lucide-check" :label="t('cockpit.allow')" @click="act(r, 'allow')" />
              <UButton v-else size="xs" color="error" variant="outline" icon="i-lucide-ban" :label="t('cockpit.block')" @click="act(r, 'block')" />
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="next" class="flex justify-center py-2"><UButton color="neutral" variant="outline" :loading="busy" :label="t('cockpit.more')" @click="load(true)" /></div>
    </div>
  </UCard>
</template>
