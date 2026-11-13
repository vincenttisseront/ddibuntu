<script setup lang="ts">
// Zones DNS depuis Windows (0.12.3) : 1) création des zones d'après l'inventaire ; 2) transfert (AXFR) du contenu d'une zone depuis le serveur Windows.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { isAdmin } = useRole()
const emit = defineEmits<{ done: [] }>()
const csv = ref(''), name = ref(''), coexist = reactive({ on: false, server: '' }), plan = ref<any>(null), busy = ref(''), err = ref(''), viewId = ref<number | null>(null)
const { data: views } = await useFetch<any>('/api/dns/views', { server: false })
const viewItems = computed(() => (views.value?.items ?? []).map((v: any) => ({ label: v.name, value: v.id })))
const { data: zones, refresh: refreshZones } = await useFetch<any>('/api/dns/zones', { server: false })
const primary = computed(() => (zones.value?.items ?? []).filter((z: any) => z.type === 'primary').map((z: any) => ({ label: z.name + (z.view ? ` (${z.view})` : ''), value: z.id })))
const REASON = computed<Record<string, string>>(() => ({ stub: t('mid.r_stub'), no_masters: t('mid.r_no_masters'), invalid_name: t('mid.r_invalid_name'), duplicate: t('mid.r_duplicate') }))
const ACTION = computed<Record<string, string>>(() => ({ create: t('mid.a_create'), exists: t('mid.a_exists'), skip: t('mid.a_skip') }))
async function pick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]; if (!f) return
  if (f.size > 5 * 1024 * 1024) { err.value = t('err.too_large'); return }
  csv.value = await f.text(); name.value = f.name; await analyse()
}
async function analyse() {
  busy.value = 'plan'; err.value = ''; plan.value = null
  try { plan.value = await api.call('POST', '/migration/zones/preview', { content: csv.value, ...(viewId.value ? { view_id: viewId.value } : {}), ...(coexist.on && coexist.server ? { coexist: coexist.server } : {}) }, { silent: true }) }
  catch (x: any) { err.value = x?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
async function create() {
  if (!(await ask(t('mid.confirm_title'), t('mid.confirm_msg', { n: plan.value.toCreate }), false))) return
  busy.value = 'create'; err.value = ''
  try {
    const r = await api.call('POST', '/migration/zones/commit', { content: csv.value, filename: name.value, ...(viewId.value ? { view_id: viewId.value } : {}), ...(coexist.on && coexist.server ? { coexist: coexist.server } : {}) }, { silent: true })
    toast.add({ title: t('mid.created', { n: r.created }), color: 'success', icon: 'i-lucide-check' }); plan.value = null; csv.value = ''; await refreshZones(); emit('done')
  } catch (x: any) { err.value = x?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
// transfert de zone
const tx = reactive({ server: '', zone_id: 0, mode: 'skip', pre: null as any, err: '' })
async function txPreview() {
  busy.value = 'tx'; tx.err = ''; tx.pre = null
  try { tx.pre = await api.call('POST', '/migration/axfr/preview', { server: tx.server, zone_id: tx.zone_id }, { silent: true }) }
  catch (x: any) { tx.err = x?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
async function txGo() {
  if (!(await ask(t('mid.tx_confirm_title'), t('mid.tx_confirm_msg', { n: tx.pre.new }), false))) return
  busy.value = 'tx'; tx.err = ''
  try { const r = await api.call('POST', '/migration/axfr/commit', { server: tx.server, zone_id: tx.zone_id, mode: tx.mode }, { silent: true }); toast.add({ title: t('mid.tx_done', { n: r.inserted }), color: 'success', icon: 'i-lucide-check' }); tx.pre = null; emit('done') }
  catch (x: any) { tx.err = x?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
// coexistence : zones secondaires dont le maître est le serveur Windows
const { data: co, refresh: refreshCo } = await useFetch<any>('/api/migration/coexist', { server: false })
const checks = reactive<Record<number, any>>({})
async function check(z: any) {
  busy.value = `c${z.id}`; err.value = ''
  try { checks[z.id] = await api.call('POST', '/migration/coexist/check', { zone_id: z.id }, { silent: true }) } catch (x: any) { err.value = x?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
async function promote(z: any) {
  if (!(await ask(t('mid.promote_title', { z: z.name }), t('mid.promote_msg', { z: z.name, m: z.masters[0] }), true))) return
  busy.value = `p${z.id}`; err.value = ''
  try { const r = await api.call('POST', '/migration/coexist/promote', { zone_id: z.id }, { silent: true }); toast.add({ title: t('mid.promoted', { z: z.name, n: r.inserted }), color: 'success', icon: 'i-lucide-check' }); delete checks[z.id]; await refreshCo(); await refreshZones(); emit('done') }
  catch (x: any) { err.value = x?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
watch(primary, (p) => { if (!tx.zone_id && p.length) tx.zone_id = p[0].value }, { immediate: true })
</script>

<template>
  <div class="flex flex-col gap-3">
    <div class="flex flex-col gap-2 rounded-md bg-elevated/50 p-3">
      <span class="text-sm font-medium">{{ t('mid.zones_title') }}</span>
      <p class="text-xs text-muted">{{ t('mid.zones_hint') }}</p>
      <USelect v-if="viewItems.length" v-model="viewId" :items="viewItems" class="w-64" :placeholder="t('dnsv.view')" :aria-label="t('dnsv.view')" @update:model-value="csv && analyse()" />
      <div class="flex flex-wrap items-center gap-3">
        <USwitch v-model="coexist.on" :label="t('mid.coexist')" data-test="mid-coexist" @update:model-value="csv && analyse()" />
        <UInput v-if="coexist.on" v-model="coexist.server" class="w-56 font-mono" placeholder="10.0.0.10" :aria-label="t('mid.tx_server')" data-test="mid-coexist-server" @change="csv && analyse()" />
      </div>
      <p v-if="coexist.on" class="text-xs text-muted">{{ t('mid.coexist_hint') }}</p>
      <input type="file" accept=".csv,text/csv,text/plain" class="block w-full text-sm" :aria-label="t('mid.zones_title')" data-test="mid-file" @change="pick">
      <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
      <template v-if="plan">
        <UAlert v-if="plan.errors.length" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('mid.e_csv')" role="alert" />
        <template v-else>
          <ul class="text-sm flex flex-col gap-1" data-test="mid-plan">
            <li v-for="i in plan.items" :key="i.name" class="flex flex-wrap items-center gap-2">
              <UBadge :color="i.action === 'create' ? 'success' : i.action === 'exists' ? 'neutral' : 'warning'" variant="subtle" :label="ACTION[i.action]" />
              <span class="font-mono">{{ i.name }}</span><UBadge color="neutral" variant="outline" :label="i.type ?? i.winType" />
              <span v-if="i.reason" class="text-muted">{{ REASON[i.reason] }}</span><span v-if="i.signed" class="text-warning">{{ t('mid.signed') }}</span>
            </li>
          </ul>
          <div><UButton icon="i-lucide-folder-plus" :label="t('mid.create', { n: plan.toCreate })" :loading="busy === 'create'" :disabled="!plan.toCreate" data-test="mid-create" @click="create" /></div>
        </template>
      </template>
    </div>
    <div v-if="co?.items?.length" class="flex flex-col gap-2 rounded-md bg-elevated/50 p-3" data-test="mid-co">
      <span class="text-sm font-medium">{{ t('mid.co_title') }}</span>
      <p class="text-xs text-muted">{{ t('mid.co_hint') }}</p>
      <ul class="flex flex-col gap-2 text-sm">
        <li v-for="z in co.items" :key="z.id" class="flex flex-wrap items-center gap-2">
          <span class="font-mono">{{ z.name }}</span><span class="text-muted font-mono">← {{ z.masters.join(', ') }}</span>
          <UBadge v-if="checks[z.id]" :color="checks[z.id].ok ? 'success' : 'error'" variant="subtle" :label="checks[z.id].ok ? t('mid.co_ok', { n: checks[z.id].records }) : t('mid.co_ko')" />
          <span v-if="isAdmin" class="ml-auto flex gap-2">
            <UButton size="xs" color="neutral" variant="outline" icon="i-lucide-plug-zap" :label="t('mid.co_check')" :loading="busy === `c${z.id}`" @click="check(z)" />
            <UButton size="xs" color="warning" variant="soft" icon="i-lucide-crown" :label="t('mid.co_promote')" :loading="busy === `p${z.id}`" @click="promote(z)" />
          </span>
        </li>
      </ul>
    </div>
    <div v-if="isAdmin" class="flex flex-col gap-2 rounded-md bg-elevated/50 p-3">
      <span class="text-sm font-medium">{{ t('mid.tx_title') }}</span>
      <p class="text-xs text-muted">{{ t('mid.tx_hint') }}</p>
      <div class="grid gap-3 md:grid-cols-3">
        <UFormField :label="t('mid.tx_server')"><UInput v-model="tx.server" class="w-full font-mono" placeholder="10.0.0.10" data-test="mid-server" /></UFormField>
        <UFormField :label="t('dns.zone')"><USelect v-model="tx.zone_id" :items="primary" class="w-full" /></UFormField>
        <UFormField :label="t('import.mode')"><USelect v-model="tx.mode" :items="[{ label: t('import.mode_skip'), value: 'skip' }, { label: t('import.mode_replace'), value: 'replace' }]" class="w-full" /></UFormField>
      </div>
      <UAlert v-if="tx.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="tx.err" role="alert" />
      <div class="flex flex-wrap items-center gap-2">
        <UButton color="neutral" variant="outline" icon="i-lucide-search" :label="t('mid.tx_preview')" :loading="busy === 'tx'" :disabled="!tx.server || !tx.zone_id" data-test="mid-tx-preview" @click="txPreview" />
        <template v-if="tx.pre">
          <UBadge color="success" variant="subtle" :label="t('mid.tx_new', { n: tx.pre.new })" /><UBadge color="neutral" variant="outline" :label="t('mid.tx_same', { i: tx.pre.identical, c: tx.pre.conflicts })" />
          <UBadge v-if="tx.pre.adCritical" color="warning" variant="subtle" :label="t('mid.tx_critical', { n: tx.pre.adCritical })" />
          <UButton icon="i-lucide-download" :label="t('mid.tx_go')" :loading="busy === 'tx'" data-test="mid-tx-go" @click="txGo" />
        </template>
      </div>
    </div>
  </div>
</template>
