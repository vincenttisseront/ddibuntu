<script setup lang="ts">
const { t } = useT(); const api = useApi(); const toast = useToast()
const { canWrite, isAdmin } = useRole(); const { ask } = useConfirm()
const tab = useHashTab('cockpit', ['cockpit', 'lists', 'rules', 'test', 'stats', 'settings'])
const tabs = computed(() => [{ label: t('cockpit.title'), value: 'cockpit', icon: 'i-lucide-gauge' }, { label: t('filter.lists'), value: 'lists', icon: 'i-lucide-list-x' }, { label: t('filter.rules'), value: 'rules', icon: 'i-lucide-list-checks' }, { label: t('filter.test'), value: 'test', icon: 'i-lucide-search-check' }, { label: t('filter.stats'), value: 'stats', icon: 'i-lucide-chart-line' }, { label: t('dns.settings'), value: 'settings', icon: 'i-lucide-sliders-horizontal' }])
const CATS = ['adult', 'malware', 'phishing', 'ads', 'tracking', 'gambling', 'social', 'custom']

const listCols = computed(() => [{ key: 'name', label: t('common.name') }, { key: 'category', label: t('filter.category'), kind: 'badge', trans: 'filter.cat' }, { key: 'entries', label: t('filter.entries'), kind: 'num' }, { key: 'enabled', label: t('common.enabled'), kind: 'bool' }, { key: 'updated_at', label: t('filter.updated'), kind: 'date' },
  { key: 'last_error', label: t('filter.error'), fmt: (v: string) => (v ? t(`err.${v}`) : '') }])
const listFields = computed(() => [
  { key: 'name', label: t('common.name'), type: 'text', required: true }, { key: 'category', label: t('filter.category'), type: 'select', required: true, default: 'ads', options: CATS.map((v) => ({ label: t(`filter.cat.${v}`), value: v })) },
  { key: 'source_url', label: t('filter.source_url'), type: 'text', placeholder: 'https://…', hint: t('filter.source_hint') },
  { key: 'format', label: t('filter.format'), type: 'select', default: 'domains', options: ['domains', 'hosts', 'adblock'].map((v) => ({ label: t(`filter.fmt.${v}`), value: v })) }, { key: 'enabled', label: t('common.enabled'), type: 'switch', default: true },
] as any[])
const lists = ref<any>(null)
const importOpen = ref(false), importId = ref(0), importText = ref(''), importErr = ref('')
async function remoteUpdate(row: any) {
  try { const r: any = await api.call('POST', `/filter/lists/${row.id}/update`); toast.add({ title: t('filter.updated_n', { n: r.entries }), color: 'success', icon: 'i-lucide-check' }) }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) }
  await lists.value?.refresh()
}
function openImport(row: any) { importId.value = row.id; importText.value = ''; importErr.value = ''; importOpen.value = true }
async function doImport() {
  importErr.value = ''
  try { const r: any = await api.call('POST', `/filter/lists/${importId.value}/import`, { content: importText.value }); toast.add({ title: t('filter.updated_n', { n: r.entries }), color: 'success', icon: 'i-lucide-check' }); importOpen.value = false; await lists.value?.refresh() }
  catch (e: any) { importErr.value = e.info?.message ?? t('err.internal') }
}
async function pickFile(e: Event) { const f = (e.target as HTMLInputElement).files?.[0]; if (f) importText.value = await f.text() }

const ruleCols = computed(() => [{ key: 'domain', label: t('filter.domain'), kind: 'mono' }, { key: 'action', label: t('filter.action'), kind: 'badge', trans: 'filter.act' }, { key: 'comment', label: t('common.description') }])
const ruleFields = computed(() => [{ key: 'domain', label: t('filter.domain'), type: 'text', required: true, mono: true, placeholder: 'ads.example.com' }, { key: 'action', label: t('filter.action'), type: 'select', default: 'block', options: ['block', 'allow'].map((v) => ({ label: t(`filter.act.${v}`), value: v })), hint: t('filter.rule_hint') }, { key: 'comment', label: t('common.description'), type: 'text' }] as any[])

// Test d'un domaine
const dom = ref(''), verdict = ref<any>(null), vErr = ref('')
async function check() { vErr.value = ''; verdict.value = null; try { verdict.value = await api.call('GET', `/filter/check?domain=${encodeURIComponent(dom.value)}`) } catch (e: any) { vErr.value = e.info?.message ?? t('err.internal') } }

// Statistiques
const range = ref('1h')
const rangeOptions = ['15m', '1h', '6h', '24h'].map((v) => ({ label: v, value: v }))
const { data: stats, refresh: refreshStats } = await useFetch<any>(() => `/api/filter/stats?range=${range.value}`, { watch: [range] })
const binMs = computed(() => ({ '1 minute': 60000, '5 minutes': 300000, '15 minutes': 900000 } as Record<string, number>)[stats.value?.bin ?? '1 minute'] ?? 60000)
const now = ref(Date.now())
onMounted(() => { now.value = Date.now() })
const span = computed(() => ({ '15m': 15, '1h': 60, '6h': 360, '24h': 1440 } as Record<string, number>)[range.value]! * 60000)
const serie = (kind: string) => (stats.value?.series ?? []).filter((r: any) => r.kind === kind).map((r: any) => ({ t: new Date(r.t).getTime(), v: Number(r.n) }))
const cats = computed(() => (stats.value?.byCategory ?? []).map((c: any) => ({ label: c.category === 'rule' ? t('filter.cat.rule') : t(`filter.cat.${c.category}`), value: Number(c.n) })))
const logText = ref(''), logMsg = ref('')
async function ingest() { try { const r: any = await api.call('POST', '/filter/ingest-log', { content: logText.value }); logMsg.value = t('filter.ingested', { n: r.events }); logText.value = ''; await refreshStats() } catch (e: any) { logMsg.value = e.info?.message ?? t('err.internal') } }

// Paramètres RPZ
const { data: fs, refresh: refreshFs } = await useFetch<any>('/api/filter/settings')
const sf = reactive<any>({ rpzEnabled: false, rpzAction: 'nxdomain', sinkhole4: '0.0.0.0', sinkhole6: '::' })
watch(fs, (s) => { if (s) Object.assign(sf, s) }, { immediate: true })
const sErr = ref('')
async function saveSettings() { sErr.value = ''; try { await api.call('PUT', '/filter/settings', { rpzEnabled: sf.rpzEnabled, rpzAction: sf.rpzAction, sinkhole4: sf.sinkhole4, sinkhole6: sf.sinkhole6 }); toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await refreshFs() } catch (e: any) { sErr.value = e.info?.message ?? t('err.internal') } }
// Cockpit
const dash = ref<any>(null), qlog = ref<any>(null)
const bulkOpen = ref(false), bulkText = ref(''), bulkAction = ref('allow'), bulkRes = ref<any>(null), bulkErr = ref('')
async function doBulk() {
  bulkErr.value = ''; bulkRes.value = null
  try { bulkRes.value = await api.call('POST', '/filter/rules/bulk', { domains: bulkText.value.split(/[\s,;]+/).filter(Boolean), action: bulkAction.value }); bulkText.value = '' } catch (e: any) { bulkErr.value = e.info?.message ?? t('err.internal') }
}
const { data: ck } = await useFetch<any>('/api/cockpit/settings')
const cf = reactive<any>({ retentionDays: 7, anonymize: 'none', autoDeploy: false })
watch(ck, (s) => { if (s) Object.assign(cf, { retentionDays: s.retentionDays, anonymize: s.anonymize, autoDeploy: s.autoDeploy }) }, { immediate: true })
async function saveCk() {
  try { await api.call('PUT', '/cockpit/settings', { retentionDays: Number(cf.retentionDays), anonymize: cf.anonymize, autoDeploy: cf.autoDeploy }); toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }) }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) }
}
async function purge() {
  if (!(await ask(t('cockpit.purge'), t('cockpit.purge_confirm'), true))) return
  try { const r: any = await api.call('POST', '/cockpit/purge', {}); toast.add({ title: t('cockpit.purged', { n: r.deleted }), color: 'success', icon: 'i-lucide-check' }) } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) }
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <UTabs v-model="tab" :items="tabs" :content="false" :aria-label="t('nav.filtering')" />
    <div v-if="tab === 'rules' && canWrite" class="flex justify-end"><UButton icon="i-lucide-list-plus" color="neutral" variant="outline" :label="t('cockpit.bulk')" @click="bulkOpen = true; bulkRes = null" /></div>
    <div v-if="tab === 'cockpit'" class="flex flex-col gap-4"><CockpitDashboard ref="dash" @changed="qlog?.load()" /><QueryLog ref="qlog" @changed="dash?.refresh()" /></div>
    <ResourceTable v-else-if="tab === 'lists'" ref="lists" endpoint="/filter/lists" :columns="listCols" :fields="listFields" :can-write="canWrite" create-url="/filter/lists" :update-url="(r: any) => `/filter/lists/${r.id}`" :delete-url="(r: any) => `/filter/lists/${r.id}`" :delete-name="(r: any) => r.name" :create-label="t('filter.add_list')">
      <template #actions="{ row }">
        <UButton v-if="canWrite && row.source_url" icon="i-lucide-cloud-download" size="xs" color="neutral" variant="ghost" :aria-label="t('filter.update')" @click="remoteUpdate(row)" />
        <UButton v-if="canWrite" icon="i-lucide-upload" size="xs" color="neutral" variant="ghost" :aria-label="t('filter.import')" @click="openImport(row)" />
      </template>
    </ResourceTable>
    <ResourceTable v-else-if="tab === 'rules'" endpoint="/filter/rules" :columns="ruleCols" :fields="ruleFields" :can-write="canWrite" create-url="/filter/rules" :delete-url="(r: any) => `/filter/rules/${r.id}`" :delete-name="(r: any) => r.domain" :create-label="t('filter.add_rule')" />
    <UCard v-else-if="tab === 'test'" class="max-w-2xl">
      <form class="flex gap-2 items-end" @submit.prevent="check"><UFormField :label="t('filter.domain')" class="flex-1"><UInput v-model="dom" class="w-full font-mono" placeholder="ads.example.com" /></UFormField><UButton type="submit" :label="t('filter.check')" :disabled="!dom" /></form>
      <UAlert v-if="vErr" class="mt-3" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="vErr" />
      <div v-if="verdict" class="mt-4" aria-live="polite">
        <UAlert :color="verdict.blocked ? 'error' : 'success'" variant="subtle" :icon="verdict.blocked ? 'i-lucide-ban' : 'i-lucide-check'" :title="verdict.blocked ? t('filter.blocked') : t('filter.not_blocked')" :description="t(`filter.reason.${verdict.reason}`)" />
        <ul v-if="verdict.matches.length" class="mt-3 text-sm flex flex-col gap-1"><li v-for="(m, i) in verdict.matches" :key="i" class="font-mono text-xs">{{ m.domain }} · {{ t(`filter.match.${m.kind}`) }}<template v-if="m.source"> · {{ m.source }} ({{ t(`filter.cat.${m.category}`) }})</template></li></ul>
      </div>
    </UCard>
    <div v-else-if="tab === 'stats'" class="flex flex-col gap-3">
      <div class="flex gap-2 items-center"><USelect v-model="range" :items="rangeOptions" class="w-28" :aria-label="t('filter.range')" /><span class="text-xs text-muted">{{ t('filter.stats_hint') }}</span></div>
      <div class="grid gap-4 lg:grid-cols-3">
        <UCard class="lg:col-span-2"><template #header><span class="font-medium">{{ t('filter.queries') }}</span></template>
          <LineChart :series="[{ name: t('filter.q_total'), color: '#3b82f6', points: serie('query') }, { name: t('filter.q_blocked'), color: '#f59e0b', points: serie('blocked') }]" :bin-ms="binMs" :from="now - span" :to="now" :label="t('filter.queries')" /></UCard>
        <UCard><template #header><span class="font-medium">{{ t('filter.by_category') }}</span></template>
          <BarChart v-if="cats.length" :items="cats" :label="t('filter.by_category')" /><p v-else class="text-sm text-muted">{{ t('common.empty') }}</p></UCard>
      </div>
      <UCard v-if="canWrite"><template #header><span class="font-medium">{{ t('filter.ingest') }}</span></template>
        <div class="flex flex-col gap-2"><UTextarea v-model="logText" :rows="3" class="w-full font-mono" :placeholder="t('filter.ingest_ph')" /><div class="flex items-center gap-2"><UButton icon="i-lucide-upload" :label="t('filter.ingest_do')" :disabled="!logText" @click="ingest" /><span class="text-sm text-muted" aria-live="polite">{{ logMsg }}</span></div></div></UCard>
    </div>
    <div v-else class="flex flex-col gap-4">
    <UCard class="max-w-2xl">
      <form class="grid gap-3 md:grid-cols-2" @submit.prevent="saveSettings">
        <UAlert v-if="sErr" class="md:col-span-2" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="sErr" />
        <UFormField :label="t('filter.rpz_enabled')" :help="t('filter.rpz_hint')" class="md:col-span-2"><USwitch v-model="sf.rpzEnabled" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('filter.rpz_action')" class="md:col-span-2"><USelect v-model="sf.rpzAction" :items="['nxdomain', 'nodata', 'sinkhole'].map((v) => ({ label: t(`filter.rpz.${v}`), value: v }))" class="w-full" :disabled="!isAdmin" /></UFormField>
        <template v-if="sf.rpzAction === 'sinkhole'"><UFormField label="IPv4"><UInput v-model="sf.sinkhole4" class="w-full font-mono" :disabled="!isAdmin" /></UFormField><UFormField label="IPv6"><UInput v-model="sf.sinkhole6" class="w-full font-mono" :disabled="!isAdmin" /></UFormField></template>
        <p class="md:col-span-2 text-xs text-muted">{{ t('filter.rpz_apply') }}</p>
        <div class="md:col-span-2 flex justify-end"><UButton v-if="isAdmin" type="submit" :label="t('common.save')" /></div>
      </form>
    </UCard>
    <UCard class="max-w-2xl"><template #header><span class="font-medium">{{ t('cockpit.settings') }}</span></template>
      <form class="grid gap-3 md:grid-cols-2" @submit.prevent="saveCk">
        <UFormField :label="t('cockpit.retention')" :help="t('cockpit.retention_hint')"><UInput v-model.number="cf.retentionDays" type="number" min="0" max="90" class="w-full" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('cockpit.anonymize')" :help="t('cockpit.anonymize_hint')"><USelect v-model="cf.anonymize" :items="[{ label: t('cockpit.anon_none'), value: 'none' }, { label: t('cockpit.anon_mask'), value: 'mask' }]" class="w-full" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('cockpit.autodeploy')" :help="t('cockpit.autodeploy_hint')" class="md:col-span-2"><USwitch v-model="cf.autoDeploy" :disabled="!isAdmin" /></UFormField>
        <div class="md:col-span-2 flex justify-between"><UButton v-if="isAdmin" color="error" variant="outline" icon="i-lucide-eraser" :label="t('cockpit.purge')" @click="purge" /><UButton v-if="isAdmin" type="submit" :label="t('common.save')" /></div>
      </form></UCard>
    </div>
    <UModal v-model:open="bulkOpen" :title="t('cockpit.bulk')" :description="t('cockpit.bulk_desc')">
      <template #body><div class="flex flex-col gap-3">
        <UAlert v-if="bulkErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="bulkErr" />
        <UAlert v-if="bulkRes" color="success" variant="subtle" icon="i-lucide-check" :title="t('cockpit.bulk_done', { a: bulkRes.added, r: bulkRes.replaced, e: bulkRes.existing, i: bulkRes.invalid })" />
        <USelect v-model="bulkAction" :items="[{ label: t('filter.act.allow'), value: 'allow' }, { label: t('filter.act.block'), value: 'block' }]" :aria-label="t('filter.action')" />
        <UTextarea v-model="bulkText" :rows="8" class="w-full font-mono" placeholder="ads.example.com&#10;tracker.example.org" :aria-label="t('cockpit.bulk')" />
        <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.close')" @click="bulkOpen = false" /><UButton :label="t('common.add')" :disabled="!bulkText.trim()" @click="doBulk" /></div></div></template>
    </UModal>
    <UModal v-model:open="importOpen" :title="t('filter.import')" :description="t('filter.import_desc')">
      <template #body><div class="flex flex-col gap-3">
        <UAlert v-if="importErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="importErr" />
        <input type="file" accept=".txt,.list,.hosts,text/plain" class="text-sm" :aria-label="t('import.file')" @change="pickFile">
        <UTextarea v-model="importText" :rows="8" class="w-full font-mono" />
        <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="importOpen = false" /><UButton :label="t('filter.import')" :disabled="!importText" @click="doImport" /></div></div></template>
    </UModal>
  </div>
</template>
