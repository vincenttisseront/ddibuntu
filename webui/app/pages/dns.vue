<script setup lang="ts">
const { t } = useT(); const api = useApi(); const toast = useToast()
const { canWrite, isAdmin } = useRole()
const tab = useHashTab('zones', ['zones', 'views', 'records', 'health', 'settings', 'deploy'])
const tabs = computed(() => [{ label: t('dns.zones'), value: 'zones', icon: 'i-lucide-folder-tree' }, { label: t('dnsv.title'), value: 'views', icon: 'i-lucide-split' }, { label: t('dns.records'), value: 'records', icon: 'i-lucide-file-text' }, { label: t('dnshealth.title'), value: 'health', icon: 'i-lucide-heart-pulse' }, { label: t('dns.settings'), value: 'settings', icon: 'i-lucide-sliders-horizontal' }, { label: t('apply.title'), value: 'deploy', icon: 'i-lucide-rocket' }])
const { data: zones, refresh: refreshZones } = await useFetch<any>('/api/dns/zones')
const { data: types } = await useFetch<any>('/api/dns/types')
const { data: viewList, refresh: refreshViews } = await useFetch<any>('/api/dns/views')
const viewItems = computed<any[]>(() => viewList.value?.items ?? [])
const hasViews = computed(() => viewItems.value.length > 0)
const looseZones = computed(() => (zones.value?.items ?? []).filter((z: any) => !z.view_id).length)
const zlabel = (z: any) => (z.view ? `${z.name} · ${z.view}` : z.name)
const zoneKey = ref(0)
async function viewsChanged() { await Promise.all([refreshViews(), refreshZones()]); zoneKey.value++ }
const primary = computed(() => (zones.value?.items ?? []).filter((z: any) => z.type === 'primary').map((z: any) => ({ label: zlabel(z), value: z.id })))
const zoneFilter = ref(0), typeFilter = ref('')
useQueryId('zone', (id) => { zoneFilter.value = id })
const zoneFilterOptions = computed(() => [{ label: t('common.all'), value: 0 }, ...(zones.value?.items ?? []).map((z: any) => ({ label: zlabel(z), value: z.id }))])
const typeOptions = computed(() => (types.value?.items ?? []).map((v: string) => ({ label: v, value: v })))
const typeFilterOptions = computed(() => [{ label: t('common.all'), value: '' }, ...typeOptions.value])

const zoneCols = computed(() => [
  { key: 'name', label: t('common.name'), kind: 'mono' }, ...(hasViews.value ? [{ key: 'view', label: t('dnsv.view'), kind: 'mono' }] : []), { key: 'type', label: t('common.type'), kind: 'badge', trans: 'dns.ztype' }, { key: 'records', label: t('dns.records'), kind: 'num' },
  { key: 'serial', label: 'SOA', kind: 'mono' }, { key: 'dirty', label: t('dns.pending'), kind: 'bool' }, { key: 'ad_integrated', label: 'AD', kind: 'bool' }, { key: 'disabled', label: t('common.disabled'), kind: 'bool' },
])
const zoneFields = computed(() => [
  ...(hasViews.value ? [{ key: 'view_id', label: t('dnsv.view'), type: 'select', required: true, default: viewItems.value[0]?.id, hint: t('dnsv.zone_hint'), options: viewItems.value.map((v: any) => ({ label: v.name, value: v.id })) }] : []),
  { key: 'name', label: t('dns.zone_name'), type: 'text', required: true, mono: true, placeholder: 'corp.example.com' },
  { key: 'type', label: t('common.type'), type: 'select', required: true, default: 'primary', options: ['primary', 'secondary', 'forward'].map((v) => ({ label: t(`dns.ztype.${v}`), value: v })) },
  { key: 'masters', label: t('dns.masters'), type: 'list', hint: t('dns.masters_hint') }, { key: 'forwarders', label: t('dns.forwarders'), type: 'list', hint: t('dns.forwarders_hint') },
  { key: 'allow_transfer', label: t('dns.allow_transfer'), type: 'list', hint: t('common.list_hint') },
  { key: 'ddns_enabled', label: t('dns.ddns'), type: 'switch' },
  { key: 'ddns_secure', label: t('dns.ddns_secure'), type: 'select', default: 'none', hint: t('dns.ddns_secure_hint'), options: ['none', 'ms-self', 'krb5-self', 'both'].map((v) => ({ label: t(`dns.secure.${v}`), value: v })) },
  { key: 'ad_integrated', label: t('dns.ad_integrated'), type: 'switch' }, { key: 'disabled', label: t('common.disabled'), type: 'switch' },
  { key: 'soa_mname', label: t('dns.soa_mname'), type: 'text', placeholder: 'ns1.corp.example.com.' }, { key: 'soa_rname', label: t('dns.soa_rname'), type: 'text', placeholder: 'hostmaster.corp.example.com.' },
  { key: 'soa_refresh', label: 'SOA refresh', type: 'number', default: 3600 }, { key: 'soa_retry', label: 'SOA retry', type: 'number', default: 600 }, { key: 'soa_expire', label: 'SOA expire', type: 'number', default: 1209600 },
  { key: 'soa_minimum', label: 'SOA minimum', type: 'number', default: 3600 }, { key: 'default_ttl', label: t('dns.default_ttl'), type: 'number', default: 3600 }, { key: 'comment', label: t('common.description'), type: 'text' },
] as any[])
const exportOpen = ref(false), exported = ref<any>(null)
async function exportZone(z: any) { exported.value = await api.call('GET', `/dns/zones/${z.id}/export`); exportOpen.value = true }
const copyOpen = ref(false), copyZone = ref<any>(null), copyTo = ref(0), copyBusy = ref(false), copyErr = ref('')
const copyTargets = computed(() => viewItems.value.filter((v: any) => v.id !== copyZone.value?.view_id).map((v: any) => ({ label: v.name, value: v.id })))
function openCopy(z: any) { copyZone.value = z; copyErr.value = ''; copyTo.value = viewItems.value.find((v: any) => v.id !== z.view_id)?.id ?? 0; copyOpen.value = true }
async function doCopy() {
  copyBusy.value = true; copyErr.value = ''
  try { const r = await api.call<any>('POST', `/dns/zones/${copyZone.value.id}/copy`, { view_id: copyTo.value }); copyOpen.value = false
    toast.add({ title: t('dnsv.copied', { n: r.records }), color: 'success', icon: 'i-lucide-check' }); await viewsChanged() } catch (e: any) { copyErr.value = e.info?.message ?? t('err.internal') } finally { copyBusy.value = false }
}
function showRecords(z: any) { zoneFilter.value = z.id; tab.value = 'records' }

const recCols = computed(() => [
  { key: 'zone', label: t('dns.zone'), kind: 'mono' }, ...(hasViews.value ? [{ key: 'view', label: t('dnsv.view'), kind: 'mono' }] : []), { key: 'name', label: t('common.name'), kind: 'mono' }, { key: 'type', label: t('common.type'), kind: 'badge' }, { key: 'ttl', label: 'TTL', kind: 'num' },
  { key: 'rdata', label: t('dns.rdata'), kind: 'mono' }, { key: 'protected', label: t('dns.protected'), kind: 'bool' }, { key: 'dynamic', label: t('leasedns.col'), kind: 'bool' }, { key: 'disabled', label: t('common.disabled'), kind: 'bool' },
])
const recFields = computed(() => [
  { key: 'zone_id', label: t('dns.zone'), type: 'select', required: true, options: primary.value, default: zoneFilter.value || primary.value[0]?.value },
  { key: 'name', label: t('common.name'), type: 'text', required: true, mono: true, placeholder: '@  ·  www  ·  _sip._tcp', hint: t('dns.name_hint') },
  { key: 'type', label: t('common.type'), type: 'select', required: true, options: typeOptions.value, default: 'A' },
  { key: 'rdata', label: t('dns.rdata'), type: 'textarea', required: true, mono: true, rows: 2, hint: (s: any) => t(`dns.hint.${s.type}`) },
  { key: 'ttl', label: 'TTL', type: 'number', hint: t('dns.ttl_hint') }, { key: 'comment', label: t('common.description'), type: 'text' }, { key: 'disabled', label: t('common.disabled'), type: 'switch' },
] as any[])
const recQuery = computed(() => ({ ...(zoneFilter.value ? { zone_id: zoneFilter.value } : {}), ...(typeFilter.value ? { type: typeFilter.value } : {}) }))

// Paramètres globaux
const { data: settings, refresh: refreshSettings } = await useFetch<any>('/api/dns/settings')
const sf = reactive<any>({})
const lists = ['listenOn', 'allowRecursion', 'allowQuery', 'forwarders']
watch(settings, (s) => { if (s) { for (const k of lists) sf[k] = (s[k] ?? []).join(', '); sf.dnssecValidation = s.dnssecValidation; sf.queryLog = s.queryLog
  sf.rrlEnabled = !!s.rrlEnabled; sf.rrlResponsesPerSecond = s.rrlResponsesPerSecond ?? 20; sf.rrlWindow = s.rrlWindow ?? 15; sf.rrlSlip = s.rrlSlip ?? 2; sf.rrlLogOnly = s.rrlLogOnly !== false; sf.rrlExempt = (s.rrlExempt ?? []).join(', ') } }, { immediate: true })
const sErr = ref('')
async function saveSettings() {
  sErr.value = ''
  const split = (v: string) => String(v ?? '').split(/[,\s]+/).filter(Boolean)
  try {
    await api.call('PUT', '/dns/settings', { ...settings.value, listenOn: split(sf.listenOn), allowRecursion: split(sf.allowRecursion), allowQuery: split(sf.allowQuery), forwarders: split(sf.forwarders), dnssecValidation: sf.dnssecValidation, queryLog: sf.queryLog,
      rrlEnabled: !!sf.rrlEnabled, rrlResponsesPerSecond: Number(sf.rrlResponsesPerSecond), rrlWindow: Number(sf.rrlWindow), rrlSlip: Number(sf.rrlSlip), rrlLogOnly: !!sf.rrlLogOnly, rrlExempt: split(sf.rrlExempt) })
    toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await refreshSettings()
  } catch (e: any) { sErr.value = e.info?.message ?? t('err.internal') }
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <UTabs v-model="tab" :items="tabs" :content="false" :aria-label="t('nav.dns')" />
    <ResourceTable v-if="tab === 'zones'" :key="zoneKey" endpoint="/dns/zones" :columns="zoneCols" :fields="zoneFields" :can-write="canWrite" create-url="/dns/zones" :update-url="(r: any) => `/dns/zones/${r.id}`" :delete-url="(r: any) => `/dns/zones/${r.id}?force=1`" :delete-name="(r: any) => r.name" :create-label="t('dns.add_zone')" @changed="refreshZones">
      <template #actions="{ row }">
        <UButton v-if="row.type === 'primary'" icon="i-lucide-file-text" size="xs" color="neutral" variant="ghost" :aria-label="t('dns.records')" @click="showRecords(row)" />
        <UButton v-if="hasViews && row.type !== 'forward' && canWrite && viewItems.length > 1" icon="i-lucide-copy" size="xs" color="neutral" variant="ghost" :aria-label="t('dnsv.copy')" @click="openCopy(row)" />
        <UButton v-if="row.type === 'primary'" icon="i-lucide-file-down" size="xs" color="neutral" variant="ghost" :aria-label="t('dns.export')" @click="exportZone(row)" />
      </template>
    </ResourceTable>
    <DnsViews v-else-if="tab === 'views'" :loose-zones="looseZones" @changed="viewsChanged" />
    <div v-else-if="tab === 'records'" class="flex flex-col gap-3">
      <div class="flex gap-2 flex-wrap"><USelect v-model="zoneFilter" :items="zoneFilterOptions" class="w-64" :aria-label="t('dns.zone')" /><USelect v-model="typeFilter" :items="typeFilterOptions" class="w-36" :aria-label="t('common.type')" /></div>
      <ResourceTable :key="`${zoneFilter}-${typeFilter}`" endpoint="/dns/records" :query="recQuery" :columns="recCols" :fields="recFields" :can-write="canWrite" create-url="/dns/records" :update-url="(r: any) => `/dns/records/${r.id}`" :delete-url="(r: any) => `/dns/records/${r.id}`" :delete-name="(r: any) => `${r.name} ${r.type}`" :create-label="t('dns.add_record')" searchable @changed="refreshZones" />
    </div>
    <DnsHealth v-else-if="tab === 'health'" />
    <div v-else-if="tab === 'settings'" class="flex flex-col gap-4 max-w-3xl">
    <UCard>
      <form class="grid gap-3 md:grid-cols-2" @submit.prevent="saveSettings">
        <UAlert v-if="sErr" class="md:col-span-2" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="sErr" />
        <UFormField :label="t('dns.forwarders')" :help="t('dns.global_forwarders_hint')"><UInput v-model="sf.forwarders" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dns.listen_on')" :help="t('dns.listen_hint')"><UInput v-model="sf.listenOn" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dns.allow_recursion')" :help="t('common.list_hint')"><UInput v-model="sf.allowRecursion" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dns.allow_query')" :help="t('dns.allow_query_hint')"><UInput v-model="sf.allowQuery" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dns.dnssec')"><USelect v-model="sf.dnssecValidation" :items="[{ label: t('dns.dnssec_auto'), value: 'auto' }, { label: t('dns.dnssec_off'), value: 'no' }]" class="w-full" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dns.query_log')" :help="t('dns.query_log_hint')"><USwitch v-model="sf.queryLog" :disabled="!isAdmin" /></UFormField>
        <div class="md:col-span-2 border-t border-default pt-3">
          <div class="flex items-center gap-3"><USwitch v-model="sf.rrlEnabled" :disabled="!isAdmin" :aria-label="t('dns.rrl')" /><span class="font-medium">{{ t('dns.rrl') }}</span></div>
          <p class="text-sm text-muted mt-1">{{ t('dns.rrl_hint') }}</p>
        </div>
        <template v-if="sf.rrlEnabled">
          <UFormField :label="t('dns.rrl_rps')" :help="t('dns.rrl_rps_hint')"><UInput v-model="sf.rrlResponsesPerSecond" type="number" min="1" max="1000" class="w-full" :disabled="!isAdmin" /></UFormField>
          <UFormField :label="t('dns.rrl_window')" :help="t('dns.rrl_window_hint')"><UInput v-model="sf.rrlWindow" type="number" min="5" max="3600" class="w-full" :disabled="!isAdmin" /></UFormField>
          <UFormField :label="t('dns.rrl_slip')" :help="t('dns.rrl_slip_hint')"><UInput v-model="sf.rrlSlip" type="number" min="0" max="10" class="w-full" :disabled="!isAdmin" /></UFormField>
          <UFormField :label="t('dns.rrl_logonly')" :help="t('dns.rrl_logonly_hint')"><USwitch v-model="sf.rrlLogOnly" :disabled="!isAdmin" /></UFormField>
          <UFormField class="md:col-span-2" :label="t('dns.rrl_exempt')" :help="t('dns.rrl_exempt_hint')"><UInput v-model="sf.rrlExempt" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        </template>
        <div class="md:col-span-2 flex justify-end"><UButton v-if="isAdmin" type="submit" :label="t('common.save')" /></div>
      </form>
    </UCard>
    <LeaseDnsSync />
    </div>
    <ConfigApply v-else />
    <UModal v-model:open="copyOpen" :title="t('dnsv.copy')" :description="t('dnsv.copy_desc', { z: copyZone?.name ?? '', v: copyZone?.view ?? '' })">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="doCopy">
          <UAlert v-if="copyErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="copyErr" />
          <UFormField :label="t('dnsv.copy_to')"><USelect v-model="copyTo" :items="copyTargets" class="w-full" /></UFormField>
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="copyOpen = false" /><UButton type="submit" icon="i-lucide-copy" :loading="copyBusy" :disabled="!copyTo" :label="t('dnsv.copy')" /></div>
        </form>
      </template>
    </UModal>
    <UModal v-model:open="exportOpen" :title="exported?.name" :description="t('dns.export_desc')">
      <template #body><pre class="text-xs font-mono overflow-auto max-h-96 whitespace-pre">{{ exported?.content }}</pre></template>
    </UModal>
  </div>
</template>
