<script setup lang="ts">
import { prune } from '~/composables/useRole'
const { t } = useT(); const api = useApi(); const toast = useToast()
const { canWrite, isAdmin } = useRole()
const tab = useHashTab('subnets', ['subnets', 'addresses', 'vlans', 'search', 'discovery', 'sources'])
const baseTabs = computed(() => [{ label: t('ipam.subnets'), value: 'subnets', icon: 'i-lucide-network' }, { label: t('ipam.addresses'), value: 'addresses', icon: 'i-lucide-list-ordered' }, { label: t('ipam.vlans'), value: 'vlans', icon: 'i-lucide-tags' }, { label: t('common.search'), value: 'search', icon: 'i-lucide-search' }])
const tabs = computed(() => [...baseTabs.value, ...(canWrite.value ? [{ label: t('disc.title'), value: 'discovery', icon: 'i-lucide-radar' }] : []), ...(isAdmin.value ? [{ label: t('nbw.title'), value: 'sources', icon: 'i-lucide-database-zap' }] : [])])
const { data: subnets, refresh: refreshSubnets } = await useFetch<any>('/api/ipam/subnets')
const { data: vlans, refresh: refreshVlans } = await useFetch<any>('/api/ipam/vlans')
const { data: zones } = await useFetch<any>('/api/dns/zones')
const subnetOptions = computed(() => (subnets.value?.items ?? []).map((s: any) => ({ label: `${s.cidr} — ${s.name}`, value: s.id })))
const vlanOptions = computed(() => [{ label: t('common.none'), value: 0 }, ...(vlans.value?.items ?? []).map((v: any) => ({ label: `${v.vlan_id} — ${v.name}`, value: v.id }))])
const zoneOptions = computed(() => [{ label: t('common.none'), value: 0 }, ...(zones.value?.items ?? []).filter((z: any) => z.type === 'primary').map((z: any) => ({ label: z.name, value: z.id }))])
const sel = ref<number | null>(null)
watch(() => subnets.value, (s) => { if (sel.value === null && s?.items?.length) sel.value = s.items[0].id }, { immediate: true })
const addrTable = ref<any>(null)

const subnetCols = computed(() => [
  { key: 'cidr', label: 'CIDR', kind: 'mono' }, { key: 'name', label: t('common.name') }, { key: 'site', label: t('ipam.site') }, { key: 'vlan', label: 'VLAN', kind: 'num' },
  { key: 'used', label: t('ipam.used'), kind: 'num' }, { key: 'capacity', label: t('ipam.capacity'), kind: 'num' }, { key: 'percent', label: t('ipam.occupancy'), kind: 'progress' },
  { key: 'has_dhcp', label: 'DHCP', kind: 'bool' },
])
const subnetFields = computed(() => [
  { key: 'cidr', label: 'CIDR', type: 'text', required: true, createOnly: true, placeholder: '10.20.0.0/24', mono: true }, { key: 'name', label: t('common.name'), type: 'text', required: true },
  { key: 'description', label: t('common.description'), type: 'text' }, { key: 'site', label: t('ipam.site'), type: 'text' },
  { key: 'gateway', label: t('ipam.gateway'), type: 'text', placeholder: '10.20.0.1' }, { key: 'vlan_id', label: 'VLAN', type: 'select', options: vlanOptions.value, default: 0 },
  { key: 'tags', label: t('ipam.tags'), type: 'list', hint: t('common.list_hint') },
] as any[])
const subnetBody = (b: any, editing: boolean) => { const o = { ...b, vlan_id: b.vlan_id || null }; if (editing) delete o.cidr; return o }
const addrCols = computed(() => [
  { key: 'ip', label: 'IP', kind: 'mono' }, { key: 'status', label: t('common.status'), kind: 'badge', trans: 'ipam.status' }, { key: 'hostname', label: t('ipam.hostname') },
  { key: 'mac', label: 'MAC', kind: 'mono' }, { key: 'description', label: t('common.description') },
])
const statusOptions = computed(() => ['used', 'reserved', 'dhcp', 'gateway', 'infra'].map((v) => ({ label: t(`ipam.status.${v}`), value: v })))
const addrFields = computed(() => [
  { key: 'ip', label: 'IP', type: 'text', required: true, createOnly: true, mono: true }, { key: 'status', label: t('common.status'), type: 'select', options: statusOptions.value, default: 'used' },
  { key: 'hostname', label: t('ipam.hostname'), type: 'text', placeholder: 'srv-app-01' }, { key: 'mac', label: 'MAC', type: 'text', placeholder: 'aa:bb:cc:dd:ee:ff' },
  { key: 'description', label: t('common.description'), type: 'text' }, { key: 'owner', label: t('ipam.owner'), type: 'text' },
  { key: 'dns_zone_id', label: t('ipam.dns_sync'), type: 'select', options: zoneOptions.value, default: 0, createOnly: true, hint: t('ipam.dns_sync_hint') },
] as any[])
const addrBody = (b: any) => { const o = { ...b }; if (!o.dns_zone_id || !o.hostname) delete o.dns_zone_id; return o }
const vlanCols = computed(() => [{ key: 'vlan_id', label: 'VLAN ID', kind: 'num' }, { key: 'name', label: t('common.name') }, { key: 'description', label: t('common.description') }, { key: 'subnets', label: t('ipam.subnets'), kind: 'num' }])
const vlanFields = computed(() => [{ key: 'vlan_id', label: 'VLAN ID', type: 'number', required: true }, { key: 'name', label: t('common.name'), type: 'text', required: true }, { key: 'description', label: t('common.description'), type: 'text' }] as any[])

// IP suivante libre
const nextOpen = ref(false), nextState = reactive({ hostname: '', status: 'used', dns_zone_id: 0 }), nextErr = ref('')
async function allocate() {
  nextErr.value = ''
  try {
    const r: any = await api.call('POST', `/ipam/subnets/${sel.value}/next`, prune({ status: nextState.status, hostname: nextState.hostname || undefined, dns_zone_id: nextState.hostname && nextState.dns_zone_id ? nextState.dns_zone_id : undefined }))
    toast.add({ title: t('ipam.allocated', { ip: r.ip }), color: 'success', icon: 'i-lucide-check' }); nextOpen.value = false
    await addrTable.value?.refresh(); await refreshSubnets()
  } catch (e: any) { nextErr.value = e.info?.message ?? t('err.internal') }
}
// Recherche
const sq = ref(''), found = ref<any>({ subnets: [], addresses: [] })
let timer: any
watch(sq, (v) => { clearTimeout(timer); timer = setTimeout(async () => { found.value = v.length >= 2 ? await api.call('GET', `/ipam/search?q=${encodeURIComponent(v)}`) : { subnets: [], addresses: [] } }, 250) })
function openSubnet(id: number) { sel.value = id; tab.value = 'addresses' }
</script>

<template>
  <div class="flex flex-col gap-3">
    <UTabs v-model="tab" :items="tabs" :content="false" :aria-label="t('nav.ipam')" />
    <ResourceTable v-if="tab === 'subnets'" endpoint="/ipam/subnets" :columns="subnetCols" :fields="subnetFields" :can-write="canWrite" create-url="/ipam/subnets" :update-url="(r: any) => `/ipam/subnets/${r.id}`" :delete-url="(r: any) => `/ipam/subnets/${r.id}?force=1`" :delete-name="(r: any) => r.cidr" :create-label="t('ipam.add_subnet')" :transform="subnetBody" @changed="refreshSubnets">
      <template #actions="{ row }"><UButton icon="i-lucide-list-ordered" size="xs" color="neutral" variant="ghost" :aria-label="t('ipam.addresses')" @click="openSubnet(row.id)" /></template>
    </ResourceTable>
    <div v-else-if="tab === 'addresses'" class="flex flex-col gap-3">
      <div class="flex gap-2 items-center flex-wrap"><USelect v-model="sel" :items="subnetOptions" class="w-80" :aria-label="t('ipam.subnet')" />
        <UButton v-if="canWrite && sel" icon="i-lucide-wand-sparkles" color="neutral" variant="outline" :label="t('ipam.next_free')" @click="nextOpen = true" />
        <UButton icon="i-lucide-download" color="neutral" variant="ghost" :label="t('ipam.export')" href="/api/ipam/export/addresses" external /></div>
      <ResourceTable v-if="sel" :key="sel" ref="addrTable" :endpoint="`/ipam/subnets/${sel}/addresses`" :columns="addrCols" :fields="addrFields" :can-write="canWrite" :create-url="`/ipam/subnets/${sel}/addresses`" :update-url="(r: any) => `/ipam/addresses/${r.id}`" :delete-url="(r: any) => `/ipam/addresses/${r.id}`" :delete-name="(r: any) => r.ip" :transform="addrBody" searchable @changed="refreshSubnets" />
      <UModal v-model:open="nextOpen" :title="t('ipam.next_free')" :description="t('ipam.next_desc')">
        <template #body><form class="flex flex-col gap-3" @submit.prevent="allocate">
          <UAlert v-if="nextErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="nextErr" />
          <UFormField :label="t('ipam.hostname')"><UInput v-model="nextState.hostname" class="w-full" /></UFormField>
          <UFormField :label="t('common.status')"><USelect v-model="nextState.status" :items="statusOptions" class="w-full" /></UFormField>
          <UFormField :label="t('ipam.dns_sync')" :help="t('ipam.dns_sync_hint')"><USelect v-model="nextState.dns_zone_id" :items="zoneOptions" class="w-full" /></UFormField>
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="nextOpen = false" /><UButton type="submit" :label="t('ipam.allocate')" /></div></form></template>
      </UModal>
    </div>
    <ResourceTable v-else-if="tab === 'vlans'" endpoint="/ipam/vlans" :columns="vlanCols" :fields="vlanFields" :can-write="canWrite" create-url="/ipam/vlans" :update-url="(r: any) => `/ipam/vlans/${r.id}`" :delete-url="(r: any) => `/ipam/vlans/${r.id}`" :delete-name="(r: any) => r.name" @changed="refreshVlans" />
    <DiscoveryWizard v-else-if="tab === 'discovery' && canWrite" />
    <NetboxWizard v-else-if="tab === 'sources' && isAdmin" />
    <div v-else class="flex flex-col gap-3">
      <UInput v-model="sq" icon="i-lucide-search" :placeholder="t('ipam.search_ph')" :aria-label="t('common.search')" class="w-96" autofocus />
      <div class="grid gap-4 lg:grid-cols-2">
        <UCard><template #header><span class="font-medium">{{ t('ipam.subnets') }} ({{ found.subnets.length }})</span></template>
          <ul class="text-sm flex flex-col gap-1"><li v-for="s in found.subnets" :key="s.id"><UButton variant="link" size="sm" :label="`${s.cidr} — ${s.name}`" class="font-mono" @click="openSubnet(s.id)" /></li></ul></UCard>
        <UCard><template #header><span class="font-medium">{{ t('ipam.addresses') }} ({{ found.addresses.length }})</span></template>
          <ul class="text-sm flex flex-col gap-1 max-h-96 overflow-auto"><li v-for="a in found.addresses" :key="a.id" class="font-mono text-xs"><UButton variant="link" size="xs" :label="a.ip" @click="openSubnet(a.subnet_id)" /> {{ a.hostname }} {{ a.mac }}</li></ul></UCard>
      </div>
    </div>
  </div>
</template>
