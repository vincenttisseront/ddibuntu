<script setup lang="ts">
import { prune } from '~/composables/useRole'
const { t } = useT(); const api = useApi(); const toast = useToast()
const { canWrite, isAdmin } = useRole()
const tab = useHashTab('scopes', ['scopes', 'ranges', 'leases', 'settings', 'deploy'])
const tabs = computed(() => [{ label: t('dhcp.scopes'), value: 'scopes', icon: 'i-lucide-server' }, { label: t('dhcp.ranges'), value: 'ranges', icon: 'i-lucide-bookmark' }, { label: t('dhcp.leases'), value: 'leases', icon: 'i-lucide-clock' }, { label: t('dhcp.settings'), value: 'settings', icon: 'i-lucide-sliders-horizontal' }, { label: t('apply.title'), value: 'deploy', icon: 'i-lucide-rocket' }])
const { data: scopes, refresh: refreshScopes } = await useFetch<any>('/api/dhcp/scopes')
const { data: subnets } = await useFetch<any>('/api/ipam/subnets')
const free = computed(() => (subnets.value?.items ?? []).filter((s: any) => s.family === 4 && !s.has_dhcp).map((s: any) => ({ label: `${s.cidr} — ${s.name}`, value: s.id })))
const scopeOptions = computed(() => (scopes.value?.items ?? []).map((s: any) => ({ label: `${s.cidr} — ${s.name ?? s.subnet_name}`, value: s.id })))
const sel = ref<number | null>(null)
watch(scopes, (s) => { if (sel.value === null && s?.items?.length) sel.value = s.items[0].id }, { immediate: true })
useQueryId('scope', (id) => { sel.value = id })

const scopeCols = computed(() => [{ key: 'cidr', label: 'CIDR', kind: 'mono' }, { key: 'name', label: t('common.name') }, { key: 'lease_time', label: t('dhcp.lease_time'), kind: 'num' }, { key: 'enabled', label: t('common.enabled'), kind: 'bool' }, { key: 'pools', label: t('dhcp.pools'), kind: 'num' }, { key: 'reservations', label: t('dhcp.reservations'), kind: 'num' },
  { key: 'options.routers', label: t('dhcp.routers'), kind: 'list' }, { key: 'options.dnsServers', label: 'DNS', kind: 'list' }])
const scopeFields = computed(() => [
  { key: 'subnet_id', label: t('ipam.subnet'), type: 'select', required: true, createOnly: true, options: free.value, default: free.value[0]?.value, hint: t('dhcp.subnet_hint') },
  { key: 'name', label: t('common.name'), type: 'text' }, { key: 'lease_time', label: t('dhcp.lease_time'), type: 'number', default: 86400, hint: t('dhcp.lease_hint') }, { key: 'enabled', label: t('common.enabled'), type: 'switch', default: true },
  { key: 'options.routers', label: t('dhcp.routers'), type: 'list', hint: t('common.list_hint') }, { key: 'options.dnsServers', label: t('dhcp.dns_servers'), type: 'list', hint: t('common.list_hint') },
  { key: 'options.domainName', label: t('dhcp.domain_name'), type: 'text', placeholder: 'corp.example.com' }, { key: 'options.domainSearch', label: t('dhcp.domain_search'), type: 'list' },
  { key: 'options.ntpServers', label: t('dhcp.ntp'), type: 'list' }, { key: 'options.tftpServer', label: t('dhcp.tftp'), type: 'text' }, { key: 'options.bootFile', label: t('dhcp.boot_file'), type: 'text' },
] as any[])
const scopeBody = (b: any) => ({ ...b, options: prune(b.options) ?? {} })

const poolCols = computed(() => [{ key: 'start_ip', label: t('dhcp.start'), kind: 'mono' }, { key: 'end_ip', label: t('dhcp.end'), kind: 'mono' }])
const poolFields = computed(() => [{ key: 'start', label: t('dhcp.start'), type: 'text', required: true, mono: true }, { key: 'end', label: t('dhcp.end'), type: 'text', required: true, mono: true }] as any[])
const resCols = computed(() => [{ key: 'mac', label: 'MAC', kind: 'mono' }, { key: 'ip', label: 'IP', kind: 'mono' }, { key: 'hostname', label: t('ipam.hostname') }, { key: 'description', label: t('common.description') }])
const resFields = computed(() => [{ key: 'mac', label: 'MAC', type: 'text', required: true, mono: true, placeholder: 'aa:bb:cc:dd:ee:ff' }, { key: 'ip', label: 'IP', type: 'text', required: true, mono: true }, { key: 'hostname', label: t('ipam.hostname'), type: 'text' }, { key: 'description', label: t('common.description'), type: 'text' }] as any[])

const { data: leases } = await useFetch<any>('/api/dhcp/leases')
const leaseCols = computed(() => [{ key: 'ip', label: 'IP', kind: 'mono' }, { key: 'mac', label: 'MAC', kind: 'mono' }, { key: 'hostname', label: t('ipam.hostname') }, { key: 'expire', label: t('dhcp.expires'), kind: 'date' }])

// Paramètres globaux (administrateur)
const { data: ds, refresh: refreshDs } = await useFetch<any>('/api/dhcp/settings')
const f = reactive<any>({ interfaces: '', ddns: false, type: 'postgresql', name: '', user: '', host: '', password: '', routers: '', dnsServers: '', domainName: '', ntpServers: '' })
const sErr = ref('')
watch(ds, (s) => { if (!s) return; f.interfaces = (s.interfaces ?? []).join(', '); f.ddns = s.ddns; f.type = s.lease.type; f.name = s.lease.name; f.user = s.lease.user ?? ''; f.host = s.lease.host ?? ''; const g = s.globalOptions ?? {}; f.routers = (g.routers ?? []).join(', '); f.dnsServers = (g.dnsServers ?? []).join(', '); f.domainName = g.domainName ?? ''; f.ntpServers = (g.ntpServers ?? []).join(', ') }, { immediate: true })
const split = (v: string) => String(v ?? '').split(/[,\s]+/).filter(Boolean)
async function saveSettings() {
  sErr.value = ''
  try {
    await api.call('PUT', '/dhcp/settings', { interfaces: split(f.interfaces), ddns: f.ddns, lease: prune({ type: f.type, name: f.name, user: f.user, host: f.host, password: f.password }), globalOptions: prune({ routers: split(f.routers), dnsServers: split(f.dnsServers), domainName: f.domainName, ntpServers: split(f.ntpServers) }) ?? {} })
    f.password = ''; toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await refreshDs()
  } catch (e: any) { sErr.value = e.info?.message ?? t('err.internal') }
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <UTabs v-model="tab" :items="tabs" :content="false" :aria-label="t('nav.dhcp')" />
    <ResourceTable v-if="tab === 'scopes'" endpoint="/dhcp/scopes" :columns="scopeCols" :fields="scopeFields" :can-write="canWrite" create-url="/dhcp/scopes" :update-url="(r: any) => `/dhcp/scopes/${r.id}`" :delete-url="(r: any) => `/dhcp/scopes/${r.id}`" :delete-name="(r: any) => r.cidr" :create-label="t('dhcp.add_scope')" :transform="scopeBody" @changed="refreshScopes" />
    <div v-else-if="tab === 'ranges'" class="flex flex-col gap-3">
      <USelect v-model="sel" :items="scopeOptions" class="w-80" :aria-label="t('dhcp.scope')" />
      <div v-if="sel" :key="sel" class="grid gap-4 lg:grid-cols-2">
        <UCard><template #header><span class="font-medium">{{ t('dhcp.pools') }}</span></template>
          <ResourceTable :endpoint="`/dhcp/scopes/${sel}`" items-key="pools" :columns="poolCols" :fields="poolFields" :can-write="canWrite" :create-url="`/dhcp/scopes/${sel}/pools`" :delete-url="(r: any) => `/dhcp/pools/${r.id}`" :delete-name="(r: any) => `${r.start_ip} – ${r.end_ip}`" :create-label="t('dhcp.add_pool')" @changed="refreshScopes" /></UCard>
        <UCard><template #header><span class="font-medium">{{ t('dhcp.reservations') }}</span></template>
          <ResourceTable :endpoint="`/dhcp/scopes/${sel}`" items-key="reservations" :columns="resCols" :fields="resFields" :can-write="canWrite" :create-url="`/dhcp/scopes/${sel}/reservations`" :delete-url="(r: any) => `/dhcp/reservations/${r.id}`" :delete-name="(r: any) => `${r.mac} → ${r.ip}`" :create-label="t('dhcp.add_reservation')" @changed="refreshScopes" /></UCard>
      </div>
      <p v-else class="text-sm text-muted">{{ t('dhcp.no_scope') }}</p>
    </div>
    <div v-else-if="tab === 'leases'" class="flex flex-col gap-3">
      <UAlert v-if="!leases?.available" color="neutral" variant="subtle" icon="i-lucide-info" :title="t('dhcp.leases_unavailable')" />
      <ResourceTable endpoint="/dhcp/leases" :columns="leaseCols" />
    </div>
    <UCard v-else-if="tab === 'settings'" class="max-w-3xl">
      <form class="grid gap-3 md:grid-cols-2" @submit.prevent="saveSettings">
        <UAlert v-if="sErr" class="md:col-span-2" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="sErr" />
        <UFormField :label="t('dhcp.interfaces')" :help="t('dhcp.interfaces_hint')"><UInput v-model="f.interfaces" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dhcp.ddns')" :help="t('dhcp.ddns_hint')"><USwitch v-model="f.ddns" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dhcp.backend')"><USelect v-model="f.type" :items="[{ label: 'PostgreSQL', value: 'postgresql' }, { label: t('dhcp.memfile'), value: 'memfile' }]" class="w-full" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dhcp.db_name')"><UInput v-model="f.name" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <template v-if="f.type === 'postgresql'">
          <UFormField :label="t('dhcp.db_user')"><UInput v-model="f.user" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
          <UFormField :label="t('dhcp.db_host')"><UInput v-model="f.host" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
          <UFormField :label="t('dhcp.db_password')" :help="ds?.lease?.passwordSet ? t('dhcp.password_set') : ''"><UInput v-model="f.password" type="password" autocomplete="new-password" class="w-full" :disabled="!isAdmin" /></UFormField>
        </template>
        <p class="md:col-span-2 text-sm font-medium pt-2">{{ t('dhcp.global_options') }}</p>
        <UFormField :label="t('dhcp.routers')"><UInput v-model="f.routers" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dhcp.dns_servers')"><UInput v-model="f.dnsServers" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dhcp.domain_name')"><UInput v-model="f.domainName" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <UFormField :label="t('dhcp.ntp')"><UInput v-model="f.ntpServers" class="w-full font-mono" :disabled="!isAdmin" /></UFormField>
        <div class="md:col-span-2 flex justify-end"><UButton v-if="isAdmin" type="submit" :label="t('common.save')" /></div>
      </form>
    </UCard>
    <ConfigApply v-else />
  </div>
</template>
