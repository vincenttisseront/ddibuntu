<script setup lang="ts">
import { prune } from '~/composables/useRole'
import type { DCol } from '~/components/DenseTable.vue'
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { canWrite, isAdmin } = useRole()
// « subnets » reste l'identifiant de l'onglet Réseaux : les liens existants (#subnets) continuent de fonctionner.
const tab = useHashTab('subnets', ['spaces', 'subnets', 'pools', 'addresses', 'templates', 'vlans', 'ghosts', 'search', 'discovery', 'sources'])
const baseTabs = computed(() => [
  { label: t('ipam.spaces'), value: 'spaces', icon: 'i-lucide-layers' }, { label: t('ipam.networks'), value: 'subnets', icon: 'i-lucide-network' },
  { label: t('ipam.pools'), value: 'pools', icon: 'i-lucide-brackets' }, { label: t('ipam.addresses'), value: 'addresses', icon: 'i-lucide-list-ordered' },
  { label: t('ipam.templates'), value: 'templates', icon: 'i-lucide-file-sliders' }, { label: t('ipam.vlans'), value: 'vlans', icon: 'i-lucide-tags' }, { label: t('ghost.title'), value: 'ghosts', icon: 'i-lucide-ghost' }, { label: t('common.search'), value: 'search', icon: 'i-lucide-search' }])
const tabs = computed(() => [...baseTabs.value, ...(canWrite.value ? [{ label: t('disc.title'), value: 'discovery', icon: 'i-lucide-radar' }] : []), ...(isAdmin.value ? [{ label: t('nbw.title'), value: 'sources', icon: 'i-lucide-database-zap' }] : [])])

// ---- Contexte partagé : espace et famille d'adresses (comme les boutons V4/V6 d'une console IPAM) ----
const spaceId = ref(0), fam = ref(0)
const famItems = [{ label: t('ipam.all'), value: 0 }, { label: 'IPv4', value: 4 }, { label: 'IPv6', value: 6 }]
const { data: spaces, refresh: refreshSpaces } = await useFetch<any>('/api/ipam/spaces')
const netQuery = computed(() => ({ ...(spaceId.value ? { space_id: spaceId.value } : {}), ...(fam.value ? { family: fam.value } : {}) }))
const { data: nets, pending: netsPending, refresh: refreshNets } = await useFetch<any>('/api/ipam/subnets', { query: netQuery, watch: [netQuery] })
const { data: vlans, refresh: refreshVlans } = await useFetch<any>('/api/ipam/vlans')
const { data: templates, refresh: refreshTemplates } = await useFetch<any>('/api/ipam/templates')
const { data: zones } = await useFetch<any>('/api/dns/zones')
const poolQuery = computed(() => ({ ...(spaceId.value ? { space_id: spaceId.value } : {}) }))
const { data: pools, pending: poolsPending, refresh: refreshPools } = await useFetch<any>('/api/ipam/pools', { query: poolQuery, watch: [poolQuery] })

const spaceItems = computed(() => [{ label: t('ipam.all_spaces'), value: 0 }, ...(spaces.value?.items ?? []).map((s: any) => ({ label: s.name, value: s.id }))])
const spaceOptions = computed(() => (spaces.value?.items ?? []).map((s: any) => ({ label: s.name, value: s.id })))
const vlanOptions = computed(() => [{ label: t('common.none'), value: 0 }, ...(vlans.value?.items ?? []).map((v: any) => ({ label: `${v.vlan_id} — ${v.name}`, value: v.id }))])
const primaryZones = computed(() => (zones.value?.items ?? []).filter((z: any) => z.type === 'primary').map((z: any) => ({ label: z.name, value: z.id })))
const zoneOptions = computed(() => [{ label: t('ipam.zone_template'), value: 0 }, { label: t('ipam.zone_none'), value: -1 }, ...primaryZones.value])
const tplZoneOptions = computed(() => [{ label: t('common.none'), value: 0 }, ...primaryZones.value])
const templateOptions = computed(() => [{ label: t('common.none'), value: 0 }, ...(templates.value?.items ?? []).map((x: any) => ({ label: x.name, value: x.id }))])
const leafOptions = computed(() => (nets.value?.items ?? []).filter((n: any) => n.kind === 'network').map((n: any) => ({ label: `${n.cidr} — ${n.name}${spaceId.value ? '' : ` (${n.space})`}`, value: n.id })))
const statusOptions = computed(() => ['used', 'reserved', 'dhcp', 'gateway', 'infra'].map((v) => ({ label: t(`ipam.status.${v}`), value: v })))
const refreshAll = () => Promise.all([refreshSpaces(), refreshNets(), refreshPools(), refreshAddrs(), refreshTemplates()])
const fail = (e: any) => toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' })
const ok = () => toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' })




// ---- Espaces ----
const spaceCols = computed<DCol[]>(() => [{ key: 'name', label: t('common.name') }, { key: 'description', label: t('common.description') }, { key: 'subnets', label: t('ipam.networks'), kind: 'num' }, { key: 'addresses', label: t('ipam.addresses'), kind: 'num' }])
const spaceFields = computed(() => [{ key: 'name', label: t('common.name'), type: 'text', required: true }, { key: 'description', label: t('common.description'), type: 'text' }] as any[])
const form = reactive<{ open: boolean; kind: string; row: any | null }>({ open: false, kind: '', row: null })
const openForm = (kind: string, row: any | null = null) => { form.kind = kind; form.row = row; form.open = true }

// ---- Réseaux (arborescence) ----
const netCols = computed<DCol[]>(() => [
  { key: 'cidr', label: t('ipam.address_prefix'), kind: 'mono', width: '15rem' }, { key: 'name', label: t('common.name') },
  { key: 'size_label', label: t('ipam.size'), kind: 'num' }, { key: 'allocated', label: t('ipam.allocated_pct'), kind: 'progress' }, { key: 'percent', label: t('ipam.used_pct'), kind: 'progress' },
  { key: 'site', label: t('ipam.site') }, { key: 'vlan', label: 'VLAN', kind: 'num' }, { key: 'has_dhcp', label: 'DHCP', kind: 'bool' },
  { key: 'template', label: t('ipam.template') }, { key: 'parent.name', label: t('ipam.container') }, { key: 'space', label: t('ipam.space'), hidden: !!spaceId.value },
])
const netFields = computed(() => [
  { key: 'cidr', label: 'CIDR', type: 'text', required: true, createOnly: true, placeholder: '10.20.0.0/24', mono: true }, { key: 'name', label: t('common.name'), type: 'text', required: true },
  { key: 'kind', label: t('ipam.kind'), type: 'select', options: [{ label: t('ipam.kind.network'), value: 'network' }, { label: t('ipam.kind.container'), value: 'container' }], default: 'network', hint: t('ipam.kind_hint') },
  { key: 'space_id', label: t('ipam.space'), type: 'select', options: spaceOptions.value, default: spaceId.value || 1 },
  { key: 'template_id', label: t('ipam.template'), type: 'select', options: templateOptions.value, default: 0, hint: t('ipam.template_hint') },
  { key: 'description', label: t('common.description'), type: 'text' }, { key: 'site', label: t('ipam.site'), type: 'text' },
  { key: 'gateway', label: t('ipam.gateway'), type: 'text', placeholder: '10.20.0.1' }, { key: 'vlan_id', label: 'VLAN', type: 'select', options: vlanOptions.value, default: 0 },
  { key: 'tags', label: t('ipam.tags'), type: 'list', hint: t('common.list_hint') },
] as any[])
const netBody = (b: any) => { const o = { ...b, vlan_id: b.vlan_id || null, template_id: b.template_id || null }; if (o.kind === 'container') delete o.gateway; return o }
const netSelected = ref<number[]>([])
const netTable = ref<any>(null)
const netRowClass = (r: any) => (r.kind === 'container' ? 'font-medium' : '')
async function removeNet(row: any) {
  if (!(await ask(t('common.delete'), t('ipam.delete_net_confirm', { name: row.cidr, n: row.children })))) return
  try { await api.call('DELETE', `/ipam/subnets/${row.id}?force=1`); netSelected.value = netSelected.value.filter((i) => i !== row.id); await refreshAll() } catch (e: any) { fail(e) }
}
async function bulkDelete() {
  const ids = [...netSelected.value]
  if (!ids.length || !(await ask(t('common.delete'), t('ipam.bulk_delete_confirm', { n: ids.length })))) return
  let failed = 0
  for (const id of ids) { try { await api.call('DELETE', `/ipam/subnets/${id}?force=1`) } catch { failed++ } }
  netSelected.value = []; await refreshAll()
  toast.add({ title: failed ? t('ipam.bulk_partial', { n: failed }) : t('common.deleted'), color: failed ? 'warning' : 'success', icon: 'i-lucide-check' })
}
const moveOpen = ref(false), moveTo = ref(1), moveErr = ref('')
async function bulkMove() {
  moveErr.value = ''; let failed = 0
  for (const id of netSelected.value) { try { await api.call('PUT', `/ipam/subnets/${id}`, { space_id: moveTo.value }) } catch { failed++ } }
  if (failed) moveErr.value = t('ipam.bulk_partial', { n: failed }); else { moveOpen.value = false; netSelected.value = [] }
  await refreshAll()
}
function openAddresses(row: any) { addrSubnet.value = row.id; addrOffset.value = 0; tab.value = 'addresses' }
function openPools(row: any) { poolFilter.value = row.id; tab.value = 'pools' }

// ---- Pools ----
const poolFilter = ref(0)
const poolRows = computed(() => (pools.value?.items ?? []).filter((p: any) => !poolFilter.value || p.subnet_id === poolFilter.value))
const poolCols = computed<DCol[]>(() => [
  { key: 'name', label: t('common.name') }, { key: 'cidr', label: t('ipam.network'), kind: 'mono' }, { key: 'start_ip', label: t('ipam.start'), kind: 'mono' }, { key: 'end_ip', label: t('ipam.end'), kind: 'mono' },
  { key: 'size', label: t('ipam.size'), kind: 'num' }, { key: 'used', label: t('ipam.used'), kind: 'num' }, { key: 'percent', label: t('ipam.used_pct'), kind: 'progress' },
  { key: 'description', label: t('common.description') }, { key: 'space', label: t('ipam.space'), hidden: !!spaceId.value },
])
const poolFields = computed(() => [
  { key: 'subnet_id', label: t('ipam.network'), type: 'select', options: leafOptions.value, required: true, createOnly: true, default: poolFilter.value || leafOptions.value[0]?.value },
  { key: 'name', label: t('common.name'), type: 'text', required: true }, { key: 'start_ip', label: t('ipam.start'), type: 'text', required: true, mono: true, placeholder: '10.20.0.100' },
  { key: 'end_ip', label: t('ipam.end'), type: 'text', required: true, mono: true, placeholder: '10.20.0.199' }, { key: 'description', label: t('common.description'), type: 'text' },
] as any[])
async function removePool(row: any) {
  if (!(await ask(t('common.delete'), t('common.delete_confirm', { name: row.name })))) return
  try { await api.call('DELETE', `/ipam/pools/${row.id}`); await refreshAll() } catch (e: any) { fail(e) }
}

// ---- Adresses (vue transverse, pagination côté serveur) ----
const addrSubnet = ref(0), addrQ = ref(''), addrStatus = ref(''), addrOffset = ref(0)
useQueryId('subnet', (id) => { addrSubnet.value = id; addrOffset.value = 0 })
const LIMIT = 200
const addrQuery = computed(() => ({ limit: LIMIT, offset: addrOffset.value, ...(spaceId.value ? { space_id: spaceId.value } : {}), ...(fam.value ? { family: fam.value } : {}), ...(addrSubnet.value ? { subnet_id: addrSubnet.value } : {}), ...(addrQ.value ? { q: addrQ.value } : {}), ...(addrStatus.value ? { status: addrStatus.value } : {}) }))
const { data: addrs, pending: addrsPending, refresh: refreshAddrs } = await useFetch<any>('/api/ipam/addresses', { query: addrQuery, watch: [addrQuery] })
// Grille d'occupation : recalculée à chaque rechargement des adresses ; un clic filtre le tableau sur l'IP, ou ouvre la création si elle est libre
const gridKey = ref(0)
watch(addrs, () => { gridKey.value++ })
function pickCell(c: { ip: string; state: string; item: unknown }) {
  const free = ['.', 'o', 'p'].includes(c.state)
  if (free && canWrite.value) { addrPrefill.value = c.ip; openForm('addr') } else { addrQ.value = c.ip; addrOffset.value = 0 }
}
watch([spaceId, fam, addrSubnet, addrQ, addrStatus], () => { addrOffset.value = 0 })
const addrCols = computed<DCol[]>(() => [
  { key: 'ip', label: 'IP', kind: 'mono' }, { key: 'status', label: t('common.status'), kind: 'badge', trans: 'ipam.status' }, { key: 'hostname', label: t('ipam.hostname') }, { key: 'mac', label: 'MAC', kind: 'mono' },
  { key: 'description', label: t('common.description') }, { key: 'owner', label: t('ipam.owner') }, { key: 'cidr', label: t('ipam.network'), kind: 'mono' }, { key: 'space', label: t('ipam.space'), hidden: !!spaceId.value },
])
const addrPrefill = ref('')
watch(() => form.open, (o) => { if (!o) addrPrefill.value = '' })
const addrFields = computed(() => [
  { key: 'subnet_id', label: t('ipam.network'), type: 'select', options: leafOptions.value, required: true, createOnly: true, default: addrSubnet.value || leafOptions.value[0]?.value },
  { key: 'ip', label: 'IP', type: 'text', required: true, createOnly: true, mono: true, default: addrPrefill.value }, { key: 'status', label: t('common.status'), type: 'select', options: statusOptions.value, default: 'used' },
  { key: 'hostname', label: t('ipam.hostname'), type: 'text', placeholder: 'srv-app-01' }, { key: 'mac', label: 'MAC', type: 'text', placeholder: 'aa:bb:cc:dd:ee:ff' },
  { key: 'description', label: t('common.description'), type: 'text' }, { key: 'owner', label: t('ipam.owner'), type: 'text' },
  { key: 'dns_zone_id', label: t('ipam.dns_sync'), type: 'select', options: zoneOptions.value, default: 0, createOnly: true, hint: t('ipam.dns_sync_hint') },
] as any[])
async function removeAddr(row: any) {
  if (!(await ask(t('common.delete'), t('common.delete_confirm', { name: row.ip })))) return
  try { await api.call('DELETE', `/ipam/addresses/${row.id}`); await refreshAll() } catch (e: any) { fail(e) }
}
const addrFrom = computed(() => (addrs.value?.total ? addrOffset.value + 1 : 0))
const addrTo = computed(() => Math.min(addrOffset.value + LIMIT, addrs.value?.total ?? 0))

// ---- Gabarits ----
const tplCols = computed<DCol[]>(() => [
  { key: 'name', label: t('common.name') }, { key: 'description', label: t('common.description') }, { key: 'create_scope', label: t('ipam.tpl_scope'), kind: 'bool' },
  { key: 'lease_time', label: t('ipam.tpl_lease'), kind: 'num' }, { key: 'dns_zone', label: t('ipam.tpl_zone') }, { key: 'hostname_pattern', label: t('ipam.tpl_pattern'), kind: 'mono' }, { key: 'subnets', label: t('ipam.networks'), kind: 'num' },
])
const tplFields = computed(() => [
  { key: 'name', label: t('common.name'), type: 'text', required: true }, { key: 'description', label: t('common.description'), type: 'text' },
  { key: 'create_scope', label: t('ipam.tpl_scope'), type: 'switch', default: true, hint: t('ipam.tpl_scope_hint') },
  { key: 'lease_time', label: t('ipam.tpl_lease'), type: 'number', default: 86400 },
  { key: 'opt_dns', label: t('ipam.tpl_dns'), type: 'list', hint: t('common.list_hint') }, { key: 'opt_domain', label: t('ipam.tpl_domain'), type: 'text', placeholder: 'corp.example.com' },
  { key: 'opt_ntp', label: t('ipam.tpl_ntp'), type: 'list', hint: t('common.list_hint') },
  { key: 'dns_zone_id', label: t('ipam.tpl_zone'), type: 'select', options: tplZoneOptions.value, default: 0, hint: t('ipam.tpl_zone_hint') },
  { key: 'hostname_pattern', label: t('ipam.tpl_pattern'), type: 'text', mono: true, placeholder: 'srv-###', hint: t('ipam.tpl_pattern_hint') },
] as any[])
const tplBody = (b: any) => {
  const o: Record<string, any> = {}
  if (b.opt_dns?.length) o.dnsServers = b.opt_dns
  if (b.opt_domain) o.domainName = b.opt_domain
  if (b.opt_ntp?.length) o.ntpServers = b.opt_ntp
  return { name: b.name, description: b.description, create_scope: !!b.create_scope, lease_time: b.lease_time || 86400, dhcp_options: o, dns_zone_id: b.dns_zone_id || null, hostname_pattern: b.hostname_pattern || null }
}
const tplRow = (r: any) => ({ ...r, dns_zone_id: r.dns_zone_id ?? 0, opt_dns: r.dhcp_options?.dnsServers ?? [], opt_domain: r.dhcp_options?.domainName ?? '', opt_ntp: r.dhcp_options?.ntpServers ?? [] })
async function removeTemplate(row: any) {
  if (!(await ask(t('common.delete'), t('ipam.tpl_delete_confirm', { name: row.name, n: row.subnets })))) return
  try { await api.call('DELETE', `/ipam/templates/${row.id}`); await refreshAll() } catch (e: any) { fail(e) }
}
// Retour d'une écriture qui a piloté DHCP/DNS dans la même transaction
function feedback(r: any) {
  const msgs: string[] = []
  if (r?.dhcp && ['created', 'updated', 'removed', 'no_mac', 'no_scope', 'scope_created', 'scope_skipped', 'ipv6'].includes(r.dhcp)) msgs.push(t(`ipam.dhcp_${r.dhcp}`))
  if (r?.dns) msgs.push(t('ipam.dns_created'))
  if (msgs.length) toast.add({ title: msgs.join(' · '), color: ['no_mac', 'no_scope', 'scope_skipped', 'ipv6'].includes(r?.dhcp) ? 'warning' : 'info', icon: 'i-lucide-workflow' })
}

// ---- Envoi des formulaires ----
async function submitForm(b: any) {
  const row = form.row
  switch (form.kind) {
    case 'space': if (row) await api.call('PUT', `/ipam/spaces/${row.id}`, b); else await api.call('POST', '/ipam/spaces', b); break
    case 'net': { const body = netBody(b); if (row) await api.call('PUT', `/ipam/subnets/${row.id}`, body); else feedback(await api.call('POST', '/ipam/subnets', body)); break }
    case 'container': await api.call('POST', '/ipam/subnets', netBody({ ...b, kind: 'container' })); break
    case 'tpl': { const body = tplBody(b); if (row) await api.call('PUT', `/ipam/templates/${row.id}`, body); else await api.call('POST', '/ipam/templates', body); break }
    case 'pool': { const { subnet_id, ...rest } = b; if (row) await api.call('PUT', `/ipam/pools/${row.id}`, rest); else await api.call('POST', `/ipam/subnets/${subnet_id}/pools`, rest); break }
    case 'addr': { const { subnet_id, ...rest } = b; if (rest.dns_zone_id === -1) rest.dns_zone_id = null; else if (!rest.dns_zone_id) delete rest.dns_zone_id; if (row) { delete rest.dns_zone_id; await api.call('PUT', `/ipam/addresses/${row.id}`, rest) } else feedback(await api.call('POST', `/ipam/subnets/${subnet_id}/addresses`, rest)); break }
    case 'vlan': if (row) await api.call('PUT', `/ipam/vlans/${row.id}`, b); else await api.call('POST', '/ipam/vlans', b); break
  }
  ok(); await Promise.all([refreshAll(), refreshVlans()])
}
const formFields = computed(() => ({ tpl: tplFields.value, space: spaceFields.value, net: netFields.value, container: netFields.value.filter((f: any) => !['kind', 'gateway'].includes(f.key)), pool: poolFields.value, addr: addrFields.value, vlan: vlanFields.value } as Record<string, any[]>)[form.kind] ?? [])
const formTitle = computed(() => ({ tpl: t('ipam.add_template'), space: t('ipam.add_space'), net: t('ipam.add_subnet'), container: t('ipam.add_container'), pool: t('ipam.add_pool'), addr: t('common.add'), vlan: t('common.add') } as Record<string, string>)[form.kind] ?? '')

// ---- VLAN ----
const vlanCols = computed(() => [{ key: 'vlan_id', label: 'VLAN ID', kind: 'num' }, { key: 'name', label: t('common.name') }, { key: 'description', label: t('common.description') }, { key: 'subnets', label: t('ipam.subnets'), kind: 'num' }])
const vlanFields = computed(() => [{ key: 'vlan_id', label: 'VLAN ID', type: 'number', required: true }, { key: 'name', label: t('common.name'), type: 'text', required: true }, { key: 'description', label: t('common.description'), type: 'text' }] as any[])

// ---- IP suivante libre (réseau et pool au choix) ----
const nextOpen = ref(false), nextState = reactive({ subnet_id: 0, pool_id: 0, hostname: '', status: 'used', dns_zone_id: 0 }), nextErr = ref('')
const nextPoolOptions = computed(() => [{ label: t('ipam.no_pool'), value: 0 }, ...(pools.value?.items ?? []).filter((p: any) => p.subnet_id === nextState.subnet_id).map((p: any) => ({ label: `${p.name} (${p.start_ip} – ${p.end_ip})`, value: p.id }))])
function openNext(subnetId = 0, poolId = 0) { nextState.subnet_id = subnetId || addrSubnet.value || (leafOptions.value[0]?.value as number) || 0; nextState.pool_id = poolId; nextErr.value = ''; nextOpen.value = true }
watch(() => nextState.subnet_id, () => { if (!nextPoolOptions.value.some((o) => o.value === nextState.pool_id)) nextState.pool_id = 0 })
async function allocate() {
  nextErr.value = ''
  try {
    const r: any = await api.call('POST', `/ipam/subnets/${nextState.subnet_id}/next`, prune({ status: nextState.status, hostname: nextState.hostname || undefined, pool_id: nextState.pool_id || undefined, dns_zone_id: nextState.hostname && nextState.dns_zone_id ? nextState.dns_zone_id : undefined }))
    toast.add({ title: t('ipam.allocated', { ip: r.ip }), color: 'success', icon: 'i-lucide-check' }); feedback(r); nextOpen.value = false
    await refreshAll()
  } catch (e: any) { nextErr.value = e.info?.message ?? t('err.internal') }
}

// ---- Recherche ----
const sq = ref(''), found = ref<any>({ subnets: [], addresses: [] })
let timer: any
watch(sq, (v) => { clearTimeout(timer); timer = setTimeout(async () => { found.value = v.length >= 2 ? await api.call('GET', `/ipam/search?q=${encodeURIComponent(v)}`) : { subnets: [], addresses: [] } }, 250) })
function openSubnet(id: number) { addrSubnet.value = id; addrOffset.value = 0; tab.value = 'addresses' }
</script>

<template>
  <div class="flex flex-col gap-3">
    <UTabs v-model="tab" :items="tabs" :content="false" :aria-label="t('nav.ipam')" />
    <OccupancyGrid v-if="tab === 'addresses' && addrSubnet" :subnet-id="addrSubnet" :refresh-key="gridKey" @pick="pickCell" />

    <!-- Contexte commun : espace + famille -->
    <div v-if="['subnets', 'pools', 'addresses'].includes(tab)" class="flex items-center gap-2 flex-wrap">
      <USelect v-model="spaceId" :items="spaceItems" class="w-56" icon="i-lucide-layers" :aria-label="t('ipam.space')" />
      <div class="inline-flex rounded-md border border-default overflow-hidden" role="group" :aria-label="t('ipam.family')">
        <button v-for="f in famItems" :key="f.value" type="button" class="px-2.5 py-1 text-xs font-medium" :class="fam === f.value ? 'bg-primary text-inverted' : 'hover:bg-elevated'" :aria-pressed="fam === f.value" @click="fam = f.value">{{ f.label }}</button>
      </div>
    </div>

    <!-- Espaces -->
    <DenseTable v-if="tab === 'spaces'" :rows="spaces?.items ?? []" :columns="spaceCols" export-name="ipam-espaces">
      <template #toolbar><UButton v-if="canWrite" icon="i-lucide-plus" size="sm" :label="t('ipam.add_space')" @click="openForm('space')" /></template>
      <template #actions="{ row }">
        <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-network" :aria-label="t('ipam.networks')" @click="spaceId = row.id; tab = 'subnets'" />
        <UButton v-if="canWrite" size="xs" color="neutral" variant="ghost" icon="i-lucide-pencil" :aria-label="t('common.edit')" @click="openForm('space', row)" />
        <UButton v-if="canWrite && row.id !== 1" size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" @click="ask(t('common.delete'), t('common.delete_confirm', { name: row.name })).then(async (y) => { if (y) { try { await api.call('DELETE', `/ipam/spaces/${row.id}`); if (spaceId === row.id) spaceId = 0; await refreshAll() } catch (e: any) { fail(e) } } })" />
      </template>
    </DenseTable>

    <!-- Réseaux : arborescence -->
    <DenseTable v-else-if="tab === 'subnets'" ref="netTable" v-model:selected="netSelected" :rows="nets?.items ?? []" :columns="netCols" :loading="netsPending" tree :selectable="canWrite" :row-class="netRowClass" export-name="ipam-reseaux" @row-click="openAddresses">
      <template #toolbar>
        <UButton v-if="canWrite" icon="i-lucide-plus" size="sm" :label="t('ipam.add_subnet')" @click="openForm('net')" />
        <UButton v-if="canWrite" icon="i-lucide-folder-plus" size="sm" color="neutral" variant="outline" :label="t('ipam.add_container')" @click="openForm('container')" />
        <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-chevrons-down-up" :label="t('ipam.collapse_all')" @click="netTable?.collapseAll()" />
        <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-chevrons-up-down" :label="t('ipam.expand_all')" @click="netTable?.expandAll()" />
        <template v-if="canWrite && netSelected.length">
          <UButton size="xs" color="neutral" variant="outline" icon="i-lucide-arrow-right-left" :label="t('ipam.move_to_space')" @click="moveTo = spaceOptions[0]?.value ?? 1; moveErr = ''; moveOpen = true" />
          <UButton size="xs" color="error" variant="outline" icon="i-lucide-trash-2" :label="t('ipam.delete_selected', { n: netSelected.length })" @click="bulkDelete" />
        </template>
      </template>
      <template #actions="{ row }">
        <UButton v-if="row.kind === 'network'" size="xs" color="neutral" variant="ghost" icon="i-lucide-list-ordered" :aria-label="t('ipam.addresses')" @click="openAddresses(row)" />
        <UButton v-if="row.kind === 'network'" size="xs" color="neutral" variant="ghost" icon="i-lucide-brackets" :aria-label="t('ipam.pools')" @click="openPools(row)" />
        <UButton v-if="canWrite" size="xs" color="neutral" variant="ghost" icon="i-lucide-pencil" :aria-label="t('common.edit')" @click="openForm('net', row)" />
        <UButton v-if="canWrite" size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" @click="removeNet(row)" />
      </template>
    </DenseTable>

    <!-- Pools -->
    <DenseTable v-else-if="tab === 'pools'" :rows="poolRows" :columns="poolCols" :loading="poolsPending" export-name="ipam-pools">
      <template #toolbar>
        <UButton v-if="canWrite" icon="i-lucide-plus" size="sm" :label="t('ipam.add_pool')" :disabled="!leafOptions.length" @click="openForm('pool')" />
        <UButton v-if="poolFilter" size="xs" color="neutral" variant="ghost" icon="i-lucide-filter-x" :label="t('ipam.all_networks')" @click="poolFilter = 0" />
      </template>
      <template #actions="{ row }">
        <UButton v-if="canWrite" size="xs" color="neutral" variant="ghost" icon="i-lucide-wand-sparkles" :aria-label="t('ipam.next_free')" @click="openNext(row.subnet_id, row.id)" />
        <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-list-ordered" :aria-label="t('ipam.addresses')" @click="openSubnet(row.subnet_id)" />
        <UButton v-if="canWrite" size="xs" color="neutral" variant="ghost" icon="i-lucide-pencil" :aria-label="t('common.edit')" @click="openForm('pool', row)" />
        <UButton v-if="canWrite" size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" @click="removePool(row)" />
      </template>
    </DenseTable>

    <!-- Adresses : toutes, tous réseaux -->
    <DenseTable v-else-if="tab === 'addresses'" :rows="addrs?.items ?? []" :columns="addrCols" :loading="addrsPending" export-name="ipam-adresses">
      <template #toolbar>
        <UInput v-model="addrQ" icon="i-lucide-search" size="sm" class="w-56" :placeholder="t('ipam.search_ph')" :aria-label="t('common.search')" />
        <USelect v-model="addrSubnet" size="sm" class="w-64" :items="[{ label: t('ipam.all_networks'), value: 0 }, ...leafOptions]" :aria-label="t('ipam.network')" />
        <USelect :model-value="addrStatus || 'all'" size="sm" class="w-40" :items="[{ label: t('ipam.all_status'), value: 'all' }, ...statusOptions]" :aria-label="t('common.status')" @update:model-value="addrStatus = $event === 'all' ? '' : $event" />
        <UButton v-if="canWrite" icon="i-lucide-plus" size="sm" :label="t('common.add')" :disabled="!leafOptions.length" @click="openForm('addr')" />
        <UButton v-if="canWrite" icon="i-lucide-wand-sparkles" size="sm" color="neutral" variant="outline" :label="t('ipam.next_free')" :disabled="!leafOptions.length" @click="openNext()" />
        <UButton icon="i-lucide-download" size="sm" color="neutral" variant="ghost" :label="t('ipam.export')" href="/api/ipam/export/addresses" external />
      </template>
      <template #actions="{ row }">
        <UButton v-if="canWrite" size="xs" color="neutral" variant="ghost" icon="i-lucide-pencil" :aria-label="t('common.edit')" @click="openForm('addr', row)" />
        <UButton v-if="canWrite" size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" @click="removeAddr(row)" />
      </template>
      <template #footer>
        <span v-if="addrs?.total > LIMIT">· {{ addrFrom }}–{{ addrTo }} / {{ addrs.total }}</span>
        <UButton v-if="addrOffset > 0" size="xs" color="neutral" variant="outline" icon="i-lucide-chevron-left" :aria-label="t('ipam.prev')" @click="addrOffset = Math.max(0, addrOffset - LIMIT)" />
        <UButton v-if="addrs && addrOffset + LIMIT < addrs.total" size="xs" color="neutral" variant="outline" icon="i-lucide-chevron-right" :aria-label="t('ipam.next')" @click="addrOffset += LIMIT" />
      </template>
    </DenseTable>

    <!-- Gabarits -->
    <DenseTable v-else-if="tab === 'templates'" :rows="templates?.items ?? []" :columns="tplCols" export-name="ipam-gabarits">
      <template #toolbar><UButton v-if="canWrite" icon="i-lucide-plus" size="sm" :label="t('ipam.add_template')" @click="openForm('tpl')" /><span class="text-xs text-muted">{{ t('ipam.tpl_intro') }}</span></template>
      <template #actions="{ row }">
        <UButton v-if="canWrite" size="xs" color="neutral" variant="ghost" icon="i-lucide-pencil" :aria-label="t('common.edit')" @click="openForm('tpl', tplRow(row))" />
        <UButton v-if="canWrite" size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" @click="removeTemplate(row)" />
      </template>
    </DenseTable>

    <ResourceTable v-else-if="tab === 'vlans'" endpoint="/ipam/vlans" :columns="vlanCols" :fields="vlanFields" :can-write="canWrite" create-url="/ipam/vlans" :update-url="(r: any) => `/ipam/vlans/${r.id}`" :delete-url="(r: any) => `/ipam/vlans/${r.id}`" :delete-name="(r: any) => r.name" @changed="refreshVlans" />
    <GhostAddresses v-else-if="tab === 'ghosts'" />
    <DiscoveryWizard v-else-if="tab === 'discovery' && canWrite" />
    <NetboxWizard v-else-if="tab === 'sources' && isAdmin" />
    <div v-else-if="tab === 'search'" class="flex flex-col gap-3">
      <UInput v-model="sq" icon="i-lucide-search" :placeholder="t('ipam.search_ph')" :aria-label="t('common.search')" class="w-96" autofocus />
      <div class="grid gap-4 lg:grid-cols-2">
        <UCard><template #header><span class="font-medium">{{ t('ipam.subnets') }} ({{ found.subnets.length }})</span></template>
          <ul class="text-sm flex flex-col gap-1"><li v-for="s in found.subnets" :key="s.id"><UButton variant="link" size="sm" :label="`${s.cidr} — ${s.name}`" class="font-mono" @click="openSubnet(s.id)" /></li></ul></UCard>
        <UCard><template #header><span class="font-medium">{{ t('ipam.addresses') }} ({{ found.addresses.length }})</span></template>
          <ul class="text-sm flex flex-col gap-1 max-h-96 overflow-auto"><li v-for="a in found.addresses" :key="a.id" class="font-mono text-xs"><UButton variant="link" size="xs" :label="a.ip" @click="openSubnet(a.subnet_id)" /> {{ a.hostname }} {{ a.mac }}</li></ul></UCard>
      </div>
    </div>

    <!-- Formulaires -->
    <EntityForm v-model:open="form.open" :title="form.row ? t('common.edit') : formTitle" :fields="formFields" :row="form.row" :submit="submitForm" />
    <UModal v-model:open="nextOpen" :title="t('ipam.next_free')" :description="t('ipam.next_desc')">
      <template #body><form class="flex flex-col gap-3" @submit.prevent="allocate">
        <UAlert v-if="nextErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="nextErr" />
        <UFormField :label="t('ipam.network')"><USelect v-model="nextState.subnet_id" :items="leafOptions" class="w-full" /></UFormField>
        <UFormField :label="t('ipam.pool')"><USelect v-model="nextState.pool_id" :items="nextPoolOptions" class="w-full" /></UFormField>
        <UFormField :label="t('ipam.hostname')"><UInput v-model="nextState.hostname" class="w-full" /></UFormField>
        <UFormField :label="t('common.status')"><USelect v-model="nextState.status" :items="statusOptions" class="w-full" /></UFormField>
        <UFormField :label="t('ipam.dns_sync')" :help="t('ipam.dns_sync_hint')"><USelect v-model="nextState.dns_zone_id" :items="zoneOptions" class="w-full" /></UFormField>
        <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="nextOpen = false" /><UButton type="submit" :label="t('ipam.allocate')" /></div></form></template>
    </UModal>
    <UModal v-model:open="moveOpen" :title="t('ipam.move_to_space')" :description="t('ipam.move_desc', { n: netSelected.length })">
      <template #body><form class="flex flex-col gap-3" @submit.prevent="bulkMove">
        <UAlert v-if="moveErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="moveErr" />
        <UFormField :label="t('ipam.space')"><USelect v-model="moveTo" :items="spaceOptions" class="w-full" /></UFormField>
        <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="moveOpen = false" /><UButton type="submit" :label="t('ipam.move')" /></div></form></template>
    </UModal>
  </div>
</template>
