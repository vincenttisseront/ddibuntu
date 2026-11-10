<script setup lang="ts">
// Assistant d'import Active Directory : connexion, sous-réseaux et sites (lus en direct par LDAP), DNS (transfert de zone), DHCP (export Windows), application.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const step = ref(0), busy = ref(false), error = ref(''), done = ref(false)
const steps = computed(() => [{ id: 'conn', label: t('adw.s_conn') }, { id: 'subnets', label: t('adw.s_subnets') }, { id: 'dns', label: t('adw.s_dns') }, { id: 'dhcp', label: t('adw.s_dhcp') }, { id: 'apply', label: t('adw.s_apply') }])
const fail = (e: any) => { error.value = e.info?.message ?? t('err.internal') }

const { data: ad } = useFetch<any>('/api/ad/settings', { server: false })
const configured = computed(() => !!ad.value?.urls?.length && !!ad.value?.bindDn && !!ad.value?.bindPasswordSet)
const test = ref<any>(null)
async function runTest() { busy.value = true; test.value = null; error.value = ''; try { test.value = await api.call('POST', '/ad/test', {}) } catch (e: any) { fail(e) } finally { busy.value = false } }

const disc = ref<any>(null), sel = reactive<Record<string, boolean>>({})
async function discover() {
  busy.value = true; error.value = ''
  try { const r: any = await api.call('POST', '/import/ad/discover', {}); disc.value = r; for (const k of Object.keys(sel)) delete sel[k]; for (const x of r.subnets) sel[x.cidr] = !x.exists; if (!dns.server) dns.server = r.dcs?.[0] ?? '' }
  catch (e: any) { fail(e) } finally { busy.value = false }
}
const chosen = computed(() => Object.keys(sel).filter((k) => sel[k]))
const setAll = (v: boolean) => { for (const x of disc.value?.subnets ?? []) if (!x.exists) sel[x.cidr] = v }

const dns = reactive({ skip: true, server: '', zone: '', create: true }), dnsPrev = ref<any>(null)
async function dnsPreview() {
  busy.value = true; error.value = ''; dnsPrev.value = null
  try { dnsPrev.value = await api.call('POST', '/import/ad/dns/preview', { server: dns.server, zone: dns.zone.trim() }) } catch (e: any) { fail(e) } finally { busy.value = false }
}
const results = ref<any[]>([])
async function apply() {
  if (!(await ask(t('adw.apply'), t('adw.apply_confirm'), false))) return
  busy.value = true; error.value = ''; results.value = []
  try {
    if (chosen.value.length) results.value.push({ kind: 'subnets', r: await api.call('POST', '/import/ad/subnets', { cidrs: chosen.value }) })
    if (!dns.skip && dnsPrev.value) results.value.push({ kind: 'dns', r: await api.call('POST', '/import/ad/dns/commit', { server: dns.server, zone: dns.zone.trim(), create: dns.create }) })
    done.value = true; toast.add({ title: t('import.done'), color: 'success', icon: 'i-lucide-check' })
  } catch (e: any) { fail(e) } finally { busy.value = false }
}
async function undo(id: number) {
  if (!(await ask(t('restore.restore'), t('restore.undo_confirm'), true))) return
  try { await api.call('POST', `/snapshots/${id}/restore`, {}); toast.add({ title: t('restore.done'), color: 'success', icon: 'i-lucide-check' }); results.value = [] } catch (e: any) { fail(e) }
}
const canNext = computed(() => [configured.value && !!test.value?.ok, !!disc.value, dns.skip || !!dnsPrev.value, true, !done.value && (chosen.value.length > 0 || (!dns.skip && !!dnsPrev.value))][step.value] ?? false)
const PS = 'Export-DhcpServer -ComputerName <SERVEUR> -File dhcp.xml -Leases'
</script>

<template>
  <WizardShell v-model="step" :steps="steps" :can-next="canNext" :busy="busy" :finish-label="t('adw.apply')" :hide-footer="done" @finish="apply">
    <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" class="mb-3" />
    <template #conn>
      <UCard><div class="flex flex-col gap-3 text-sm">
        <p class="text-muted">{{ t('adw.conn_desc') }}</p>
        <UAlert v-if="!configured" color="warning" variant="subtle" icon="i-lucide-plug-zap" :title="t('adw.not_configured')"><template #actions><UButton to="/import#ad" size="xs" color="warning" variant="outline" :label="t('adw.configure')" /></template></UAlert>
        <dl v-else class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1"><dt class="text-muted">{{ t('ad.urls') }}</dt><dd class="font-mono">{{ ad.urls.join(', ') }}</dd><dt class="text-muted">Base DN</dt><dd class="font-mono">{{ ad.baseDn }}</dd><dt class="text-muted">{{ t('ad.bind_dn') }}</dt><dd class="font-mono break-all">{{ ad.bindDn }}</dd></dl>
        <div><UButton icon="i-lucide-plug-zap" :disabled="!configured" :loading="busy" :label="t('ad.test_do')" @click="runTest" /></div>
        <UAlert v-if="test" :color="test.ok ? 'success' : 'error'" variant="subtle" :icon="test.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert'" :title="test.ok ? t('ad.ok') : t('ad.fail')" />
      </div></UCard>
    </template>
    <template #subnets>
      <UCard><div class="flex flex-col gap-3 text-sm">
        <p class="text-muted">{{ t('adw.subnets_desc') }}</p>
        <div><UButton icon="i-lucide-search" :loading="busy" :label="t('adw.read')" @click="discover" /></div>
        <template v-if="disc">
          <p class="num">{{ t('adw.found', { n: disc.subnets.length, s: disc.sites.length }) }}</p>
          <div class="flex gap-2"><UButton size="xs" color="neutral" variant="outline" :label="t('adw.select_new')" @click="setAll(true)" /><UButton size="xs" color="neutral" variant="outline" :label="t('adw.select_none')" @click="setAll(false)" /></div>
          <div class="overflow-auto max-h-72"><table class="w-full"><caption class="sr-only">{{ t('adw.s_subnets') }}</caption>
            <thead><tr class="text-muted"><th scope="col" class="p-1 w-8"><span class="sr-only">{{ t('adw.select') }}</span></th><th scope="col" class="text-start p-1">CIDR</th><th scope="col" class="text-start p-1">{{ t('ipam.site') }}</th><th scope="col" class="text-start p-1">{{ t('common.description') }}</th><th scope="col" class="p-1" /></tr></thead>
            <tbody><tr v-for="x in disc.subnets" :key="x.cidr" class="border-t border-default"><td class="p-1"><input v-model="sel[x.cidr]" type="checkbox" :disabled="x.exists" :aria-label="`${t('adw.select')} ${x.cidr}`"></td><td class="p-1 font-mono">{{ x.cidr }}</td><td class="p-1">{{ x.site }}</td><td class="p-1 text-muted">{{ x.description }}</td><td class="p-1"><UBadge v-if="x.exists" color="neutral" variant="subtle" :label="t('adw.exists')" /></td></tr></tbody></table></div>
          <p class="num text-muted">{{ t('adw.selected', { n: chosen.length }) }}</p>
        </template>
      </div></UCard>
    </template>
    <template #dns>
      <UCard><div class="flex flex-col gap-3 text-sm">
        <p class="text-muted">{{ t('adw.dns_desc') }}</p>
        <USwitch v-model="dns.skip" :label="t('adw.dns_skip')" @update:model-value="dnsPrev = null" />
        <template v-if="!dns.skip">
          <UFormField :label="t('adw.dc')"><USelect v-model="dns.server" :items="(disc?.dcs ?? []).map((d: string) => ({ label: d, value: d }))" class="w-full" /></UFormField>
          <UFormField :label="t('dns.zone')" :help="t('adw.zone_hint')"><UInput v-model="dns.zone" class="w-full font-mono" placeholder="corp.example.com" @update:model-value="dnsPrev = null" /></UFormField>
          <USwitch v-model="dns.create" :label="t('adw.create_zone')" />
          <div><UButton icon="i-lucide-search-check" color="neutral" variant="outline" :disabled="!dns.zone || !dns.server" :loading="busy" :label="t('import.analyse')" @click="dnsPreview" /></div>
          <UAlert v-if="dnsPrev" color="info" variant="subtle" icon="i-lucide-info" :title="t('adw.dns_found', { n: dnsPrev.total, c: dnsPrev.adCritical })" :description="dnsPrev.zoneExists ? t('adw.zone_exists') : t('adw.zone_new')" />
        </template>
      </div></UCard>
    </template>
    <template #dhcp>
      <UCard><div class="flex flex-col gap-3 text-sm">
        <p class="text-muted">{{ t('adw.dhcp_desc') }}</p>
        <pre class="rounded bg-elevated p-2 font-mono text-xs overflow-auto">{{ PS }}</pre>
        <ImportPanel preview-url="/import/dhcp/preview" commit-url="/import/dhcp/commit" accept=".xml,text/xml" :hint="t('import.dhcp_hint')" />
      </div></UCard>
    </template>
    <template #apply>
      <UCard><div class="flex flex-col gap-3 text-sm">
        <template v-if="!done">
          <p>{{ t('adw.summary') }}</p>
          <ul class="list-disc ps-5"><li class="num">{{ t('adw.sum_subnets', { n: chosen.length }) }}</li><li v-if="!dns.skip && dnsPrev" class="num">{{ t('adw.sum_dns', { z: dns.zone, n: dnsPrev.total }) }}</li></ul>
          <UAlert color="info" variant="subtle" icon="i-lucide-undo-2" :title="t('restore.auto_point')" />
        </template>
        <template v-else>
          <UAlert color="success" variant="subtle" icon="i-lucide-check" :title="t('import.done')" />
          <ul class="flex flex-col gap-2"><li v-for="x in results" :key="x.kind" class="flex items-center gap-3"><span class="font-medium">{{ t(`adw.k_${x.kind}`) }}</span><span class="font-mono text-xs text-muted flex-1">{{ JSON.stringify(Object.fromEntries(Object.entries(x.r).filter(([k, v]) => typeof v !== 'object' && k !== 'snapshotId'))) }}</span>
            <UButton v-if="x.r.snapshotId" size="xs" color="neutral" variant="outline" icon="i-lucide-undo-2" :label="t('restore.undo')" @click="undo(x.r.snapshotId)" /></li></ul>
          <UAlert color="warning" variant="subtle" icon="i-lucide-rocket" :title="t('adw.deploy_hint')"><template #actions><UButton to="/dns#deploy" size="xs" color="warning" variant="outline" :label="t('apply.deploy')" /></template></UAlert>
        </template>
      </div></UCard>
    </template>
  </WizardShell>
</template>
