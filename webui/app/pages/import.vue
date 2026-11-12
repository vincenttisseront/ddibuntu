<script setup lang="ts">
const { t } = useT(); const api = useApi(); const toast = useToast()
const { canWrite, isAdmin } = useRole()
const tab = useHashTab(isAdmin.value ? 'wizard' : 'dns', ['wizard', 'dns', 'dhcp', 'subnets', 'csv', 'ad', 'history'])
const baseTabs = computed(() => [{ label: t('import.t_dns'), value: 'dns', icon: 'i-lucide-globe' }, { label: t('import.t_dhcp'), value: 'dhcp', icon: 'i-lucide-server' }, { label: t('import.t_subnets'), value: 'subnets', icon: 'i-lucide-map-pinned' },
  { label: t('import.t_csv'), value: 'csv', icon: 'i-lucide-table' }, { label: t('import.t_ad'), value: 'ad', icon: 'i-lucide-key-round' }, { label: t('import.history'), value: 'history', icon: 'i-lucide-history' }])
const tabs = computed(() => [...(isAdmin.value ? [{ label: t('adw.title'), value: 'wizard', icon: 'i-lucide-wand-sparkles' }] : []), ...baseTabs.value])
const { data: zones } = await useFetch<any>('/api/dns/zones')
const primary = computed(() => (zones.value?.items ?? []).filter((z: any) => z.type === 'primary').map((z: any) => ({ label: z.name, value: z.id })))
const dnsExtra = reactive<any>({ zone_id: 0, mode: 'skip', apply_soa: false })
watch(primary, (p) => { if (!dnsExtra.zone_id && p.length) dnsExtra.zone_id = p[0].value }, { immediate: true })
const csvExtra = reactive<any>({ kind: 'subnets' })

const histCols = computed(() => [{ key: 'created_at', label: t('common.date'), kind: 'date' }, { key: 'kind', label: t('common.type'), kind: 'badge' }, { key: 'filename', label: t('import.file') }, { key: 'username', label: t('system.user') }, { key: 'summary', label: t('import.result'), kind: 'mono', fmt: (v: any) => JSON.stringify(v).slice(0, 160) }])

// ---- Active Directory (authentification LDAPS) ----
const { data: ad, refresh: refreshAd } = await useFetch<any>('/api/ad/settings', { server: false })
const f = reactive<any>({ enabled: false, urls: '', baseDn: '', bindDn: '', bindPassword: '', userAttr: 'sAMAccountName', groups: '', nestedGroups: true, tlsRejectUnauthorized: true, caPem: '' })
watch(ad, (s) => { if (!s) return; f.enabled = s.enabled; f.urls = (s.urls ?? []).join('\n'); f.baseDn = s.baseDn; f.bindDn = s.bindDn; f.userAttr = s.userAttr; f.groups = (s.groupMap ?? []).map((g: any) => `${g.groupDn} | ${g.role}${g.spaceIds?.length ? ' | ' + g.spaceIds.join(',') : ''}`).join('\n'); f.nestedGroups = s.nestedGroups; f.tlsRejectUnauthorized = s.tlsRejectUnauthorized; f.caPem = s.caPem ?? '' }, { immediate: true })
const adErr = ref(''), testRes = ref<any>(null), testUser = ref('')
const parseGroups = () => String(f.groups ?? '').split('\n').map((l) => l.trim()).filter(Boolean).map((l) => { const [dn, role, sp] = l.split('|').map((x) => x.trim()); const spaceIds = (sp ?? '').split(/[\s,;]+/).filter(Boolean).map(Number).filter((n) => Number.isInteger(n) && n > 0); return { groupDn: dn, role, ...(spaceIds.length ? { spaceIds } : {}) } })
async function saveAd() {
  adErr.value = ''
  try {
    await api.call('PUT', '/ad/settings', { enabled: f.enabled, urls: String(f.urls).split(/\s+/).filter(Boolean), baseDn: f.baseDn, bindDn: f.bindDn, ...(f.bindPassword ? { bindPassword: f.bindPassword } : {}), userAttr: f.userAttr, groupMap: parseGroups(), nestedGroups: f.nestedGroups, tlsRejectUnauthorized: f.tlsRejectUnauthorized, caPem: f.caPem })
    f.bindPassword = ''; toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await refreshAd()
  } catch (e: any) { adErr.value = e.info?.message ?? t('err.internal') }
}
async function testAd() { testRes.value = null; try { testRes.value = await api.call('POST', '/ad/test', testUser.value ? { username: testUser.value } : {}) } catch (e: any) { testRes.value = { ok: false, step: 'error', message: e.info?.message } } }
</script>

<template>
  <div class="flex flex-col gap-3">
    <UTabs v-model="tab" :items="tabs" :content="false" :aria-label="t('nav.import')" />
    <p v-if="!canWrite" class="text-sm text-muted">{{ t('import.readonly') }}</p>
    <AdWizard v-else-if="tab === 'wizard'" />
    <ImportPanel v-else-if="tab === 'dns'" preview-url="/import/dns/preview" commit-url="/import/dns/commit" :extra="dnsExtra" accept=".dns,.txt,.zone,text/plain" :hint="t('import.dns_hint')">
      <UFormField :label="t('dns.zone')"><USelect v-model="dnsExtra.zone_id" :items="primary" class="w-full" /></UFormField>
      <UFormField :label="t('import.mode')" :help="t('import.mode_hint')"><USelect v-model="dnsExtra.mode" :items="[{ label: t('import.mode_skip'), value: 'skip' }, { label: t('import.mode_replace'), value: 'replace', disabled: !isAdmin }]" class="w-full" /></UFormField>
      <USwitch v-model="dnsExtra.apply_soa" :label="t('import.apply_soa')" />
    </ImportPanel>
    <ImportPanel v-else-if="tab === 'dhcp'" preview-url="/import/dhcp/preview" commit-url="/import/dhcp/commit" accept=".xml,text/xml" :hint="t('import.dhcp_hint')" />
    <ImportPanel v-else-if="tab === 'subnets'" preview-url="/import/ad-subnets/preview" commit-url="/import/ad-subnets/commit" accept=".csv,text/csv" :hint="t('import.subnets_hint')" />
    <ImportPanel v-else-if="tab === 'csv'" commit-url="/import/ipam-csv/commit" :extra="csvExtra" accept=".csv,text/csv" :hint="t('import.csv_hint')">
      <UFormField :label="t('common.type')"><USelect v-model="csvExtra.kind" :items="[{ label: t('ipam.subnets'), value: 'subnets' }, { label: t('ipam.addresses'), value: 'addresses' }]" class="w-full" /></UFormField>
    </ImportPanel>
    <div v-else-if="tab === 'ad'" class="grid gap-4 lg:grid-cols-2">
      <UCard><template #header><span class="font-medium">{{ t('ad.title') }}</span></template>
        <form class="flex flex-col gap-3" @submit.prevent="saveAd">
          <p class="text-sm text-muted">{{ t('ad.desc') }}</p>
          <UAlert v-if="adErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="adErr" />
          <USwitch v-model="f.enabled" :label="t('ad.enabled')" :disabled="!isAdmin" />
          <UFormField :label="t('ad.urls')" :help="t('ad.urls_hint')"><UTextarea v-model="f.urls" :rows="2" class="w-full font-mono" :disabled="!isAdmin" placeholder="ldaps://dc01.corp.example.com" /></UFormField>
          <UFormField label="Base DN"><UInput v-model="f.baseDn" class="w-full font-mono" :disabled="!isAdmin" placeholder="DC=corp,DC=example,DC=com" /></UFormField>
          <UFormField :label="t('ad.bind_dn')"><UInput v-model="f.bindDn" class="w-full font-mono" :disabled="!isAdmin" placeholder="CN=svc-ddi,OU=Services,DC=corp,DC=example,DC=com" /></UFormField>
          <UFormField :label="t('ad.bind_password')" :help="ad?.bindPasswordSet ? t('ad.password_set') : ''"><UInput v-model="f.bindPassword" type="password" autocomplete="new-password" class="w-full" :disabled="!isAdmin" /></UFormField>
          <UFormField :label="t('ad.user_attr')"><USelect v-model="f.userAttr" :items="[{ label: 'sAMAccountName', value: 'sAMAccountName' }, { label: 'userPrincipalName', value: 'userPrincipalName' }]" class="w-full" :disabled="!isAdmin" /></UFormField>
          <UFormField :label="t('ad.groups')" :help="t('ad.groups_hint')"><UTextarea v-model="f.groups" :rows="3" class="w-full font-mono" :disabled="!isAdmin" placeholder="CN=DDI-Admins,OU=Groupes,DC=corp,DC=example,DC=com | admin" /></UFormField>
          <USwitch v-model="f.nestedGroups" :label="t('ad.nested')" :disabled="!isAdmin" />
          <USwitch v-model="f.tlsRejectUnauthorized" :label="t('ad.tls_verify')" :disabled="!isAdmin" />
          <UFormField :label="t('ad.ca')" :help="t('ad.ca_hint')"><UTextarea v-model="f.caPem" :rows="3" class="w-full font-mono text-xs" :disabled="!isAdmin" /></UFormField>
          <div class="flex justify-end"><UButton v-if="isAdmin" type="submit" :label="t('common.save')" /></div>
        </form></UCard>
      <UCard><template #header><span class="font-medium">{{ t('ad.test') }}</span></template>
        <div class="flex flex-col gap-3"><p class="text-sm text-muted">{{ t('ad.test_desc') }}</p>
          <UFormField :label="t('ad.test_user')"><UInput v-model="testUser" class="w-full" :disabled="!isAdmin" /></UFormField>
          <UButton icon="i-lucide-plug-zap" color="neutral" variant="outline" :label="t('ad.test_do')" :disabled="!isAdmin" @click="testAd" />
          <UAlert v-if="testRes" :color="testRes.ok ? 'success' : 'error'" variant="subtle" :icon="testRes.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert'" :title="testRes.ok ? t('ad.ok') : t('ad.fail')" :description="t(`ad.step.${testRes.step}`)" aria-live="polite" /></div></UCard>
    </div>
    <ResourceTable v-else endpoint="/import/runs" :columns="histCols" />
  </div>
</template>
