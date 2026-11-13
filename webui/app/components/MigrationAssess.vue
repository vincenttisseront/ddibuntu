<script setup lang="ts">
// Évaluation de compatibilité (0.12.1) : dépôt de l'export DHCP (XML) et/ou de l'inventaire DNS (CSV) → rapport repris / adapté / non pris en charge. Lecture seule.
const { t } = useT(); const api = useApi()
const emit = defineEmits<{ done: [] }>()
const dhcp = ref(''), zones = ref(''), names = reactive({ dhcp: '', zones: '' })
const res = ref<any>(null), busy = ref(false), err = ref('')
async function pick(e: Event, k: 'dhcp' | 'zones') {
  const f = (e.target as HTMLInputElement).files?.[0]; if (!f) return
  if (f.size > 25 * 1024 * 1024) { err.value = t('err.too_large'); return }
  const txt = await f.text()
  if (k === 'dhcp') dhcp.value = txt; else zones.value = txt
  names[k] = f.name; res.value = null; err.value = ''
}
const TXT = computed<Record<string, { label: string; hint: string }>>(() => ({
  dhcp_scopes: { label: t('mia.dhcp_scopes'), hint: t('mia.dhcp_scopes_h') }, dhcp_reservations: { label: t('mia.dhcp_reservations'), hint: t('mia.dhcp_reservations_h') },
  dhcp_invalid: { label: t('mia.dhcp_invalid'), hint: t('mia.dhcp_invalid_h') }, dhcp_options: { label: t('mia.dhcp_options'), hint: t('mia.dhcp_options_h') },
  dhcp_policies: { label: t('mia.dhcp_policies'), hint: t('mia.dhcp_policies_h') }, dhcp_classes: { label: t('mia.dhcp_classes'), hint: t('mia.dhcp_classes_h') },
  dhcp_filters: { label: t('mia.dhcp_filters'), hint: t('mia.dhcp_filters_h') }, dhcp_failover: { label: t('mia.dhcp_failover'), hint: t('mia.dhcp_failover_h') },
  dhcp_superscopes: { label: t('mia.dhcp_superscopes'), hint: t('mia.dhcp_superscopes_h') }, dhcp_ipv6: { label: t('mia.dhcp_ipv6'), hint: t('mia.dhcp_ipv6_h') },
  dhcp_leases: { label: t('mia.dhcp_leases'), hint: t('mia.dhcp_leases_h') },
  dns_primary: { label: t('mia.dns_primary'), hint: t('mia.dns_primary_h') }, dns_reverse: { label: t('mia.dns_reverse'), hint: t('mia.dns_reverse_h') },
  dns_ds: { label: t('mia.dns_ds'), hint: t('mia.dns_ds_h') }, dns_secondary: { label: t('mia.dns_secondary'), hint: t('mia.dns_secondary_h') },
  dns_stub: { label: t('mia.dns_stub'), hint: t('mia.dns_stub_h') }, dns_forwarder: { label: t('mia.dns_forwarder'), hint: t('mia.dns_forwarder_h') },
  dns_signed: { label: t('mia.dns_signed'), hint: t('mia.dns_signed_h') }, dns_secure_update: { label: t('mia.dns_secure_update'), hint: t('mia.dns_secure_update_h') },
  dns_ad_critical: { label: t('mia.dns_ad_critical'), hint: t('mia.dns_ad_critical_h') },
}))
const ERR = computed<Record<string, string>>(() => ({ dhcp_xml_invalid: t('mia.e_dhcp_xml_invalid'), dhcp_no_ipv4: t('mia.e_dhcp_no_ipv4'), dns_csv_invalid: t('mia.e_dns_csv_invalid') }))
const LEVEL = computed<Record<string, { label: string; color: string; icon: string }>>(() => ({
  ok: { label: t('mia.l_ok'), color: 'success', icon: 'i-lucide-circle-check' }, adapted: { label: t('mia.l_adapted'), color: 'warning', icon: 'i-lucide-wrench' }, unsupported: { label: t('mia.l_unsupported'), color: 'error', icon: 'i-lucide-circle-x' },
}))
async function run() {
  busy.value = true; err.value = ''; res.value = null
  try { res.value = await api.call('POST', '/migration/assess', { ...(dhcp.value ? { dhcp: dhcp.value } : {}), ...(zones.value ? { zones: zones.value } : {}) }, { silent: true }); emit('done') }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
const verdict = computed(() => (res.value ? ({ ready: t('mia.v_ready'), review: t('mia.v_review'), blocked: t('mia.v_blocked') } as Record<string, string>)[res.value.verdict] : ''))
</script>

<template>
  <div class="flex flex-col gap-3 rounded-md bg-elevated/50 p-3">
    <div class="grid gap-3 md:grid-cols-2">
      <UFormField :label="t('mia.f_dhcp')" :help="t('mia.f_dhcp_h')"><input type="file" accept=".xml,text/xml" class="block w-full text-sm" :aria-label="t('mia.f_dhcp')" data-test="mia-dhcp" @change="(e) => pick(e, 'dhcp')"></UFormField>
      <UFormField :label="t('mia.f_zones')" :help="t('mia.f_zones_h')"><input type="file" accept=".csv,text/csv,text/plain" class="block w-full text-sm" :aria-label="t('mia.f_zones')" data-test="mia-zones" @change="(e) => pick(e, 'zones')"></UFormField>
    </div>
    <div><UButton icon="i-lucide-clipboard-check" :label="t('mia.run')" :loading="busy" :disabled="!dhcp && !zones" data-test="mia-run" @click="run" /></div>
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <template v-if="res">
      <UAlert v-for="e in res.errors" :key="e" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="ERR[e] ?? e" role="alert" />
      <div v-if="res.findings.length" class="flex flex-col gap-2">
        <div class="flex flex-wrap items-center gap-2" data-test="mia-verdict">
          <UBadge :color="res.verdict === 'ready' ? 'success' : 'warning'" variant="subtle" size="lg" :label="verdict" />
          <UBadge v-for="(l, k) in LEVEL" :key="k" :color="l.color as any" variant="outline" :label="`${l.label} : ${res.findings.filter((f: any) => f.level === k).length}`" />
        </div>
        <ul class="flex flex-col gap-2">
          <li v-for="f in res.findings" :key="f.code" class="flex gap-3 rounded-md border border-default p-3">
            <UIcon :name="LEVEL[f.level]!.icon" class="size-5 mt-0.5 shrink-0" :class="f.level === 'ok' ? 'text-success' : f.level === 'adapted' ? 'text-warning' : 'text-error'" />
            <div class="text-sm"><div class="font-medium">{{ TXT[f.code]?.label }} <span class="text-muted">· {{ f.count }}</span><span v-if="f.detail" class="font-mono text-muted"> ({{ f.detail }})</span></div><div class="text-muted">{{ TXT[f.code]?.hint }}</div></div>
          </li>
        </ul>
      </div>
    </template>
  </div>
</template>
