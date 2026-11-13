<script setup lang="ts">
// Vérification avant bascule (0.12.5) : export DHCP Windows ↔ étendues de la console, réponses DNS du serveur Windows ↔ de notre BIND. Lecture seule.
const { t } = useT(); const api = useApi()
const props = defineProps<{ admin: boolean }>()
const emit = defineEmits<{ done: [] }>()
const dhcp = ref(''), dres = ref<any>(null), dbusy = ref(false), derr = ref('')
const server = ref(''), ddi = ref('127.0.0.1'), nres = ref<any>(null), nbusy = ref(false), nerr = ref('')
async function pick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]; if (!f) return
  if (f.size > 25 * 1024 * 1024) { derr.value = t('err.too_large'); return }
  dhcp.value = await f.text(); dres.value = null; derr.value = ''
}
const KIND = computed<Record<string, string>>(() => ({
  scope_missing: t('mv.k_scope_missing'), scope_extra: t('mv.k_scope_extra'), lease_differs: t('mv.k_lease_differs'), state_differs: t('mv.k_state_differs'),
  pool_missing: t('mv.k_pool_missing'), pool_extra: t('mv.k_pool_extra'), reservation_missing: t('mv.k_reservation_missing'),
  reservation_extra: t('mv.k_reservation_extra'), reservation_differs: t('mv.k_reservation_differs'), option_differs: t('mv.k_option_differs'),
}))
async function runDhcp() {
  dbusy.value = true; derr.value = ''; dres.value = null
  try { dres.value = await api.call('POST', '/migration/verify/dhcp', { content: dhcp.value }, { silent: true }); emit('done') }
  catch (e: any) { derr.value = e?.info?.message ?? t('err.internal') } finally { dbusy.value = false }
}
async function runDns() {
  nbusy.value = true; nerr.value = ''; nres.value = null
  try { nres.value = await api.call('POST', '/migration/verify/dns', { server: server.value.trim(), ddi: ddi.value.trim() || undefined }, { silent: true }); emit('done') }
  catch (e: any) { nerr.value = e?.info?.message ?? t('err.internal') } finally { nbusy.value = false }
}
const show = (a: string[] | null) => (a === null ? t('mv.silent') : a.length ? a.join(' | ') : t('mv.empty'))
</script>

<template>
  <div class="flex flex-col gap-4 rounded-md bg-elevated/50 p-3">
    <div class="flex flex-col gap-2">
      <div class="font-medium text-sm">{{ t('mv.dhcp_title') }}</div>
      <UFormField :label="t('mia.f_dhcp')" :help="t('mv.dhcp_help')"><input type="file" accept=".xml,text/xml" class="block w-full text-sm" :aria-label="t('mia.f_dhcp')" data-test="mv-dhcp" @change="pick"></UFormField>
      <div><UButton icon="i-lucide-scale" :label="t('mv.run_dhcp')" :loading="dbusy" :disabled="!dhcp" data-test="mv-run-dhcp" @click="runDhcp" /></div>
      <UAlert v-if="derr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="derr" role="alert" />
      <template v-if="dres">
        <UAlert v-if="!dres.findings.length" color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('mv.dhcp_ok', { n: dres.scopes })" data-test="mv-dhcp-ok" />
        <ul v-else class="flex flex-col gap-1" data-test="mv-dhcp-list">
          <li v-for="(f, i) in dres.findings" :key="i" class="text-sm flex flex-wrap gap-2 rounded-md border border-default p-2"><UBadge color="warning" variant="subtle" :label="KIND[f.kind] ?? f.kind" /><span class="font-mono">{{ f.scope }}</span><span class="font-mono text-muted">{{ f.detail }}</span></li>
        </ul>
      </template>
    </div>
    <div v-if="props.admin" class="flex flex-col gap-2">
      <div class="font-medium text-sm">{{ t('mv.dns_title') }}</div>
      <div class="grid gap-3 md:grid-cols-2">
        <UFormField :label="t('mv.win_server')" :help="t('mv.win_server_h')"><UInput v-model="server" class="w-full" placeholder="192.0.2.1" data-test="mv-server" /></UFormField>
        <UFormField :label="t('mv.ddi_server')" :help="t('mv.ddi_server_h')"><UInput v-model="ddi" class="w-full" data-test="mv-ddi" /></UFormField>
      </div>
      <div><UButton icon="i-lucide-scale" :label="t('mv.run_dns')" :loading="nbusy" :disabled="!server.trim()" data-test="mv-run-dns" @click="runDns" /></div>
      <UAlert v-if="nerr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="nerr" role="alert" />
      <template v-if="nres">
        <UAlert v-if="!nres.diffs.length" color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('mv.dns_ok', { n: nres.checked })" data-test="mv-dns-ok" />
        <template v-else>
          <p class="text-sm text-muted">{{ t('mv.dns_diffs', { d: nres.diffs.length, n: nres.checked }) }}<span v-if="nres.truncated"> {{ t('mv.truncated') }}</span></p>
          <ul class="flex flex-col gap-1" data-test="mv-dns-list">
            <li v-for="(d, i) in nres.diffs" :key="i" class="text-sm rounded-md border border-default p-2"><span class="font-mono">{{ d.name }}</span> <UBadge color="neutral" variant="outline" :label="d.type" /><div class="text-muted font-mono">Windows : {{ show(d.windows) }}</div><div class="text-muted font-mono">DDI : {{ show(d.ddi) }}</div></li>
          </ul>
        </template>
      </template>
    </div>
  </div>
</template>
