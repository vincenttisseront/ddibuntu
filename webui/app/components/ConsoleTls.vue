<script setup lang="ts">
// Certificat HTTPS de la console, automatique et commun à tous les nœuds (0.21.0) : voir server/utils/console-tls.ts.
const { t } = useT(); const api = useApi(); const toast = useToast(); const fmt = useFmt()
const data = ref<any>(null), err = ref(''), busy = ref(false), loaded = ref(false)
const f = reactive({ auto: false, ca: '', names: '' })
const errOf = (e: any) => e?.info?.message ?? t('err.internal')
async function load(init = false) {
  try {
    const r: any = await api.call('GET', '/system/console-tls', undefined, { silent: true })
    data.value = r
    if (init || !loaded.value) { f.auto = r.auto; f.ca = r.ca; f.names = (r.names ?? []).join('\n') }
    err.value = ''
  } catch (e: any) { err.value = errOf(e) } finally { loaded.value = true }
}
const names = () => f.names.split(/[\s,;]+/).map((x) => x.trim().toLowerCase()).filter(Boolean)
async function save() {
  busy.value = true; err.value = ''
  try { data.value = await api.call('PUT', '/system/console-tls', { auto: f.auto, ca: f.ca, names: names() }, { silent: true }); toast.add({ title: t('tls.saved'), color: 'success', icon: 'i-lucide-check' }); await load(true) }
  catch (e: any) { err.value = errOf(e) } finally { busy.value = false }
}
async function issue(force: boolean) {
  busy.value = true; err.value = ''
  try { data.value = await api.call('POST', '/system/console-tls/issue', { force }, { silent: true }); toast.add({ title: t('tls.issued'), color: 'success', icon: 'i-lucide-check' }) }
  catch (e: any) { err.value = errOf(e) } finally { busy.value = false }
}
const issuers = computed<string[]>(() => data.value?.issuers ?? [])
const days = (ms: number) => Math.floor((ms - Date.now()) / 86_400_000)
onMounted(() => load(true))
</script>

<template>
  <UCard data-test="console-tls">
    <template #header><span class="font-medium">{{ t('tls.title') }}</span></template>
    <p class="text-sm text-muted mb-3">{{ t('tls.help') }}</p>
    <UAlert v-if="err" color="error" variant="subtle" :title="err" class="mb-3" data-test="console-tls-error" />
    <div v-if="loaded && data" class="flex flex-col gap-3">
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt class="text-muted">{{ t('tls.served') }}</dt>
        <dd data-test="console-tls-served">
          <template v-if="data.served"><UBadge :color="data.served.selfSigned ? 'warning' : 'success'" variant="subtle">{{ data.served.selfSigned ? t('tls.selfsigned') : t('tls.from_pki') }}</UBadge>
            <span class="font-mono text-xs ml-2">{{ data.served.subject }}</span> <span class="text-xs text-muted">· {{ t('tls.expires') }} {{ fmt.dateTime(new Date(data.served.notAfter).toISOString()) }}</span>
            <div class="text-xs text-muted font-mono">{{ [...data.served.dns, ...data.served.ip].join(', ') }}</div></template>
          <span v-else class="text-muted">—</span>
        </dd>
        <dt class="text-muted">{{ t('tls.cert') }}</dt>
        <dd data-test="console-tls-cert">
          <template v-if="data.cert"><span class="font-mono text-xs">{{ data.cert.serial }}</span> <span class="text-xs text-muted">· {{ t('tls.expires') }} {{ fmt.dateTime(new Date(data.cert.notAfter).toISOString()) }} ({{ t('tls.days_left', { n: days(data.cert.notAfter) }) }})</span>
            <div class="text-xs text-muted font-mono">{{ [...data.cert.dns, ...data.cert.ip].join(', ') }}</div></template>
          <span v-else class="text-muted">{{ t('tls.none') }}</span>
        </dd>
        <dt class="text-muted">{{ t('tls.wanted') }}</dt>
        <dd class="font-mono text-xs" data-test="console-tls-wanted">{{ [...data.want.dns, ...data.want.ip].join(', ') || '—' }}</dd>
      </dl>
      <UAlert v-if="data.want.truncated" color="warning" variant="subtle" :title="t('tls.truncated')" />
      <UAlert v-if="data.pending" color="info" variant="subtle" :title="t('tls.pending')" data-test="console-tls-pending" />
      <UAlert v-if="data.last && !data.last.ok" color="error" variant="subtle" :title="t('tls.last_fail', { msg: data.last.message })" data-test="console-tls-failed" />
      <UAlert v-if="!data.leader" color="neutral" variant="subtle" :title="t('tls.not_leader')" />
      <UAlert v-if="!issuers.length" color="warning" variant="subtle" :title="t('tls.no_issuer')" />
      <div class="grid gap-3 md:grid-cols-2">
        <UFormField :label="t('tls.ca')"><USelect v-model="f.ca" :items="issuers" class="w-full" :placeholder="t('enroll.ca_pick')" data-test="console-tls-ca" /></UFormField>
        <UFormField :label="t('tls.names')" :help="t('tls.names_help')"><UTextarea v-model="f.names" :rows="3" class="w-full font-mono" placeholder="console.example.org" data-test="console-tls-names" /></UFormField>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <USwitch v-model="f.auto" :label="t('tls.auto')" data-test="console-tls-auto" />
        <UButton icon="i-lucide-save" :loading="busy" :label="t('common.save')" data-test="console-tls-save" @click="save" />
        <UButton color="neutral" variant="outline" icon="i-lucide-refresh-cw" :loading="busy" :disabled="!data.auto || !data.leader" :label="t('tls.check')" data-test="console-tls-check" @click="issue(false)" />
        <UButton color="neutral" variant="outline" icon="i-lucide-badge-check" :loading="busy" :disabled="!data.auto || !data.leader" :label="t('tls.renew')" data-test="console-tls-renew" @click="issue(true)" />
      </div>
    </div>
  </UCard>
</template>
