<script setup lang="ts">
// Export des journaux vers un SIEM : destinations (syslog UDP/TCP/TLS ou HTTPS), format (RFC 5424, RFC 3164, CEF, LEEF, JSON) et flux choisis.
import type { DCol } from '~/components/DenseTable.vue'
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { data, refresh } = await useFetch<any>('/api/siem/targets')
const SOURCES = ['audit', 'dns_queries', 'dns_blocked', 'alerts', 'deployments'] as const
const FORMATS = ['rfc5424', 'rfc3164', 'cef', 'leef', 'json'] as const
const PORTS: Record<string, number> = { udp: 514, tcp: 514, tls: 6514, https: 443 }
const blank = () => ({ id: 0, name: '', enabled: true, protocol: 'tcp', host: '', port: 514 as number | null, url: '', format: 'rfc5424', framing: 'newline', facility: 16, sources: ['audit'] as string[], tls_verify: true, auth_prefix: 'Bearer', secret: '', has_secret: false })
const f = reactive(blank())
const open = ref(false), busy = ref(false), err = ref(''), testing = ref<number | null>(null), running = ref(false)
const protoItems = computed(() => (['udp', 'tcp', 'tls', 'https'] as const).map((v) => ({ label: t(`siem.proto.${v}`), value: v })))
const fmtItems = computed(() => FORMATS.map((v) => ({ label: t(`siem.fmt.${v}`), value: v })))
const framingItems = computed(() => [{ label: t('siem.framing.newline'), value: 'newline' }, { label: t('siem.framing.octet'), value: 'octet' }])
const facilityItems = computed(() => Array.from({ length: 24 }, (_, i) => ({ label: i >= 16 ? `local${i - 16} (${i})` : `${i}`, value: i })))
const isHttps = computed(() => f.protocol === 'https'), isStream = computed(() => f.protocol === 'tcp' || f.protocol === 'tls')
const srcLabel = (s: string) => t(`siem.src.${s}`)
const valid = computed(() => f.name.trim() !== '' && f.sources.length > 0 && (isHttps.value ? /^https?:\/\//i.test(f.url) : f.host.trim() !== '' && !!f.port))
watch(() => f.protocol, (p, o) => { if (open.value && o && f.port === PORTS[o]) f.port = PORTS[p]!; if (p === 'udp') f.framing = 'newline' })
const toggle = (s: string) => { f.sources = f.sources.includes(s) ? f.sources.filter((x) => x !== s) : [...f.sources, s] }

function begin(row?: any) {
  Object.assign(f, blank(), row ? { ...row, sources: [...(row.sources ?? [])], secret: '', port: row.port ?? PORTS[row.protocol] } : {})
  err.value = ''; open.value = true
}
async function save() {
  busy.value = true; err.value = ''
  const body: any = { name: f.name.trim(), enabled: f.enabled, protocol: f.protocol, host: isHttps.value ? '' : f.host.trim(), port: isHttps.value ? null : Number(f.port), url: isHttps.value ? f.url.trim() : '',
    format: f.format, framing: isStream.value ? f.framing : 'newline', facility: Number(f.facility), sources: f.sources, tls_verify: f.tls_verify, auth_prefix: f.auth_prefix }
  if (isHttps.value && f.secret) body.secret = f.secret
  try {
    if (f.id) await api.call('PUT', `/siem/targets/${f.id}`, body); else await api.call('POST', '/siem/targets', body)
    open.value = false; toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await refresh()
  } catch (e: any) { err.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function remove(row: any) {
  if (!(await ask(t('siem.delete'), t('siem.delete_confirm', { name: row.name }), true))) return
  try { await api.call('DELETE', `/siem/targets/${row.id}`); toast.add({ title: t('common.deleted'), color: 'success', icon: 'i-lucide-check' }); await refresh() }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) }
}
async function test(row: any) {
  testing.value = row.id
  try {
    const r: any = await api.call('POST', `/siem/targets/${row.id}/test`, {}, { busy: true })
    toast.add({ title: r.ok ? t('siem.test_ok', { name: row.name }) : t('siem.test_ko', { name: row.name, detail: r.detail }), color: r.ok ? 'success' : 'error', icon: r.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) } finally { testing.value = null }
}
async function toggleEnabled(row: any) {
  try { await api.call('PUT', `/siem/targets/${row.id}`, { name: row.name, enabled: !row.enabled, protocol: row.protocol, host: row.host, port: row.port, url: row.url, format: row.format, framing: row.framing, facility: row.facility, sources: row.sources, tls_verify: row.tls_verify, auth_prefix: row.auth_prefix }); await refresh() }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) }
}
async function runNow() {
  running.value = true
  try { const r: any = await api.call('POST', '/siem/run', {}, { busy: true }); toast.add({ title: t('siem.run_done', { n: r.sent }), color: r.failed ? 'warning' : 'success', icon: 'i-lucide-send' }); await refresh() }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) } finally { running.value = false }
}

const cols = computed<DCol[]>(() => [
  { key: 'name', label: t('common.name') }, { key: 'dest', label: t('siem.dest'), kind: 'mono' }, { key: 'format_l', label: t('siem.format') }, { key: 'src_l', label: t('siem.sources') },
  { key: 'state', label: t('common.status') }, { key: 'sent', label: t('siem.sent'), kind: 'num' }, { key: 'last', label: t('siem.last') },
])
const rows = computed(() => (data.value?.items ?? []).map((r: any) => ({
  ...r, dest: r.protocol === 'https' ? r.url : `${r.protocol}://${r.host}:${r.port}`, format_l: t(`siem.fmt.${r.format}`), src_l: (r.sources ?? []).map(srcLabel).join(', '),
  state: !r.enabled ? t('siem.st_off') : r.last_ok === false ? t('siem.st_error') : r.last_ok ? t('siem.st_ok') : t('siem.st_wait'),
  last: r.last_error ? r.last_error : r.last_at ? new Date(r.last_at).toLocaleString() : '—',
})))
</script>

<template>
  <div class="flex flex-col gap-3">
    <UAlert color="neutral" variant="subtle" icon="i-lucide-radar" :title="t('siem.title')" :description="t('siem.intro')" />
    <div class="flex flex-wrap gap-2">
      <UButton icon="i-lucide-plus" :label="t('siem.add')" data-test="siem-add" @click="begin()" />
      <UButton icon="i-lucide-send" color="neutral" variant="outline" :label="t('siem.run')" :loading="running" :disabled="!rows.length" @click="runNow" />
    </div>
    <DenseTable :rows="rows" :columns="cols" export-name="siem">
      <template #cell-state="{ row }"><UBadge size="sm" variant="subtle" :color="!row.enabled ? 'neutral' : row.last_ok === false ? 'error' : row.last_ok ? 'success' : 'info'" :label="row.state" /></template>
      <template #actions="{ row }">
        <div class="flex items-center justify-end gap-0.5">
          <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-plug-zap" :aria-label="t('siem.test')" :title="t('siem.test')" :loading="testing === row.id" @click="test(row)" />
          <UButton size="xs" color="neutral" variant="ghost" :icon="row.enabled ? 'i-lucide-pause' : 'i-lucide-play'" :aria-label="row.enabled ? t('siem.disable') : t('siem.enable')" :title="row.enabled ? t('siem.disable') : t('siem.enable')" @click="toggleEnabled(row)" />
          <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-pencil" :aria-label="t('common.edit')" @click="begin(row)" />
          <UButton size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" @click="remove(row)" />
        </div>
      </template>
    </DenseTable>
    <p v-if="!rows.length" class="text-sm text-muted">{{ t('siem.none') }}</p>

    <UModal v-model:open="open" :dismissible="!busy" :title="f.id ? t('siem.edit') : t('siem.add')" :description="t('siem.form_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="save">
          <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" />
          <div class="grid grid-cols-2 gap-3">
            <UFormField :label="t('common.name')" required><UInput v-model="f.name" class="w-full" autocomplete="off" :disabled="busy" data-test="siem-name" /></UFormField>
            <UFormField :label="t('siem.protocol')"><USelect v-model="f.protocol" :items="protoItems" class="w-full" :disabled="busy" /></UFormField>
          </div>
          <div v-if="!isHttps" class="grid grid-cols-3 gap-3">
            <UFormField class="col-span-2" :label="t('siem.host')" required><UInput v-model="f.host" class="w-full font-mono" autocomplete="off" placeholder="siem.example.com" :disabled="busy" data-test="siem-host" /></UFormField>
            <UFormField :label="t('siem.port')" required><UInput v-model.number="f.port" type="number" class="w-full" :disabled="busy" /></UFormField>
          </div>
          <template v-else>
            <UFormField :label="t('siem.url')" required :hint="t('siem.url_hint')"><UInput v-model="f.url" class="w-full font-mono" autocomplete="off" placeholder="https://splunk.example.com:8088/services/collector/raw" :disabled="busy" data-test="siem-url" /></UFormField>
            <div class="grid grid-cols-3 gap-3">
              <UFormField :label="t('siem.auth_prefix')"><UInput v-model="f.auth_prefix" class="w-full" autocomplete="off" placeholder="Bearer" :disabled="busy" /></UFormField>
              <UFormField class="col-span-2" :label="t('siem.secret')" :hint="f.has_secret ? t('siem.secret_set') : undefined"><UInput v-model="f.secret" type="password" class="w-full" autocomplete="new-password" :placeholder="f.has_secret ? '••••••••' : ''" :disabled="busy" /></UFormField>
            </div>
          </template>
          <div class="grid grid-cols-3 gap-3">
            <UFormField :label="t('siem.format')"><USelect v-model="f.format" :items="fmtItems" class="w-full" :disabled="busy" /></UFormField>
            <UFormField v-if="isStream" :label="t('siem.framing')"><USelect v-model="f.framing" :items="framingItems" class="w-full" :disabled="busy" /></UFormField>
            <UFormField v-if="!isHttps" :label="t('siem.facility')"><USelect v-model="f.facility" :items="facilityItems" class="w-full" :disabled="busy" /></UFormField>
          </div>
          <UFormField :label="t('siem.sources')" required :hint="t('siem.sources_hint')">
            <ul class="flex flex-col gap-1 rounded-md border border-default p-2" role="group" :aria-label="t('siem.sources')">
              <li v-for="s in SOURCES" :key="s">
                <label class="flex items-start gap-2 text-sm cursor-pointer"><input type="checkbox" class="mt-1" :checked="f.sources.includes(s)" :disabled="busy" :data-test="`siem-src-${s}`" @change="toggle(s)">
                  <span><span class="font-medium">{{ srcLabel(s) }}</span><span class="block text-xs text-muted">{{ t(`siem.src_desc.${s}`) }}</span></span></label>
              </li>
            </ul>
          </UFormField>
          <div class="flex flex-wrap gap-4">
            <UCheckbox v-if="f.protocol === 'tls' || f.protocol === 'https'" v-model="f.tls_verify" :label="t('siem.tls_verify')" :disabled="busy" />
            <UCheckbox v-model="f.enabled" :label="t('siem.enabled')" :disabled="busy" />
          </div>
          <p class="text-xs text-muted">{{ t('siem.from_now') }}</p>
          <div class="flex justify-end gap-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" :disabled="busy" @click="open = false" />
            <UButton type="submit" :label="t('common.save')" :loading="busy" :disabled="!valid" data-test="siem-save" />
          </div>
        </form>
      </template>
    </UModal>
  </div>
</template>
