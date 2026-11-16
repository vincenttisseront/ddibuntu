<script setup lang="ts">
// Accès réseau — service RADIUS de CE nœud (0.13.0, itération 1) : état du service, déploiement, arrêt, test d'un Access-Request,
// clients (contrôleurs Wi-Fi, passerelles VPN, commutateurs) et, pour l'administrateur, l'annuaire Active Directory (0.13.1, composant RadiusDirectory)
// les certificats EAP-TLS (0.13.2, composant RadiusPki) et les règles d'accès (0.13.3, composant RadiusRules). Le service est piloté par root (ddibuntu-radius) à partir d'une demande
// déposée par la console : après chaque action on attend la publication du résultat (même mécanique que le pare-feu).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()
const { isAdmin } = useRole()
const tab = useHashTab('service', ['service', 'clients', 'directory', 'certs', 'rules'])
const tabs = computed(() => [{ label: t('radius.tab_service'), value: 'service', icon: 'i-lucide-radio-tower' }, { label: t('radius.tab_clients'), value: 'clients', icon: 'i-lucide-router' }, ...(isAdmin.value ? [{ label: t('radius.tab_directory'), value: 'directory', icon: 'i-lucide-network' }, { label: t('radius.tab_certs'), value: 'certs', icon: 'i-lucide-shield-check' }, { label: t('radius.tab_rules'), value: 'rules', icon: 'i-lucide-list-checks' }] : [])])

const data = ref<any>(null), busy = ref<'' | 'apply' | 'stop' | 'test'>(''), err = ref(''), probe = ref<any>(null)
const status = computed(() => data.value?.status ?? null)
const waiting = computed(() => !!busy.value || !!data.value?.requestPending)
const result = computed(() => data.value?.result ?? null)
async function load() { try { data.value = await api.call('GET', '/radius', undefined, { silent: true }) } catch (e: any) { err.value = e?.info?.message ?? '' } }
async function settle() {   // attend que root ait traité la demande (le résultat est publié, la demande disparaît)
  for (let i = 0; i < 40; i++) { await new Promise((r) => setTimeout(r, 1500)); await load(); if (!data.value?.requestPending) return }
}
async function act(kind: 'apply' | 'stop') {
  if (waiting.value) return
  const ok = kind === 'apply' ? await ask(t('radius.deploy_title'), t('radius.deploy_body'), false) : await ask(t('radius.stop_title'), t('radius.stop_body'), true)
  if (!ok) return
  busy.value = kind; err.value = ''; probe.value = null
  try { await api.call('POST', `/radius/${kind}`, {}); toast.add({ title: t('radius.sent'), color: 'success' }); await settle() }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
async function runTest() {
  if (waiting.value) return
  busy.value = 'test'; err.value = ''; probe.value = null
  try { probe.value = await api.call('POST', '/radius/test', {}) } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
const probeMsg = computed(() => {
  const p = probe.value
  if (!p) return null
  if (p.ok) return { color: p.reply === 'reject' ? 'success' : 'info', text: t(`radius.test_${p.reply}`, { ms: p.ms }) }
  return { color: 'warning', text: t(`radius.test_${p.error ?? 'timeout'}`) }
})
const resultText = computed(() => (result.value ? `${result.value.ok ? '✔' : '✖'} ${result.value.message}` : ''))

// ---- Clients ----
const clientCols = computed(() => [{ key: 'name', label: t('common.name'), kind: 'mono' }, { key: 'address', label: t('radius.cl_address'), kind: 'mono' }, { key: 'usage', label: t('radius.cl_usage'), kind: 'badge', trans: 'radius.u' }, { key: 'enabled', label: t('common.enabled'), kind: 'bool' }, { key: 'comment', label: t('common.description') }])
const USAGES = ['wifi', 'vpn', 'switch', 'other']
const clientFields = computed(() => [
  { key: 'name', label: t('common.name'), type: 'text', required: true, mono: true, hint: t('radius.cl_name_hint') },
  { key: 'address', label: t('radius.cl_address'), type: 'text', required: true, mono: true, hint: t('radius.cl_address_hint'), placeholder: '10.10.0.0/24' },
  { key: 'usage', label: t('radius.cl_usage'), type: 'select', options: USAGES.map((v) => ({ label: t(`radius.u.${v}`), value: v })), default: 'wifi' },
  { key: 'secret', label: t('radius.cl_secret'), type: 'password', hint: t('radius.cl_secret_hint') },
  { key: 'enabled', label: t('common.enabled'), type: 'switch', default: true },
  { key: 'comment', label: t('common.description'), type: 'text' },
] as any[])
const clientBody = (b: any) => ({ ...b, secret: b.secret || null, comment: b.comment || null })
const table = ref<any>(null)
const shown = reactive({ open: false, name: '', secret: '' })
function showSecret(name: string, secret: string) { Object.assign(shown, { open: true, name, secret }) }
function onSaved(ev: { editing: boolean; result: any }) {
  if (!ev.editing && ev.result?.secret) showSecret(String(ev.result.name ?? ''), ev.result.secret)
  void load()
}
async function regen(row: any) {
  if (!(await ask(t('radius.regen_title'), t('radius.regen_body', { name: row.name }), true))) return
  try { const r: any = await api.call('POST', `/radius/clients/${row.id}/secret`, {}); showSecret(row.name, r.secret); void load() } catch { /* message déjà affiché par api.call */ }
}
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
await load()
</script>

<template>
  <div class="flex flex-col gap-3">
    <UTabs v-model="tab" :items="tabs" :content="false" :aria-label="t('nav.radius')" />

    <div v-if="tab === 'service'" class="flex flex-col gap-3">
      <p class="text-sm text-muted">{{ t('radius.intro') }}</p>
      <UAlert v-if="status && !status.installed" color="warning" variant="subtle" icon="i-lucide-package-x" :title="t('radius.absent_title')" :description="t('radius.absent_body')" data-test="radius-absent" />
      <UCard>
        <template #header>
          <div class="flex items-center justify-between gap-2">
            <span class="font-medium">{{ t('radius.state') }}</span>
            <UBadge v-if="status" :color="status.active ? 'success' : 'neutral'" variant="subtle" :label="status.active ? t('radius.running') : t('radius.stopped')" data-test="radius-state" />
            <UBadge v-else color="neutral" variant="subtle" :label="t('radius.never')" data-test="radius-state" />
          </div>
        </template>
        <dl v-if="status" class="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-3 text-sm">
          <div><dt class="text-muted">{{ t('radius.package') }}</dt><dd>{{ status.installed ? t('radius.installed') : t('radius.absent') }}</dd></div>
          <div><dt class="text-muted">{{ t('radius.version') }}</dt><dd class="font-mono">{{ status.version || '—' }}</dd></div>
          <div><dt class="text-muted">{{ t('radius.boot') }}</dt><dd>{{ status.enabled ? t('common.yes') : t('common.no') }}</dd></div>
          <div><dt class="text-muted">{{ t('radius.clients_active') }}</dt><dd class="num">{{ status.clients }}</dd></div>
          <div><dt class="text-muted">{{ t('radius.eap') }}</dt><dd data-test="radius-eap">{{ status.eap?.enabled ? t('radius.eap_on') : t('radius.eap_off') }}</dd></div>
          <div><dt class="text-muted">{{ t('radius.rules_state') }}</dt><dd data-test="radius-rules-state">{{ status.authz?.enabled ? t('radius.rules_on', { n: status.authz.rules }) : t('radius.rules_off') }}</dd></div>
          <div><dt class="text-muted">{{ t('radius.ports') }}</dt><dd class="font-mono">1812, 1813</dd></div>
          <div><dt class="text-muted">{{ t('radius.read_at') }}</dt><dd>{{ fmt.dateTime(status.at * 1000) }}</dd></div>
        </dl>
        <p v-else class="text-sm text-muted">{{ t('radius.never_hint') }}</p>
        <p class="text-xs text-dimmed mt-3">{{ t('radius.node_note') }}</p>
        <p v-if="result" class="text-xs mt-2" :class="result.ok ? 'text-muted' : 'text-error'" data-test="radius-result">{{ t('radius.last') }} {{ fmt.dateTime(result.at * 1000) }} — {{ resultText }}</p>
        <p v-if="data?.requestPending" class="text-xs text-muted mt-2" role="status">{{ t('radius.pending') }}</p>
        <p v-if="data?.rules?.pending" class="text-xs text-warning mt-2" role="status" data-test="radius-rules-pending">{{ t('radius.rules_pending') }}</p>
        <p v-if="err" class="text-sm text-error mt-2" role="alert">{{ err }}</p>
        <div v-if="isAdmin" class="flex flex-wrap gap-2 mt-4">
          <UButton icon="i-lucide-rocket" :label="t('radius.deploy')" :loading="busy === 'apply'" :disabled="waiting && busy !== 'apply'" data-test="radius-apply" @click="act('apply')" />
          <UButton icon="i-lucide-power" color="neutral" variant="outline" :label="t('radius.stop')" :loading="busy === 'stop'" :disabled="waiting || !status?.active" data-test="radius-stop" @click="act('stop')" />
          <UButton icon="i-lucide-activity" color="neutral" variant="outline" :label="t('radius.test')" :loading="busy === 'test'" :disabled="waiting || !status?.active" data-test="radius-test" @click="runTest" />
        </div>
      </UCard>
      <UAlert v-if="probeMsg" :color="(probeMsg.color as any)" variant="subtle" :icon="probeMsg.color === 'warning' ? 'i-lucide-triangle-alert' : 'i-lucide-circle-check'" :title="probeMsg.text" data-test="radius-probe" />
      <p v-if="isAdmin" class="text-xs text-dimmed">{{ t('radius.test_hint') }}</p>
    </div>

    <RadiusDirectory v-else-if="tab === 'directory' && isAdmin" />
    <RadiusPki v-else-if="tab === 'certs' && isAdmin" :eap="status?.eap ?? null" />
    <RadiusRules v-else-if="tab === 'rules' && isAdmin" @changed="load" />

    <div v-else class="flex flex-col gap-3">
      <p class="text-sm text-muted">{{ t('radius.cl_help') }}</p>
      <ResourceTable ref="table" endpoint="/radius/clients" :columns="clientCols" :fields="clientFields" :can-write="isAdmin" create-url="/radius/clients" :update-url="(r: any) => `/radius/clients/${r.id}`" :delete-url="(r: any) => `/radius/clients/${r.id}`" :delete-name="(r: any) => r.name" :create-label="t('radius.cl_add')" :transform="clientBody" @saved="onSaved" @changed="load">
        <template v-if="isAdmin" #actions="{ row }"><UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-key-round" :aria-label="t('radius.regen')" :title="t('radius.regen')" @click="regen(row)" /></template>
      </ResourceTable>
      <p class="text-xs text-dimmed">{{ t('radius.cl_apply_note') }}</p>
    </div>

    <UModal v-model:open="shown.open" :title="t('radius.secret_title')" :description="t('radius.secret_desc', { name: shown.name })">
      <template #body>
        <div class="flex flex-col gap-3">
          <div class="flex gap-2 items-center"><code class="flex-1 break-all text-sm" data-test="radius-secret">{{ shown.secret }}</code><UButton size="xs" icon="i-lucide-copy" color="neutral" variant="outline" :label="t('common.copy')" @click="copy(shown.secret)" /></div>
          <UAlert color="warning" variant="subtle" icon="i-lucide-eye-off" :title="t('radius.secret_once')" />
          <div class="flex justify-end"><UButton color="neutral" variant="outline" :label="t('common.close')" @click="shown.open = false" /></div>
        </div>
      </template>
    </UModal>
  </div>
</template>
