<script setup lang="ts">
// PKI du DDI (0.14.0) — EJBCA Community dans un conteneur Podman, sur CE nœud : installation, démarrage / arrêt, état, nom public (URL gravée dans
// les certificats), réseaux autorisés, enregistrement DNS ; 0.14.1 : autorités (composant PkiCas) et remise à zéro d'une PKI vide ; 0.14.2 : publication des autorités dans l'AD
// (composant PkiAd) ; 0.14.3 : certificats (composant PkiCerts : émission, liste, révocation) ; 0.14.5 : sauvegarde et clé de récupération (composant PkiRecovery).
// Le service est piloté par root (ddibuntu-pki) à partir d'une demande déposée par la console : après chaque action on attend le résultat publié.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()
const tab = useHashTab('state', ['state', 'cas', 'certs', 'ad', 'recovery'])
const tabs = computed(() => [{ label: t('pki.tab_state'), value: 'state', icon: 'i-lucide-badge-check' }, { label: t('pki.tab_cas'), value: 'cas', icon: 'i-lucide-shield-check' }, { label: t('pki.tab_certs'), value: 'certs', icon: 'i-lucide-file-badge' }, { label: t('pki.tab_ad'), value: 'ad', icon: 'i-lucide-building-2' }, { label: t('pki.tab_recovery'), value: 'recovery', icon: 'i-lucide-archive-restore' }])

const data = ref<any>(null), busy = ref(''), err = ref('')
const status = computed(() => data.value?.status ?? null)
const result = computed(() => data.value?.result ?? null)
const waiting = computed(() => !!busy.value || !!data.value?.requestPending)
const installed = computed(() => !!status.value?.installed)
const form = reactive({ hostname: '', nets: '' })
let formLoaded = false
async function load() {
  try {
    data.value = await api.call('GET', '/pki', undefined, { silent: true })
    if (!formLoaded) {   // le formulaire ne se réécrit jamais pendant la saisie : seulement au premier chargement
      formLoaded = true
      form.hostname = data.value.hostname ?? ''
      form.nets = (data.value.status?.installed ? data.value.status.nets : data.value.settings?.nets ?? []).join('\n')
    }
  } catch (e: any) { err.value = e?.info?.message ?? '' }
}
async function settle() {   // attend que root ait traité la demande (le résultat est publié, la demande disparaît)
  for (let i = 0; i < 80; i++) { await new Promise((r) => setTimeout(r, 1500)); await load(); if (!data.value?.requestPending) return }
}
async function send(path: string, body: Record<string, unknown> = {}) {
  if (waiting.value) return false
  busy.value = path; err.value = ''
  try { await api.call('POST', `/pki/${path}`, body); toast.add({ title: t('pki.sent'), color: 'success' }); await settle(); return true }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal'); return false } finally { busy.value = '' }
}
const netList = computed(() => form.nets.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean))
async function install() {
  if (!(await ask(t('pki.install_title'), t('pki.install_body', { host: form.hostname }), false))) return
  await send('apply', { hostname: form.hostname, version: data.value?.settings?.version, nets: netList.value })
}
async function saveNets() { await send('apply', { hostname: status.value.hostname, version: status.value.version, nets: netList.value }) }
async function ctl(a: 'start' | 'stop' | 'restart') {
  const label = t(`pki.${a}`)
  if (a !== 'start' && !(await ask(label, t('pki.ctl_body'), true))) return
  await send(a)
}

// ---- Désinstallation (saisie du nom public) ----
const un = reactive({ open: false, typed: '' })
async function uninstall() {
  if (un.typed.trim().toLowerCase() !== status.value?.hostname) return
  if (await send('uninstall', { confirm: un.typed })) un.open = false
}

// ---- Remise à zéro (PKI sans autorité avec clé) : saisie du nom public des données ----
const rs = reactive({ open: false, typed: '' })
const resetHost = computed(() => (status.value?.dataHostname || status.value?.hostname || 'reset').toLowerCase())
const hasData = computed(() => !!status.value && (status.value.dataPresent || status.value.installed))
async function resetPki() {
  if (rs.typed.trim().toLowerCase() !== resetHost.value) return
  if (await send('reset', { confirm: rs.typed })) rs.open = false
}

// ---- DNS du nom public ----
const dns = computed(() => data.value?.dns ?? null)
const dnsAddr = ref('')
watch(() => dns.value?.suggested, (s) => { if (!dnsAddr.value && s?.length) dnsAddr.value = s[0] }, { immediate: true })
async function createDns() {
  busy.value = 'dns'; err.value = ''
  try { await api.call('POST', '/pki/dns', { address: dnsAddr.value }); toast.add({ title: t('pki.dns_done'), color: 'success' }); await load() }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}

// ---- Suivi : tant que le conteneur démarre, on redemande l'état à root (il n'est publié qu'à la demande) ----
let timer: ReturnType<typeof setTimeout> | undefined, stopped = false
async function follow() {
  if (stopped) return
  if (status.value?.state === 'starting' && !data.value?.requestPending && !busy.value) {
    try { await api.call('POST', '/pki/status', {}, { silent: true }); await settle() } catch { /* prochaine boucle */ }
  }
  if (!stopped) timer = setTimeout(follow, 10000)
}
onMounted(() => { timer = setTimeout(follow, 10000) })
onBeforeUnmount(() => { stopped = true; if (timer) clearTimeout(timer) })

const badge = computed(() => {
  const s = status.value?.state ?? 'absent'
  return { color: s === 'healthy' ? 'success' : s === 'unhealthy' ? 'error' : s === 'starting' ? 'warning' : 'neutral', label: t(`pki.state.${s}`) }
})
const resultText = computed(() => (result.value ? `${result.value.ok ? '✔' : '✖'} ${result.value.message}` : ''))
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
await load()
</script>

<template>
  <div class="flex flex-col gap-3">
    <UTabs v-model="tab" :items="tabs" :content="false" :aria-label="t('nav.pki')" />
    <PkiCas v-if="tab === 'cas'" :status="status" :waiting="waiting" :settle="settle" :result="result" @changed="load" />
    <PkiCerts v-else-if="tab === 'certs'" :status="status" :waiting="waiting" />
    <PkiAd v-else-if="tab === 'ad'" />
    <PkiRecovery v-else-if="tab === 'recovery'" :waiting="waiting" @changed="load" />
    <template v-else>
    <p class="text-sm text-muted">{{ t('pki.intro') }}</p>
    <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.ce_title')" :description="t('pki.ce_body')" data-test="pki-ce" />
    <UAlert v-if="status && !status.podman" color="warning" variant="subtle" icon="i-lucide-package-x" :title="t('pki.podman_title')" :description="t('pki.podman_body')" data-test="pki-podman" />
    <UAlert v-if="!installed && status?.dataPresent && !status.secretsPresent" color="error" variant="subtle" icon="i-lucide-key-round" :title="t('pki.secrets_missing_title')" :description="t('pki.secrets_missing_body')" data-test="pki-secrets-missing" />
    <UAlert v-else-if="!installed && status?.dataPresent" color="info" variant="subtle" icon="i-lucide-database" :title="t('pki.data_found_title', { host: status.dataHostname })" :description="t('pki.data_found_body')" data-test="pki-data-found" />

    <UCard>
      <template #header>
        <div class="flex items-center justify-between gap-2">
          <span class="font-medium">{{ t('pki.state_title') }}</span>
          <UBadge :color="(badge.color as any)" variant="subtle" :label="badge.label" data-test="pki-state" />
        </div>
      </template>
      <dl v-if="status" class="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-3 text-sm">
        <div><dt class="text-muted">{{ t('pki.hostname') }}</dt><dd class="font-mono break-all" data-test="pki-hostname">{{ status.hostname || '—' }}</dd></div>
        <div><dt class="text-muted">{{ t('pki.version') }}</dt><dd class="font-mono">{{ status.version ? `EJBCA CE ${status.version}` : '—' }}</dd></div>
        <div><dt class="text-muted">{{ t('pki.health') }}</dt><dd class="font-mono">{{ status.health || '—' }}</dd></div>
        <div><dt class="text-muted">{{ t('pki.port') }}</dt><dd class="font-mono">{{ status.port }}</dd></div>
        <div><dt class="text-muted">{{ t('pki.nets') }}</dt><dd class="font-mono break-all" data-test="pki-nets">{{ status.nets.length ? status.nets.join(', ') : t('pki.nets_none') }}</dd></div>
        <div><dt class="text-muted">{{ t('radius.read_at') }}</dt><dd>{{ fmt.dateTime(status.at * 1000) }}</dd></div>
      </dl>
      <p v-else class="text-sm text-muted">{{ t('pki.never') }}</p>
      <p v-if="status?.state === 'starting'" class="text-xs text-muted mt-3" role="status" data-test="pki-starting">{{ t('pki.starting_hint') }}</p>
      <p v-if="status?.installed && !status.nets.length" class="text-xs text-warning mt-3" role="status">{{ t('pki.nets_closed') }}</p>
      <p v-if="result" class="text-xs mt-2" :class="result.ok ? 'text-muted' : 'text-error'" data-test="pki-result">{{ t('radius.last') }} {{ fmt.dateTime(result.at * 1000) }} — {{ resultText }}</p>
      <p v-if="data?.requestPending" class="text-xs text-muted mt-2" role="status">{{ t('radius.pending') }}</p>
      <p v-if="err" class="text-sm text-error mt-2" role="alert" data-test="pki-error">{{ err }}</p>
      <div v-if="installed" class="flex flex-wrap gap-2 mt-4">
        <UButton icon="i-lucide-play" :label="t('pki.start')" :loading="busy === 'start'" :disabled="waiting || status.active" data-test="pki-start" @click="ctl('start')" />
        <UButton icon="i-lucide-power" color="neutral" variant="outline" :label="t('pki.stop')" :loading="busy === 'stop'" :disabled="waiting || !status.active" data-test="pki-stop" @click="ctl('stop')" />
        <UButton icon="i-lucide-rotate-cw" color="neutral" variant="outline" :label="t('pki.restart')" :loading="busy === 'restart'" :disabled="waiting || !status.active" data-test="pki-restart" @click="ctl('restart')" />
        <UButton icon="i-lucide-refresh-cw" color="neutral" variant="ghost" :label="t('pki.refresh')" :loading="busy === 'status'" :disabled="waiting" data-test="pki-refresh" @click="send('status')" />
      </div>
    </UCard>

    <UCard>
      <template #header><span class="font-medium">{{ installed ? t('pki.nets_title') : t('pki.install_card') }}</span></template>
      <div class="flex flex-col gap-3">
        <UFormField :label="t('pki.hostname')" :hint="installed ? t('pki.hostname_locked') : data?.hostnameFixed ? t('pki.hostname_data') : t('pki.hostname_hint')">
          <UInput v-model="form.hostname" class="w-full font-mono" :disabled="installed || data?.hostnameFixed || waiting" placeholder="pki.lab.test" data-test="pki-host-input" />
        </UFormField>
        <UAlert v-if="!installed && !data?.hostnameFixed" color="info" variant="subtle" icon="i-lucide-info" :title="t('pki.hostname_warn_title')" :description="t('pki.hostname_warn')" />
        <UFormField :label="t('pki.nets')" :hint="t('pki.nets_hint')">
          <UTextarea v-model="form.nets" class="w-full font-mono" :rows="4" :disabled="waiting" placeholder="10.10.0.0/16&#10;192.168.1.0/24" data-test="pki-nets-input" />
        </UFormField>
        <div class="flex justify-end">
          <UButton v-if="!installed" icon="i-lucide-download" :label="t('pki.install')" :loading="busy === 'apply'" :disabled="waiting || !form.hostname || (status && !status.podman)" data-test="pki-install" @click="install" />
          <UButton v-else icon="i-lucide-save" :label="t('pki.nets_save')" :loading="busy === 'apply'" :disabled="waiting" data-test="pki-nets-save" @click="saveNets" />
        </div>
      </div>
    </UCard>

    <UCard v-if="dns && dns.hostname">
      <template #header><span class="font-medium">{{ t('pki.dns_title') }}</span></template>
      <div class="flex flex-col gap-2 text-sm">
        <p v-if="!dns.zone" class="text-muted" data-test="pki-dns-nozone">{{ t('pki.dns_nozone', { host: dns.hostname }) }}</p>
        <template v-else>
          <p v-if="dns.records.length" data-test="pki-dns-ok"><UIcon name="i-lucide-circle-check" class="text-success align-text-bottom" /> {{ t('pki.dns_ok', { host: dns.hostname, zone: dns.zone }) }} <code class="font-mono">{{ dns.records.map((r: any) => r.rdata).join(', ') }}</code></p>
          <template v-else>
            <p class="text-muted" data-test="pki-dns-missing">{{ t('pki.dns_missing', { host: dns.hostname, zone: dns.zone }) }}</p>
            <div class="flex flex-wrap items-center gap-2">
              <UInput v-model="dnsAddr" class="font-mono w-48" :placeholder="t('pki.dns_addr')" data-test="pki-dns-addr" />
              <UButton icon="i-lucide-plus" color="neutral" variant="outline" :label="t('pki.dns_create')" :loading="busy === 'dns'" :disabled="waiting || !dnsAddr" data-test="pki-dns-create" @click="createDns" />
            </div>
            <p class="text-xs text-dimmed">{{ t('pki.dns_hint') }}</p>
          </template>
        </template>
      </div>
    </UCard>

    <UCard v-if="installed && data?.endpoints?.health">
      <template #header><span class="font-medium">{{ t('pki.endpoints') }}</span></template>
      <div class="flex gap-2 items-center text-sm"><code class="flex-1 break-all" data-test="pki-health-url">{{ data.endpoints.health }}</code><UButton size="xs" icon="i-lucide-copy" color="neutral" variant="ghost" :aria-label="t('common.copy')" @click="copy(data.endpoints.health)" /></div>
      <p class="text-xs text-dimmed mt-2">{{ t('pki.endpoints_hint') }}</p>
    </UCard>

    <UCard v-if="installed">
      <template #header><span class="font-medium text-error">{{ t('pki.danger') }}</span></template>
      <p class="text-sm text-muted mb-3">{{ t('pki.uninstall_body') }}</p>
      <UButton color="error" variant="outline" icon="i-lucide-trash-2" :label="t('pki.uninstall')" :disabled="waiting" data-test="pki-uninstall" @click="un.open = true; un.typed = ''" />
    </UCard>

    <UCard v-if="hasData">
      <template #header><span class="font-medium text-error">{{ t('pki.reset_title') }}</span></template>
      <p class="text-sm text-muted mb-3">{{ t('pki.reset_body') }}</p>
      <p v-if="!status.resetAllowed" class="text-sm text-warning mb-3" data-test="pki-reset-refused">{{ t('pki.reset_refused', { n: status.casCount ?? '?' }) }}</p>
      <UButton color="error" variant="outline" icon="i-lucide-eraser" :label="t('pki.reset_go')" :disabled="waiting || !status.resetAllowed" data-test="pki-reset" @click="rs.open = true; rs.typed = ''" />
    </UCard>

    <UModal v-model:open="un.open" :title="t('pki.uninstall')" :description="t('pki.uninstall_confirm', { host: status?.hostname })">
      <template #body>
        <div class="flex flex-col gap-3">
          <UInput v-model="un.typed" class="font-mono" :placeholder="status?.hostname" data-test="pki-uninstall-input" />
          <div class="flex justify-end gap-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="un.open = false" />
            <UButton color="error" :label="t('pki.uninstall')" :loading="busy === 'uninstall'" :disabled="un.typed.trim().toLowerCase() !== status?.hostname" data-test="pki-uninstall-go" @click="uninstall" />
          </div>
        </div>
      </template>
    </UModal>

    <UModal v-model:open="rs.open" :title="t('pki.reset_title')" :description="t('pki.reset_confirm', { host: resetHost })">
      <template #body>
        <div class="flex flex-col gap-3">
          <UInput v-model="rs.typed" class="font-mono" :placeholder="resetHost" data-test="pki-reset-input" />
          <div class="flex justify-end gap-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="rs.open = false" />
            <UButton color="error" :label="t('pki.reset_go')" :loading="busy === 'reset'" :disabled="rs.typed.trim().toLowerCase() !== resetHost" data-test="pki-reset-confirm" @click="resetPki" />
          </div>
        </div>
      </template>
    </UModal>
    </template>
  </div>
</template>
