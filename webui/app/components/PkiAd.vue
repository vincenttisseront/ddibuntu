<script setup lang="ts">
// PKI du DDI — publication des autorités dans l'Active Directory (0.14.2). Chaque autorité (racine, racine hors ligne, émettrice) est écrite dans la partition
// Configuration de la forêt : les machines du domaine lui font alors confiance. Un compte de service DÉDIÉ écrit (délégation minimale sur deux conteneurs) ;
// la publication courante est faite par une tâche de fond de la console, cette page règle, teste (sans écrire), déclenche, vérifie et retire.
// Le mot de passe du compte est chiffré côté serveur et n'est jamais renvoyé. Un retrait n'est jamais automatique.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()

const data = ref<any>(null), loaded = ref(false), err = ref('')
const f = reactive({ enabled: false, source: 'radius' as 'radius' | 'own', urls: '', caPem: '', tlsRejectUnauthorized: true, bindDn: '', bindPassword: '', clearPassword: false, repair: 'auto' as 'auto' | 'manual' })
const pwSet = ref(false)
const saving = ref(false), testing = ref(false), running = ref(''), test = ref<any>(null)
const urlList = () => f.urls.split(/\s+/).filter(Boolean)

async function load(initForm = false) {
  try {
    const r: any = await api.call('GET', '/pki/ad', undefined, { silent: true })
    data.value = r
    if (initForm || !loaded.value) {   // le formulaire ne se réécrit jamais pendant la saisie : seulement au premier chargement et après un enregistrement
      const s = r.settings
      Object.assign(f, { enabled: s.enabled, source: s.source, urls: s.urls.join('\n'), caPem: '', tlsRejectUnauthorized: s.tlsRejectUnauthorized, bindDn: s.bindDn, bindPassword: '', clearPassword: false, repair: s.repair })
      pwSet.value = !!s.bindPasswordSet
    }
  } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { loaded.value = true }
}
const connOk = computed(() => (f.source === 'radius' ? (data.value?.connection.radiusServers ?? 0) > 0 : urlList().length > 0) && !!f.bindDn.trim() && (pwSet.value ? !f.clearPassword : !!f.bindPassword))
const pubs = computed<any[]>(() => data.value?.publications ?? [])
const run = computed(() => data.value?.state?.lastRun ?? null)

function body(enabled: boolean) {
  const b: any = { enabled, source: f.source, urls: f.source === 'own' ? urlList() : [], tlsRejectUnauthorized: f.tlsRejectUnauthorized, bindDn: f.bindDn.trim(), repair: f.repair, clearPassword: f.clearPassword }
  if (f.bindPassword) b.bindPassword = f.bindPassword
  if (f.source === 'own' && f.caPem.trim()) b.caPem = f.caPem.trim() + '\n'
  return b
}
async function save(enabled = f.enabled, quiet = false): Promise<boolean> {
  saving.value = true; err.value = ''
  try {
    await api.call('PUT', '/pki/ad', body(enabled), { silent: true })
    if (!quiet) toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' })
    await load(true); return true
  } catch (e: any) { err.value = e?.info?.message ?? t('err.internal'); return false } finally { saving.value = false }
}
async function toggle(v: boolean) {
  if (v && !(await ask(t('pki.ad.enable_confirm_title'), t('pki.ad.enable_confirm_body'), true))) { f.enabled = false; return }
  f.enabled = v
  if (!(await save(v))) f.enabled = !v
}
async function runTest() {   // enregistre puis teste : le serveur teste toujours les réglages ENREGISTRÉS
  testing.value = true; test.value = null
  try { if (await save(f.enabled, true)) { test.value = await api.call('POST', '/pki/ad/test', {}, { silent: true }); await load() } }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { testing.value = false }
}
async function act(kind: string, path: string, b: Record<string, unknown> = {}) {
  running.value = kind; err.value = ''
  try { const r: any = await api.call('POST', path, b, { silent: true }); await load(); return r } catch (e: any) { err.value = e?.info?.message ?? t('err.internal'); await load() } finally { running.value = '' }
}
const publishAll = () => act('all', '/pki/ad/publish', {})
const reconcile = () => act('reconcile', '/pki/ad/reconcile', {})
const publishOne = (name: string, republish = false) => act(`pub:${name}`, '/pki/ad/publish', { name, ...(republish ? { republish: true } : {}) })

const wd = reactive({ open: false, name: '', typed: '' })
function askWithdraw(name: string) { Object.assign(wd, { open: true, name, typed: '' }) }
async function withdraw() {
  if (wd.typed.trim().toLowerCase() !== wd.name.toLowerCase()) return
  const r = await act(`wd:${wd.name}`, `/pki/ad/${encodeURIComponent(wd.name)}/withdraw`, { confirm: wd.typed })
  if (r) wd.open = false
}

const STATE_COLOR: Record<string, string> = { published: 'success', pending: 'info', failed: 'error', conflict: 'warning', drift: 'warning', withdrawn: 'neutral', not_published: 'neutral' }
const STATE_ICON: Record<string, string> = { published: 'i-lucide-circle-check', pending: 'i-lucide-clock', failed: 'i-lucide-circle-x', conflict: 'i-lucide-git-compare', drift: 'i-lucide-triangle-alert', withdrawn: 'i-lucide-undo-2', not_published: 'i-lucide-minus' }
function detail(p: any): string {
  const bits: string[] = []
  if (p.orphan) bits.push(t('pki.ad.d_orphan'))
  if (p.state === 'published' && p.publishedAt) bits.push(t('pki.ad.d_published', { at: fmt.dateTime(p.publishedAt) }))
  if (p.state === 'published' && p.checkedAt) bits.push(t('pki.ad.d_checked', { at: fmt.dateTime(p.checkedAt) }))
  if (p.reason && (p.state === 'failed' || p.state === 'conflict' || p.state === 'drift')) bits.push(t(`pki.ad.reason.${p.reason}`))
  if (p.state === 'failed' && p.nextTryAt) bits.push(t('pki.ad.d_next', { at: fmt.dateTime(p.nextTryAt) }))
  return bits.join(' · ')
}
const canPublish = computed(() => !!data.value?.settings.enabled && !!data.value?.complete)
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
const containerLabel = (c: string) => t(`pki.ad.c_${c}`)
onMounted(() => load(true))
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('pki.ad.intro') }}</p>
    <UAlert color="warning" variant="subtle" icon="i-lucide-shield-alert" :title="t('pki.ad.warn_title')" :description="t('pki.ad.warn_body')" data-test="pki-ad-warn" />
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" data-test="pki-ad-error" />

    <UCard>
      <template #header>
        <div class="flex items-center justify-between gap-2">
          <div class="flex items-center gap-2"><UIcon name="i-lucide-building-2" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('pki.ad.pub_title') }}</h2></div>
          <UBadge :color="data?.settings.enabled ? 'success' : 'neutral'" variant="subtle" :label="data?.settings.enabled ? t('pki.ad.on') : t('pki.ad.off')" data-test="pki-ad-state" />
        </div>
      </template>
      <div class="flex flex-col gap-4">
        <div class="flex flex-wrap items-center gap-4">
          <USwitch :model-value="f.enabled" :label="t('pki.ad.enable')" :disabled="saving || (!f.enabled && !data?.complete)" data-test="pki-ad-enable" @update:model-value="toggle" />
          <UFormField :label="t('pki.ad.repair')" class="min-w-64">
            <USelect v-model="f.repair" :items="[{ label: t('pki.ad.repair_auto'), value: 'auto' }, { label: t('pki.ad.repair_manual'), value: 'manual' }]" class="w-full" data-test="pki-ad-repair" @update:model-value="save(f.enabled, true)" />
          </UFormField>
        </div>
        <p v-if="!data?.complete" class="text-sm text-muted" data-test="pki-ad-notconf">{{ t('pki.ad.not_configured') }}</p>

        <div v-if="data" class="text-sm text-muted flex flex-col gap-1" data-test="pki-ad-run">
          <span v-if="run">{{ t('pki.ad.last_run') }} : {{ fmt.dateTime(run.at * 1000) }} — {{ t('pki.ad.last_run_body', { published: run.published, unchanged: run.unchanged, failed: run.failed, conflicts: run.conflicts, drift: run.drift }) }}<template v-if="!run.ok"> — <span class="text-error">{{ t(`pki.ad.reason.${run.reason}`) }}</span></template></span>
          <span v-else>{{ t('pki.ad.last_run_none') }}</span>
          <span v-if="data.state.lastReconcile">{{ t('pki.ad.last_reconcile', { at: fmt.dateTime(data.state.lastReconcile * 1000) }) }}</span>
        </div>

        <div v-if="pubs.length" class="overflow-x-auto">
          <table class="w-full text-sm" data-test="pki-ad-table">
            <thead><tr class="text-left text-muted"><th class="py-1 pr-3 font-normal">{{ t('pki.ad.col_ca') }}</th><th class="py-1 pr-3 font-normal">{{ t('pki.ad.col_where') }}</th><th class="py-1 pr-3 font-normal">{{ t('pki.ad.col_state') }}</th><th class="py-1 pr-3 font-normal">{{ t('pki.ad.col_detail') }}</th><th /></tr></thead>
            <tbody>
              <tr v-for="p in pubs" :key="p.name" class="border-t border-default align-top" :data-test="`pki-ad-row-${p.name}`">
                <td class="py-2 pr-3 font-mono">{{ p.name }}</td>
                <td class="py-2 pr-3">{{ containerLabel(p.container) }}</td>
                <td class="py-2 pr-3"><UBadge :color="(STATE_COLOR[p.state] as any)" variant="subtle" :icon="STATE_ICON[p.state]" :label="t(`pki.ad.st.${p.state}`)" :data-test="`pki-ad-st-${p.name}`" /></td>
                <td class="py-2 pr-3 text-muted">{{ detail(p) }}</td>
                <td class="py-2 text-right whitespace-nowrap">
                  <UButton v-if="!p.orphan && p.state !== 'published' && p.state !== 'withdrawn'" size="xs" icon="i-lucide-upload" color="neutral" variant="outline" :label="t('pki.ad.publish')" :loading="running === `pub:${p.name}`" :disabled="!canPublish || !!running" :data-test="`pki-ad-pub-${p.name}`" @click="publishOne(p.name)" />
                  <UButton v-if="!p.orphan && p.state === 'withdrawn'" size="xs" icon="i-lucide-undo-2" color="neutral" variant="outline" :label="t('pki.ad.republish')" :loading="running === `pub:${p.name}`" :disabled="!canPublish || !!running" :data-test="`pki-ad-republish-${p.name}`" @click="publishOne(p.name, true)" />
                  <UButton v-if="p.state !== 'withdrawn' && p.state !== 'not_published' && p.state !== 'pending'" size="xs" icon="i-lucide-trash-2" color="error" variant="ghost" :label="t('pki.ad.withdraw')" :disabled="!data?.complete || !!running" :data-test="`pki-ad-withdraw-${p.name}`" @click="askWithdraw(p.name)" />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="text-sm text-muted" data-test="pki-ad-empty">{{ t('pki.ad.none') }}</p>

        <div class="flex flex-wrap justify-end gap-2">
          <UButton color="neutral" variant="outline" icon="i-lucide-scan-search" :label="t('pki.ad.reconcile')" :loading="running === 'reconcile'" :disabled="!canPublish || !!running" data-test="pki-ad-reconcile" @click="reconcile" />
          <UButton icon="i-lucide-upload" :label="t('pki.ad.publish_all')" :loading="running === 'all'" :disabled="!canPublish || !!running" data-test="pki-ad-publish-all" @click="publishAll" />
        </div>
      </div>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-network" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('pki.ad.conn_title') }}</h2></div></template>
      <form class="flex flex-col gap-4" @submit.prevent="save()">
        <UFormField :label="t('pki.ad.source')">
          <URadioGroup v-model="f.source" :items="[{ label: t('pki.ad.source_radius', { n: data?.connection.radiusServers ?? 0 }), value: 'radius' }, { label: t('pki.ad.source_own'), value: 'own' }]" data-test="pki-ad-source" />
        </UFormField>
        <p v-if="f.source === 'radius' && !(data?.connection.radiusServers)" class="text-sm text-warning" data-test="pki-ad-radius-none">{{ t('pki.ad.source_radius_none') }}</p>
        <div v-if="f.source === 'own'" class="grid gap-4 md:grid-cols-2">
          <UFormField :label="t('radius.dir.urls')" :help="t('radius.dir.urls_help')" required><UTextarea v-model="f.urls" :rows="2" class="w-full font-mono" placeholder="ldaps://dc1.exemple.fr" data-test="pki-ad-urls" /></UFormField>
          <UFormField :label="t('radius.dir.ca')" :help="data?.settings.caSet ? t('pki.ad.ca_set') : t('radius.dir.ca_help')"><UTextarea v-model="f.caPem" :rows="3" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" data-test="pki-ad-ca" /></UFormField>
          <div class="flex flex-col gap-2 md:col-span-2">
            <USwitch v-model="f.tlsRejectUnauthorized" :label="t('radius.dir.tls_verify')" data-test="pki-ad-tls" />
            <UAlert v-if="!f.tlsRejectUnauthorized" color="warning" variant="subtle" icon="i-lucide-shield-alert" :title="t('radius.dir.tls_off_title')" :description="t('radius.dir.tls_off_body')" />
          </div>
        </div>
        <div class="grid gap-4 md:grid-cols-2">
          <UFormField :label="t('pki.ad.bind_dn')" :help="t('pki.ad.bind_dn_help')" required><UInput v-model="f.bindDn" class="w-full font-mono" placeholder="svc-ddi-pki@exemple.fr" autocomplete="off" data-test="pki-ad-binddn" /></UFormField>
          <UFormField :label="t('radius.dir.bind_pw')" :help="pwSet && !f.clearPassword ? t('radius.dir.pw_set') : t('radius.dir.pw_none')">
            <UInput v-model="f.bindPassword" type="password" autocomplete="new-password" class="w-full" :disabled="f.clearPassword" data-test="pki-ad-pw" />
            <UCheckbox v-if="pwSet" v-model="f.clearPassword" :label="t('radius.dir.pw_clear')" class="mt-2" data-test="pki-ad-pw-clear" />
          </UFormField>
        </div>
        <template v-if="test">
          <UAlert v-if="test.ok" color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('pki.ad.t_ok')" data-test="pki-ad-test-result">
            <template #description>
              <ul class="text-sm flex flex-col gap-1 mt-1">
                <li><code>{{ test.server }}</code> — {{ t('pki.ad.t_host', { host: test.host }) }}</li>
                <li>{{ t('pki.ad.t_nc') }} <code>{{ test.configNc }}</code></li>
                <li v-for="c in test.containers" :key="c.container" class="flex items-center gap-2" :data-test="`pki-ad-cont-${c.container}`">
                  <UIcon :name="c.exists && c.canCreate ? 'i-lucide-check' : 'i-lucide-x'" class="size-4" :class="c.exists && c.canCreate ? 'text-success' : 'text-error'" />
                  <span>{{ containerLabel(c.container) }} : {{ !c.exists ? t('pki.ad.t_missing') : c.canCreate ? t('pki.ad.t_can') : t('pki.ad.t_cannot') }}</span>
                </li>
              </ul>
            </template>
          </UAlert>
          <UAlert v-else color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.ad.t_ko')" :description="t(`pki.ad.reason.${test.reason}`)" data-test="pki-ad-test-result" />
        </template>
        <div class="flex flex-wrap justify-end gap-2">
          <UButton color="neutral" variant="outline" icon="i-lucide-plug-zap" :loading="testing" :disabled="!connOk || saving" :label="t('pki.ad.test')" data-test="pki-ad-test" @click="runTest" />
          <UButton type="submit" :loading="saving && !testing" :disabled="testing" :label="t('common.save')" data-test="pki-ad-save" />
        </div>
      </form>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-key-round" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('pki.ad.deleg_title') }}</h2></div></template>
      <div class="flex flex-col gap-3">
        <p class="text-sm text-muted">{{ t('pki.ad.deleg_body') }}</p>
        <p v-if="!data?.delegation" class="text-sm text-warning" data-test="pki-ad-deleg-need">{{ t('pki.ad.deleg_need_test') }}</p>
        <template v-else>
          <div v-for="d in data.delegation" :key="d.container" class="flex flex-col gap-2" :data-test="`pki-ad-deleg-${d.container}`">
            <h3 class="text-sm font-medium">{{ containerLabel(d.container) }}</h3>
            <div class="relative"><pre class="text-xs bg-elevated rounded-md p-3 pr-10 overflow-x-auto whitespace-pre-wrap break-all">{{ d.dsacls }}</pre><UButton class="absolute top-1 right-1" size="xs" icon="i-lucide-copy" color="neutral" variant="ghost" :aria-label="t('common.copy')" @click="copy(d.dsacls)" /></div>
            <p class="text-xs text-muted">{{ t('pki.ad.deleg_dsacls_note') }}</p>
            <div v-if="d.samba" class="relative"><pre class="text-xs bg-elevated rounded-md p-3 pr-10 overflow-x-auto whitespace-pre-wrap break-all">{{ d.samba }}</pre><UButton class="absolute top-1 right-1" size="xs" icon="i-lucide-copy" color="neutral" variant="ghost" :aria-label="t('common.copy')" @click="copy(d.samba)" /></div>
          </div>
          <p class="text-xs text-muted">{{ t('pki.ad.deleg_samba_note') }}</p>
        </template>
      </div>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-file-terminal" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('pki.ad.fb_title') }}</h2></div></template>
      <div class="flex flex-col gap-3">
        <p class="text-sm text-muted">{{ t('pki.ad.fb_body') }}</p>
        <div><UButton icon="i-lucide-download" color="neutral" variant="outline" :label="t('pki.ad.fb_dl')" href="/api/pki/ad/script" download external :disabled="!data?.eligible" data-test="pki-ad-script" /></div>
      </div>
    </UCard>

    <UModal v-model:open="wd.open" :title="t('pki.ad.wd_title', { name: wd.name })" :description="t('pki.ad.wd_body')">
      <template #body>
        <div class="flex flex-col gap-3">
          <UInput v-model="wd.typed" class="font-mono" :placeholder="wd.name" data-test="pki-ad-wd-input" />
          <div class="flex justify-end gap-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="wd.open = false" />
            <UButton color="error" :label="t('pki.ad.wd_go')" :loading="running === `wd:${wd.name}`" :disabled="wd.typed.trim().toLowerCase() !== wd.name.toLowerCase()" data-test="pki-ad-wd-confirm" @click="withdraw" />
          </div>
        </div>
      </template>
    </UModal>
  </div>
</template>
