<script setup lang="ts">
// Alertes : liste des alertes ouvertes, silences, historique, notifications (webhook, e-mail), seuils et jeton de l'export Prometheus.
// Toute action un peu longue affiche un spinner ; toutes les boîtes de dialogue sont maison (jamais de fenêtre système).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const data = ref<any>(null), conf = ref<any>(null), loadError = ref(false), dirty = ref(false)
const lang = useCookie<string>('ddi_lang')
async function load() { try { data.value = await api.call('GET', '/alerts', undefined, { silent: true }); loadError.value = false } catch { loadError.value = true } }
async function loadConf() { conf.value = await api.call('GET', '/alerts/config', undefined, { silent: true }); fillForm(); await nextTick(); dirty.value = false }
let poll: ReturnType<typeof setInterval> | undefined
onMounted(() => { load(); loadConf().catch(() => {}); poll = setInterval(load, 15000) })
onBeforeUnmount(() => { if (poll) clearInterval(poll) })

const fmt = useFmt()
const when = (v: string | number | null | undefined) => (v ? fmt.dateTime(v) : '—')
const ruleText = (a: any) => t(`alerts.rule.${a.rule}`, { node: a.node || '?', subject: a.subject || '', ...(a.params ?? {}) })
const sevColor = (s: string) => (s === 'critical' ? 'error' : s === 'warning' ? 'warning' : 'info')
const sevIcon = (s: string) => (s === 'critical' ? 'i-lucide-octagon-alert' : s === 'warning' ? 'i-lucide-triangle-alert' : 'i-lucide-info')
const runsHere = computed(() => data.value?.engine?.runsHere !== false)

// ---- évaluation immédiate
const evaluating = ref(false)
async function evaluate() {
  evaluating.value = true
  try { const r = await api.call('POST', '/alerts/evaluate', {}, { busy: true }); await load(); toast.add({ title: t('alerts.evaluated', { n: r.findings ?? 0 }), color: 'success', icon: 'i-lucide-check' }) }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) }
  finally { evaluating.value = false }
}

// ---- silences
const silenceFor = ref<any>(null), silForm = reactive({ scope: 'exact', hours: 4, comment: '' }), silBusy = ref(false), silErr = ref('')
const silOpen = computed({ get: () => silenceFor.value !== null, set: (v: boolean) => { if (!v && !silBusy.value) silenceFor.value = null } })
function openSilence(a: any) { silenceFor.value = a; Object.assign(silForm, { scope: 'exact', hours: 4, comment: '' }); silErr.value = '' }
const scopeItems = computed(() => { const a = silenceFor.value; if (!a) return []; return [
  { label: t('alerts.silence.scope.exact'), value: 'exact' }, { label: t('alerts.silence.scope.rule'), value: 'rule' }, ...(a.node ? [{ label: t('alerts.silence.scope.node', { node: a.node }), value: 'node' }] : [])] })
const hourItems = [1, 4, 24, 168, 720].map((h) => ({ label: t(`alerts.silence.h${h}`), value: h }))
async function createSilence() {
  const a = silenceFor.value; if (!a) return
  const body: any = { hours: Number(silForm.hours), comment: silForm.comment.trim() }
  if (silForm.scope === 'exact') Object.assign(body, { rule: a.rule, node: a.node || null, subject: a.subject || null })
  else if (silForm.scope === 'rule') Object.assign(body, { rule: a.rule })
  else Object.assign(body, { node: a.node })
  silBusy.value = true; silErr.value = ''
  try { await api.call('POST', '/alerts/silences', body, { busy: true }); silenceFor.value = null; await load() }
  catch (e: any) { silErr.value = e.info?.message ?? t('err.internal') }
  finally { silBusy.value = false }
}
async function unsilence(s: any) {
  try { await api.call('DELETE', `/alerts/silences/${s.id}`, undefined, { busy: true }); await load() } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) }
}
const silenceScope = (s: any) => [s.rule ? t(`alerts.rn.${s.rule}`) : t('alerts.silence.all'), s.node, s.subject].filter(Boolean).join(' · ')

// ---- réglages
const form = reactive<any>({ minSeverity: 'warning', repeatHours: 0, lang: 'fr', thresholds: {}, webhook: { enabled: false, url: '', secret: '', clearSecret: false, hasSecret: false },
  email: { enabled: false, host: '', port: 587, security: 'starttls', verifyCert: true, user: '', password: '', clearPassword: false, hasPassword: false, from: '', to: '' } })
function fillForm() {
  const c = conf.value; if (!c) return
  Object.assign(form, { minSeverity: c.minSeverity, repeatHours: c.repeatHours, lang: c.lang, thresholds: { ...c.thresholds } })
  Object.assign(form.webhook, { enabled: c.webhook.enabled, url: c.webhook.url, secret: '', clearSecret: false, hasSecret: c.webhook.hasSecret })
  Object.assign(form.email, { enabled: c.email.enabled, host: c.email.host, port: c.email.port, security: c.email.security, verifyCert: c.email.verifyCert, user: c.email.user, password: '', clearPassword: false, hasPassword: c.email.hasPassword, from: c.email.from, to: c.email.to.join('\n') })
}
const sevItems = ['info', 'warning', 'critical'].map((v) => ({ label: t(`alerts.sev.${v}`), value: v }))
const langItems = [{ label: 'Français', value: 'fr' }, { label: 'English', value: 'en' }]
const secItems = computed(() => ['starttls', 'tls', 'none'].map((v) => ({ label: t(`alerts.cfg.security.${v}`), value: v })))
const thKeys = ['diskWarn', 'diskCrit', 'certWarnDays', 'certCritDays', 'lagMiB', 'backupMaxAgeHours', 'subnetWarn', 'subnetCrit']
const saving = ref(false), cfgErr = ref('')
watch(form, () => { dirty.value = true }, { deep: true })
async function save() {
  cfgErr.value = ''; saving.value = true
  const w = form.webhook, e = form.email
  const body = {
    minSeverity: form.minSeverity, repeatHours: Number(form.repeatHours), lang: form.lang,
    thresholds: Object.fromEntries(thKeys.map((k) => [k, Number(form.thresholds[k])])),
    webhook: { enabled: w.enabled, url: w.url.trim(), ...(w.clearSecret ? { secret: null } : w.secret ? { secret: w.secret } : {}) },
    email: { enabled: e.enabled, host: e.host.trim(), port: Number(e.port), security: e.security, verifyCert: e.verifyCert, user: e.user.trim(), from: e.from.trim(), to: e.to.split(/[\n,; ]+/).map((x: string) => x.trim()).filter(Boolean),
      ...(e.clearPassword ? { password: null } : e.password ? { password: e.password } : {}) },
  }
  try { conf.value = await api.call('PUT', '/alerts/config', body, { busy: true }); fillForm(); await nextTick(); dirty.value = false; toast.add({ title: t('alerts.cfg.saved'), color: 'success', icon: 'i-lucide-check' }) }
  catch (er: any) { cfgErr.value = er.info?.issues?.length ? er.info.issues.map((i: any) => `${i.path}: ${i.message}`).join(' · ') : (er.info?.message ?? t('err.internal')) }
  finally { saving.value = false }
}
const testing = ref('')
async function test(ch: 'webhook' | 'email') {
  testing.value = ch
  try {
    const d = await api.call('POST', `/alerts/test/${ch}`, {}, { busy: true })
    toast.add({ title: d.ok ? t('alerts.test.ok', { d: d.detail }) : t('alerts.test.ko', { d: d.detail }), color: d.ok ? 'success' : 'error', icon: d.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
    await load()
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { testing.value = '' }
}

// ---- jeton Prometheus
const token = ref(''), tokenBusy = ref(false), host = ref('<adresse>')
onMounted(() => { host.value = location.host })
async function makeToken() {
  if (conf.value?.metricsToken && !(await ask(t('alerts.prom.regen'), t('alerts.prom.regen_confirm'), true))) return
  tokenBusy.value = true
  try { token.value = (await api.call('POST', '/alerts/metrics-token', {}, { busy: true })).token; await loadConf() } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { tokenBusy.value = false }
}
async function revokeToken() {
  if (!(await ask(t('alerts.prom.revoke'), t('alerts.prom.revoke_confirm'), true))) return
  tokenBusy.value = true
  try { await api.call('DELETE', '/alerts/metrics-token', undefined, { busy: true }); token.value = ''; await loadConf() } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { tokenBusy.value = false }
}
async function copy(s: string) { try { await navigator.clipboard.writeText(s); toast.add({ title: t('alerts.prom.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
const promExample = computed(() => `scrape_configs:\n  - job_name: ddibuntu\n    scheme: https\n    metrics_path: /api/metrics\n    authorization:\n      credentials: ${token.value || '<jeton>'}\n    tls_config:\n      insecure_skip_verify: true   # certificat auto-signé : à remplacer par votre autorité\n    static_configs:\n      - targets: ['${host.value}']`)
</script>

<template>
  <div class="flex flex-col gap-4">
    <UAlert v-if="loadError && !data" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('err.network')" />

    <UCard>
      <template #header>
        <div class="flex flex-wrap items-center gap-2">
          <span class="font-medium">{{ t('alerts.title') }}</span>
          <UBadge v-if="data" :color="data.summary.critical ? 'error' : data.summary.warning ? 'warning' : 'success'" variant="subtle"
            :label="data.summary.critical + data.summary.warning + data.summary.info ? t('dash.alerts.some', { n: data.summary.critical + data.summary.warning + data.summary.info }) : t('dash.alerts.ok')" />
          <span class="flex-1" />
          <UButton size="xs" color="neutral" variant="outline" icon="i-lucide-refresh-cw" :label="t('alerts.evaluate')" :loading="evaluating" :disabled="evaluating || !runsHere" @click="evaluate" />
        </div>
      </template>
      <p class="text-sm text-muted">{{ t('alerts.intro') }}</p>
      <UAlert v-if="data && !runsHere" class="mt-3" color="info" variant="subtle" icon="i-lucide-info" :title="t('alerts.engine.replica')" />
      <p v-else-if="data?.engine?.last?.ok === false" class="mt-3 text-sm text-error">{{ t('alerts.engine.error', { e: data.engine.last.error }) }}</p>
      <p v-else class="mt-3 text-xs text-muted">{{ data?.engine?.last ? t('alerts.engine.last', { at: when(data.engine.last.at * 1000) }) : t('alerts.engine.never') }}</p>
      <div v-if="evaluating" class="flex items-center gap-2 text-sm text-muted mt-2" role="status"><UIcon name="i-lucide-loader-circle" class="animate-spin" />{{ t('alerts.evaluating') }}</div>
    </UCard>

    <UCard>
      <template #header><span class="font-medium">{{ t('alerts.active') }}</span></template>
      <p v-if="data && !data.active.length" class="text-sm text-muted flex items-center gap-2"><UIcon name="i-lucide-circle-check" class="size-4 text-success" />{{ t('alerts.none') }}</p>
      <ul v-else class="flex flex-col divide-y divide-default">
        <li v-for="a in data?.active ?? []" :key="a.id" class="py-2 flex flex-wrap items-start gap-3">
          <UBadge :color="sevColor(a.severity)" variant="subtle" :icon="sevIcon(a.severity)" :label="t(`alerts.sev.${a.severity}`)" />
          <div class="flex-1 min-w-48">
            <div class="text-sm">{{ ruleText(a) }}</div>
            <div class="text-xs text-muted">{{ t('alerts.col.since') }} {{ when(a.started_at) }}<template v-if="a.node"> · <span class="font-mono">{{ a.node }}</span></template></div>
          </div>
          <UBadge v-if="a.silenced" color="neutral" variant="outline" icon="i-lucide-bell-off" :label="t('alerts.silenced')" />
          <UButton v-else size="xs" color="neutral" variant="outline" icon="i-lucide-bell-off" :label="t('alerts.silence')" @click="openSilence(a)" />
        </li>
      </ul>
    </UCard>

    <UCard>
      <template #header><span class="font-medium">{{ t('alerts.silences') }}</span></template>
      <p v-if="data && !data.silences.length" class="text-sm text-muted">{{ t('alerts.silences_none') }}</p>
      <ul v-else class="flex flex-col divide-y divide-default text-sm">
        <li v-for="s in data?.silences ?? []" :key="s.id" class="py-2 flex flex-wrap items-center gap-3">
          <div class="flex-1 min-w-48"><div>{{ silenceScope(s) }}</div>
            <div class="text-xs text-muted">{{ t('alerts.until', { at: when(s.until) }) }}<template v-if="s.created_by"> · {{ t('alerts.by', { u: s.created_by }) }}</template><template v-if="s.comment"> · {{ s.comment }}</template></div></div>
          <UButton size="xs" color="neutral" variant="outline" icon="i-lucide-bell" :label="t('alerts.unsilence')" @click="unsilence(s)" />
        </li>
      </ul>
    </UCard>

    <UCard>
      <template #header>
        <div class="flex items-center gap-2"><span class="font-medium">{{ t('alerts.cfg.title') }}</span></div>
      </template>
      <p class="text-sm text-muted mb-3">{{ t('alerts.cfg.intro') }}</p>
      <form v-if="conf" class="flex flex-col gap-5" @submit.prevent="save">
        <div class="grid sm:grid-cols-3 gap-3">
          <UFormField :label="t('alerts.cfg.min')"><USelect v-model="form.minSeverity" :items="sevItems" class="w-full" /></UFormField>
          <UFormField :label="t('alerts.cfg.repeat')"><UInput v-model.number="form.repeatHours" type="number" min="0" max="168" class="w-full" /></UFormField>
          <UFormField :label="t('alerts.cfg.lang')"><USelect v-model="form.lang" :items="langItems" class="w-full" /></UFormField>
        </div>

        <fieldset class="rounded-lg border border-default p-3 flex flex-col gap-3">
          <legend class="px-1 text-sm font-medium">{{ t('alerts.cfg.webhook') }}</legend>
          <USwitch v-model="form.webhook.enabled" :label="t('alerts.cfg.webhook_enabled')" />
          <div class="grid sm:grid-cols-2 gap-3">
            <UFormField :label="t('alerts.cfg.webhook_url')"><UInput v-model="form.webhook.url" class="w-full" placeholder="https://hooks.example.com/…" autocomplete="off" /></UFormField>
            <UFormField :label="t('alerts.cfg.webhook_secret')" :hint="form.webhook.hasSecret && !form.webhook.clearSecret ? t('alerts.cfg.secret_kept') : undefined"><UInput v-model="form.webhook.secret" type="password" class="w-full" autocomplete="new-password" /></UFormField>
          </div>
          <UCheckbox v-if="form.webhook.hasSecret" v-model="form.webhook.clearSecret" :label="t('alerts.cfg.secret_clear')" />
          <div><UButton size="xs" color="neutral" variant="outline" icon="i-lucide-send" :label="t('alerts.cfg.test')" :loading="testing === 'webhook'" :disabled="!!testing || dirty || !conf.webhook.enabled" @click="test('webhook')" /></div>
        </fieldset>

        <fieldset class="rounded-lg border border-default p-3 flex flex-col gap-3">
          <legend class="px-1 text-sm font-medium">{{ t('alerts.cfg.email') }}</legend>
          <USwitch v-model="form.email.enabled" :label="t('alerts.cfg.email_enabled')" />
          <div class="grid sm:grid-cols-3 gap-3">
            <UFormField :label="t('alerts.cfg.host')"><UInput v-model="form.email.host" class="w-full" placeholder="smtp.example.com" autocomplete="off" /></UFormField>
            <UFormField :label="t('alerts.cfg.port')"><UInput v-model.number="form.email.port" type="number" min="1" max="65535" class="w-full" /></UFormField>
            <UFormField :label="t('alerts.cfg.security')"><USelect v-model="form.email.security" :items="secItems" class="w-full" /></UFormField>
            <UFormField :label="t('alerts.cfg.user')"><UInput v-model="form.email.user" class="w-full" autocomplete="off" /></UFormField>
            <UFormField :label="t('alerts.cfg.password')" :hint="form.email.hasPassword && !form.email.clearPassword ? t('alerts.cfg.password_kept') : undefined"><UInput v-model="form.email.password" type="password" class="w-full" autocomplete="new-password" /></UFormField>
            <UFormField :label="t('alerts.cfg.from')"><UInput v-model="form.email.from" class="w-full" placeholder="ddibuntu@example.com" autocomplete="off" /></UFormField>
          </div>
          <UFormField :label="t('alerts.cfg.to')"><UTextarea v-model="form.email.to" :rows="2" class="w-full" autocomplete="off" /></UFormField>
          <div class="flex flex-wrap gap-4">
            <UCheckbox v-model="form.email.verifyCert" :label="t('alerts.cfg.verify')" />
            <UCheckbox v-if="form.email.hasPassword" v-model="form.email.clearPassword" :label="t('alerts.cfg.password_clear')" />
          </div>
          <div><UButton size="xs" color="neutral" variant="outline" icon="i-lucide-send" :label="t('alerts.cfg.test')" :loading="testing === 'email'" :disabled="!!testing || dirty || !conf.email.enabled" @click="test('email')" /></div>
        </fieldset>
        <p v-if="dirty" class="text-xs text-muted -mt-3">{{ t('alerts.cfg.test_save_first') }}</p>

        <fieldset class="rounded-lg border border-default p-3">
          <legend class="px-1 text-sm font-medium">{{ t('alerts.cfg.thresholds') }}</legend>
          <div class="grid sm:grid-cols-2 gap-3">
            <UFormField v-for="k in thKeys" :key="k" :label="t(`alerts.th.${k}`)"><UInput v-model.number="form.thresholds[k]" type="number" min="0" class="w-full" /></UFormField>
          </div>
        </fieldset>

        <UAlert v-if="cfgErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="cfgErr" />
        <div class="flex items-center gap-3">
          <UButton type="submit" icon="i-lucide-save" :label="t('alerts.cfg.save')" :loading="saving" :disabled="saving" />
          <span v-if="saving" class="flex items-center gap-2 text-sm text-muted" role="status"><UIcon name="i-lucide-loader-circle" class="animate-spin" />{{ t('alerts.cfg.save') }}…</span>
        </div>
      </form>
    </UCard>

    <UCard v-if="conf">
      <template #header><span class="font-medium">{{ t('alerts.prom.title') }}</span></template>
      <p class="text-sm text-muted mb-3">{{ t('alerts.prom.intro') }}</p>
      <p class="text-sm mb-3 flex items-center gap-2"><UIcon :name="conf.metricsToken ? 'i-lucide-key-round' : 'i-lucide-key-square'" class="size-4" />{{ conf.metricsToken ? t('alerts.prom.active') : t('alerts.prom.none') }}</p>
      <div v-if="token" class="mb-3 rounded-lg border border-default p-3">
        <p class="text-sm font-medium mb-1">{{ t('alerts.prom.once') }}</p>
        <div class="flex flex-wrap items-center gap-2"><code class="font-mono text-xs break-all select-all" data-testid="metrics-token">{{ token }}</code><UButton size="xs" color="neutral" variant="outline" icon="i-lucide-copy" :label="t('alerts.prom.copy')" @click="copy(token)" /></div>
      </div>
      <div class="flex flex-wrap gap-2">
        <UButton size="sm" icon="i-lucide-key-round" :label="conf.metricsToken ? t('alerts.prom.regen') : t('alerts.prom.create')" :loading="tokenBusy" :disabled="tokenBusy" @click="makeToken" />
        <UButton v-if="conf.metricsToken" size="sm" color="error" variant="outline" icon="i-lucide-key-square" :label="t('alerts.prom.revoke')" :disabled="tokenBusy" @click="revokeToken" />
      </div>
      <details v-if="conf.metricsToken" class="mt-3"><summary class="text-sm cursor-pointer">{{ t('alerts.prom.example') }}</summary><pre class="mt-2 text-xs font-mono overflow-x-auto rounded bg-elevated p-3">{{ promExample }}</pre></details>
    </UCard>

    <div class="grid gap-4 lg:grid-cols-2">
      <UCard>
        <template #header><span class="font-medium">{{ t('alerts.history') }}</span></template>
        <p v-if="data && !data.history.length" class="text-sm text-muted">{{ t('alerts.history_none') }}</p>
        <ul v-else class="flex flex-col divide-y divide-default text-sm max-h-80 overflow-auto">
          <li v-for="a in data?.history ?? []" :key="a.id" class="py-1.5 flex items-start gap-2">
            <UIcon :name="sevIcon(a.severity)" class="size-4 mt-0.5 shrink-0" :class="a.severity === 'critical' ? 'text-error' : a.severity === 'warning' ? 'text-warning' : 'text-info'" />
            <div class="min-w-0"><div>{{ ruleText(a) }}</div><div class="text-xs text-muted">{{ when(a.started_at) }} → {{ when(a.resolved_at) }}</div></div>
          </li>
        </ul>
      </UCard>
      <UCard>
        <template #header><span class="font-medium">{{ t('alerts.deliveries') }}</span></template>
        <p v-if="data && !data.deliveries.length" class="text-sm text-muted">{{ t('alerts.deliveries_none') }}</p>
        <ul v-else class="flex flex-col divide-y divide-default text-sm max-h-80 overflow-auto">
          <li v-for="d in data?.deliveries ?? []" :key="d.id" class="py-1.5 flex flex-wrap items-center gap-2">
            <UBadge :color="d.ok ? 'success' : 'error'" variant="subtle" :label="d.ok ? t('alerts.delivery.ok') : t('alerts.delivery.ko')" />
            <span>{{ t(`alerts.channel.${d.channel}`) }} · {{ t(`alerts.kind.${d.kind}`) }}</span>
            <span class="text-xs text-muted font-mono">{{ d.detail }}</span><span class="flex-1" /><span class="text-xs text-muted num">{{ when(d.at) }}</span>
          </li>
        </ul>
      </UCard>
    </div>

    <UModal v-model:open="silOpen" :title="t('alerts.silence.title')" :description="silenceFor ? t('alerts.silence.intro', { what: ruleText(silenceFor) }) : ''">
      <template #body>
        <div class="flex flex-col gap-3">
          <UFormField :label="t('alerts.silence.scope.label')"><USelect v-model="silForm.scope" :items="scopeItems" class="w-full" /></UFormField>
          <UFormField :label="t('alerts.silence.duration')"><USelect v-model="silForm.hours" :items="hourItems" class="w-full" /></UFormField>
          <UFormField :label="t('alerts.silence.comment')"><UInput v-model="silForm.comment" maxlength="200" class="w-full" autocomplete="off" /></UFormField>
          <UAlert v-if="silErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="silErr" />
        </div>
      </template>
      <template #footer>
        <div class="flex justify-end gap-2 w-full">
          <UButton color="neutral" variant="outline" :label="t('common.cancel')" :disabled="silBusy" @click="silOpen = false" />
          <UButton icon="i-lucide-bell-off" :label="t('alerts.silence.create')" :loading="silBusy" :disabled="silBusy" @click="createSilence" />
        </div>
      </template>
    </UModal>
  </div>
</template>
