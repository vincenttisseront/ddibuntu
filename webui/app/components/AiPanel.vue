<script setup lang="ts">
// Assistant IA (0.23.0) : connexion à un serveur de modèles externe (API Ollama ou compatible OpenAI), choix du modèle, usages, garde-fous.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { load: reloadStatus } = useAi()
const USES = ['audit', 'radius', 'radius_summary'] as const
const f = reactive<any>({ enabled: false, api: 'ollama', url: '', model: '', key: '', clearKey: false, tlsVerify: true, caPem: '', allowHttp: false, timeoutSec: 60, pseudonymize: false, perHour: 30, uses: { audit: true, radius: true, radius_summary: true } })
const keySet = ref(false), busy = ref(false), testing = ref(false), err = ref(''), test = ref<{ version: string | null; models: string[]; modelFound: boolean | null } | null>(null)
const apiItems = computed(() => [{ label: t('ai.api_ollama'), value: 'ollama' }, { label: t('ai.api_openai'), value: 'openai' }])
const modelItems = computed<string[]>(() => [...new Set([...(test.value?.models ?? []), ...(f.model ? [f.model] : [])])])
const isHttp = computed(() => /^http:\/\//i.test(f.url.trim()))
const valid = computed(() => !f.enabled || (f.url.trim() !== '' && f.model.trim() !== '' && (!isHttp.value || f.allowHttp)))
const placeholder = computed(() => (f.api === 'ollama' ? 'https://ia.example.lan:11434' : 'https://ia.example.lan/v1'))

async function load() {
  const r: any = await api.call('GET', '/ai/settings')
  Object.assign(f, { ...r, key: '', clearKey: false, caPem: r.caPem ?? '', uses: { ...f.uses, ...r.uses } }); keySet.value = r.keySet
}
onMounted(load)
const conn = () => ({ api: f.api, url: f.url.trim(), tlsVerify: f.tlsVerify, allowHttp: f.allowHttp, ...(f.caPem.trim() ? { caPem: f.caPem.trim() } : {}), ...(f.key ? { key: f.key } : {}) })
const errText = (e: any) => (e.info?.upstream?.detail ? `${e.info.message} (${e.info.upstream.status} : ${e.info.upstream.detail})` : e.info?.message ?? t('err.internal'))

async function runTest() {
  testing.value = true; err.value = ''; test.value = null
  try {
    test.value = await api.call('POST', '/ai/test', { ...conn(), ...(f.model ? { model: f.model } : {}) }, { busy: true, silent: true })
    if (!f.model && test.value?.models.length) f.model = test.value.models[0]!
  } catch (e: any) { err.value = errText(e) } finally { testing.value = false }
}
async function save() {
  busy.value = true; err.value = ''
  try {
    const b: any = { enabled: f.enabled, ...conn(), model: f.model.trim(), timeoutSec: Number(f.timeoutSec), pseudonymize: f.pseudonymize, perHour: Number(f.perHour), uses: { ...f.uses } }
    if (f.clearKey) b.key = ''
    await api.call('PUT', '/ai/settings', b, { silent: true })
    toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await load(); await reloadStatus(true)
  } catch (e: any) { err.value = errText(e) } finally { busy.value = false }
}
</script>

<template>
  <div class="flex flex-col gap-3" data-test="ai-panel">
    <UAlert color="neutral" variant="subtle" icon="i-lucide-sparkles" :title="t('ai.title')" :description="t('ai.intro')" />
    <UCard>
      <form class="flex flex-col gap-3" @submit.prevent="save">
        <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" data-test="ai-error" />
        <USwitch v-model="f.enabled" :label="t('ai.enabled')" :description="t('ai.enabled_hint')" :disabled="busy" data-test="ai-enabled" />
        <div class="grid gap-3 sm:grid-cols-3">
          <UFormField :label="t('ai.api')"><USelect v-model="f.api" :items="apiItems" class="w-full" :disabled="busy" /></UFormField>
          <UFormField class="sm:col-span-2" :label="t('ai.url')" :hint="t('ai.url_hint')" required><UInput v-model="f.url" class="w-full font-mono" autocomplete="off" :placeholder="placeholder" :disabled="busy" data-test="ai-url" /></UFormField>
        </div>
        <UAlert v-if="isHttp" :color="f.allowHttp ? 'warning' : 'error'" variant="subtle" icon="i-lucide-lock-open" :title="t('ai.http_warn')">
          <template #description><UCheckbox v-model="f.allowHttp" class="mt-1" :label="t('ai.allow_http')" :disabled="busy" data-test="ai-allow-http" /></template>
        </UAlert>
        <div class="grid gap-3 sm:grid-cols-2">
          <UFormField :label="t('ai.key')" :hint="keySet ? t('ai.key_set') : t('ai.key_hint')"><UInput v-model="f.key" type="password" class="w-full" autocomplete="new-password" :placeholder="keySet ? '••••••••' : ''" :disabled="busy || f.clearKey" /></UFormField>
          <div class="flex items-end"><UCheckbox v-if="keySet" v-model="f.clearKey" :label="t('ai.key_clear')" :disabled="busy" /></div>
        </div>
        <div v-if="!isHttp" class="flex flex-col gap-2">
          <UCheckbox v-model="f.tlsVerify" :label="t('ai.tls_verify')" :disabled="busy" />
          <UFormField :label="t('ai.ca')" :hint="t('ai.ca_hint')"><UTextarea v-model="f.caPem" :rows="3" class="w-full font-mono text-xs" :disabled="busy" placeholder="-----BEGIN CERTIFICATE-----" /></UFormField>
        </div>
        <div class="flex flex-wrap items-end gap-3">
          <UButton type="button" icon="i-lucide-plug-zap" color="neutral" variant="outline" :label="t('ai.test')" :loading="testing" :disabled="!f.url.trim() || busy || testing" data-test="ai-test" @click="runTest" />
          <UFormField :label="t('ai.model')" class="grow min-w-60" required :hint="t('ai.model_hint')">
            <USelectMenu v-if="modelItems.length" v-model="f.model" :items="modelItems" class="w-full font-mono" create-item :disabled="busy" data-test="ai-model" @create="(v: string) => { f.model = v }" />
            <UInput v-else v-model="f.model" class="w-full font-mono" autocomplete="off" placeholder="llama3.1:8b" :disabled="busy" data-test="ai-model" />
          </UFormField>
        </div>
        <p v-if="test" class="text-sm" data-test="ai-test-result">
          <UIcon name="i-lucide-circle-check" class="text-success align-middle" /> {{ t('ai.test_ok', { n: test.models.length }) }}<template v-if="test.version"> · {{ t('ai.version', { v: test.version }) }}</template>
          <template v-if="test.modelFound === false"> · <span class="text-warning">{{ t('ai.model_missing') }}</span></template>
        </p>

        <UFormField :label="t('ai.uses')" :hint="t('ai.uses_hint')">
          <ul class="flex flex-col gap-1 rounded-md border border-default p-2" role="group" :aria-label="t('ai.uses')">
            <li v-for="u in USES" :key="u"><label class="flex items-start gap-2 text-sm cursor-pointer"><input v-model="f.uses[u]" type="checkbox" class="mt-1" :disabled="busy" :data-test="`ai-use-${u}`">
              <span><span class="font-medium">{{ t(`ai.use.${u}`) }}</span><span class="block text-xs text-muted">{{ t(`ai.use_desc.${u}`) }}</span></span></label></li>
          </ul>
        </UFormField>
        <USwitch v-model="f.pseudonymize" :label="t('ai.pseudo')" :description="t('ai.pseudo_hint')" :disabled="busy" data-test="ai-pseudo" />
        <div class="grid gap-3 sm:grid-cols-2">
          <UFormField :label="t('ai.timeout')" :hint="t('ai.timeout_hint')"><UInput v-model.number="f.timeoutSec" type="number" :min="10" :max="300" class="w-full" :disabled="busy" /></UFormField>
          <UFormField :label="t('ai.per_hour')" :hint="t('ai.per_hour_hint')"><UInput v-model.number="f.perHour" type="number" :min="1" :max="500" class="w-full" :disabled="busy" /></UFormField>
        </div>
        <ul class="text-xs text-muted list-disc ps-5 flex flex-col gap-0.5"><li>{{ t('ai.rule_read_only') }}</li><li>{{ t('ai.rule_secrets') }}</li><li>{{ t('ai.rule_external') }}</li><li>{{ t('ai.rule_audit') }}</li></ul>
        <div class="flex justify-end"><UButton type="submit" icon="i-lucide-save" :label="t('common.save')" :loading="busy" :disabled="!valid || busy" data-test="ai-save" /></div>
      </form>
    </UCard>
  </div>
</template>
