<script setup lang="ts">
// Accès réseau — import d'un NPS Windows (0.13.10, itération 5). Trois temps : (1) exporter la configuration du NPS (script PowerShell à exécuter sur le serveur),
// (2) déposer le fichier : la console en tire un PLAN — clients et stratégies réseau, chacun « repris », « adapté » ou « non pris en charge », avec la raison —
// et n'écrit rien, (3) valider : le même plan est refait sous verrou, puis écrit en une transaction. Rien n'est déployé : clients et règles attendent « Déployer ».
import { PS_NPS } from '~/utils/migration-scripts'
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const emit = defineEmits<{ changed: [] }>()

const text = ref(''), filename = ref(''), readErr = ref('')
const activate = ref(false)
const usages = reactive<Record<string, string>>({})
const excluded = reactive(new Set<string>())
const prev = ref<any>(null), digest = ref(''), analysing = ref(false), importing = ref(false), error = ref('')
const result = ref<any>(null)
const USAGES = ['wifi', 'vpn', 'switch', 'other']
const usageItems = computed(() => USAGES.map((u) => ({ label: t(`radius.u.${u}`), value: u })))

// L'export de netsh est le plus souvent en UTF-16 : on lit les octets et on décode d'après la marque d'ordre des octets (sinon UTF-8).
async function decode(f: File): Promise<string> {
  const b = new Uint8Array(await f.arrayBuffer())
  if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le').decode(b)
  if (b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be').decode(b)
  return new TextDecoder('utf-8').decode(b)
}
async function pick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]
  if (!f) return
  readErr.value = ''
  if (f.size > 8_000_000) { readErr.value = t('radius.nps.too_big'); return }
  text.value = await decode(f); filename.value = f.name
  prev.value = null; result.value = null; error.value = ''; excluded.clear(); for (const k of Object.keys(usages)) delete usages[k]
}
const payload = () => ({ content: text.value, filename: filename.value || undefined, usages: { ...usages }, exclude: [...excluded], activate: activate.value })
async function analyse() {
  if (!text.value || analysing.value) return
  analysing.value = true; error.value = ''; result.value = null
  try { const r: any = await api.call('POST', '/radius/nps/preview', payload(), { silent: true, busy: true }); prev.value = r.plan; digest.value = r.digest }
  catch (e: any) { prev.value = null; error.value = e?.info?.message ?? t('err.internal') } finally { analysing.value = false }
}
// une option (usage, case décochée, activation) change le plan : on le recalcule pour que l'empreinte validée soit celle qu'on voit
watch([activate, () => JSON.stringify(usages), () => [...excluded].join('|')], () => { if (prev.value) void analyse() })

const plan = computed(() => prev.value)
const clients = computed<any[]>(() => plan.value?.clients ?? [])
const rules = computed<any[]>(() => plan.value?.rules ?? [])
const toCreate = computed(() => ({ clients: clients.value.filter((c) => c.selected && c.status !== 'skipped').length, rules: rules.value.filter((r) => r.selected && r.status !== 'skipped').length }))
const generated = computed(() => clients.value.filter((c) => c.selected && c.status !== 'skipped' && c.secret === 'generated').length)
const badge = (s: string) => (s === 'imported' ? { color: 'success', icon: 'i-lucide-circle-check' } : s === 'adapted' ? { color: 'warning', icon: 'i-lucide-pencil-ruler' } : { color: 'neutral', icon: 'i-lucide-circle-slash' })
const noteText = (n: any) => t(`radius.nps.n.${n.code}`, n.params ?? {})
function toggle(key: string, on: boolean) { if (on) excluded.delete(key); else excluded.add(key) }
function setUsage(c: any, v: string) { usages[c.original] = v }

async function doImport() {
  if (!toCreate.value.clients && !toCreate.value.rules) return
  if (!(await ask(t('radius.nps.commit_title'), t('radius.nps.commit_body', { c: toCreate.value.clients, r: toCreate.value.rules }), false))) return
  importing.value = true; error.value = ''
  try {
    result.value = await api.call('POST', '/radius/nps/commit', { ...payload(), digest: digest.value }, { silent: true })
    prev.value = null; text.value = ''; filename.value = ''
    toast.add({ title: t('radius.nps.done'), color: 'success', icon: 'i-lucide-check' }); emit('changed')
  } catch (e: any) { error.value = e?.info?.message ?? t('err.internal') } finally { importing.value = false }
}
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
function download(name: string, data: string) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([data], { type: 'text/plain' })); a.download = name; a.click(); URL.revokeObjectURL(a.href) }
const secretsCsv = () => 'client;secret\n' + (result.value?.generated ?? []).map((g: any) => `${g.name};${g.secret}`).join('\n') + '\n'
const dirNote = computed(() => (plan.value?.directory === 'ok' ? '' : t(`radius.nps.dir_${plan.value?.directory}`)))
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('radius.nps.intro') }}</p>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-terminal" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.nps.s1_title') }}</h2></div></template>
      <div class="flex flex-col gap-2">
        <p class="text-sm text-muted">{{ t('radius.nps.s1_body') }}</p>
        <pre class="text-xs font-mono bg-elevated rounded-md p-3 overflow-x-auto" data-test="nps-script">{{ PS_NPS }}</pre>
        <div class="flex flex-wrap items-center gap-2">
          <UButton size="xs" icon="i-lucide-copy" :label="t('radius.nps.copy')" data-test="nps-copy" @click="copy(PS_NPS)" />
          <UButton size="xs" color="neutral" variant="outline" icon="i-lucide-download" :label="t('radius.nps.download')" @click="download('export-nps.ps1', PS_NPS)" />
        </div>
        <UAlert color="warning" variant="subtle" icon="i-lucide-key-round" :title="t('radius.nps.secrets_title')" :description="t('radius.nps.secrets_body')" />
      </div>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-file-up" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.nps.s2_title') }}</h2></div></template>
      <form class="flex flex-col gap-3" @submit.prevent="analyse">
        <UFormField :label="t('radius.nps.file')" :help="t('radius.nps.file_help')"><input type="file" accept=".xml,text/xml" class="block w-full text-sm" :aria-label="t('radius.nps.file')" data-test="nps-file" @change="pick"></UFormField>
        <UAlert v-if="readErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="readErr" role="alert" />
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" data-test="nps-error" />
        <div class="flex items-center gap-3">
          <UButton type="submit" icon="i-lucide-scan-search" :label="t('radius.nps.analyse')" :loading="analysing" :disabled="!text || analysing || importing" data-test="nps-analyse" />
          <span v-if="analysing" class="text-sm text-muted" role="status">{{ t('radius.nps.analysing') }}</span>
        </div>
      </form>
    </UCard>

    <template v-if="plan">
      <UAlert v-if="dirNote" color="warning" variant="subtle" icon="i-lucide-network" :title="t('radius.nps.dir_title')" :description="dirNote" data-test="nps-dir" />
      <UAlert v-if="!plan.clientsContainer" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('radius.nps.no_clients_container')" />

      <UCard>
        <template #header>
          <div class="flex flex-wrap items-center gap-2">
            <UIcon name="i-lucide-router" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.nps.clients_title') }}</h2>
            <UBadge color="success" variant="subtle" :label="t('radius.nps.st_imported', { n: plan.totals.clients.imported })" />
            <UBadge color="warning" variant="subtle" :label="t('radius.nps.st_adapted', { n: plan.totals.clients.adapted })" />
            <UBadge color="neutral" variant="subtle" :label="t('radius.nps.st_skipped', { n: plan.totals.clients.skipped })" />
          </div>
        </template>
        <p v-if="!clients.length" class="text-sm text-muted">{{ t('radius.nps.no_clients') }}</p>
        <ul v-else class="divide-y divide-default" data-test="nps-clients">
          <li v-for="c in clients" :key="c.key" class="flex flex-wrap items-start gap-3 py-3" :class="c.status === 'skipped' || !c.selected ? 'opacity-70' : ''" data-test="nps-client">
            <UCheckbox :model-value="c.selected" :disabled="c.status === 'skipped'" :aria-label="t('radius.nps.include', { name: c.original })" @update:model-value="(v: any) => toggle(c.key, v === true)" />
            <div class="min-w-0 flex-1">
              <div class="flex flex-wrap items-center gap-2">
                <span class="font-medium">{{ c.original }}</span>
                <template v-if="c.status !== 'skipped' && c.name !== c.original"><UIcon name="i-lucide-arrow-right" class="size-4 text-muted" /><code class="text-xs">{{ c.name }}</code></template>
                <UBadge :color="badge(c.status).color as any" variant="subtle" :icon="badge(c.status).icon" :label="t(`radius.nps.status_${c.status}`)" />
                <code class="text-xs text-muted">{{ c.address ?? c.rawAddress }}</code>
                <UBadge v-if="c.secret" color="neutral" variant="outline" :label="t(`radius.nps.secret_${c.secret}`)" />
              </div>
              <ul v-if="c.notes.length" class="mt-1 list-disc pl-5 text-sm text-muted"><li v-for="(n, i) in c.notes" :key="i">{{ noteText(n) }}</li></ul>
            </div>
            <USelect v-if="c.status !== 'skipped'" :model-value="c.usage" :items="usageItems" size="sm" class="w-36" :aria-label="t('radius.nps.usage_of', { name: c.original })" data-test="nps-usage" @update:model-value="(v: any) => setUsage(c, String(v))" />
          </li>
        </ul>
      </UCard>

      <UCard>
        <template #header>
          <div class="flex flex-wrap items-center gap-2">
            <UIcon name="i-lucide-list-checks" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.nps.rules_title') }}</h2>
            <UBadge color="success" variant="subtle" :label="t('radius.nps.st_imported', { n: plan.totals.rules.imported })" />
            <UBadge color="warning" variant="subtle" :label="t('radius.nps.st_adapted', { n: plan.totals.rules.adapted })" />
            <UBadge color="neutral" variant="subtle" :label="t('radius.nps.st_skipped', { n: plan.totals.rules.skipped })" />
          </div>
        </template>
        <UAlert v-if="plan.connectionPolicies" color="neutral" variant="subtle" icon="i-lucide-route" :title="t('radius.nps.conn_title', { n: plan.connectionPolicies })" :description="t('radius.nps.conn_body')" class="mb-3" data-test="nps-conn" />
        <p v-if="!rules.length" class="text-sm text-muted">{{ t('radius.nps.no_rules') }}</p>
        <ul v-else class="divide-y divide-default" data-test="nps-rules">
          <li v-for="r in rules" :key="r.key" class="flex flex-wrap items-start gap-3 py-3" :class="r.status === 'skipped' || !r.selected ? 'opacity-70' : ''" data-test="nps-rule">
            <UCheckbox :model-value="r.selected" :disabled="r.status === 'skipped'" :aria-label="t('radius.nps.include', { name: r.name })" @update:model-value="(v: any) => toggle(r.key, v === true)" />
            <div class="min-w-0 flex-1">
              <div class="flex flex-wrap items-center gap-2">
                <span v-if="r.order !== null" class="text-xs text-muted">#{{ r.order }}</span>
                <span class="font-medium">{{ r.name }}</span>
                <UBadge :color="badge(r.status).color as any" variant="subtle" :icon="badge(r.status).icon" :label="t(`radius.nps.status_${r.status}`)" />
                <UBadge :color="r.action === 'accept' ? 'success' : 'error'" variant="outline" :label="t(`radius.rules.${r.action}`)" />
                <UBadge v-if="r.status !== 'skipped'" :color="r.enabled ? 'primary' : 'neutral'" variant="outline" :label="r.enabled ? t('common.enabled') : t('radius.rules.disabled')" />
              </div>
              <div v-if="r.status !== 'skipped'" class="mt-1 flex flex-wrap gap-1 text-xs text-muted">
                <UBadge v-if="r.kind" color="neutral" variant="subtle" :label="t(`radius.dir.kind_${r.kind}`)" />
                <UBadge v-for="g in r.groups" :key="g.dn" color="neutral" variant="subtle" icon="i-lucide-users" :label="g.name" />
                <UBadge v-for="x in r.clients" :key="x" color="neutral" variant="subtle" icon="i-lucide-router" :label="x" />
                <UBadge v-for="u in r.usages" :key="u" color="neutral" variant="subtle" :label="t(`radius.u.${u}`)" />
                <UBadge v-for="s in r.ssids" :key="s" color="neutral" variant="subtle" icon="i-lucide-wifi" :label="s" />
              </div>
              <ul v-if="r.notes.length" class="mt-1 list-disc pl-5 text-sm text-muted"><li v-for="(n, i) in r.notes" :key="i">{{ noteText(n) }}</li></ul>
              <details v-if="r.conditions.length" class="mt-1 text-xs text-muted"><summary class="cursor-pointer">{{ t('radius.nps.original') }}</summary><pre class="mt-1 overflow-x-auto rounded bg-elevated p-2 font-mono">{{ r.conditions.join('\n') }}</pre></details>
            </div>
          </li>
        </ul>
      </UCard>

      <UCard>
        <div class="flex flex-col gap-3">
          <USwitch v-model="activate" :label="t('radius.nps.activate')" :description="t('radius.nps.activate_help')" data-test="nps-activate" />
          <UAlert v-if="generated" color="info" variant="subtle" icon="i-lucide-key-round" :title="t('radius.nps.generated_title', { n: generated })" :description="t('radius.nps.generated_body')" />
          <div class="flex flex-wrap items-center gap-3">
            <UButton icon="i-lucide-download" :label="t('radius.nps.import', { c: toCreate.clients, r: toCreate.rules })" :loading="importing" :disabled="importing || analysing || (!toCreate.clients && !toCreate.rules)" data-test="nps-import" @click="doImport" />
            <span v-if="importing" class="text-sm text-muted" role="status">{{ t('radius.nps.importing') }}</span>
            <span class="text-sm text-muted">{{ t('radius.nps.nothing_applied') }}</span>
          </div>
        </div>
      </UCard>
    </template>

    <UCard v-if="result" data-test="nps-result">
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-circle-check" class="size-5 text-success" /><h2 class="font-semibold">{{ t('radius.nps.result_title') }}</h2></div></template>
      <div class="flex flex-col gap-3">
        <p class="text-sm">{{ t('radius.nps.result_body', { c: result.clients, r: result.rules, a: result.activeRules }) }}</p>
        <p v-if="result.clientsSkipped || result.rulesSkipped" class="text-sm text-muted">{{ t('radius.nps.result_skipped', { c: result.clientsSkipped, r: result.rulesSkipped }) }}</p>
        <div v-if="result.generated.length" class="flex flex-col gap-2" data-test="nps-generated">
          <UAlert color="warning" variant="subtle" icon="i-lucide-key-round" :title="t('radius.nps.once_title')" :description="t('radius.nps.once_body')" />
          <ul class="divide-y divide-default rounded-md border border-default">
            <li v-for="g in result.generated" :key="g.name" class="flex flex-wrap items-center gap-3 px-3 py-2"><code class="text-sm font-medium">{{ g.name }}</code><code class="flex-1 break-all text-sm" data-test="nps-secret">{{ g.secret }}</code><UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-copy" :aria-label="t('common.copy')" @click="copy(g.secret)" /></li>
          </ul>
          <div><UButton size="xs" color="neutral" variant="outline" icon="i-lucide-download" :label="t('radius.nps.secrets_csv')" @click="download('secrets-radius.csv', secretsCsv())" /></div>
        </div>
        <p class="text-sm text-muted">{{ t('radius.nps.next') }}</p>
      </div>
    </UCard>
  </div>
</template>
