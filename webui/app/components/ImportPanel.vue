<script setup lang="ts">
// Import en deux temps : analyse (aucune écriture) puis import confirmé. Fichier ou texte collé.
const props = defineProps<{ previewUrl?: string; commitUrl: string; accept?: string; extra?: Record<string, any>; hint?: string }>()
const { t } = useT()
const api = useApi()
const toast = useToast()
const { ask } = useConfirm()
const text = ref(''), filename = ref(''), busy = ref(false)
const preview = ref<any | null>(null), result = ref<any | null>(null)
const error = ref<string | null>(null)

async function pick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]
  if (!f) return
  if (f.size > 25 * 1024 * 1024) { error.value = t('err.too_large'); return }
  text.value = await f.text(); filename.value = f.name; preview.value = null; result.value = null; error.value = null
}
const payload = () => ({ content: text.value, filename: filename.value || undefined, ...(props.extra ?? {}) })
async function analyse() {
  busy.value = true; error.value = null; result.value = null
  try { preview.value = await api.call('POST', props.previewUrl!, payload()) } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function commit() {
  if (!(await ask(t('import.commit'), t('import.commit_confirm'), false))) return
  busy.value = true; error.value = null
  try { result.value = await api.call('POST', props.commitUrl, payload()); toast.add({ title: t('import.done'), color: 'success', icon: 'i-lucide-check' }) } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
const flat = (o: any) => Object.entries(o ?? {}).filter(([, v]) => typeof v !== 'object' || v === null).map(([k, v]) => [k, v])
</script>

<template>
  <div class="grid gap-4 lg:grid-cols-2">
    <UCard>
      <template #header><span class="font-medium">{{ t('import.source') }}</span></template>
      <div class="flex flex-col gap-3">
        <slot />
        <p v-if="hint" class="text-sm text-muted">{{ hint }}</p>
        <UFormField :label="t('import.file')"><input type="file" :accept="accept" class="block w-full text-sm" :aria-label="t('import.file')" @change="pick"></UFormField>
        <UFormField :label="t('import.or_paste')"><UTextarea v-model="text" :rows="6" class="w-full font-mono" @update:model-value="preview = null; result = null" /></UFormField>
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" />
        <div class="flex gap-2 justify-end">
          <UButton v-if="previewUrl" color="neutral" variant="outline" icon="i-lucide-search-check" :label="t('import.analyse')" :disabled="!text" :loading="busy" @click="analyse" />
          <UButton icon="i-lucide-download" :label="t('import.commit')" :disabled="!text || (!!previewUrl && !preview)" :loading="busy" @click="commit" />
        </div>
      </div>
    </UCard>
    <UCard>
      <template #header><span class="font-medium">{{ result ? t('import.result') : t('import.preview') }}</span></template>
      <p v-if="!preview && !result" class="text-sm text-muted">{{ t('import.nothing') }}</p>
      <dl v-else class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <template v-for="[k, v] in flat(result ?? preview)" :key="k"><dt class="text-muted">{{ t(`import.k.${k}`) }}</dt><dd class="num font-mono">{{ v }}</dd></template>
        <template v-if="(result ?? preview)?.byType"><dt class="text-muted">{{ t('import.k.byType') }}</dt><dd class="font-mono text-xs">{{ Object.entries((result ?? preview).byType).map(([a, b]) => `${a}:${b}`).join('  ') }}</dd></template>
      </dl>
      <template v-for="list in ['warnings', 'errors']" :key="list">
        <div v-if="(result ?? preview)?.[list]?.length" class="mt-3">
          <p class="text-sm font-medium">{{ t(`import.${list}`) }} ({{ (result ?? preview)[list].length }})</p>
          <ul class="max-h-40 overflow-auto text-xs font-mono mt-1"><li v-for="(w, i) in (result ?? preview)[list]" :key="i">{{ JSON.stringify(w) }}</li></ul>
        </div>
      </template>
      <div v-if="preview?.scopes?.length" class="mt-3 overflow-auto max-h-48">
        <table class="text-xs w-full"><thead><tr><th class="text-start">CIDR</th><th class="text-start">{{ t('common.name') }}</th><th>Pools</th><th>{{ t('dhcp.reservations') }}</th></tr></thead>
          <tbody><tr v-for="s in preview.scopes" :key="s.cidr"><td class="font-mono">{{ s.cidr }}</td><td>{{ s.name }}</td><td class="num text-center">{{ s.pools }}</td><td class="num text-center">{{ s.reservations }}</td></tr></tbody></table>
      </div>
    </UCard>
  </div>
</template>
