<script setup lang="ts">
// Classes de clients et filtres MAC « refuser » depuis l'export DHCP Windows (0.12.8) : aperçu, puis création. Les listes « autoriser » ne sont pas reprises.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const emit = defineEmits<{ done: [] }>()
const xml = ref(''), name = ref(''), plan = ref<any>(null), busy = ref(''), err = ref('')
async function pick(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0]; if (!f) return
  if (f.size > 25 * 1024 * 1024) { err.value = t('err.too_large'); return }
  xml.value = await f.text(); name.value = f.name; plan.value = null; err.value = ''
}
const REASON = computed<Record<string, string>>(() => ({ class_data: t('mcl.r_class_data'), allow_list: t('mcl.r_allow'), mac_invalid: t('mcl.r_mac') }))
const STATUS = computed<Record<string, string>>(() => ({ create: t('mcl.s_create'), exists: t('mcl.s_exists'), skip: t('mcl.s_skip') }))
async function preview() {
  busy.value = 'p'; err.value = ''; plan.value = null
  try { plan.value = await api.call('POST', '/migration/classes/preview', { content: xml.value }, { silent: true }) } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
async function commit() {
  if (!(await ask(t('mcl.confirm_title'), t('mcl.confirm_msg', { n: plan.value.toCreate }), false))) return
  busy.value = 'c'; err.value = ''
  try {
    const r = await api.call('POST', '/migration/classes/commit', { content: xml.value, filename: name.value }, { silent: true }) as any
    toast.add({ title: t('mcl.done', { n: r.created }), color: 'success', icon: 'i-lucide-check' }); plan.value = null; emit('done')
  } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
</script>

<template>
  <div class="flex flex-col gap-2 rounded-md bg-elevated/50 p-3" data-test="mcl-root">
    <div class="font-medium text-sm">{{ t('mcl.title') }}</div>
    <UFormField :label="t('mia.f_dhcp')" :help="t('mcl.help')"><input type="file" accept=".xml,text/xml" class="block w-full text-sm" :aria-label="t('mia.f_dhcp')" data-test="mcl-file" @change="pick"></UFormField>
    <div><UButton icon="i-lucide-search" :label="t('mcl.preview')" :loading="busy === 'p'" :disabled="!xml" data-test="mcl-preview" @click="preview" /></div>
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <template v-if="plan">
      <p class="text-sm text-muted" data-test="mcl-summary">{{ t('mcl.summary', { c: plan.toCreate, e: plan.exists, s: plan.skipped }) }}</p>
      <ul v-if="plan.items.length" class="flex flex-col gap-1" data-test="mcl-list">
        <li v-for="(i, k) in plan.items" :key="k" class="text-sm flex flex-wrap gap-2 rounded-md border border-default p-2"><UBadge :color="i.status === 'create' ? 'success' : i.status === 'skip' ? 'warning' : 'neutral'" variant="subtle" :label="STATUS[i.status]" /><span class="font-mono">{{ i.name }}</span><span class="text-muted">{{ i.kind }} {{ i.match }}</span><span v-if="i.reason" class="text-muted">{{ REASON[i.reason] }}</span></li>
      </ul>
      <div v-if="plan.toCreate"><UButton icon="i-lucide-plus" :label="t('mcl.commit', { n: plan.toCreate })" :loading="busy === 'c'" data-test="mcl-commit" @click="commit" /></div>
    </template>
  </div>
</template>
