<script setup lang="ts">
// Pare-feu de CE nœud : réseaux autorisés à administrer l'appliance (SSH + console web). Application avec retour arrière automatique :
// il faut confirmer depuis un poste qui a encore accès, sinon les règles précédentes reviennent seules.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()
const data = ref<any>(null), busy = ref(false), err = ref(''), text = ref(''), now = ref(Date.now())
let timer: ReturnType<typeof setInterval> | null = null
const parsed = computed(() => text.value.split(/[\s,;]+/).filter(Boolean))
const dirty = computed(() => !!data.value && parsed.value.join(',') !== (data.value.adminNets ?? []).join(','))
const left = computed(() => (data.value?.pending ? Math.max(0, Math.round(data.value.pending.until - now.value / 1000)) : 0))
const waiting = computed(() => !!data.value && (data.value.requestPending || (data.value.pending && left.value > 0)))
const resultMsg = computed(() => (data.value?.result ? `${data.value.result.ok ? '✔' : '✖'} ${data.value.result.message}` : ''))
function apply(d: any, keepText = false) { data.value = d; if (!keepText || !dirty.value) text.value = (d.adminNets ?? []).join('\n') }
async function load(keep = true) {
  try { apply(await api.call('GET', '/system/firewall', undefined, { silent: true }), keep) } catch (e: any) { err.value = e?.info?.message ?? '' }
}
async function settle() {   // attend que root ait traité la demande (publication du résultat ou du délai de confirmation)
  for (let i = 0; i < 20; i++) { await new Promise((r) => setTimeout(r, 1500)); await load(false); if (!data.value?.requestPending) return }
}
async function save(force = false) {
  if (busy.value || !parsed.value.length) return
  if (!force && !data.value.meCovered && parsed.value.length && !(await ask(t('fw.lockout_title'), t('fw.lockout_body', { ip: data.value.me ?? '?' }), true))) return
  busy.value = true; err.value = ''
  try {
    await api.call('PUT', '/system/firewall/nets', { nets: parsed.value, force: true })
    toast.add({ title: t('fw.sent'), color: 'success' }); await settle()
  } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function confirmNow() {
  busy.value = true; err.value = ''
  try { await api.call('POST', '/system/firewall/confirm', {}); toast.add({ title: t('fw.confirmed'), color: 'success' }); await settle() }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function rollbackNow() {
  if (!(await ask(t('fw.rollback_title'), t('fw.rollback_body'), true))) return
  busy.value = true; err.value = ''
  try { await api.call('POST', '/system/firewall/rollback', {}); toast.add({ title: t('fw.rolledback'), color: 'success' }); await settle() }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
function addMe() { const ip = data.value?.me; if (ip && !parsed.value.includes(ip)) text.value = `${text.value.trim()}${text.value.trim() ? '\n' : ''}${String(ip).replace(/^::ffff:/i, '')}` }
onMounted(() => { timer = setInterval(() => { now.value = Date.now(); if (data.value?.pending && left.value === 0) void load(false) }, 1000) })
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
await load(false)
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex items-center justify-between gap-2">
        <span class="font-medium">{{ t('fw.title') }}</span>
        <UBadge v-if="data" color="neutral" variant="subtle" :label="`TCP ${data.adminTcp}`" />
      </div>
    </template>
    <p class="text-sm text-muted mb-3">{{ t('fw.hint') }}</p>

    <UAlert v-if="data?.pending && left > 0" color="warning" variant="subtle" icon="i-lucide-timer" :title="t('fw.pending_title')" :description="t('fw.pending_body', { s: left })" class="mb-3" data-test="fw-pending">
      <template #actions>
        <UButton :label="t('fw.confirm')" color="primary" :loading="busy" data-test="fw-confirm" @click="confirmNow" />
        <UButton :label="t('fw.rollback')" color="neutral" variant="outline" :disabled="busy" data-test="fw-rollback" @click="rollbackNow" />
      </template>
    </UAlert>

    <UFormField :label="t('fw.nets')" :help="t('fw.nets_hint', { max: data?.max ?? 32 })">
      <UTextarea v-model="text" :rows="5" class="w-full font-mono" :disabled="busy || waiting" placeholder="192.168.1.0/24&#10;10.20.0.15" data-test="fw-nets" />
    </UFormField>
    <p v-if="data && !data.meCovered && !dirty" class="text-xs text-warning mt-2">{{ t('fw.me_not_covered', { ip: data.me ?? '?' }) }}</p>
    <p class="text-xs text-dimmed mt-2">{{ t('fw.node_note') }}</p>
    <p v-if="resultMsg" class="text-xs mt-2" :class="data.result.ok ? 'text-muted' : 'text-error'" data-test="fw-result">{{ t('fw.last') }} {{ fmt.dateTime(data.result.at * 1000) }} — {{ resultMsg }}</p>
    <p v-if="err" class="text-sm text-error mt-2" role="alert">{{ err }}</p>
    <div class="flex flex-wrap gap-2 mt-3">
      <UButton :label="t('fw.save')" :loading="busy || !!data?.requestPending" :disabled="!parsed.length || !dirty || waiting" data-test="fw-save" @click="save(false)" />
      <UButton :label="t('fw.add_me', { ip: data?.me ?? '' })" color="neutral" variant="outline" icon="i-lucide-monitor" :disabled="busy || waiting || !data?.me" @click="addMe" />
    </div>
  </UCard>
</template>
