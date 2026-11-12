<script setup lang="ts">
// Réglages de session communs à tous les nœuds du cluster (0.9.14) : durée maximale et inactivité, enregistrés en base (donc répliqués).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const data = ref<any>(null), busy = ref(false), err = ref('')
const f = reactive({ hours: 8, idle: 30 })
const lim = computed(() => data.value?.limits ?? { hours: { min: 1, max: 72 }, idle: { min: 5, max: 1440 } })
const inRange = (v: number, r: { min: number; max: number }) => Number.isInteger(v) && v >= r.min && v <= r.max
const valid = computed(() => inRange(f.hours, lim.value.hours) && inRange(f.idle, lim.value.idle))
const dirty = computed(() => !!data.value && (f.hours !== data.value.hours || f.idle !== data.value.idleMinutes))
function apply(d: any) { data.value = d; f.hours = d.hours; f.idle = d.idleMinutes }
async function load() { try { apply(await api.call('GET', '/system/session', undefined, { silent: true })) } catch (e: any) { err.value = e?.info?.message ?? '' } }
async function save() {
  if (!valid.value || busy.value) return
  busy.value = true; err.value = ''
  try { apply(await api.call('PUT', '/system/session', { hours: Number(f.hours), idleMinutes: Number(f.idle) })); toast.add({ title: t('sess.saved'), color: 'success' }) }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function reset() {
  const d = data.value?.defaults; if (!d || busy.value) return
  if (!(await ask(t('sess.reset_title'), t('sess.reset_body', { hours: d.hours, idle: d.idleMinutes }), false))) return
  busy.value = true; err.value = ''
  try { apply(await api.call('DELETE', '/system/session')); toast.add({ title: t('sess.reset_done'), color: 'success' }) }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
await load()
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex items-center justify-between gap-2">
        <span class="font-medium">{{ t('sess.title') }}</span>
        <UBadge v-if="data" :color="data.stored ? 'success' : 'neutral'" variant="subtle" :label="data.stored ? t('sess.source_stored') : t('sess.source_default')" />
      </div>
    </template>
    <p class="text-sm text-muted mb-3">{{ t('sess.hint') }}</p>
    <div class="flex flex-wrap items-start gap-4">
      <UFormField :label="t('sess.hours')" :help="t('sess.range', { min: lim.hours.min, max: lim.hours.max })" :error="inRange(f.hours, lim.hours) ? undefined : t('sess.invalid')">
        <UInput v-model.number="f.hours" type="number" :min="lim.hours.min" :max="lim.hours.max" class="w-32" data-test="sess-hours" />
      </UFormField>
      <UFormField :label="t('sess.idle')" :help="t('sess.range', { min: lim.idle.min, max: lim.idle.max })" :error="inRange(f.idle, lim.idle) ? undefined : t('sess.invalid')">
        <UInput v-model.number="f.idle" type="number" :min="lim.idle.min" :max="lim.idle.max" class="w-32" data-test="sess-idle" />
      </UFormField>
    </div>
    <p class="text-xs text-dimmed mt-2">{{ t('sess.replica_note') }}</p>
    <p v-if="err" class="text-sm text-error mt-2" role="alert">{{ err }}</p>
    <div class="flex gap-2 mt-3">
      <UButton :label="t('sess.save')" :loading="busy" :disabled="!valid || !dirty" @click="save" />
      <UButton :label="t('sess.reset')" color="neutral" variant="outline" :disabled="busy || !data?.stored" @click="reset" />
    </div>
  </UCard>
</template>
