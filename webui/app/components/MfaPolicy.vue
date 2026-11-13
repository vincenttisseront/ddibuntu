<script setup lang="ts">
// MFA obligatoire par rôle (0.9.52) : les comptes locaux des rôles cochés doivent activer la double authentification à leur prochaine connexion.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const data = ref<any>(null), busy = ref(false), err = ref('')
const sel = ref<string[]>([])
const roleLabel: Record<string, string> = { admin: t('system.role.admin'), operator: t('system.role.operator'), viewer: t('system.role.viewer') }
const dirty = computed(() => !!data.value && [...sel.value].sort().join() !== [...data.value.roles].sort().join())
function apply(d: any) { data.value = d; sel.value = [...d.roles] }
async function load() { try { apply(await api.call('GET', '/mfa/policy', undefined, { silent: true })) } catch (e: any) { err.value = e?.info?.message ?? '' } }
const toggle = (r: string, on: boolean) => { sel.value = on ? [...new Set([...sel.value, r])] : sel.value.filter((x) => x !== r) }
async function save() {
  if (!dirty.value || busy.value) return
  const n = sel.value.reduce((a, r) => a + (data.value.pending[r] ?? 0), 0)
  if (n > 0 && !(await ask(t('mfapol.confirm_title'), t('mfapol.confirm_body', { n }), false))) return
  busy.value = true; err.value = ''
  try { apply(await api.call('PUT', '/mfa/policy', { roles: sel.value })); toast.add({ title: t('mfapol.saved'), color: 'success' }) }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
await load()
</script>

<template>
  <UCard>
    <template #header><span class="font-medium">{{ t('mfapol.title') }}</span></template>
    <p class="text-sm text-muted mb-3">{{ t('mfapol.hint') }}</p>
    <div v-if="data" class="flex flex-wrap gap-6">
      <div v-for="r in data.available" :key="r" class="flex items-center gap-2">
        <UCheckbox :model-value="sel.includes(r)" :label="roleLabel[r]" :data-test="'mfapol-' + r" @update:model-value="(v: any) => toggle(r, !!v)" />
        <UBadge v-if="data.pending[r]" color="warning" variant="subtle" :label="t('mfapol.pending', { n: data.pending[r] })" />
      </div>
    </div>
    <p class="text-xs text-dimmed mt-2">{{ t('mfapol.scope') }}</p>
    <p v-if="err" class="text-sm text-error mt-2" role="alert">{{ err }}</p>
    <div class="mt-3"><UButton :label="t('mfapol.save')" :loading="busy" :disabled="!dirty" @click="save" /></div>
  </UCard>
</template>
