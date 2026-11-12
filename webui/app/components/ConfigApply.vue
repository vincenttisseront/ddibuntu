<script setup lang="ts">
// Génération, validation (outils officiels) et déploiement atomique de la configuration DNS/DHCP.
const { t } = useT(); const fmt = useFmt(); const api = useApi(); const { isAdmin } = useRole(); const toast = useToast(); const { ask } = useConfirm()
const result = ref<any>(null), files = ref<any>(null), busy = ref(false), sel = ref('')
async function loadFiles() { try { files.value = await api.call('GET', '/system/render'); sel.value = files.value.files[0]?.path ?? '' } catch { /* droits insuffisants */ } }
async function run(deploy: boolean) {
  if (deploy && !(await ask(t('apply.deploy'), t('apply.deploy_confirm'), false))) return
  busy.value = true
  try {
    result.value = await api.call('POST', '/system/apply', { deploy })
    toast.add({ title: result.value.deployed ? t('apply.deployed') : result.value.ok ? t('apply.valid') : t('apply.invalid'), color: result.value.ok ? 'success' : 'error', icon: result.value.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
    await loadFiles()
    if (deploy) setTimeout(loadReload, 4000)   // le rechargement privilégié est asynchrone : on relit son résultat réel
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { busy.value = false }
}
const reload = ref<any>(null)
async function loadReload() { try { reload.value = (await api.call<any>('GET', '/system/reload-status', undefined, { silent: true })).status } catch { /* droits insuffisants */ } }
onMounted(() => { loadFiles(); loadReload() })
const current = computed(() => files.value?.files?.find((f: any) => f.path === sel.value))
</script>

<template>
  <div class="grid gap-4 lg:grid-cols-2">
    <UCard>
      <template #header><span class="font-medium">{{ t('apply.title') }}</span></template>
      <p class="text-sm text-muted mb-3">{{ t('apply.desc') }}</p>
      <div class="flex gap-2 mb-4">
        <UButton icon="i-lucide-badge-check" color="neutral" variant="outline" :label="t('apply.validate')" :loading="busy" :disabled="!isAdmin" @click="run(false)" />
        <UButton icon="i-lucide-rocket" :label="t('apply.deploy')" :loading="busy" :disabled="!isAdmin" @click="run(true)" />
      </div>
      <UAlert v-if="!isAdmin" color="neutral" variant="subtle" :title="t('apply.admin_only')" class="mb-3" />
      <UAlert v-if="reload" :color="reload.ok ? 'success' : 'error'" variant="subtle" :icon="reload.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'" :title="reload.ok ? t('restore.reload_ok') : t('restore.reload_ko')" :description="`${fmt.dateTime(reload.at * 1000)} — ${reload.message}`" class="mb-3"><template v-if="!reload.ok && isAdmin" #actions><UButton to="/system#restore" size="xs" color="error" variant="outline" :label="t('restore.tab')" /></template></UAlert>
      <ul v-if="result" class="flex flex-col gap-2 text-sm" aria-live="polite">
        <li v-for="r in result.results" :key="r.name" class="flex gap-2 items-start">
          <UIcon :name="r.ok === true ? 'i-lucide-circle-check' : r.ok === false ? 'i-lucide-circle-x' : 'i-lucide-circle-help'" :class="r.ok === true ? 'text-success' : r.ok === false ? 'text-error' : 'text-warning'" class="mt-0.5 shrink-0" />
          <div><span class="font-mono">{{ r.name }}</span><pre v-if="r.output" class="text-xs whitespace-pre-wrap text-muted">{{ r.output }}</pre><p v-if="r.note === 'deferred'" class="text-xs text-muted">{{ t('apply.deferred') }}</p></div>
        </li>
        <li v-for="wn in result.warnings" :key="wn" class="text-warning text-xs">⚠ {{ t(`apply.warn.${wn.split(':')[0]}`, { name: wn.split(':')[1] ?? '' }) }}</li>
      </ul>
    </UCard>
    <UCard>
      <template #header><div class="flex items-center gap-2"><span class="font-medium">{{ t('apply.files') }}</span><div class="flex-1" /><USelect v-if="files" v-model="sel" :items="files.files.map((f: any) => ({ label: f.path, value: f.path }))" size="sm" class="w-64" :aria-label="t('apply.files')" /></div></template>
      <pre v-if="current" class="text-xs font-mono overflow-auto max-h-[calc(100vh-24rem)] whitespace-pre">{{ current.content }}</pre>
      <p v-if="current?.truncated" class="text-xs text-muted mt-2">{{ t('apply.truncated', { n: current.lines }) }}</p>
      <p v-if="!files" class="text-sm text-muted">{{ t('common.empty') }}</p>
    </UCard>
  </div>
</template>
