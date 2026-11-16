<script setup lang="ts">
// Hôtes trouvés par la découverte planifiée et absents de l'IPAM : la liste (celle de l'alerte d'hygiène) puis l'import au choix de l'utilisateur.
// Rien n'est créé sans lui ; un point de restauration précède l'import.
const emit = defineEmits<{ changed: [] }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { data, refresh } = await useFetch<any>('/api/discovery/found')
const hosts = computed<any[]>(() => data.value?.hosts ?? [])
const sel = reactive<Record<string, boolean>>({})
watch(hosts, (h) => { for (const k of Object.keys(sel)) if (!h.some((x) => x.ip === k)) delete sel[k] }, { immediate: true })
const chosen = computed(() => hosts.value.filter((h) => sel[h.ip]).map((h) => h.ip))
const allPicked = computed(() => hosts.value.length > 0 && chosen.value.length === hosts.value.length)
const toggleAll = (v: boolean) => { for (const h of hosts.value) sel[h.ip] = v }
const fmt = useFmt()
const busy = ref(false)
async function doImport() {
  if (!chosen.value.length) return
  if (!(await ask(t('dfound.import'), t('dfound.confirm', { n: chosen.value.length }), false))) return
  busy.value = true
  try {
    const r = await api.call('POST', '/discovery/found/import', { ips: chosen.value }, { busy: true })
    toast.add({ title: t('dfound.done', { n: r.created }), color: 'success', icon: 'i-lucide-check' })
    await refresh(); emit('changed')
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) }
  finally { busy.value = false }
}
</script>

<template>
  <UCard data-test="disc-found">
    <template #header><span class="font-medium">{{ t('dfound.title') }}</span></template>
    <p v-if="!data?.at" class="text-sm text-muted" data-test="dfound-never">{{ t('dfound.never') }}</p>
    <p v-else-if="!hosts.length" class="text-sm text-muted" data-test="dfound-none">{{ t('dfound.none', { at: fmt.dateTime(data.at * 1000) }) }}</p>
    <div v-else class="flex flex-col gap-3 text-sm">
      <p class="text-muted">{{ t('dfound.intro', { n: hosts.length, at: fmt.dateTime(data.at * 1000) }) }}</p>
      <div class="overflow-auto max-h-80"><table class="w-full"><caption class="sr-only">{{ t('dfound.title') }}</caption>
        <thead><tr class="text-muted">
          <th scope="col" class="p-1 w-8"><input type="checkbox" :checked="allPicked" :aria-label="t('adw.select')" data-test="dfound-all" @change="toggleAll(($event.target as HTMLInputElement).checked)"></th>
          <th scope="col" class="text-start p-1">IP</th><th scope="col" class="text-start p-1">{{ t('cockpit.domain') }}</th><th scope="col" class="text-start p-1">MAC</th>
          <th scope="col" class="text-start p-1">{{ t('dfound.subnet') }}</th><th scope="col" class="text-start p-1">{{ t('disc.via') }}</th></tr></thead>
        <tbody><tr v-for="h in hosts" :key="h.ip" class="border-t border-default" data-test="dfound-row">
          <td class="p-1"><input v-model="sel[h.ip]" type="checkbox" :aria-label="`${t('adw.select')} ${h.ip}`"></td>
          <td class="p-1 font-mono">{{ h.ip }}</td><td class="p-1 font-mono">{{ h.name ?? '—' }}</td><td class="p-1 font-mono">{{ h.mac ?? '—' }}</td>
          <td class="p-1 font-mono">{{ h.subnet ?? '—' }}</td><td class="p-1">{{ (h.via ?? []).join(', ') }}</td></tr></tbody></table></div>
      <div class="flex flex-wrap items-center gap-3">
        <UButton icon="i-lucide-download" :label="t('dfound.import_n', { n: chosen.length })" :disabled="!chosen.length" :loading="busy" data-test="dfound-import" @click="doImport" />
        <span class="text-xs text-muted">{{ t('dfound.undo') }}</span>
      </div>
    </div>
  </UCard>
</template>
