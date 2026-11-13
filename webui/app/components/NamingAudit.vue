<script setup lang="ts">
// Contrôle de convention de nommage (0.10.5) : adresses dont le nom ne respecte pas la règle de leur réseau (VLAN, sinon gabarit).
const { t } = useT(); const api = useApi()
const { data: subnets } = await useFetch<any>('/api/ipam/subnets', { server: false })
const sid = ref<number | null>(null), res = ref<any>(null), err = ref(''), busy = ref(false)
const items = computed(() => [{ label: t('nam.all'), value: 0 }, ...(subnets.value?.items ?? []).filter((s: any) => s.family === 4).map((s: any) => ({ label: `${s.cidr} — ${s.name}`, value: s.id }))])
async function run() {
  busy.value = true; err.value = ''; res.value = null
  try { res.value = await api.call('GET', `/ipam/naming/audit?subnet_id=${sid.value || 0}`, undefined, { silent: true }) } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
</script>

<template>
  <div class="flex flex-col gap-3" data-test="nam-root">
    <p class="text-sm text-muted">{{ t('nam.help') }}</p>
    <div class="flex flex-wrap gap-3 items-end">
      <USelect v-model="sid" :items="items" :placeholder="t('nam.all')" class="min-w-72" data-test="nam-subnet" />
      <UButton icon="i-lucide-spell-check" :label="t('nam.check')" :loading="busy" data-test="nam-run" @click="run" />
    </div>
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <template v-if="res">
      <UAlert v-if="!res.violations" color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('nam.ok', { n: res.checked })" data-test="nam-ok" />
      <p v-else class="text-sm text-muted">{{ t('nam.summary', { v: res.violations, n: res.checked }) }}</p>
      <p v-if="res.unnamed" class="text-sm text-muted">{{ t('nam.unnamed', { n: res.unnamed }) }}</p>
      <ul v-if="res.items.length" class="flex flex-col gap-1" data-test="nam-list">
        <li v-for="i in res.items" :key="i.id" class="text-sm flex flex-wrap gap-3 rounded-md border border-default p-2"><span class="font-mono">{{ i.ip }}</span><span class="font-mono text-error">{{ i.hostname }}</span><span class="text-muted font-mono">{{ t('nam.expected') }} {{ i.pattern }}</span></li>
      </ul>
    </template>
  </div>
</template>
