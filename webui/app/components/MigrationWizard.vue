<script setup lang="ts">
// Assistant « Migration Windows » (0.12.0) : parcours guidé depuis DNS / DHCP Windows Server vers cette console.
const { t } = useT(); const api = useApi(); const toast = useToast()
const { canWrite } = useRole()
const emit = defineEmits<{ goto: [tab: string] }>()
const st = ref<any>(null), busy = ref(''), err = ref(''), shown = ref('')
const SCRIPTS = computed<Record<string, { title: string; code: string }>>(() => ({
  inventory: { title: t('mig.s_inventory'), code: PS_INVENTORY }, leases: { title: t('mig.s_leases'), code: PS_LEASES }, dhcp: { title: t('mig.s_dhcp'), code: PS_DHCP }, dns: { title: t('mig.s_dns'), code: PS_DNS },
}))
const META = computed<Record<string, { label: string; desc: string; icon: string; tab?: string; link?: string }>>(() => ({
  scripts: { label: t('mig.st.scripts'), desc: t('mig.st.scripts_d'), icon: 'i-lucide-terminal' },
  assess: { label: t('mig.st.assess'), desc: t('mig.st.assess_d'), icon: 'i-lucide-clipboard-check' },
  subnets: { label: t('mig.st.subnets'), desc: t('mig.st.subnets_d'), icon: 'i-lucide-network', tab: 'wizard' },
  dhcp: { label: t('mig.st.dhcp'), desc: t('mig.st.dhcp_d'), icon: 'i-lucide-server', tab: 'dhcp' },
  dns: { label: t('mig.st.dns'), desc: t('mig.st.dns_d'), icon: 'i-lucide-globe', tab: 'dns' },
  review: { label: t('mig.st.review'), desc: t('mig.st.review_d'), icon: 'i-lucide-search-check', link: '/dns#health' },
  cutover: { label: t('mig.st.cutover'), desc: t('mig.st.cutover_d'), icon: 'i-lucide-arrow-right-left' },
  retire: { label: t('mig.st.retire'), desc: t('mig.st.retire_d'), icon: 'i-lucide-power' },
}))
async function load() { try { st.value = await api.call('GET', '/migration', undefined, { silent: true }) } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } }
const doneOf = (s: any) => s.manual || s.auto
const progress = computed(() => { const l = st.value?.steps ?? []; return l.length ? Math.round((100 * l.filter(doneOf).length) / l.length) : 0 })
async function mark(s: any, v: boolean) {
  busy.value = s.id; err.value = ''
  try { st.value = await api.call('PUT', '/migration', { step: s.id, done: v }) } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
async function copy(code: string) { try { await navigator.clipboard.writeText(code); toast.add({ title: t('mig.copied'), color: 'success', icon: 'i-lucide-check' }) } catch { toast.add({ title: t('mig.copy_failed'), color: 'warning' }) } }
function download(name: string, code: string) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([code], { type: 'text/plain' })); a.download = name; a.click(); URL.revokeObjectURL(a.href) }
await load()
</script>

<template>
  <div class="flex flex-col gap-4">
    <p class="text-sm text-muted">{{ t('mig.intro') }}</p>
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <div v-if="st" class="flex flex-wrap items-center gap-3">
      <UProgress :model-value="progress" class="w-64" :aria-label="t('mig.progress', { n: progress })" />
      <span class="text-sm" data-test="mig-progress">{{ t('mig.progress', { n: progress }) }}</span>
      <UBadge color="neutral" variant="subtle" :label="t('mig.totals', { s: st.totals.subnets, d: st.totals.scopes, z: st.totals.zones })" />
    </div>
    <ol v-if="st" class="flex flex-col gap-3">
      <li v-for="(s, i) in st.steps" :key="s.id" class="rounded-lg border border-default p-4 flex flex-col gap-2" :data-test="`mig-${s.id}`">
        <div class="flex flex-wrap items-center gap-3">
          <UIcon :name="doneOf(s) ? 'i-lucide-circle-check' : META[s.id]!.icon" class="size-5" :class="doneOf(s) ? 'text-success' : 'text-muted'" />
          <span class="font-medium">{{ i + 1 }}. {{ META[s.id]!.label }}</span>
          <UBadge v-if="s.auto" color="success" variant="subtle" :label="t('mig.detected', { n: s.runs })" />
          <div class="ml-auto flex gap-2">
            <UButton v-if="META[s.id]!.tab" size="xs" color="neutral" variant="outline" icon="i-lucide-external-link" :label="t('mig.open')" @click="emit('goto', META[s.id]!.tab!)" />
            <UButton v-if="META[s.id]!.link" size="xs" color="neutral" variant="outline" icon="i-lucide-external-link" :label="t('mig.open')" :to="META[s.id]!.link" />
            <UCheckbox v-if="canWrite && !s.auto" :model-value="s.manual" :label="t('mig.done')" :disabled="busy === s.id" @update:model-value="(v: any) => mark(s, !!v)" />
          </div>
        </div>
        <p class="text-sm text-muted">{{ META[s.id]!.desc }}</p>
        <MigrationDns v-if="s.id === 'dns' && canWrite" @done="load" />
        <MigrationLeases v-if="s.id === 'dhcp' && canWrite" @done="load" />
        <MigrationAssess v-if="s.id === 'assess' && canWrite" @done="load" />
        <div v-if="s.id === 'scripts'" class="flex flex-col gap-2">
          <div class="flex flex-wrap gap-2"><UButton v-for="(sc, k) in SCRIPTS" :key="k" size="xs" :color="shown === k ? 'primary' : 'neutral'" variant="outline" icon="i-lucide-file-code" :label="sc.title" @click="shown = shown === k ? '' : String(k)" /></div>
          <div v-if="shown" class="flex flex-col gap-2">
            <pre class="text-xs font-mono bg-elevated rounded-md p-3 overflow-x-auto" data-test="mig-script">{{ SCRIPTS[shown]!.code }}</pre>
            <div class="flex gap-2"><UButton size="xs" icon="i-lucide-copy" :label="t('mig.copy')" @click="copy(SCRIPTS[shown]!.code)" /><UButton size="xs" color="neutral" variant="outline" icon="i-lucide-download" :label="t('mig.download')" @click="download(`migration-${shown}.ps1`, SCRIPTS[shown]!.code)" /></div>
          </div>
        </div>
      </li>
    </ol>
  </div>
</template>
