<script setup lang="ts">
// Assistant de découverte : sous-réseaux de l'IPAM, méthodes (sondes et lectures passives), exécution suivie, revue, import des adresses choisies.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const step = ref(0), busy = ref(false), error = ref(''), done = ref(false)
const steps = computed(() => [{ id: 'scope', label: t('disc.s_scope') }, { id: 'methods', label: t('disc.s_methods') }, { id: 'run', label: t('disc.s_run') }, { id: 'review', label: t('disc.s_review') }, { id: 'apply', label: t('disc.s_apply') }])
const fail = (e: any) => { error.value = e.info?.message ?? t('err.internal') }
const { data: subs } = useFetch<any>('/api/ipam/subnets', { server: false })
const { data: caps } = useFetch<any>('/api/discovery/capabilities', { server: false })
const v4 = computed(() => (subs.value?.items ?? []).filter((s: any) => /^\d+\.\d+\.\d+\.\d+\//.test(s.cidr)))
const pick = reactive<Record<number, boolean>>({})
const ids = computed(() => v4.value.filter((s: any) => pick[s.id]).map((s: any) => s.id as number))
const hostsOf = (cidr: string) => { const p = Number(cidr.split('/')[1]); return p >= 31 ? 2 ** (32 - p) : 2 ** (32 - p) - 2 }
const total = computed(() => v4.value.filter((s: any) => pick[s.id]).reduce((n: number, s: any) => n + hostsOf(s.cidr), 0))
const m = reactive({ tcp: true, icmp: true, arp: true, leases: true, reverse: true })
const preset = ref('basic'), custom = ref('')
const customPorts = computed(() => custom.value.split(/[\s,]+/).filter(Boolean).map(Number))
const customOk = computed(() => !custom.value.trim() || (customPorts.value.length <= 20 && customPorts.value.every((n) => Number.isInteger(n) && n >= 1 && n <= 65535)))
const job = ref<any>(null), sel = reactive<Record<string, boolean>>({}), updateKnown = ref(true), result = ref<any>(null)
let timer: ReturnType<typeof setInterval> | undefined
onBeforeUnmount(() => clearInterval(timer))
async function start() {
  busy.value = true; error.value = ''
  try {
    const s: any = await api.call('POST', '/discovery/start', { subnet_ids: ids.value, methods: { ...m, icmp: m.icmp && !!caps.value?.icmp }, ports: custom.value.trim() ? customPorts.value : preset.value, timeoutMs: 800 })
    job.value = { state: 'running', total: s.total, done: 0, alive: 0, warnings: s.warnings }; step.value = 2
    timer = setInterval(async () => {
      try { job.value = await api.call('GET', `/discovery/${s.id}`); job.value.id = s.id } catch (e: any) { clearInterval(timer); fail(e); return }
      if (job.value.state !== 'running') { clearInterval(timer); for (const h of job.value.result?.hosts ?? []) sel[h.ip] = h.status === 'new' }
    }, 1000)
  } catch (e: any) { fail(e) } finally { busy.value = false }
}
async function cancel() { try { await api.call('POST', `/discovery/${job.value.id ?? ''}/cancel`, {}) } catch { /* déjà terminé */ } }
const hosts = computed(() => job.value?.result?.hosts ?? [])
const chosen = computed(() => hosts.value.filter((h: any) => h.status === 'new' && sel[h.ip]).map((h: any) => h.ip))
async function commit() {
  if (!(await ask(t('disc.apply'), t('disc.apply_confirm', { n: chosen.value.length }), false))) return
  busy.value = true; error.value = ''
  try { result.value = await api.call('POST', `/discovery/${job.value.id}/commit`, { ips: chosen.value, updateKnown: updateKnown.value }); done.value = true; toast.add({ title: t('import.done'), color: 'success', icon: 'i-lucide-check' }) } catch (e: any) { fail(e) } finally { busy.value = false }
}
async function undo() {
  if (!(await ask(t('restore.restore'), t('restore.undo_confirm'), true))) return
  try { await api.call('POST', `/snapshots/${result.value.snapshotId}/restore`, {}); toast.add({ title: t('restore.done'), color: 'success', icon: 'i-lucide-check' }); result.value = null; done.value = false } catch (e: any) { fail(e) }
}
const finished = computed(() => job.value && job.value.state !== 'running')
const canNext = computed(() => [ids.value.length > 0 && total.value <= 4096, (m.tcp || m.icmp || m.arp || m.leases) && customOk.value && total.value <= 4096, !!finished.value, true, !done.value][step.value] ?? false)
// l'étape « méthodes » lance la découverte : son bouton « suivant » est remplacé par « lancer »
const onNext = () => { if (step.value === 1) start(); else step.value++ }
</script>

<template>
  <div>
    <WizardShell v-model="step" :steps="steps" :can-next="canNext" :busy="busy" :finish-label="t('disc.apply')" :hide-footer="done || step === 1 || step === 2" @finish="commit">
      <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" class="mb-3" />
      <template #scope>
        <UCard><div class="flex flex-col gap-3 text-sm">
          <p class="text-muted">{{ t('disc.scope_desc') }}</p>
          <p v-if="!v4.length" class="text-muted">{{ t('disc.no_subnet') }}</p>
          <ul class="flex flex-col gap-1 max-h-72 overflow-auto"><li v-for="s in v4" :key="s.id"><label class="flex items-center gap-2"><input v-model="pick[s.id]" type="checkbox"><span class="font-mono">{{ s.cidr }}</span><span class="text-muted">{{ s.name }}</span><span class="num text-xs text-dimmed ms-auto">{{ t('disc.hosts', { n: hostsOf(s.cidr) }) }}</span></label></li></ul>
          <p class="num" :class="total > 4096 ? 'text-error' : 'text-muted'">{{ t('disc.total', { n: total }) }}<span v-if="total > 4096"> — {{ t('err.discovery_too_large') }}</span></p>
        </div></UCard>
      </template>
      <template #methods>
        <UCard><div class="flex flex-col gap-3 text-sm">
          <UAlert color="warning" variant="subtle" icon="i-lucide-radar" :title="t('disc.warn')" />
          <USwitch v-model="m.leases" :label="t('disc.m_leases')" /><USwitch v-model="m.arp" :label="t('disc.m_arp')" />
          <USwitch v-model="m.tcp" :label="t('disc.m_tcp')" />
          <div v-if="m.tcp" class="ps-8 flex flex-col gap-2"><USelect v-model="preset" :items="Object.keys(caps?.presets ?? { basic: 1 }).map((k) => ({ label: `${t(`disc.p_${k}`)} (${(caps?.presets?.[k] ?? []).join(', ')})`, value: k }))" :disabled="!!custom.trim()" class="w-full" :aria-label="t('disc.ports')" />
            <UFormField :label="t('disc.custom_ports')" :error="customOk ? undefined : t('disc.ports_bad')"><UInput v-model="custom" class="w-full font-mono" placeholder="22, 443, 8443" /></UFormField></div>
          <USwitch v-model="m.icmp" :label="t('disc.m_icmp')" :disabled="caps && !caps.icmp" /><p v-if="caps && !caps.icmp" class="ps-8 text-xs text-muted">{{ t('disc.icmp_off') }}</p>
          <USwitch v-model="m.reverse" :label="t('disc.m_reverse')" />
          <div class="flex justify-between mt-2"><UButton color="neutral" variant="outline" icon="i-lucide-arrow-left" :label="t('wizard.back')" @click="step = 0" /><UButton icon="i-lucide-play" :disabled="!canNext" :loading="busy" :label="t('disc.start')" @click="onNext" /></div>
        </div></UCard>
      </template>
      <template #run>
        <UCard><div class="flex flex-col gap-3 text-sm" aria-live="polite">
          <UProgress :model-value="job?.total ? Math.round(((job?.done ?? 0) / job.total) * 100) : 0" />
          <p class="num">{{ t('disc.progress', { d: job?.done ?? 0, n: job?.total ?? 0, a: job?.alive ?? 0 }) }}</p>
          <ul v-if="job?.warnings?.length" class="text-xs text-muted"><li v-for="w in job.warnings" :key="w">{{ t(`disc.warn_${String(w).split(':').pop()}`) }}</li></ul>
          <UAlert v-if="job?.state === 'error'" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('err.internal')" />
          <div class="flex justify-between"><UButton v-if="!finished" color="neutral" variant="outline" icon="i-lucide-square" :label="t('common.cancel')" @click="cancel" /><span v-else /><UButton :disabled="!finished || job?.state === 'error'" trailing-icon="i-lucide-arrow-right" :label="t('wizard.next')" @click="step = 3" /></div>
        </div></UCard>
      </template>
      <template #review>
        <UCard><div class="flex flex-col gap-3 text-sm">
          <p class="num">{{ t('disc.found', { n: hosts.length, k: hosts.filter((h: any) => h.status === 'new').length }) }}</p>
          <div class="overflow-auto max-h-80"><table class="w-full"><caption class="sr-only">{{ t('disc.s_review') }}</caption>
            <thead><tr class="text-muted"><th scope="col" class="p-1 w-8"><span class="sr-only">{{ t('adw.select') }}</span></th><th scope="col" class="text-start p-1">IP</th><th scope="col" class="text-start p-1">{{ t('cockpit.domain') }}</th><th scope="col" class="text-start p-1">MAC</th><th scope="col" class="text-start p-1">{{ t('disc.open') }}</th><th scope="col" class="text-start p-1">{{ t('disc.via') }}</th><th scope="col" class="text-start p-1">{{ t('cockpit.status') }}</th></tr></thead>
            <tbody><tr v-for="h in hosts" :key="h.ip" class="border-t border-default"><td class="p-1"><input v-if="h.status === 'new'" v-model="sel[h.ip]" type="checkbox" :aria-label="`${t('adw.select')} ${h.ip}`"></td><td class="p-1 font-mono">{{ h.ip }}</td><td class="p-1 font-mono">{{ h.ptr ?? h.leaseName ?? h.known?.hostname ?? '' }}</td><td class="p-1 font-mono text-xs">{{ h.mac ?? '' }}</td><td class="p-1 num">{{ h.ports.join(', ') }}</td><td class="p-1 text-xs">{{ h.via.join(', ') }}</td>
              <td class="p-1"><UBadge :color="h.status === 'new' ? 'primary' : h.status === 'mac_changed' ? 'warning' : 'neutral'" variant="subtle" :label="t(`disc.st_${h.status}`)" /></td></tr></tbody></table></div>
          <div v-if="job?.result?.stale?.length"><p class="font-medium">{{ t('disc.stale', { n: job.result.stale.length }) }}</p><p class="text-xs text-muted font-mono">{{ job.result.stale.slice(0, 30).map((s: any) => s.ip).join(', ') }}</p></div>
        </div></UCard>
      </template>
      <template #apply>
        <UCard><div class="flex flex-col gap-3 text-sm">
          <template v-if="!done"><p class="num">{{ t('disc.sum', { n: chosen.length }) }}</p><USwitch v-model="updateKnown" :label="t('disc.update_known')" /><UAlert color="info" variant="subtle" icon="i-lucide-undo-2" :title="t('restore.auto_point')" /></template>
          <template v-else><UAlert color="success" variant="subtle" icon="i-lucide-check" :title="t('import.done')" /><p class="num">{{ t('disc.result', { c: result.created, u: result.updated }) }}</p><div><UButton color="neutral" variant="outline" icon="i-lucide-undo-2" :label="t('restore.undo')" @click="undo" /></div></template>
        </div></UCard>
      </template>
    </WizardShell>
  </div>
</template>
