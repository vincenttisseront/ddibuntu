<script setup lang="ts">
// Test de bascule guidé (0.9.3) : pré-contrôles, vraie bascule mesurée (et retour au primaire d'origine), rapport conservé dans le cluster.
// La console ne pilote rien : elle dépose une demande que root valide de nouveau ; l'avancement et les rapports sont des fichiers publiés par root.
// Toute attente affiche un spinner, toute confirmation est une boîte maison (jamais système).
const props = defineProps<{ st: any; result: any; replica: boolean }>()
const emit = defineEmits<{ (e: 'reload'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { isAdmin } = useRole(); const fmt = useFmt()

const view = ref<any>(null)
async function loadView() {
  try { view.value = await api.call('GET', '/cluster/drills', undefined, { silent: true }) } catch { /* le nœud change de rôle pendant le test : on réessaie au prochain tour */ }
}
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => { void loadView(); timer = setInterval(() => { if (!document.hidden) void loadView() }, 5000) })
onBeforeUnmount(() => { if (timer) clearInterval(timer) })

const reports = computed<any[]>(() => view.value?.drills?.reports ?? [])
const active = computed(() => view.value?.drills?.active ?? null)
const live = computed(() => (view.value?.live?.running ? view.value.live : null))
const isData = computed(() => props.st?.nodeRole === 'data')
const canRun = computed(() => isAdmin.value && isData.value && !props.replica && !props.st?.stale)

const COLOR: Record<string, any> = { ok: 'success', warn: 'warning', fail: 'error', skip: 'neutral', success: 'success', warning: 'warning', failed: 'error', refused: 'neutral' }
const ICON: Record<string, string> = { ok: 'i-lucide-circle-check', warn: 'i-lucide-triangle-alert', fail: 'i-lucide-circle-x', skip: 'i-lucide-minus' }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
// durées : millisecondes sous la seconde, sinon secondes avec une décimale, minutes au-delà
const dur = (v: number | null | undefined) => (v === null || v === undefined ? '—' : v < 1000 ? `${Math.round(v)} ms` : v < 60000 ? `${(v / 1000).toFixed(1)} s` : `${Math.floor(v / 60000)} min ${Math.round((v % 60000) / 1000)} s`)
const bytes = (n: number | null | undefined) => (n === null || n === undefined ? '—' : n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KiB` : `${(n / 1048576).toFixed(1)} MiB`)
const when = (s: number) => (s ? fmt.dateTime(s * 1000) : '—')
const sec = (ms: number) => Math.round(ms / 1000)

// ---------------------------------------------------------------- lancement
type Stage = 'checking' | 'ready' | 'running'
const open = ref(false), stage = ref<Stage>('checking'), err = ref(''), chk = ref<any>(null)
const candidate = ref(''), back = ref(true), typed = ref(''), running = ref(false), startedAt = ref(0), tick = ref(0)
const busyAny = computed(() => running.value || !!view.value?.busy)
const candidates = computed<any[]>(() => (chk.value?.candidates ?? []).filter((c: any) => c.ok))
const checkOk = computed(() => !!chk.value?.ok)
const canStart = computed(() => stage.value === 'ready' && checkOk.value && typed.value === props.st?.cluster && !running.value)
const elapsed = computed(() => (tick.value >= 0 && startedAt.value ? Math.max(0, Math.round((Date.now() - startedAt.value) / 1000)) : 0))
let clock: ReturnType<typeof setInterval> | undefined
const stopClock = () => { if (clock) { clearInterval(clock); clock = undefined } }
onBeforeUnmount(stopClock)

async function runCheck() {
  stage.value = 'checking'; err.value = ''; chk.value = null
  const before = props.result?.at ?? 0
  try {
    await api.call('POST', '/cluster/action', { action: 'drill-check', ...(candidate.value ? { node: candidate.value } : {}) }, { busy: true })
    for (let i = 0; i < 40; i++) {
      await sleep(1500); emit('reload'); await sleep(800); await loadView()
      const r = props.result
      if (r && r.at > before && r.action === 'drill-check') {
        if (!r.ok) { err.value = r.message; stage.value = 'ready'; return }
        if (view.value?.check && view.value.check.ageSeconds < 120) { chk.value = view.value.check; stage.value = 'ready'; return }
      }
    }
    err.value = t('cluster.op.timeout'); stage.value = 'ready'
  } catch (e: any) { err.value = e.info?.message ?? t('err.internal'); stage.value = 'ready' }
}
function begin() {
  if (busyAny.value) return
  candidate.value = ''; back.value = true; typed.value = ''; open.value = true
  void runCheck()
}
function close() { open.value = false }

async function start() {
  if (!canStart.value) return
  err.value = ''; running.value = true; stage.value = 'running'; startedAt.value = Date.now(); tick.value = 0
  stopClock(); clock = setInterval(() => { tick.value++ }, 1000)
  const before = props.result?.at ?? 0
  try {
    await api.call('POST', '/cluster/action', { action: 'drill', ...(candidate.value ? { node: candidate.value } : {}), back: back.value, confirm: typed.value }, { busy: true })
  } catch (e: any) { err.value = e.info?.message ?? t('err.internal'); stage.value = 'ready'; running.value = false; stopClock(); return }
  // l'avancement vient du fichier publié par le moniteur ; le verdict final, du résultat de root (action « drill »). Jusqu'à ~20 minutes.
  try {
    for (let i = 0; i < 480; i++) {
      await sleep(2500); await loadView(); emit('reload')
      const r = props.result
      if (r && r.at > before && r.action === 'drill') {
        await sleep(1500); await loadView()
        toast.add({ title: r.ok ? t('cluster.drill.finished') : t('cluster.op.failed'), description: r.message, color: r.ok ? 'success' : 'error', icon: r.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
        open.value = false; if (reports.value[0]) detailId.value = reports.value[0].id
        return
      }
    }
    err.value = t('cluster.drill.timeout')
  } finally { running.value = false; stopClock(); emit('reload'); void loadView() }
}

// ---------------------------------------------------------------- rapport
const detailId = ref<string | null>(null)
const detail = computed(() => reports.value.find((r: any) => r.id === detailId.value) ?? null)
const detailOpen = computed({ get: () => detail.value !== null, set: (v: boolean) => { if (!v) detailId.value = null } })
const last = computed(() => reports.value[0] ?? null)
const path = (r: any) => (r.from && r.to ? (r.back ? `${r.from} → ${r.to} → ${r.from}` : `${r.from} → ${r.to}`) : '—')
const checkLabel = (id: string) => { const k = `cluster.drill.check.${id}`; const v = t(k); return v === k ? id : v }
const stLabel = (s: string) => t(`cluster.drill.st.${s}`)
const lsnText = (p: any) => t(p.metrics.lsnContinuity === true ? 'cluster.drill.m.lsn_ok' : p.metrics.lsnContinuity === false ? 'cluster.drill.m.lsn_ko' : 'cluster.drill.m.lsn_unknown')
const tiles = (p: any) => [
  { id: 'noPrimary', value: dur(p.metrics.noPrimaryMs), verdict: p.verdicts.noPrimary },
  { id: 'promotion', value: dur(p.metrics.promotionMs), verdict: p.verdicts.promotion },
  { id: 'rejoin', value: dur(p.metrics.rejoinMs), verdict: p.verdicts.rejoin },
  { id: 'catchUp', value: dur(p.metrics.catchUpMs), verdict: p.verdicts.catchUp },
  { id: 'timeline', value: p.metrics.timeline[0] === null || p.metrics.timeline[1] === null ? '—' : `${p.metrics.timeline[0]} → ${p.metrics.timeline[1]}`, verdict: p.verdicts.timeline },
  { id: 'lsn', value: lsnText(p), verdict: p.verdicts.lsn },
]
const th = (r: any) => ({ a1: sec(r.thresholds.noPrimaryMs[0]), a2: sec(r.thresholds.noPrimaryMs[1]), p1: sec(r.thresholds.promotionMs[0]), p2: sec(r.thresholds.promotionMs[1]), r1: sec(r.thresholds.rejoinMs[0]), r2: sec(r.thresholds.rejoinMs[1]) })
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex items-center justify-between gap-2">
        <span class="font-medium">{{ t('cluster.drill.title') }}</span>
        <UBadge v-if="last" :color="COLOR[last.outcome]" variant="subtle" :label="t(`cluster.drill.out.${last.outcome}`)" />
      </div>
    </template>
    <p class="text-sm text-muted">{{ t('cluster.drill.desc') }}</p>

    <UAlert v-if="busyAny && !open" class="mt-3" color="info" variant="subtle" icon="i-lucide-loader" :title="t('cluster.drill.running_other', { n: active?.node ?? live?.node ?? st.node, p: t(`cluster.drill.phase.${live?.phase || active?.phase || 'checks'}`) })" :description="t('cluster.drill.running_hint')" :ui="{ icon: 'animate-spin' }" />

    <p v-if="!reports.length" class="text-sm text-muted mt-3">{{ t('cluster.drill.none') }}</p>
    <div v-else class="overflow-x-auto mt-3">
      <table class="w-full text-sm">
        <thead><tr class="text-left text-muted"><th class="py-1 pr-4">{{ t('cluster.drill.when') }}</th><th class="pr-4">{{ t('cluster.drill.result') }}</th><th class="pr-4">{{ t('cluster.drill.path') }}</th><th class="pr-4">{{ t('cluster.drill.m.noPrimary') }}</th><th class="pr-4">{{ t('cluster.drill.m.promotion') }}</th><th /></tr></thead>
        <tbody>
          <tr v-for="r in reports" :key="r.id" class="border-t border-default">
            <td class="py-1.5 pr-4 whitespace-nowrap">{{ when(r.startedAt) }}</td>
            <td class="pr-4"><UBadge :color="COLOR[r.outcome]" variant="subtle" :label="t(`cluster.drill.out.${r.outcome}`)" /></td>
            <td class="pr-4 font-mono whitespace-nowrap">{{ path(r) }}</td>
            <td class="pr-4 font-mono">{{ r.phases[0] ? dur(r.phases[0].metrics.noPrimaryMs) : '—' }}</td>
            <td class="pr-4 font-mono">{{ r.phases[0] ? dur(r.phases[0].metrics.promotionMs) : '—' }}</td>
            <td class="text-right"><UButton size="xs" color="neutral" variant="outline" icon="i-lucide-file-text" :label="t('cluster.drill.open')" @click="detailId = r.id" /></td>
          </tr>
        </tbody>
      </table>
    </div>

    <p v-if="!isAdmin" class="text-xs text-muted mt-3">{{ t('cluster.drill.admin_only') }}</p>
    <p v-else-if="replica" class="text-xs text-muted mt-3">{{ t('cluster.drill.read_only') }}</p>
    <div v-else-if="canRun" class="mt-3">
      <UButton icon="i-lucide-arrow-left-right" :label="t('cluster.drill.btn')" :disabled="busyAny" @click="begin" />
    </div>
  </UCard>

  <!-- lancement : pré-contrôles → confirmation → avancement en direct -->
  <UModal v-model:open="open" :title="t('cluster.drill.modal.title')" :description="t('cluster.drill.modal.desc')">
    <template #body>
      <div class="flex flex-col gap-3">
        <div v-if="stage === 'checking'" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader" class="animate-spin" />{{ t('cluster.drill.checking') }}</div>

        <template v-if="stage !== 'checking' && chk">
          <div class="text-sm font-medium">{{ t('cluster.drill.checks_title') }}</div>
          <ul class="flex flex-col gap-1 text-sm">
            <li v-for="c in chk.checks" :key="c.id" class="flex items-start gap-2">
              <UIcon :name="ICON[c.status] ?? ICON.skip!" class="mt-0.5 shrink-0" :class="{ 'text-success': c.status === 'ok', 'text-warning': c.status === 'warn', 'text-error': c.status === 'fail', 'text-muted': c.status === 'skip' }" />
              <span><span class="font-medium">{{ checkLabel(c.id) }}</span> <span class="text-muted">— {{ c.detail }}</span></span>
            </li>
          </ul>
          <UAlert v-if="checkOk" color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('cluster.drill.ready')" />
          <UAlert v-else color="error" variant="subtle" icon="i-lucide-circle-x" :title="t('cluster.drill.not_ready')" />
        </template>

        <template v-if="stage === 'ready' && checkOk">
          <UFormField v-if="candidates.length > 1" :label="t('cluster.drill.candidate')">
            <USelectMenu v-model="candidate" class="w-full" :items="[{ label: t('cluster.drill.candidate_auto', { n: chk.candidate }), value: '' }, ...candidates.map((c: any) => ({ label: c.name, value: c.name }))]" value-key="value" @update:model-value="runCheck" />
          </UFormField>
          <UCheckbox v-model="back" :label="t('cluster.drill.back')" :description="t('cluster.drill.back_hint')" />
          <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('cluster.drill.warn_title')" :description="t('cluster.drill.warn_desc')" />
          <label class="text-sm">{{ t('cluster.op.type', { v: st.cluster }) }}
            <UInput v-model="typed" class="w-full mt-1" autocomplete="off" @keyup.enter="start" />
          </label>
        </template>

        <template v-if="stage === 'running'">
          <div class="flex items-center gap-2 text-sm"><UIcon name="i-lucide-loader" class="animate-spin" />
            <span class="font-medium">{{ t(`cluster.drill.phase.${live?.phase || 'checks'}`) }}</span>
            <span class="text-muted">{{ t('cluster.drill.elapsed', { s: elapsed }) }}</span>
          </div>
          <p v-if="!live" class="text-sm text-muted">{{ t('cluster.drill.waiting') }}</p>
          <ol v-else class="flex flex-col gap-1 text-sm">
            <li v-for="(s, i) in live.steps" :key="i" class="flex gap-2"><span class="font-mono text-muted w-16 shrink-0 text-right">{{ dur(s.t) }}</span><span>{{ s.text }}</span></li>
          </ol>
          <p class="text-xs text-muted">{{ t('cluster.drill.running') }}</p>
        </template>

        <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" />
      </div>
    </template>
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton v-if="stage === 'ready'" color="neutral" variant="outline" icon="i-lucide-refresh-cw" :label="t('cluster.drill.recheck')" @click="runCheck" />
        <UButton color="neutral" variant="outline" :label="stage === 'running' ? t('common.close') : t('common.cancel')" @click="close" />
        <UButton v-if="stage !== 'running'" :label="t('cluster.drill.go')" icon="i-lucide-play" :disabled="!canStart" :loading="running" @click="start" />
      </div>
    </template>
  </UModal>

  <!-- rapport -->
  <UModal v-model:open="detailOpen" :title="detail ? t('cluster.drill.report.title', { id: detail.id }) : ''" :ui="{ content: 'sm:max-w-4xl' }">
    <template #body>
      <div v-if="detail" class="flex flex-col gap-4">
        <div class="flex flex-wrap items-center gap-2 text-sm">
          <UBadge :color="COLOR[detail.outcome]" variant="subtle" size="lg" :label="t(`cluster.drill.out.${detail.outcome}`)" />
          <span class="font-mono">{{ path(detail) }}</span>
          <span class="text-muted">{{ when(detail.startedAt) }}</span>
        </div>
        <p class="text-sm text-muted">{{ t('cluster.drill.report.meta', { n: detail.node, by: t(`cluster.drill.report.by_${detail.by}`), d: dur(detail.durationMs) }) }}</p>
        <UAlert v-if="detail.outcome === 'refused'" color="neutral" variant="subtle" icon="i-lucide-info" :title="t('cluster.drill.report.refused')" />

        <div v-if="detail.outcome === 'refused' || !detail.phases.length">
          <div class="text-sm font-medium mb-1">{{ t('cluster.drill.report.pre') }}</div>
          <ul class="flex flex-col gap-1 text-sm">
            <li v-for="c in detail.pre.checks" :key="c.id" class="flex items-start gap-2">
              <UIcon :name="ICON[c.status] ?? ICON.skip!" class="mt-0.5 shrink-0" :class="{ 'text-success': c.status === 'ok', 'text-warning': c.status === 'warn', 'text-error': c.status === 'fail', 'text-muted': c.status === 'skip' }" />
              <span><span class="font-medium">{{ checkLabel(c.id) }}</span> <span class="text-muted">— {{ c.detail }}</span></span>
            </li>
          </ul>
        </div>

        <UCard v-for="p in detail.phases" :key="p.name">
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-2">
              <span class="font-medium">{{ t(`cluster.drill.phase.${p.name}`) }} <span class="font-mono text-muted">{{ p.from }} → {{ p.to }}</span></span>
              <UBadge :color="p.ok ? 'success' : 'error'" variant="subtle" :label="p.ok ? t('cluster.drill.st.ok') : t('cluster.drill.st.fail')" />
            </div>
          </template>
          <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <div v-for="m in tiles(p)" :key="m.id" class="rounded-md border border-default p-3">
              <div class="text-xs text-muted">{{ t(`cluster.drill.m.${m.id}`) }}</div>
              <div class="text-lg font-mono mt-0.5">{{ m.value }}</div>
              <UBadge class="mt-1" :color="COLOR[m.verdict]" variant="subtle" size="sm" :label="stLabel(m.verdict)" />
            </div>
          </div>
          <p class="text-xs text-muted mt-3">{{ t('cluster.drill.m.lag') }} : <span class="font-mono">{{ bytes(p.metrics.lagMaxBytes) }}</span> · {{ t('cluster.drill.m.settle') }} : <span class="font-mono">{{ dur(p.metrics.settleMs) }}</span> · {{ t('cluster.drill.report.cmd', { rc: p.cmdRc ?? '—', d: dur(p.cmdMs) }) }}</p>
          <p v-if="p.output" class="text-xs text-muted font-mono mt-1 break-all">{{ p.output }}</p>
          <div class="text-sm font-medium mt-3 mb-1">{{ t('cluster.drill.report.post') }}</div>
          <ul class="flex flex-col gap-1 text-sm">
            <li v-for="c in p.post" :key="c.id" class="flex items-start gap-2">
              <UIcon :name="ICON[c.status] ?? ICON.skip!" class="mt-0.5 shrink-0" :class="{ 'text-success': c.status === 'ok', 'text-warning': c.status === 'warn', 'text-error': c.status === 'fail' }" />
              <span><span class="font-medium">{{ checkLabel(c.id) }}</span> <span class="text-muted">— {{ c.detail }}</span></span>
            </li>
          </ul>
        </UCard>

        <div v-if="detail.phases.length">
          <div class="text-sm font-medium mb-1">{{ t('cluster.drill.report.events') }}</div>
          <p v-if="!detail.events.length" class="text-sm text-muted">{{ t('cluster.drill.report.no_events') }}</p>
          <div v-else class="max-h-72 overflow-auto rounded-md border border-default">
            <table class="w-full text-xs">
              <thead class="sticky top-0 bg-default"><tr class="text-left text-muted"><th class="py-1 px-2">{{ t('cluster.drill.ev.t') }}</th><th class="px-2">{{ t('cluster.drill.ev.node') }}</th><th class="px-2">{{ t('cluster.drill.ev.what') }}</th></tr></thead>
              <tbody>
                <tr v-for="(e, i) in detail.events" :key="i" class="border-t border-default"><td class="py-1 px-2 font-mono whitespace-nowrap">+{{ dur(e.t) }}</td><td class="px-2 font-mono">{{ e.node }}</td><td class="px-2">{{ e.detail }}</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="text-xs text-muted flex flex-col gap-1">
          <p>{{ t('cluster.drill.report.precision', { ms: detail.resolutionMs }) }}</p>
          <p>{{ t('cluster.drill.report.thresholds', th(detail)) }}</p>
        </div>
      </div>
    </template>
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton v-if="detail" as="a" :href="`/api/cluster/drills/${detail.id}`" :download="`ddibuntu-drill-${detail.id}.json`" color="neutral" variant="outline" icon="i-lucide-download" :label="t('cluster.drill.report.download')" />
        <UButton :label="t('common.close')" @click="detailId = null" />
      </div>
    </template>
  </UModal>
</template>
