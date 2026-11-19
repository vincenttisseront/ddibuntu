<script setup lang="ts">
// 0.14.12 — suivi EN DIRECT d'une demande traitée par root (installation, démarrage, arrêt, désinstallation, autorités…) : grande carte en haut de la page PKI.
// Les étapes viennent de root (pki-progress.json) ; pour une installation on ajoute en dernière ligne l'initialisation d'EJBCA, déduite de l'état publié (starting → healthy).
const props = defineProps<{ progress: any; status: any; result?: any }>()
const { t } = useT()
const te = (k: string) => t(k) !== k   // clé connue ?

const now = ref(Math.floor(Date.now() / 1000))
let tick: ReturnType<typeof setInterval> | undefined
onMounted(() => { tick = setInterval(() => { now.value = Math.floor(Date.now() / 1000) }, 1000) })
onBeforeUnmount(() => { if (tick) clearInterval(tick) })

const p = computed(() => props.progress ?? null)
const isApply = computed(() => p.value?.action === 'apply')
const st = computed(() => props.status?.state ?? 'absent')
// ligne finale d'une installation : EJBCA initialise sa base (quelques minutes) jusqu'à ce que la santé soit « ALLOK »
const initRow = computed(() => {
  if (!isApply.value || p.value?.state !== 'done') return null
  if (!['starting', 'healthy', 'unhealthy'].includes(st.value)) return null
  return { id: 'init', status: st.value === 'healthy' ? 'done' : st.value === 'unhealthy' ? 'failed' : 'running', detail: st.value === 'starting' ? t('pki.prog.init_hint') : '' }
})
const steps = computed(() => [...(p.value?.steps ?? []), ...(initRow.value ? [initRow.value] : [])])
const running = computed(() => !!p.value && ((p.value.state === 'running' && !p.value.stale) || initRow.value?.status === 'running'))
const failed = computed(() => !!p.value && (p.value.state === 'failed' || p.value.stale || initRow.value?.status === 'failed'))
const age = computed(() => (p.value ? Math.max(0, now.value - (p.value.finishedAt || p.value.at)) : 0))
const visible = computed(() => {
  if (!p.value) return false
  if (running.value) return true
  if (failed.value) return age.value < 900
  return age.value < 120   // terminé : le bilan reste visible un instant
})
const total = computed(() => steps.value.length)
const doneCount = computed(() => steps.value.filter((s: any) => s.status === 'done').length)
const generic = computed(() => total.value === 1 && p.value?.steps?.[0]?.id === 'work')
const percent = computed(() => (running.value && generic.value ? null : failed.value ? Math.round((doneCount.value / Math.max(1, total.value)) * 100) : running.value ? Math.max(4, Math.round(((doneCount.value + 0.5) / Math.max(1, total.value)) * 100)) : 100))
const elapsed = computed(() => {
  const s = Math.max(0, (running.value ? now.value : (p.value?.finishedAt || now.value)) - (p.value?.startedAt || now.value))
  return s >= 60 ? `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, '0')} s` : `${s} s`
})
// raison donnée par root quand la demande échoue (même action, résultat postérieur au début de la tâche)
const reason = computed(() => (failed.value && props.result && !props.result.ok && props.result.action === p.value?.action && props.result.at >= (p.value?.startedAt ?? 0) - 2 ? String(props.result.message) : ''))
const tone = computed(() => (failed.value ? 'error' : running.value ? 'primary' : 'success'))
const title = computed(() => {
  const a = p.value?.action ?? ''
  const key = `pki.prog.title.${running.value ? 'run' : failed.value ? 'ko' : 'ok'}.${te(`pki.prog.title.run.${a}`) ? a : 'other'}`
  return t(key)
})
const label = (id: string) => (te(`pki.prog.step.${id}`) ? t(`pki.prog.step.${id}`) : id)
const icon = (s: string) => ({ done: 'i-lucide-circle-check', running: 'i-lucide-loader-circle', failed: 'i-lucide-circle-x', todo: 'i-lucide-circle' } as Record<string, string>)[s] ?? 'i-lucide-circle'
const iconClass = (s: string) => ({ done: 'text-success', running: 'text-primary animate-spin', failed: 'text-error', todo: 'text-dimmed' } as Record<string, string>)[s] ?? ''
const ring = computed(() => ({ primary: 'ring-2 ring-primary', error: 'ring-2 ring-error', success: 'ring-2 ring-success' } as Record<string, string>)[tone.value])
const headIcon = computed(() => (failed.value ? 'i-lucide-triangle-alert' : running.value ? 'i-lucide-loader-circle' : 'i-lucide-circle-check-big'))
const headClass = computed(() => `${failed.value ? 'text-error bg-error/10' : running.value ? 'text-primary bg-primary/10' : 'text-success bg-success/10'} ${running.value ? '[&>span]:animate-spin' : ''}`)
</script>

<template>
  <UCard v-if="visible" :class="ring" :ui="{ body: 'flex flex-col gap-4' }" data-test="pki-progress" :data-state="failed ? 'failed' : running ? 'running' : 'done'">
    <div class="flex items-center gap-4">
      <div class="flex size-12 shrink-0 items-center justify-center rounded-full text-3xl" :class="headClass"><UIcon :name="headIcon" /></div>
      <div class="min-w-0 flex-1">
        <p class="text-lg font-semibold" data-test="pki-progress-title">{{ title }}</p>
        <p class="text-sm text-muted">{{ t('pki.prog.elapsed', { t: elapsed }) }}<template v-if="running"> · {{ t('pki.prog.live') }}</template></p>
      </div>
      <UBadge v-if="total > 1" :color="tone" variant="subtle" size="lg">{{ doneCount }} / {{ total }}</UBadge>
    </div>
    <UProgress :model-value="percent" :color="tone" size="lg" :aria-label="title" data-test="pki-progress-bar" />
    <ol class="flex flex-col gap-1" data-test="pki-progress-steps">
      <li v-for="s in steps" :key="s.id" class="flex items-center gap-3 rounded-md px-3 py-2" :class="s.status === 'running' ? 'bg-primary/10' : s.status === 'failed' ? 'bg-error/10' : ''" :data-test="`pki-progress-step-${s.id}`" :data-status="s.status">
        <UIcon :name="icon(s.status)" class="size-6 shrink-0" :class="iconClass(s.status)" />
        <div class="min-w-0 flex-1">
          <p class="text-sm" :class="s.status === 'todo' ? 'text-muted' : 'font-medium'">{{ label(s.id) }}</p>
          <p v-if="s.detail" class="text-xs text-muted">{{ s.detail }}</p>
        </div>
      </li>
    </ol>
    <UAlert v-if="reason" color="error" variant="subtle" icon="i-lucide-circle-x" :title="t('pki.prog.reason')" :description="reason" role="alert" data-test="pki-progress-reason" />
  </UCard>
</template>
