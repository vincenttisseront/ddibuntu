<script setup lang="ts">
// Sauvegardes de la base et restauration à un instant donné (PITR). La console ne fait que déposer des demandes ; root les valide et les exécute.
// Toute opération longue affiche un spinner et suit l'avancement ; toutes les confirmations sont des boîtes maison (jamais de fenêtre système).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const data = ref<any>(null), loadError = ref(false)
const st = computed(() => data.value?.status ?? null)
const result = computed(() => data.value?.result ?? null)
const restoreState = computed(() => data.value?.restore ?? null)
async function load(silent = true) {
  try { data.value = await api.call('GET', '/backup/status', undefined, { silent }); loadError.value = false } catch (e) { loadError.value = true; throw e }
}
const restoreActive = computed(() => !!restoreState.value?.active)
let poll: ReturnType<typeof setInterval> | undefined
// une restauration lancée ailleurs (autre session, page rechargée) reste visible : on suit son avancement tant qu'elle est active
onMounted(() => { load().catch(() => {}); poll = setInterval(() => { if (restoreActive.value && !restoring.value) load().catch(() => {}) }, 5000) })
onBeforeUnmount(() => { if (poll) clearInterval(poll) })

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const fmt = useFmt()
const when = (s: number | null | undefined) => (s ? fmt.dateTime(s * 1000) : '—')
const bytes = (n: number | null | undefined) => (n == null ? '—' : n < 1048576 ? `${Math.round(n / 1024)} Kio` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} Mio` : `${(n / 1073741824).toFixed(2)} Gio`)
const ageText = computed(() => { const s = st.value?.ageSeconds ?? 0; return s < 120 ? `${s} s` : s < 7200 ? `${Math.round(s / 60)} min` : `${Math.round(s / 3600)} h` })
const isPrimary = computed(() => st.value?.role === 'primary')
const isWitness = computed(() => st.value?.role === 'witness')
// Prochaine sauvegarde planifiée : au plus tôt « dernière + intervalle », à partir de l'heure de début ; la première est immédiate.
const nextRun = computed(() => {
  const s = st.value; if (!s || !s.backups.length) return null
  const last = s.backups[s.backups.length - 1].finishedAt, due = last + s.intervalHours * 3600
  const d = new Date(due * 1000); if (d.getHours() < s.startHour) d.setHours(s.startHour, 0, 0, 0)
  return Math.max(Math.floor(d.getTime() / 1000), Math.floor(Date.now() / 1000))
})
const sorted = computed(() => [...(st.value?.backups ?? [])].reverse())
const archiverFailing = computed(() => (st.value?.archiver?.failedCount ?? 0) > 0 && (st.value?.archiver?.lastFailedAt ?? 0) >= (st.value?.archiver?.lastArchivedAt ?? 0))

// ---- exécution d'une demande : dépôt, puis attente du résultat publié par root (spinner + libellé d'avancement)
const working = ref(''), progress = ref('')
const busy = computed(() => !!working.value || restoreActive.value)
async function submit(action: string, url: string, body: unknown, doneMsg?: string, timeoutS = 1800) {
  working.value = action; progress.value = ''
  const before = result.value?.at ?? 0
  try {
    await api.call('POST', url, body, { busy: true })
    for (let i = 0; i < timeoutS / 3; i++) {
      await sleep(3000)
      try { await load() } catch { continue }
      const r = result.value
      if (r && r.at > before && r.action === action) {
        toast.add({ title: r.ok ? (doneMsg ?? t('backup.done.generic')) : t('backup.result.title', { a: t(`backup.act.${action}`) }), description: r.message, color: r.ok ? 'success' : 'error', icon: r.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
        return r.ok
      }
    }
    toast.add({ title: t('backup.timeout'), color: 'warning' })
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) }
  finally { working.value = ''; await load().catch(() => {}) }
  return false
}
const act = (action: string, extra: Record<string, unknown> = {}, doneMsg?: string) => submit(action, '/backup/action', { action, ...extra }, doneMsg)
async function enable() { if (await ask(t('backup.enable'), t('backup.enable_confirm'), false)) await act('enable') }
async function disable() { if (await ask(t('backup.disable'), t('backup.disable_confirm'), true)) await act('disable') }
async function removeOne(b: any) { if (await ask(t('backup.delete'), t('backup.delete_confirm', { id: b.id }), true)) await act('delete', { id: b.id }) }
async function refresh() { await submit('refresh', '/backup/refresh', {}) }

// ---- réglages
const cfgOpen = ref(false), cfgForm = reactive({ keepFull: 3, keepDays: 0, verifyAfter: true, intervalHours: 24, startHour: 2, mirrorDir: '' }), cfgErr = ref('')
function openCfg() { if (!st.value) return; Object.assign(cfgForm, { keepFull: st.value.keepFull, keepDays: st.value.keepDays ?? 0, verifyAfter: st.value.verifyAfter !== false, intervalHours: st.value.intervalHours, startHour: st.value.startHour, mirrorDir: st.value.mirrorDir ?? '' }); cfgErr.value = ''; cfgOpen.value = true }
async function saveCfg() {
  cfgErr.value = ''
  const body = { keepFull: Number(cfgForm.keepFull), keepDays: Number(cfgForm.keepDays) || 0, verifyAfter: !!cfgForm.verifyAfter, intervalHours: Number(cfgForm.intervalHours), startHour: Number(cfgForm.startHour), mirrorDir: cfgForm.mirrorDir.trim() }
  try { await api.call('POST', '/backup/configure', body, { silent: true }) } catch (e: any) { cfgErr.value = e.info?.message ?? t('err.internal'); return }
  cfgOpen.value = false
  const before = result.value?.at ?? 0
  for (let i = 0; i < 20; i++) { await sleep(1500); try { await load() } catch { continue } if ((result.value?.at ?? 0) > before) break }
  toast.add({ title: t('backup.done.generic'), color: 'success', icon: 'i-lucide-check' })
}

// ---- restauration
type Target = { mode: 'latest' } | { mode: 'id'; id: string } | { mode: 'at'; at: string }
const target = ref<Target | null>(null), typed = ref(''), restoring = ref(false), restoreErr = ref(''), consoleDown = ref(false)
const atLocal = ref('')
const pad = (n: number) => String(n).padStart(2, '0')
const localInput = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
const minAt = computed(() => (st.value?.pitrFrom ? localInput(new Date(st.value.pitrFrom * 1000)) : ''))
const maxAt = computed(() => localInput(new Date()))
const atValid = computed(() => { if (!atLocal.value) return false; const d = new Date(atLocal.value); return !Number.isNaN(d.getTime()) && d.getTime() <= Date.now() && (!st.value?.pitrFrom || d.getTime() >= st.value.pitrFrom * 1000) })
const dlgOpen = computed({ get: () => target.value !== null, set: (v: boolean) => { if (!v && !restoring.value) target.value = null } })
function beginRestore(tg: Target) { target.value = tg; typed.value = ''; restoreErr.value = ''; consoleDown.value = false }
function beginAt() { if (atValid.value) beginRestore({ mode: 'at', at: new Date(atLocal.value).toISOString().slice(0, 19) + 'Z' }) }
const targetText = computed(() => { const tg = target.value; if (!tg) return ''; return tg.mode === 'at' ? t('backup.restore.target.at', { at: fmt.dateTime(tg.at) }) : tg.mode === 'id' ? t('backup.restore.target.id', { id: tg.id }) : t('backup.restore.target.latest') })
const phaseText = computed(() => { const p = restoreState.value?.phase; return p && restoreActive.value ? t(`backup.phase.${p}`) : '' })
async function goRestore() {
  const tg = target.value; if (!tg || typed.value !== st.value?.confirmWord) return
  restoring.value = true; restoreErr.value = ''; consoleDown.value = false
  const before = result.value?.at ?? 0
  try {
    await api.call('POST', '/backup/restore', { ...tg, confirm: typed.value }, { busy: true, silent: true })
    for (let i = 0; i < 600; i++) {   // jusqu'à 30 minutes ; la console peut être coupée un moment (hors cluster), on continue d'interroger
      await sleep(3000)
      try { await load(); consoleDown.value = false } catch { consoleDown.value = true; continue }
      const r = result.value
      if (r && r.at > before && r.action === 'restore') {
        toast.add({ title: r.ok ? t('backup.phase.done') : t('backup.phase.failed'), description: r.message, color: r.ok ? 'success' : 'error', icon: r.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
        if (r.ok) target.value = null; else restoreErr.value = r.message
        return
      }
    }
    restoreErr.value = t('backup.restore.timeout')
  } catch (e: any) { restoreErr.value = e.info?.message ?? t('err.internal') }
  finally { restoring.value = false; await load().catch(() => {}) }
}
</script>

<template>
  <div class="flex flex-col gap-4">
    <UAlert v-if="loadError && !st" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('err.network')" />
    <UAlert v-else-if="data && !st" color="warning" variant="subtle" icon="i-lucide-circle-help" :title="t('backup.unavailable')" />

    <template v-if="st">
      <UCard>
        <template #header>
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-medium">{{ t('backup.title') }}</span>
            <UBadge :color="st.enabled ? 'success' : 'neutral'" variant="subtle" :label="st.enabled ? t('backup.state.on') : t('backup.state.off')" />
            <UBadge color="neutral" variant="outline" :label="`${t(`backup.role.${st.role}`)} · ${st.node || st.hostname}`" />
            <span class="flex-1" />
            <UButton size="xs" color="neutral" variant="outline" icon="i-lucide-refresh-cw" :label="t('backup.refresh')" :disabled="busy" @click="refresh" />
          </div>
        </template>
        <p class="text-sm text-muted mb-3">{{ t('backup.intro') }}</p>
        <UAlert v-if="st.stale" class="mb-3" color="warning" variant="subtle" icon="i-lucide-clock" :title="t('backup.stale', { age: ageText })" />
        <UAlert v-if="archiverFailing" class="mb-3" color="error" variant="subtle" icon="i-lucide-triangle-alert"
          :title="t('backup.archiving_fail', { n: st.archiver.failedCount, wal: st.archiver.lastFailedWal ?? '—', at: when(st.archiver.lastFailedAt) })" />
        <UAlert v-if="st.enabled && st.role !== 'witness' && st.archiveMode === 'off'" class="mb-3" color="warning" variant="subtle" icon="i-lucide-circle-alert" :title="t('backup.archive_mode_off')" />
        <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt class="text-muted">{{ t('backup.window') }}</dt>
          <dd>{{ st.pitrFrom ? t('backup.window_val', { from: when(st.pitrFrom), last: when(st.lastWalAt) }) : t('backup.window_none') }}</dd>
          <dt class="text-muted">{{ t('backup.archiving') }}</dt>
          <dd>{{ st.archiver && st.archiver.archivedCount ? t('backup.archiving_ok', { n: st.archiver.archivedCount, at: when(st.archiver.lastArchivedAt) }) : t('backup.archiving_none') }}</dd>
          <dt class="text-muted">{{ t('backup.schedule') }}</dt>
          <dd>{{ t('backup.schedule_val', { h: st.intervalHours, s: st.startHour, k: st.keepFull }) }}</dd>
          <dt class="text-muted">{{ t('backup.retention') }}</dt>
          <dd>{{ st.keepDays ? t('backup.retention_val_days', { k: st.keepFull, d: st.keepDays }) : t('backup.retention_val', { k: st.keepFull }) }}</dd>
          <template v-if="st.enabled && isPrimary"><dt class="text-muted">{{ t('backup.next') }}</dt><dd>{{ nextRun ? when(nextRun) : t('backup.next_soon') }}</dd></template>
          <dt class="text-muted">{{ t('backup.verify') }}</dt>
          <dd><span v-if="st.lastVerify" :class="st.lastVerify.ok ? '' : 'text-error font-medium'">{{ st.lastVerify.ok ? t('backup.verify_ok', { at: when(st.lastVerify.at), n: st.lastVerify.backups }) : t('backup.verify_ko', { at: when(st.lastVerify.at), n: st.lastVerify.badBackups, w: st.lastVerify.badWal }) }}</span><span v-else class="text-muted">{{ t('backup.verify_never') }}</span>
            <span class="text-xs text-muted"> · {{ st.verifyAfter ? t('backup.verify_auto_on') : t('backup.verify_auto_off') }}</span></dd>
          <dt class="text-muted">{{ t('backup.repo') }}</dt><dd class="font-mono text-xs">{{ st.repo }} · {{ bytes(st.walBytes) }} · {{ t('backup.disk_free') }} {{ bytes(st.diskFreeBytes) }}</dd>
          <dt class="text-muted">{{ t('backup.mirror') }}</dt><dd class="font-mono text-xs">{{ st.mirrorDir ?? t('backup.mirror_none') }}</dd>
          <template v-if="st.preRestoreDirs"><dt class="text-muted" /><dd class="text-xs text-muted">{{ t('backup.pre_restore', { n: st.preRestoreDirs }) }}</dd></template>
        </dl>
        <div v-if="!isWitness" class="flex flex-wrap gap-2 mt-4">
          <UButton v-if="!st.enabled" icon="i-lucide-shield-check" :label="t('backup.enable')" :loading="working === 'enable'" :disabled="busy" @click="enable" />
          <template v-else>
            <UButton icon="i-lucide-hard-drive-download" :label="t('backup.run')" :loading="working === 'run'" :disabled="busy || !isPrimary" @click="act('run', {}, t('backup.done.run'))" />
            <UButton color="neutral" variant="outline" icon="i-lucide-badge-check" :label="t('backup.verify_btn')" :loading="working === 'verify'" :disabled="busy" @click="act('verify')" />
            <UButton color="neutral" variant="outline" icon="i-lucide-eraser" :label="t('backup.prune')" :loading="working === 'prune'" :disabled="busy" @click="act('prune')" />
            <UButton color="neutral" variant="outline" icon="i-lucide-settings" :label="t('backup.settings')" :disabled="busy" @click="openCfg" />
            <UButton color="error" variant="ghost" icon="i-lucide-shield-off" :label="t('backup.disable')" :disabled="busy" @click="disable" />
          </template>
        </div>
        <div v-if="working" class="flex items-center gap-2 text-sm text-muted mt-3" role="status"><UIcon name="i-lucide-loader-circle" class="animate-spin" />{{ t('backup.working') }}</div>
      </UCard>

      <UAlert v-if="restoreActive && !restoring" color="warning" variant="subtle" icon="i-lucide-loader-circle" role="status" :title="t('backup.restore.running_elsewhere')" :description="phaseText" />
      <UAlert v-if="result && !working" :color="result.ok ? 'success' : 'error'" variant="subtle" :icon="result.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
        :title="t('backup.result.title', { a: t(`backup.act.${result.action}`) })" :description="`${when(result.at)} — ${result.message}`" />

      <UCard v-if="st.enabled && !isWitness">
        <template #header><span class="font-medium">{{ t('backup.list') }}</span></template>
        <div class="overflow-x-auto">
          <table class="w-full text-sm"><caption class="sr-only">{{ t('backup.list') }}</caption>
            <thead><tr class="text-muted"><th scope="col" class="text-start p-1">{{ t('backup.col.date') }}</th><th scope="col" class="text-start p-1">{{ t('backup.col.node') }}</th><th scope="col" class="text-start p-1">{{ t('backup.col.size') }}</th><th scope="col" class="text-start p-1">{{ t('backup.col.tl') }}</th><th scope="col" class="text-start p-1">{{ t('backup.col.wal') }}</th><th scope="col" class="p-1"><span class="sr-only">{{ t('common.actions') }}</span></th></tr></thead>
            <tbody>
              <tr v-for="b in sorted" :key="b.id" class="border-t border-default">
                <td class="p-1 whitespace-nowrap"><span class="num">{{ when(b.finishedAt) }}</span> <span class="text-xs text-muted font-mono">{{ b.id }}</span></td>
                <td class="p-1 font-mono">{{ b.node }}</td><td class="p-1 num">{{ bytes(b.sizeBytes) }}</td><td class="p-1 num">{{ b.timeline }}</td>
                <td class="p-1"><UBadge :color="b.walArchived ? 'success' : 'warning'" variant="subtle" :label="b.walArchived ? t('backup.wal_ok') : t('backup.wal_ko')" /></td>
                <td class="p-1 text-end whitespace-nowrap">
                  <UButton size="xs" color="neutral" variant="outline" icon="i-lucide-badge-check" :label="t('backup.verify_one')" :disabled="busy" @click="act('verify', { id: b.id })" />
                  <UButton size="xs" color="warning" variant="outline" icon="i-lucide-history" :label="t('backup.restore_this')" :disabled="busy || !isPrimary" @click="beginRestore({ mode: 'id', id: b.id })" />
                  <UButton size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('backup.delete')" :disabled="busy || sorted.length < 2" @click="removeOne(b)" />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-if="!sorted.length" class="text-sm text-muted">{{ t('backup.empty') }}</p>
      </UCard>

      <UCard v-if="st.enabled && !isWitness && sorted.length">
        <template #header><span class="font-medium">{{ t('backup.restore.title') }}</span></template>
        <p class="text-sm text-muted mb-3">{{ t('backup.restore.desc') }}</p>
        <UAlert v-if="!isPrimary" class="mb-3" color="neutral" variant="subtle" icon="i-lucide-info" :title="t('backup.restore.primary_only')" />
        <div class="flex flex-wrap items-end gap-3">
          <label class="text-sm">{{ t('backup.restore.at') }}
            <UInput v-model="atLocal" type="datetime-local" step="1" :min="minAt" :max="maxAt" class="block mt-1" :disabled="!isPrimary || busy" />
          </label>
          <UButton color="warning" icon="i-lucide-history" :label="t('backup.restore.at_go')" :disabled="!isPrimary || !atValid || busy" @click="beginAt" />
          <UButton color="warning" variant="outline" icon="i-lucide-fast-forward" :label="t('backup.restore.latest')" :disabled="!isPrimary || busy" @click="beginRestore({ mode: 'latest' })" />
        </div>
        <p class="text-xs text-muted mt-2">{{ t('backup.restore.at_hint') }}</p>
      </UCard>
    </template>

    <UModal v-model:open="cfgOpen" :title="t('backup.settings.title')" :description="t('backup.settings.cluster')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="saveCfg">
          <label class="text-sm">{{ t('backup.settings.keep') }}<UInput v-model.number="cfgForm.keepFull" type="number" min="1" max="30" class="w-full mt-1" /></label>
          <label class="text-sm">{{ t('backup.settings.keep_days') }}<UInput v-model.number="cfgForm.keepDays" type="number" min="0" max="365" class="w-full mt-1" /><span class="text-xs text-muted">{{ t('backup.settings.keep_days_help') }}</span></label>
          <div class="text-sm flex flex-col justify-end"><USwitch v-model="cfgForm.verifyAfter" :label="t('backup.settings.verify_after')" /><span class="text-xs text-muted mt-1">{{ t('backup.settings.verify_after_help') }}</span></div>
          <label class="text-sm">{{ t('backup.settings.interval') }}<UInput v-model.number="cfgForm.intervalHours" type="number" min="1" max="168" class="w-full mt-1" /></label>
          <label class="text-sm">{{ t('backup.settings.start') }}<UInput v-model.number="cfgForm.startHour" type="number" min="0" max="23" class="w-full mt-1" /></label>
          <label class="text-sm">{{ t('backup.settings.mirror') }}<UInput v-model="cfgForm.mirrorDir" class="w-full mt-1 font-mono" placeholder="/mnt/sauvegardes" autocomplete="off" /></label>
          <UAlert v-if="cfgErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="cfgErr" />
        </form>
      </template>
      <template #footer><div class="flex justify-end gap-2 w-full"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="cfgOpen = false" /><UButton icon="i-lucide-save" :label="t('backup.settings.save')" @click="saveCfg" /></div></template>
    </UModal>

    <UModal v-model:open="dlgOpen" :title="t('backup.restore.confirm_title')" :description="targetText" :dismissible="!restoring">
      <template #body>
        <div v-if="target" class="flex flex-col gap-3 text-sm">
          <UAlert color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('backup.restore.warn_data')" />
          <p class="text-muted">{{ t('backup.restore.warn_console') }}</p>
          <p v-if="st?.cluster" class="text-muted">{{ t('backup.restore.warn_cluster') }}</p>
          <label>{{ t('backup.restore.type', { v: st?.confirmWord ?? '' }) }}
            <UInput v-model="typed" class="w-full mt-1" autocomplete="off" :disabled="restoring" @keyup.enter="goRestore" />
          </label>
          <UAlert v-if="restoreErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="restoreErr" />
          <div v-if="restoring" class="flex flex-col gap-1 text-muted" role="status">
            <div class="flex items-center gap-2"><UIcon name="i-lucide-loader-circle" class="animate-spin" />{{ t('backup.restore.running') }}</div>
            <div v-if="phaseText" class="ps-6 text-xs">{{ phaseText }}</div>
            <div v-if="consoleDown" class="ps-6 text-xs">{{ t('backup.restore.wait_console') }}</div>
          </div>
        </div>
      </template>
      <template #footer>
        <div class="flex justify-end gap-2 w-full">
          <UButton color="neutral" variant="outline" :label="t('common.cancel')" :disabled="restoring" @click="target = null" />
          <UButton color="error" icon="i-lucide-history" :label="t('backup.restore.go')" :disabled="typed !== st?.confirmWord || restoring" :loading="restoring" @click="goRestore" />
        </div>
      </template>
    </UModal>
  </div>
</template>
