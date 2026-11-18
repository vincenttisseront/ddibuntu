<script setup lang="ts">
// Mises à jour d'EJBCA Community (0.14.7). Root cherche les nouvelles versions sur Docker Hub (une fois par jour, ou à la demande) et exécute la mise à jour : tirage de l'image,
// arrêt, sauvegarde de retour arrière (base « ejbca » + fichiers), démarrage de la nouvelle image (elle migre la base), contrôles. Un échec après l'arrêt remet tout d'avant tout
// seul ; un succès attend la validation de l'administrateur, qui peut encore revenir en arrière. Cet onglet ne fait que montrer l'état publié par root et déposer des demandes.
const props = defineProps<{ status: any; waiting: boolean }>()
const emit = defineEmits<{ (e: 'changed'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()

const data = ref<any>(null), err = ref(''), busy = ref('')
const upd = computed(() => data.value?.update ?? null)
const job = computed(() => upd.value?.job ?? null)
const running = computed(() => job.value?.state === 'running')
const pending = computed(() => job.value?.state === 'pending')
const healthy = computed(() => props.status?.state === 'healthy')
const locked = computed(() => !!busy.value || !!data.value?.requestPending || running.value)
const when = (s: number | null | undefined) => (s ? fmt.dateTime(s * 1000) : '—')
const mib = (b: number) => (b / 1048576).toFixed(1)

async function load() {
  try { data.value = await api.call('GET', '/pki/update', undefined, { silent: true }) } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') }
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
async function settle() { for (let i = 0; i < 40; i++) { await sleep(1500); await load(); if (!data.value?.requestPending) return } }
async function post(path: string, body: Record<string, unknown> = {}) {
  if (locked.value) return false
  busy.value = path; err.value = ''
  try { await api.call('POST', `/pki/update/${path}`, body); toast.add({ title: t('pki.sent'), color: 'success' }); await settle(); return true }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal'); return false } finally { busy.value = ''; await load(); emit('changed') }
}
const check = () => post('check')
async function apply(it: any) {
  const from = upd.value?.current ?? props.status?.version ?? ''
  if (!(await ask(t('pki.upd.apply_title', { to: it.tag }), t('pki.upd.apply_body', { from, to: it.tag }), false))) return
  await post('apply', { version: it.tag })
}
async function validate() {
  if (!(await ask(t('pki.upd.validate_title'), t('pki.upd.validate_body', { to: job.value?.to ?? '' }), false))) return
  await post('validate')
}
async function rollback() {
  const n = upd.value?.certsSince ?? 0
  if (!(await ask(t('pki.upd.rollback_title', { from: job.value?.from ?? '' }), `${t('pki.upd.rollback_body')}${n > 0 ? ' ' + t('pki.upd.certs_since', { n }) : ''}`, true))) return
  await post('rollback', { confirm: true })
}

// ---- suivi : pendant la mise à jour (plusieurs minutes) on relit l'avancement toutes les 3 secondes
let timer: ReturnType<typeof setTimeout> | undefined, stopped = false
async function follow() {
  if (stopped) return
  if (running.value || data.value?.requestPending) await load()
  if (!stopped) timer = setTimeout(follow, 3000)
}
watch(() => job.value?.state, (n, o) => { if (o && n !== o) emit('changed') })
onMounted(async () => { await load(); timer = setTimeout(follow, 3000) })
onBeforeUnmount(() => { stopped = true; if (timer) clearTimeout(timer) })

const stateColor = computed(() => ({ running: 'info', pending: 'warning', validated: 'success', failed: 'error', rolled_back: 'warning' } as Record<string, string>)[job.value?.state] ?? 'neutral')
const stepIcon = (s: string) => ({ done: 'i-lucide-circle-check', running: 'i-lucide-loader-circle', failed: 'i-lucide-circle-x', todo: 'i-lucide-circle' } as Record<string, string>)[s] ?? 'i-lucide-circle'
const stepClass = (s: string) => ({ done: 'text-success', running: 'text-info animate-spin', failed: 'text-error', todo: 'text-dimmed' } as Record<string, string>)[s] ?? ''
const known = (pre: string, id: string, list: string[]) => (list.includes(id) ? t(`${pre}.${id}`) : id)
const stepLabel = (id: string) => known('pki.upd.step', id, ['pull', 'stop', 'backup', 'start', 'migrate', 'checks', 'rb_stop', 'rb_db', 'rb_files', 'rb_start', 'rb_checks'])
const checkLabel = (id: string) => known('pki.upd.check', id, ['health', 'schema', 'cas', 'signing', 'crl'])
const reasonText = (r: string) => (['older_than_db', 'older', 'same', 'major_jump', 'invalid'].includes(r) ? t(`pki.upd.reason.${r}`) : t('pki.upd.reason.other'))
const checkErr = computed(() => { const c = upd.value?.checkError; return !c ? '' : t(['unreachable', 'bad_answer'].includes(c) ? `pki.upd.check_err.${c}` : 'pki.upd.check_err.other') })
const showJob = computed(() => !!job.value && (['running', 'pending', 'failed'].includes(job.value.state) || (Date.now() / 1000 - (job.value.finishedAt || job.value.updatedAt)) < 7 * 86400))
const canStart = computed(() => healthy.value && !locked.value && !pending.value && !(job.value?.state === 'failed' && job.value.rollbackAvailable))
const needsKey = computed(() => !!data.value?.installed && !data.value?.hasRecovery && (data.value?.casCount ?? 0) > 0)
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('pki.upd.intro') }}</p>
    <UAlert v-if="data && !data.installed" color="info" variant="subtle" icon="i-lucide-info" :title="t('pki.upd.not_installed')" data-test="pki-upd-notinstalled" />
    <template v-else-if="data">
      <UAlert v-if="running" color="info" variant="subtle" icon="i-lucide-loader-circle" :title="t('pki.upd.running_title', { to: job.to })" :description="t('pki.upd.running_hint')" data-test="pki-upd-running" />
      <UAlert v-if="needsKey" color="warning" variant="subtle" icon="i-lucide-key-round" :title="t('pki.upd.no_key_title')" :description="t('pki.upd.no_key_body')" data-test="pki-upd-nokey" />

      <UCard>
        <template #header>
          <div class="flex items-center justify-between gap-2">
            <span class="font-medium">{{ t('pki.upd.versions_title') }}</span>
            <UButton size="sm" icon="i-lucide-search" color="neutral" variant="outline" :label="t('pki.upd.check_now')" :loading="busy === 'check'" :disabled="locked || !data.installed" data-test="pki-upd-check" @click="check" />
          </div>
        </template>
        <dl class="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-3 text-sm">
          <div><dt class="text-muted">{{ t('pki.upd.installed') }}</dt><dd class="font-mono" data-test="pki-upd-current">EJBCA CE {{ upd?.current || data.version || '—' }}</dd></div>
          <div v-if="upd?.dbTag && upd.dbTag !== upd.current"><dt class="text-muted">{{ t('pki.upd.dbtag') }}</dt><dd class="font-mono">{{ upd.dbTag }}</dd></div>
          <div><dt class="text-muted">{{ t('pki.upd.checked') }}</dt><dd data-test="pki-upd-checked">{{ upd?.checkedAt ? when(upd.checkedAt) : t('pki.upd.never_checked') }}</dd></div>
        </dl>
        <p v-if="checkErr" class="text-sm text-warning mt-3" role="status" data-test="pki-upd-checkerr">{{ checkErr }}</p>

        <div v-if="upd?.available?.length" class="overflow-x-auto mt-4">
          <table class="w-full text-sm" data-test="pki-upd-table">
            <thead><tr class="text-left text-muted"><th class="py-1 pr-3 font-normal">{{ t('pki.upd.col_version') }}</th><th class="pr-3 font-normal">{{ t('pki.upd.col_date') }}</th><th class="pr-3 font-normal">{{ t('pki.upd.col_kind') }}</th><th class="pr-3 font-normal">{{ t('pki.upd.col_notes') }}</th><th /></tr></thead>
            <tbody>
              <tr v-for="it in upd.available" :key="it.tag" class="border-t border-default" :data-test="`pki-upd-row-${it.tag}`">
                <td class="py-2 pr-3 font-mono">{{ it.tag }} <UBadge v-if="it.tag === upd.latest" size="sm" color="success" variant="subtle" :label="t('pki.upd.latest')" /></td>
                <td class="pr-3">{{ it.pushedAt || '—' }}</td>
                <td class="pr-3"><UBadge size="sm" :color="it.kind === 'major' ? 'warning' : 'neutral'" variant="subtle" :label="t(`pki.upd.kind.${it.kind}`)" /></td>
                <td class="pr-3">
                  <a v-if="it.notes.release" :href="it.notes.release" target="_blank" rel="noopener noreferrer" class="text-primary hover:underline mr-3">{{ t('pki.upd.notes_release') }}</a>
                  <a v-if="it.notes.upgrade" :href="it.notes.upgrade" target="_blank" rel="noopener noreferrer" class="text-primary hover:underline">{{ t('pki.upd.notes_upgrade') }}</a>
                </td>
                <td class="text-right">
                  <UButton v-if="it.allowed" size="sm" icon="i-lucide-circle-arrow-up" :label="t('pki.upd.apply')" :loading="busy === 'apply'" :disabled="!canStart" :data-test="`pki-upd-apply-${it.tag}`" @click="apply(it)" />
                  <span v-else class="text-xs text-warning" :data-test="`pki-upd-refused-${it.tag}`">{{ reasonText(it.reason) }}</span>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-if="!healthy" class="text-xs text-warning mt-2" data-test="pki-upd-nothealthy">{{ t('pki.upd.not_healthy') }}</p>
        </div>
        <p v-else-if="upd?.checkedAt && !checkErr" class="text-sm text-muted mt-4" data-test="pki-upd-uptodate">{{ t('pki.upd.up_to_date', { v: upd.current }) }}</p>
        <p class="text-xs text-dimmed mt-3">{{ t('pki.upd.what') }}</p>
        <p v-if="err" class="text-sm text-error mt-2" role="alert" data-test="pki-upd-error">{{ err }}</p>
      </UCard>

      <UCard v-if="showJob">
        <template #header>
          <div class="flex items-center justify-between gap-2">
            <span class="font-medium">{{ t('pki.upd.job_title', { from: job.from, to: job.to }) }}</span>
            <UBadge :color="(stateColor as any)" variant="subtle" :label="t(`pki.upd.state.${job.state}`)" data-test="pki-upd-state" />
          </div>
        </template>
        <p class="text-sm" data-test="pki-upd-statebody">{{ t(`pki.upd.state_body.${job.state}`, { from: job.from, to: job.to, mb: mib(job.backupBytes) }) }}</p>
        <p v-if="job.message && ['failed', 'rolled_back'].includes(job.state)" class="text-xs text-muted mt-1 break-words" data-test="pki-upd-message">{{ job.message }}</p>
        <ol class="mt-3 flex flex-col gap-1 text-sm" data-test="pki-upd-steps">
          <li v-for="s in job.steps" :key="s.id" class="flex items-center gap-2" :data-test="`pki-upd-step-${s.id}`">
            <UIcon :name="stepIcon(s.status)" :class="stepClass(s.status)" /><span :class="s.status === 'todo' ? 'text-dimmed' : ''">{{ stepLabel(s.id) }}</span>
          </li>
        </ol>
        <div v-if="job.checks.length" class="mt-3" data-test="pki-upd-checks">
          <p class="text-sm text-muted mb-1">{{ t('pki.upd.checks_title') }}</p>
          <ul class="flex flex-col gap-1 text-sm">
            <li v-for="c in job.checks" :key="c.id" class="flex items-start gap-2" :data-test="`pki-upd-check-${c.id}`">
              <UIcon :name="c.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'" :class="c.ok ? 'text-success' : 'text-error'" class="mt-0.5" />
              <span>{{ checkLabel(c.id) }}<span v-if="c.detail" class="text-xs text-muted"> — {{ c.detail }}</span></span>
            </li>
          </ul>
        </div>
        <p v-if="job.backupBytes && upd.job.rollbackAvailable" class="text-xs text-dimmed mt-3">{{ t('pki.upd.backup_kept', { mb: mib(job.backupBytes) }) }}</p>
        <p v-if="upd.certsSince && job.rollbackAvailable" class="text-sm text-warning mt-2" data-test="pki-upd-certs-since">{{ t('pki.upd.certs_since', { n: upd.certsSince }) }}</p>
        <div v-if="pending || (job.state === 'failed' && job.rollbackAvailable)" class="flex flex-wrap gap-2 mt-4">
          <UButton v-if="pending" icon="i-lucide-check" :label="t('pki.upd.validate')" :loading="busy === 'validate'" :disabled="locked" data-test="pki-upd-validate" @click="validate" />
          <UButton v-if="job.rollbackAvailable" icon="i-lucide-undo-2" color="error" variant="outline" :label="t('pki.upd.rollback')" :loading="busy === 'rollback'" :disabled="locked" data-test="pki-upd-rollback" @click="rollback" />
        </div>
      </UCard>
    </template>
    <p v-else-if="err" class="text-sm text-error" role="alert">{{ err }}</p>
  </div>
</template>
