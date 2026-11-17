<script setup lang="ts">
// Clé de récupération de la PKI (0.14.5). Les clés des autorités sont dans la base « ejbca » (sauvegardée avec PostgreSQL) mais ne se lisent qu'avec les secrets d'ejbca.env :
// chaque sauvegarde reçoit un lot chiffré de ces secrets, que seul le détenteur de la clé PRIVÉE de récupération peut ouvrir. L'appliance ne garde que le certificat public.
// Cette carte crée la clé (la console la fabrique, la rend UNE fois, ne la garde nulle part), montre si la dernière sauvegarde est protégée et rappelle la procédure de restauration
// (en ligne de commande : la clé privée ne passe jamais par l'appliance en fonctionnement).
const props = defineProps<{ waiting: boolean }>()
const emit = defineEmits<{ (e: 'changed'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()

const data = ref<any>(null), err = ref('')
async function load() {
  try { data.value = await api.call('GET', '/pki/recovery', undefined, { silent: true }); err.value = '' } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') }
}
const rec = computed(() => data.value?.recovery ?? null)
const prot = computed(() => data.value?.protection ?? null)
const state = computed<string>(() => prot.value?.state ?? 'unknown')
const when = (s: number | null | undefined) => (s ? fmt.dateTime(s * 1000) : '—')
const fpGroups = (fp: string) => (fp.match(/.{1,4}/g) ?? []).join(' ')
const stateColor = computed(() => ({ ok: 'success', none: 'neutral', pending: 'info', unknown: 'neutral' } as Record<string, string>)[state.value] ?? 'warning')
const stateIcon = computed(() => ({ ok: 'i-lucide-shield-check', none: 'i-lucide-info', pending: 'i-lucide-clock', unknown: 'i-lucide-circle-help' } as Record<string, string>)[state.value] ?? 'i-lucide-triangle-alert')
const reasonText = computed(() => {
  const r = prot.value?.reason
  return !r ? '' : t(`pki.rec.reason.${['other_key', 'none', 'no-recovery-key', 'error', 'unknown'].includes(r) ? r : 'unknown'}`)
})

// ---- création / remplacement de la clé
const form = reactive({ pass: '', pass2: '', plain: false })
const busy = ref(''), fail = ref('')
const passOk = computed(() => (form.plain && !form.pass && !form.pass2) || (form.pass.length >= 10 && form.pass.length <= 128 && form.pass === form.pass2))
const out = reactive<{ open: boolean; keyPem: string; fingerprint: string; encrypted: boolean; saved: boolean; done: boolean }>({ open: false, keyPem: '', fingerprint: '', encrypted: false, saved: false, done: false })
async function create() {
  if (busy.value || props.waiting) return
  if (rec.value && !(await ask(t('pki.rec.replace_title'), t('pki.rec.replace_body'), true))) return
  busy.value = 'create'; fail.value = ''
  try {
    const r = await api.call('POST', '/pki/recovery', { ...(form.pass ? { passphrase: form.pass } : {}), ...(rec.value ? { replace: true } : {}) }, { silent: true })
    Object.assign(out, { open: true, keyPem: r.keyPem, fingerprint: r.fingerprint, encrypted: !!r.encrypted, saved: false, done: false })
    form.pass = ''; form.pass2 = ''; form.plain = false
  } catch (e: any) { fail.value = e?.info?.message ?? t('err.internal') } finally { busy.value = ''; await load(); emit('changed') }
}
function saveBlob(text: string, name: string) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' })); a.download = name
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 10_000)
}
const keyFile = computed(() => `ddibuntu-pki-recovery-${out.fingerprint.slice(0, 8)}.key.pem`)
function download() { saveBlob(out.keyPem, keyFile.value); out.done = true }
async function copyKey() { try { await navigator.clipboard.writeText(out.keyPem); out.done = true; toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
function closeKey() { if (!out.saved) return; out.open = false; out.keyPem = ''; out.done = false }   // la clé disparaît de la mémoire de la page

// ---- « Sauvegarder maintenant » : lance la sauvegarde puis suit l'apparition d'un nouveau lot
const run = reactive({ busy: false, err: '' })
async function backupNow() {
  if (run.busy) return
  run.busy = true; run.err = ''
  const before = prot.value?.last?.id ?? ''
  try {
    await api.call('POST', '/backup/action', { action: 'run' }, { silent: true })
    for (let i = 0; i < 200; i++) { await new Promise((r) => setTimeout(r, 3000)); await load(); if ((prot.value?.last?.id ?? '') !== before) break }
    emit('changed')
  } catch (e: any) { run.err = e?.info?.message ?? t('err.internal') } finally { run.busy = false }
}

const restoreCmd = computed(() => {
  const id = prot.value?.lastWithBundle?.id ?? '<ID>'
  return `ddibuntu-backup restore --id ${id}\nddibuntu-backup pki-restore --id ${id} --key /chemin/vers/la-cle-privee.pem`
})
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
onMounted(load)
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('pki.rec.intro') }}</p>

    <UAlert :color="(stateColor as any)" variant="subtle" :icon="stateIcon" :title="t(`pki.rec.state.${state}`)" :description="t(`pki.rec.state_body.${state}`, { reason: reasonText, n: data?.casCount ?? 0 })" data-test="pki-rec-state" :data-state="state" />

    <UCard>
      <template #header><span class="font-medium">{{ t('pki.rec.key_title') }}</span></template>
      <dl v-if="rec" class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
        <div class="sm:col-span-2"><dt class="text-muted">{{ t('pki.rec.fp') }}</dt><dd class="font-mono break-all" data-test="pki-rec-fp">{{ fpGroups(rec.fingerprint) }}</dd></div>
        <div><dt class="text-muted">{{ t('pki.rec.bits') }}</dt><dd class="font-mono">RSA {{ rec.bits }}</dd></div>
        <div><dt class="text-muted">{{ t('pki.rec.registered') }}</dt><dd>{{ when(rec.registeredAt) }}</dd></div>
        <div><dt class="text-muted">{{ t('pki.rec.expires') }}</dt><dd>{{ when(rec.notAfter) }}</dd></div>
        <div><dt class="text-muted">{{ t('pki.rec.subject') }}</dt><dd class="font-mono break-all">{{ rec.subject }}</dd></div>
      </dl>
      <p v-else class="text-sm text-muted" data-test="pki-rec-none">{{ t('pki.rec.no_key') }}</p>

      <div v-if="data?.backup" class="mt-4 text-sm flex flex-col gap-1" data-test="pki-rec-backups">
        <p><span class="text-muted">{{ t('pki.rec.last') }}</span> {{ prot?.last ? when(prot.last.finishedAt) : t('pki.rec.never') }}
          <UBadge v-if="prot?.last" :color="prot.last.pki.bundle ? 'success' : 'warning'" variant="subtle" size="sm" :label="prot.last.pki.bundle ? t('pki.rec.with_bundle') : t('pki.rec.without_bundle')" /></p>
        <p><span class="text-muted">{{ t('pki.rec.count') }}</span> {{ t('pki.rec.count_v', { n: data.backup.withBundle, total: data.backup.count }) }}</p>
      </div>
      <p v-if="err" class="text-sm text-error mt-2" role="alert">{{ err }}</p>
      <div class="flex flex-wrap gap-2 mt-4">
        <UButton icon="i-lucide-hard-drive-download" color="neutral" variant="outline" :label="t('pki.rec.backup_now')" :loading="run.busy" :disabled="run.busy || !data?.backup?.enabled || data?.backup?.role === 'standby'" data-test="pki-rec-backup" @click="backupNow" />
        <UButton to="/system#backup" color="neutral" variant="ghost" icon="i-lucide-arrow-right" :label="t('pki.rec.go_backup')" />
      </div>
      <p v-if="run.err" class="text-sm text-error mt-2" role="alert">{{ run.err }}</p>
    </UCard>

    <UCard>
      <template #header><span class="font-medium">{{ rec ? t('pki.rec.replace_card') : t('pki.rec.create_card') }}</span></template>
      <div class="flex flex-col gap-3">
        <UAlert color="warning" variant="subtle" icon="i-lucide-key-round" :title="t('pki.rec.warn_title')" :description="t('pki.rec.warn_body')" data-test="pki-rec-warn" />
        <UFormField :label="t('pki.rec.pass')" :hint="t('pki.rec.pass_hint')">
          <UInput v-model="form.pass" type="password" autocomplete="new-password" class="w-full font-mono" :disabled="waiting || !!busy" data-test="pki-rec-pass" />
        </UFormField>
        <UFormField :label="t('pki.rec.pass2')" :error="form.pass2 && form.pass !== form.pass2 ? t('pki.rec.pass_mismatch') : undefined">
          <UInput v-model="form.pass2" type="password" autocomplete="new-password" class="w-full font-mono" :disabled="waiting || !!busy" data-test="pki-rec-pass2" />
        </UFormField>
        <UCheckbox v-if="!form.pass && !form.pass2" v-model="form.plain" :label="t('pki.rec.plain')" data-test="pki-rec-plain" />
        <p v-if="fail" class="text-sm text-error" role="alert" data-test="pki-rec-error">{{ fail }}</p>
        <div class="flex justify-end">
          <UButton :icon="rec ? 'i-lucide-refresh-cw' : 'i-lucide-key-round'" :label="rec ? t('pki.rec.replace') : t('pki.rec.create')" :loading="busy === 'create'" :disabled="waiting || !!busy || !passOk" data-test="pki-rec-create" @click="create" />
        </div>
        <p class="text-xs text-dimmed">{{ t('pki.rec.offline') }}</p>
      </div>
    </UCard>

    <UCard>
      <template #header><span class="font-medium">{{ t('pki.rec.restore_title') }}</span></template>
      <p class="text-sm text-muted mb-2">{{ t('pki.rec.restore_body') }}</p>
      <div class="flex gap-2 items-start"><pre class="flex-1 text-xs font-mono bg-elevated rounded p-2 overflow-x-auto" data-test="pki-rec-cmd">{{ restoreCmd }}</pre>
        <UButton size="xs" icon="i-lucide-copy" color="neutral" variant="ghost" :aria-label="t('common.copy')" @click="copy(restoreCmd)" /></div>
      <p class="text-xs text-dimmed mt-2">{{ t('pki.rec.restore_hint') }}</p>
    </UCard>

    <!-- la clé privée n'est montrée qu'ici, une seule fois : impossible de fermer sans avoir confirmé qu'elle est conservée hors de cette machine -->
    <UModal v-model:open="out.open" :dismissible="false" :title="t('pki.rec.key_once_title')" :description="t('pki.rec.key_once_body', { fp: out.fingerprint.slice(0, 16) })" :close="false">
      <template #body>
        <div class="flex flex-col gap-3">
          <UAlert color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.rec.key_once_warn')" :description="out.encrypted ? t('pki.rec.key_once_enc') : t('pki.rec.key_once_plain')" />
          <textarea :value="out.keyPem" readonly rows="8" class="w-full font-mono text-xs bg-elevated rounded p-2" aria-label="clé privée" data-test="pki-rec-key" />
          <div class="flex flex-wrap gap-2">
            <UButton icon="i-lucide-download" :label="t('pki.rec.key_download')" data-test="pki-rec-key-dl" @click="download" />
            <UButton icon="i-lucide-copy" color="neutral" variant="outline" :label="t('common.copy')" @click="copyKey" />
          </div>
          <UCheckbox v-model="out.saved" :disabled="!out.done" :label="t('pki.rec.key_saved')" data-test="pki-rec-key-saved" />
          <div class="flex justify-end"><UButton :label="t('common.close')" :disabled="!out.saved" data-test="pki-rec-key-close" @click="closeKey" /></div>
        </div>
      </template>
    </UModal>
  </div>
</template>
