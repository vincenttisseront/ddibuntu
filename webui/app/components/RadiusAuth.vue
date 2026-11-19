<script setup lang="ts">
// Accès réseau — identifiant et mot de passe (0.16.0) : PEAP-MSCHAPv2 (postes Windows et mobiles) et EAP-TTLS/PAP, en plus d'EAP-TLS. Désactivés par défaut.
// PEAP-MSCHAPv2 exige que CE nœud soit joint au domaine (compte machine propre au nœud) : le compte qui joint n'est jamais conservé, il est transmis une fois à root.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()

const f = reactive({ peap: false, ttls: false, netbios: '' })
const servers = ref<string[]>([]), loaded = ref(false), saving = ref(false), error = ref('')
const status = ref<any>(null), pending = ref(false), result = ref<any>(null)
const wb = computed(() => status.value?.winbind ?? null)
const joined = computed(() => !!wb.value?.joined)

async function load() {
  try {
    const a: any = await api.call('GET', '/radius/auth', undefined, { silent: true })
    Object.assign(f, { peap: a.peap, ttls: a.ttls, netbios: a.netbios })
    servers.value = a.servers
    const r: any = await api.call('GET', '/radius', undefined, { silent: true })
    status.value = r.status; pending.value = !!r.requestPending; result.value = r.result
  } catch (e: any) { error.value = e?.info?.message ?? t('err.internal') } finally { loaded.value = true }
}
async function save() {
  saving.value = true; error.value = ''
  try {
    await api.call('PUT', '/radius/auth', { peap: f.peap, ttls: f.ttls, netbios: f.netbios.trim() }, { silent: true })
    toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' })
    await load()
  } catch (e: any) { error.value = e?.info?.message ?? t('err.internal') } finally { saving.value = false }
}

// ---- Jonction au domaine ----
const j = reactive({ realm: '', netbios: '', servers: '', user: '', password: '' })
const joining = ref(false), jerr = ref(''), outcome = ref<{ ok: boolean; message: string } | null>(null)
const serverList = () => j.servers.split(/[\s,]+/).filter(Boolean)
const joinReady = computed(() => !!j.realm.trim() && !!j.netbios.trim() && !!j.user && !!j.password && (serverList().length > 0 || servers.value.length > 0))
async function settle(action: 'join' | 'leave', since: number) {   // attend la réponse de root à CETTE demande (un résultat plus ancien n'est jamais pris pour la réponse)
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 1500)); await load()
    if (!pending.value && result.value?.action === action && result.value.at >= since) { outcome.value = { ok: !!result.value.ok, message: result.value.message }; return }
  }
  outcome.value = { ok: false, message: t('radius.auth.no_answer') }
}
async function join() {
  if (!joinReady.value || joining.value || pending.value) return
  joining.value = true; jerr.value = ''; outcome.value = null
  try {
    const b: any = { realm: j.realm.trim(), netbios: j.netbios.trim(), user: j.user, password: j.password }
    if (serverList().length) b.servers = serverList()
    const sent: any = await api.call('POST', '/radius/join', b, { silent: true })
    j.password = ''; j.user = ''   // jamais gardé dans la page
    await settle('join', sent.requestedAt)
  } catch (e: any) { jerr.value = e?.info?.message ?? t('err.internal') } finally { joining.value = false; j.password = '' }
}
const leaveUser = ref(''), leavePw = ref('')
async function leave() {
  if (joining.value || pending.value) return
  if (!(await ask(t('radius.auth.leave_title'), t('radius.auth.leave_body'), true))) return
  joining.value = true; jerr.value = ''; outcome.value = null
  try {
    const b: any = {}
    if (leaveUser.value && leavePw.value) { b.user = leaveUser.value; b.password = leavePw.value }
    const sent: any = await api.call('POST', '/radius/leave', b, { silent: true })
    leaveUser.value = ''; leavePw.value = ''
    await settle('leave', sent.requestedAt)
  } catch (e: any) { jerr.value = e?.info?.message ?? t('err.internal') } finally { joining.value = false; leavePw.value = '' }
}
onMounted(async () => { await load(); if (!j.netbios) j.netbios = f.netbios; if (!j.realm && wb.value?.realm) j.realm = wb.value.realm })
</script>

<template>
  <div class="flex flex-col gap-4" data-test="radius-auth">
    <UAlert color="neutral" variant="subtle" icon="i-lucide-key-round" :title="t('radius.auth.intro_title')" :description="t('radius.auth.intro')" />
    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-shield-question" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.auth.methods_title') }}</h2></div><p class="text-sm text-muted mt-1">{{ t('radius.auth.methods_desc') }}</p></template>
      <form class="flex flex-col gap-4" @submit.prevent="save">
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" data-test="auth-error" />
        <div class="grid gap-4 md:grid-cols-2">
          <div class="flex flex-col gap-1"><USwitch v-model="f.peap" :label="t('radius.auth.peap')" data-test="auth-peap" /><p class="text-xs text-muted">{{ t('radius.auth.peap_help') }}</p></div>
          <div class="flex flex-col gap-1"><USwitch v-model="f.ttls" :label="t('radius.auth.ttls')" data-test="auth-ttls" /><p class="text-xs text-muted">{{ t('radius.auth.ttls_help') }}</p></div>
        </div>
        <UFormField :label="t('radius.auth.netbios')" :help="t('radius.auth.netbios_help')" class="max-w-sm"><UInput v-model="f.netbios" class="w-full font-mono" autocomplete="off" maxlength="15" placeholder="AR-SYSTEMS" data-test="auth-netbios" /></UFormField>
        <UAlert v-if="f.ttls" color="warning" variant="subtle" icon="i-lucide-shield-alert" :title="t('radius.auth.ttls_warn_title')" :description="t('radius.auth.ttls_warn')" data-test="auth-ttls-warn" />
        <UAlert color="neutral" variant="subtle" icon="i-lucide-info" :description="t('radius.auth.lockout_note')" />
        <div class="flex flex-wrap items-center justify-between gap-2">
          <p class="text-xs text-muted">{{ t('radius.auth.redeploy') }}</p>
          <UButton type="submit" :loading="saving" :disabled="!loaded" :label="t('common.save')" data-test="auth-save" />
        </div>
      </form>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-link" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.auth.join_title') }}</h2></div><p class="text-sm text-muted mt-1">{{ t('radius.auth.join_desc') }}</p></template>
      <div class="flex flex-col gap-4">
        <div class="flex flex-wrap items-center gap-2" data-test="auth-join-state">
          <UBadge :color="joined ? 'success' : 'neutral'" variant="subtle" :icon="joined ? 'i-lucide-circle-check' : 'i-lucide-circle-dashed'" :label="joined ? t('radius.auth.joined') : t('radius.auth.not_joined')" />
          <template v-if="joined">
            <code>{{ wb.realm }}</code><span class="text-muted text-sm">{{ t('radius.auth.computer') }} <code>{{ wb.computer }}</code></span>
            <span v-if="wb.at" class="text-muted text-sm">· {{ fmt.dateTime(wb.at) }}</span>
            <UBadge v-if="wb.active && wb.trust === true" color="success" variant="subtle" :label="t('radius.auth.trust_ok')" data-test="auth-trust-ok" />
            <UBadge v-else-if="wb.active && wb.trust === false" color="error" variant="subtle" :label="t('radius.auth.trust_ko')" data-test="auth-trust-ko" />
            <UBadge v-else color="neutral" variant="subtle" :label="t('radius.auth.winbind_stopped')" />
          </template>
        </div>
        <UAlert v-if="f.peap && !joined" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('radius.auth.peap_needs_join')" data-test="auth-peap-needs-join" />
        <form v-if="!joined" class="flex flex-col gap-3" autocomplete="off" @submit.prevent="join">
          <div class="grid gap-3 md:grid-cols-2">
            <UFormField :label="t('radius.auth.realm')" :help="t('radius.auth.realm_help')"><UInput v-model="j.realm" class="w-full font-mono" autocomplete="off" placeholder="ar-systems.local" data-test="join-realm" /></UFormField>
            <UFormField :label="t('radius.auth.netbios')"><UInput v-model="j.netbios" class="w-full font-mono" autocomplete="off" maxlength="15" placeholder="AR-SYSTEMS" data-test="join-netbios" /></UFormField>
          </div>
          <UFormField :label="t('radius.auth.servers')" :help="servers.length ? t('radius.auth.servers_help_default', { list: servers.join(', ') }) : t('radius.auth.servers_help')"><UInput v-model="j.servers" class="w-full font-mono" autocomplete="off" data-test="join-servers" /></UFormField>
          <div class="grid gap-3 md:grid-cols-2">
            <UFormField :label="t('radius.auth.join_user')" :help="t('radius.auth.join_user_help')"><UInput v-model="j.user" class="w-full font-mono" autocomplete="off" data-test="join-user" /></UFormField>
            <UFormField :label="t('radius.auth.join_password')"><UInput v-model="j.password" type="password" class="w-full" autocomplete="new-password" data-test="join-password" /></UFormField>
          </div>
          <UAlert color="neutral" variant="subtle" icon="i-lucide-lock" :description="t('radius.auth.join_secret_note')" />
          <div class="flex justify-end"><UButton type="submit" icon="i-lucide-link" :loading="joining" :disabled="!joinReady || pending" :label="t('radius.auth.join')" data-test="join-submit" /></div>
        </form>
        <form v-else class="flex flex-col gap-3" autocomplete="off" @submit.prevent="leave">
          <p class="text-sm text-muted">{{ t('radius.auth.leave_desc') }}</p>
          <div class="grid gap-3 md:grid-cols-2">
            <UFormField :label="t('radius.auth.join_user')" :help="t('radius.auth.leave_user_help')"><UInput v-model="leaveUser" class="w-full font-mono" autocomplete="off" data-test="leave-user" /></UFormField>
            <UFormField :label="t('radius.auth.join_password')"><UInput v-model="leavePw" type="password" class="w-full" autocomplete="new-password" data-test="leave-password" /></UFormField>
          </div>
          <div class="flex justify-end"><UButton type="submit" color="error" variant="outline" icon="i-lucide-unlink" :loading="joining" :disabled="pending || (!!leaveUser !== !!leavePw)" :label="t('radius.auth.leave')" data-test="leave-submit" /></div>
        </form>
        <UAlert v-if="jerr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="jerr" role="alert" data-test="join-error" />
        <UAlert v-if="outcome" :color="outcome.ok ? 'success' : 'error'" variant="subtle" :icon="outcome.ok ? 'i-lucide-circle-check' : 'i-lucide-triangle-alert'" :title="outcome.message" data-test="join-result" />
        <p class="text-xs text-muted">{{ t('radius.auth.per_node') }}</p>
      </div>
    </UCard>
  </div>
</template>
