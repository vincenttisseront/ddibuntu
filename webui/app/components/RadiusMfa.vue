<script setup lang="ts">
// Accès réseau — second facteur (0.17.0) : fournisseur MFA qui vérifie « mot de passe + code à usage unique » pour les clients RADIUS marqués « MFA » (onglet Clients).
// Fournisseur générique : le premier type est l'OAuth2 « mot de passe » (point de jeton). Le secret client n'est jamais relu : on voit seulement s'il existe.
const { t } = useT(); const api = useApi(); const toast = useToast()

const f = reactive({ type: 'oauth2_password', tokenUrl: '', clientId: '', clientSecret: '', secretSet: false, clearSecret: false,
  fIdentity: 'username', fPassword: 'password', fOtp: 'totp', identity: 'typed', otpDigits: 6, timeoutSec: 5, tlsVerify: true, caPem: '', extra: [] as Array<{ name: string; value: string }> })
const clients = ref<string[]>([]), loaded = ref(false), saving = ref(false), error = ref(''), testing = ref(false), probe = ref<any>(null)

async function load() {
  try {
    const m: any = await api.call('GET', '/radius/mfa', undefined, { silent: true })
    Object.assign(f, { type: m.type, tokenUrl: m.tokenUrl, clientId: m.clientId, clientSecret: '', secretSet: !!m.clientSecretSet, clearSecret: false,
      fIdentity: m.fields.identity, fPassword: m.fields.password, fOtp: m.fields.otp, identity: m.identity, otpDigits: m.otpDigits, timeoutSec: m.timeoutSec,
      tlsVerify: m.tlsVerify, caPem: m.caPem ?? '', extra: (m.extra ?? []).map((e: any) => ({ name: e.name, value: e.value })) })
    clients.value = m.clients ?? []
  } catch (e: any) { error.value = e?.info?.message ?? t('err.internal') } finally { loaded.value = true }
}
const body = () => ({
  type: f.type, tokenUrl: f.tokenUrl.trim(), clientId: f.clientId.trim(),
  ...(f.clearSecret ? { clientSecret: '' } : f.clientSecret ? { clientSecret: f.clientSecret } : {}),
  fields: { identity: f.fIdentity.trim(), password: f.fPassword.trim(), otp: f.fOtp.trim() }, identity: f.identity, otpDigits: Number(f.otpDigits),
  extra: f.extra.filter((e) => e.name.trim()).map((e) => ({ name: e.name.trim(), value: e.value.trim() })), timeoutSec: Number(f.timeoutSec), tlsVerify: f.tlsVerify, caPem: f.caPem.trim(),
})
async function save() {
  saving.value = true; error.value = ''
  try {
    await api.call('PUT', '/radius/mfa', body(), { silent: true })
    toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' })
    probe.value = null; await load()
  } catch (e: any) { error.value = e?.info?.message ?? t('err.internal') } finally { saving.value = false }
}
async function test() {
  testing.value = true; error.value = ''; probe.value = null
  try { probe.value = await api.call('POST', '/radius/mfa/test', {}, { silent: true }) } catch (e: any) { error.value = e?.info?.message ?? t('err.internal') } finally { testing.value = false }
}
const probeColor = computed(() => (probe.value?.ok ? 'success' : 'warning'))
const addExtra = () => { if (f.extra.length < 5) f.extra.push({ name: '', value: String() }) }
const identityItems = computed(() => [{ label: t('radius.mfa.identity_typed'), value: 'typed' }, { label: t('radius.mfa.identity_account'), value: 'account' }])
const digitItems = [{ label: '6', value: 6 }, { label: '8', value: 8 }]
onMounted(load)
</script>

<template>
  <div class="flex flex-col gap-4" data-test="radius-mfa">
    <UAlert color="neutral" variant="subtle" icon="i-lucide-shield-check" :title="t('radius.mfa.intro_title')" :description="t('radius.mfa.intro')" />
    <UAlert v-if="!clients.length" color="info" variant="subtle" icon="i-lucide-info" :description="t('radius.mfa.no_clients')" data-test="mfa-no-clients" />
    <p v-else class="text-sm text-muted" data-test="mfa-clients">{{ t('radius.mfa.clients', { list: clients.join(', ') }) }}</p>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-key-square" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.mfa.provider_title') }}</h2></div><p class="text-sm text-muted mt-1">{{ t('radius.mfa.provider_desc') }}</p></template>
      <form class="flex flex-col gap-4" autocomplete="off" @submit.prevent="save">
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" data-test="mfa-error" />
        <UFormField :label="t('radius.mfa.type')" :help="t('radius.mfa.type_help')" class="max-w-md"><USelect v-model="f.type" :items="[{ label: t('radius.mfa.type_oauth2'), value: 'oauth2_password' }]" class="w-full" data-test="mfa-type" /></UFormField>
        <UFormField :label="t('radius.mfa.token_url')" :help="t('radius.mfa.token_url_help')"><UInput v-model="f.tokenUrl" class="w-full font-mono" autocomplete="off" placeholder="https://sso.example.local/realms/corp/protocol/openid-connect/token" data-test="mfa-url" /></UFormField>
        <div class="grid gap-4 md:grid-cols-2">
          <UFormField :label="t('radius.mfa.client_id')" :help="t('radius.mfa.charset_help')"><UInput v-model="f.clientId" class="w-full font-mono" autocomplete="off" placeholder="ddi-radius" data-test="mfa-client-id" /></UFormField>
          <UFormField :label="t('radius.mfa.client_secret')" :help="f.secretSet ? t('radius.mfa.secret_set') : t('radius.mfa.secret_none')">
            <UInput v-model="f.clientSecret" type="password" class="w-full" autocomplete="new-password" :disabled="f.clearSecret" :placeholder="f.secretSet ? '••••••••' : ''" data-test="mfa-client-secret" />
          </UFormField>
        </div>
        <USwitch v-if="f.secretSet" v-model="f.clearSecret" :label="t('radius.mfa.clear_secret')" data-test="mfa-clear-secret" />

        <h3 class="font-medium text-sm">{{ t('radius.mfa.fields_title') }}</h3>
        <p class="text-xs text-muted -mt-2">{{ t('radius.mfa.fields_desc') }}</p>
        <div class="grid gap-4 md:grid-cols-3">
          <UFormField :label="t('radius.mfa.f_identity')"><UInput v-model="f.fIdentity" class="w-full font-mono" autocomplete="off" data-test="mfa-f-identity" /></UFormField>
          <UFormField :label="t('radius.mfa.f_password')"><UInput v-model="f.fPassword" class="w-full font-mono" autocomplete="off" data-test="mfa-f-password" /></UFormField>
          <UFormField :label="t('radius.mfa.f_otp')"><UInput v-model="f.fOtp" class="w-full font-mono" autocomplete="off" data-test="mfa-f-otp" /></UFormField>
        </div>
        <div class="grid gap-4 md:grid-cols-3">
          <UFormField :label="t('radius.mfa.identity')" :help="t('radius.mfa.identity_help')"><USelect v-model="f.identity" :items="identityItems" class="w-full" data-test="mfa-identity" /></UFormField>
          <UFormField :label="t('radius.mfa.digits')" :help="t('radius.mfa.digits_help')"><USelect v-model="f.otpDigits" :items="digitItems" class="w-full" data-test="mfa-digits" /></UFormField>
          <UFormField :label="t('radius.mfa.timeout')" :help="t('radius.mfa.timeout_help')"><UInput v-model.number="f.timeoutSec" type="number" min="2" max="15" class="w-full" data-test="mfa-timeout" /></UFormField>
        </div>

        <div class="flex flex-col gap-2">
          <div class="flex items-center justify-between"><h3 class="font-medium text-sm">{{ t('radius.mfa.extra_title') }}</h3><UButton size="xs" color="neutral" variant="outline" icon="i-lucide-plus" :label="t('radius.mfa.extra_add')" :disabled="f.extra.length >= 5" data-test="mfa-extra-add" @click="addExtra" /></div>
          <p class="text-xs text-muted">{{ t('radius.mfa.extra_desc') }}</p>
          <div v-for="(e, i) in f.extra" :key="i" class="flex gap-2 items-center">
            <UInput v-model="e.name" class="w-40 font-mono" :placeholder="t('radius.mfa.extra_name')" autocomplete="off" :data-test="`mfa-extra-name-${i}`" />
            <UInput v-model="e.value" class="flex-1 font-mono" :placeholder="t('radius.mfa.extra_value')" autocomplete="off" :data-test="`mfa-extra-value-${i}`" />
            <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-x" :aria-label="t('common.delete')" @click="f.extra.splice(i, 1)" />
          </div>
        </div>

        <h3 class="font-medium text-sm">{{ t('radius.mfa.tls_title') }}</h3>
        <USwitch v-model="f.tlsVerify" :label="t('radius.mfa.tls_verify')" data-test="mfa-tls-verify" />
        <UAlert v-if="!f.tlsVerify" color="warning" variant="subtle" icon="i-lucide-shield-alert" :title="t('radius.mfa.tls_off_title')" :description="t('radius.mfa.tls_off')" data-test="mfa-tls-off" />
        <UFormField :label="t('radius.mfa.ca')" :help="t('radius.mfa.ca_help')"><UTextarea v-model="f.caPem" :rows="4" class="w-full font-mono text-xs" autocomplete="off" placeholder="-----BEGIN CERTIFICATE-----" data-test="mfa-ca" /></UFormField>

        <UAlert color="neutral" variant="subtle" icon="i-lucide-info" :description="t('radius.mfa.otp_note')" />
        <div class="flex flex-wrap items-center justify-between gap-2">
          <p class="text-xs text-muted">{{ t('radius.mfa.redeploy') }}</p>
          <div class="flex gap-2">
            <UButton color="neutral" variant="outline" icon="i-lucide-plug-zap" :label="t('radius.mfa.test')" :loading="testing" :disabled="!loaded || !f.tokenUrl" data-test="mfa-test" @click="test" />
            <UButton type="submit" :loading="saving" :disabled="!loaded" :label="t('common.save')" data-test="mfa-save" />
          </div>
        </div>
        <UAlert v-if="probe" :color="(probeColor as any)" variant="subtle" :icon="probe.ok ? 'i-lucide-circle-check' : 'i-lucide-triangle-alert'" :title="t(`radius.mfa.probe_${probe.reason}`, { ms: probe.ms, status: probe.status ?? '' })" data-test="mfa-probe" />
      </form>
    </UCard>
  </div>
</template>
