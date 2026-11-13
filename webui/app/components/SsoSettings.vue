<script setup lang="ts">
// Réglages du SSO OpenID Connect (Entra ID, Keycloak, Okta, Google Workspace, Authentik…)
const { t } = useT(); const api = useApi(); const toast = useToast()
const f = reactive<any>({ enabled: false, issuer: '', clientId: '', clientSecret: '', clearSecret: false, publicUrl: '', scopes: 'openid profile email', usernameClaim: 'preferred_username', groupsClaim: 'groups', defaultRole: null, buttonLabel: '' })
const mapText = ref(''), secretSet = ref(false), callbackUrl = ref(''), busy = ref(false), testing = ref(false), error = ref(''), test = ref<any>(null)
const roleItems = computed(() => [{ label: t('sso.no_default'), value: 'none' }, { label: t('system.role.viewer'), value: 'viewer' }, { label: t('system.role.operator'), value: 'operator' }])
const def = computed({ get: () => f.defaultRole ?? 'none', set: (v: string) => { f.defaultRole = v === 'none' ? null : v } })
async function load() {
  const r: any = await api.call('GET', '/sso/settings')
  Object.assign(f, { enabled: r.enabled, issuer: r.issuer, clientId: r.clientId, clientSecret: '', clearSecret: false, publicUrl: r.publicUrl, scopes: r.scopes, usernameClaim: r.usernameClaim, groupsClaim: r.groupsClaim, defaultRole: r.defaultRole, buttonLabel: r.buttonLabel })
  mapText.value = r.groupMap.map((g: any) => `${g.group} | ${g.role}${g.spaceIds?.length ? ' | ' + g.spaceIds.join(',') : ''}`).join('\n'); secretSet.value = r.clientSecretSet; callbackUrl.value = r.callbackUrl
}
onMounted(load)
const parseMap = () => mapText.value.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
  const [group, role, sp] = l.split('|').map((x) => x.trim()); const spaceIds = (sp ?? '').split(/[\s,;]+/).filter(Boolean).map(Number).filter((n) => Number.isInteger(n) && n > 0)
  return { group, role, ...(spaceIds.length ? { spaceIds } : {}) }
})
async function save() {
  busy.value = true; error.value = ''
  try {
    const b: any = { ...f, groupMap: parseMap() }; if (!b.clientSecret) delete b.clientSecret
    await api.call('PUT', '/sso/settings', b, { silent: true }); toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await load()
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function runTest() {
  testing.value = true; test.value = null; error.value = ''
  try { await save(); if (!error.value) test.value = await api.call('POST', '/sso/test', {}, { silent: true }) } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { testing.value = false }
}
const copy = async (v: string) => { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success', icon: 'i-lucide-check' }) } catch { /* indisponible */ } }
</script>

<template>
  <UCard>
    <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-key-round" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('sso.title') }}</h2></div><p class="text-sm text-muted mt-1">{{ t('sso.desc') }}</p></template>
    <form class="flex flex-col gap-4" @submit.prevent="save">
      <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" />
      <USwitch v-model="f.enabled" :label="t('sso.enabled')" />
      <div class="grid gap-4 md:grid-cols-2">
        <UFormField :label="t('sso.issuer')" :help="t('sso.issuer_help')" required><UInput v-model="f.issuer" placeholder="https://login.microsoftonline.com/<tenant>/v2.0" class="w-full font-mono" /></UFormField>
        <UFormField :label="t('sso.client_id')" required><UInput v-model="f.clientId" class="w-full font-mono" autocomplete="off" /></UFormField>
        <UFormField :label="t('sso.client_secret')" :help="secretSet ? t('sso.secret_set') : t('sso.secret_none')"><UInput v-model="f.clientSecret" type="password" autocomplete="new-password" class="w-full" :placeholder="secretSet ? '••••••••' : ''" /></UFormField>
        <UFormField :label="t('sso.public_url')" :help="t('sso.public_url_help')"><UInput v-model="f.publicUrl" placeholder="https://ddi.exemple.fr" class="w-full font-mono" /></UFormField>
        <UFormField :label="t('sso.scopes')"><UInput v-model="f.scopes" class="w-full font-mono" /></UFormField>
        <UFormField :label="t('sso.button')" :help="t('sso.button_help')"><UInput v-model="f.buttonLabel" :placeholder="t('sso.button_default')" class="w-full" /></UFormField>
        <UFormField :label="t('sso.username_claim')"><UInput v-model="f.usernameClaim" class="w-full font-mono" /></UFormField>
        <UFormField :label="t('sso.groups_claim')"><UInput v-model="f.groupsClaim" class="w-full font-mono" /></UFormField>
      </div>
      <UFormField :label="t('sso.group_map')" :help="t('sso.group_map_help')"><UTextarea v-model="mapText" :rows="4" class="w-full font-mono" placeholder="DDI-Admins | admin&#10;DDI-Paris | operator | 2" /></UFormField>
      <UFormField :label="t('sso.default_role')" :help="t('sso.default_role_help')"><USelect v-model="def" :items="roleItems" class="w-64" /></UFormField>
      <div class="rounded border border-default p-3 text-sm flex flex-col gap-1">
        <span class="text-muted">{{ t('sso.callback') }}</span>
        <button type="button" class="font-mono text-left break-all hover:text-primary" :title="t('common.copy')" @click="copy(callbackUrl)">{{ callbackUrl }}</button>
      </div>
      <UAlert v-if="test" color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('sso.test_ok')" :description="t('sso.test_detail', { issuer: test.issuer, keys: test.keys })" />
      <div class="flex justify-end gap-2">
        <UButton color="neutral" variant="outline" icon="i-lucide-plug-zap" :loading="testing" :disabled="!f.issuer" :label="t('sso.test')" @click="runTest" />
        <UButton type="submit" :loading="busy" :label="t('common.save')" />
      </div>
    </form>
  </UCard>
</template>
