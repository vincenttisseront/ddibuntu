<script setup lang="ts">
// Réglages de la connexion par annuaire LDAP générique (OpenLDAP, FreeIPA, 389-ds, Samba…). Active Directory se règle dans Import / AD.
const { t } = useT(); const api = useApi(); const toast = useToast()
const f = reactive<any>({ enabled: false, urls: '', baseDn: '', bindDn: '', bindPassword: '', clearPassword: false, userFilter: '', userAttr: 'uid', displayAttr: 'cn', groupMode: 'memberOf', groupBaseDn: '', groupFilter: '', tlsRejectUnauthorized: true, caPem: '' })
const mapText = ref(''), pwSet = ref(false), busy = ref(false), testing = ref(false), error = ref(''), test = ref<any>(null), testUser = ref('')
const modes = computed(() => [{ label: t('ldap.mode_memberof'), value: 'memberOf' }, { label: t('ldap.mode_search'), value: 'search' }])
const presets = computed(() => [
  { label: 'OpenLDAP', v: { userFilter: '(&(objectClass=inetOrgPerson)(uid={u}))', userAttr: 'uid', displayAttr: 'cn', groupMode: 'search', groupFilter: '(&(objectClass=groupOfNames)(member={dn}))' } },
  { label: 'FreeIPA', v: { userFilter: '(&(objectClass=posixAccount)(uid={u}))', userAttr: 'uid', displayAttr: 'cn', groupMode: 'memberOf', groupFilter: '(&(objectClass=groupOfNames)(member={dn}))' } },
  { label: '389-ds / Samba', v: { userFilter: '(&(objectClass=person)(uid={u}))', userAttr: 'uid', displayAttr: 'cn', groupMode: 'memberOf', groupFilter: '(&(objectClass=groupOfNames)(member={dn}))' } },
])
async function load() {
  const r: any = await api.call('GET', '/ldap/settings')
  Object.assign(f, { ...r, urls: r.urls.join('\n'), bindPassword: '', clearPassword: false, caPem: r.caPem ?? '' })
  mapText.value = r.groupMap.map((g: any) => `${g.groupDn} | ${g.role}${g.spaceIds?.length ? ' | ' + g.spaceIds.join(',') : ''}`).join('\n'); pwSet.value = r.bindPasswordSet
}
onMounted(load)
const parseMap = () => mapText.value.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
  const i = l.lastIndexOf('|'), parts = l.split('|').map((x) => x.trim())
  const hasSp = parts.length >= 3, sp = hasSp ? parts[parts.length - 1]! : '', roleIdx = hasSp ? parts.length - 2 : parts.length - 1
  void i; const spaceIds = sp.split(/[\s,;]+/).filter(Boolean).map(Number).filter((n) => Number.isInteger(n) && n > 0)
  return { groupDn: parts.slice(0, roleIdx).join('|'), role: parts[roleIdx], ...(spaceIds.length ? { spaceIds } : {}) }
})
async function save() {
  busy.value = true; error.value = ''
  try {
    const b: any = { ...f, urls: String(f.urls).split(/\s+/).filter(Boolean), groupMap: parseMap() }; if (!b.bindPassword) delete b.bindPassword; if (!b.caPem) delete b.caPem
    await api.call('PUT', '/ldap/settings', b, { silent: true }); toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await load()
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function runTest() {
  testing.value = true; test.value = null; error.value = ''
  try { await save(); if (!error.value) test.value = await api.call('POST', '/ldap/test', testUser.value ? { username: testUser.value } : {}, { silent: true }) } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { testing.value = false }
}
</script>

<template>
  <UCard>
    <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-book-user" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('ldap.title') }}</h2></div><p class="text-sm text-muted mt-1">{{ t('ldap.desc') }}</p></template>
    <form class="flex flex-col gap-4" @submit.prevent="save">
      <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" />
      <div class="flex flex-wrap items-center gap-3"><USwitch v-model="f.enabled" :label="t('ldap.enabled')" /><span class="text-xs text-muted ml-auto">{{ t('ldap.presets') }}</span>
        <UButton v-for="p in presets" :key="p.label" size="xs" color="neutral" variant="outline" :label="p.label" @click="Object.assign(f, p.v)" /></div>
      <div class="grid gap-4 md:grid-cols-2">
        <UFormField :label="t('ldap.urls')" :help="t('ldap.urls_help')" required><UTextarea v-model="f.urls" :rows="2" class="w-full font-mono" placeholder="ldaps://ldap.exemple.fr" /></UFormField>
        <UFormField :label="t('ldap.base_dn')" required><UInput v-model="f.baseDn" class="w-full font-mono" placeholder="ou=people,dc=exemple,dc=fr" /></UFormField>
        <UFormField :label="t('ldap.bind_dn')" required><UInput v-model="f.bindDn" class="w-full font-mono" placeholder="cn=ddi-reader,dc=exemple,dc=fr" autocomplete="off" /></UFormField>
        <UFormField :label="t('ldap.bind_pw')" :help="pwSet ? t('ldap.pw_set') : t('ldap.pw_none')"><UInput v-model="f.bindPassword" type="password" autocomplete="new-password" class="w-full" /></UFormField>
        <UFormField :label="t('ldap.user_filter')" :help="t('ldap.user_filter_help')"><UInput v-model="f.userFilter" class="w-full font-mono" /></UFormField>
        <div class="grid grid-cols-2 gap-4"><UFormField :label="t('ldap.user_attr')"><UInput v-model="f.userAttr" class="w-full font-mono" /></UFormField><UFormField :label="t('ldap.display_attr')"><UInput v-model="f.displayAttr" class="w-full font-mono" /></UFormField></div>
        <UFormField :label="t('ldap.group_mode')"><USelect v-model="f.groupMode" :items="modes" class="w-full" /></UFormField>
        <UFormField v-if="f.groupMode === 'search'" :label="t('ldap.group_base')" :help="t('ldap.group_base_help')"><UInput v-model="f.groupBaseDn" class="w-full font-mono" placeholder="ou=groups,dc=exemple,dc=fr" /></UFormField>
        <UFormField v-if="f.groupMode === 'search'" :label="t('ldap.group_filter')" :help="t('ldap.group_filter_help')" class="md:col-span-2"><UInput v-model="f.groupFilter" class="w-full font-mono" /></UFormField>
      </div>
      <UFormField :label="t('ldap.group_map')" :help="t('ldap.group_map_help')"><UTextarea v-model="mapText" :rows="4" class="w-full font-mono" placeholder="cn=ddi-admins,ou=groups,dc=exemple,dc=fr | admin&#10;cn=ddi-paris,ou=groups,dc=exemple,dc=fr | operator | 2" /></UFormField>
      <div class="grid gap-4 md:grid-cols-2">
        <USwitch v-model="f.tlsRejectUnauthorized" :label="t('ldap.tls_verify')" />
        <UFormField :label="t('ldap.ca')" :help="t('ldap.ca_help')"><UTextarea v-model="f.caPem" :rows="2" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" /></UFormField>
      </div>
      <UAlert v-if="test" :color="test.ok ? 'success' : 'warning'" variant="subtle" :icon="test.ok ? 'i-lucide-circle-check' : 'i-lucide-triangle-alert'" :title="test.ok ? t('ldap.test_ok') : t('ldap.test_ko', { step: test.step })" :description="test.step === 'search' ? t('ldap.test_found', { n: test.found }) : (test.server ?? '')" />
      <div class="flex flex-wrap items-end justify-end gap-2">
        <UFormField :label="t('ldap.test_user')" class="w-56"><UInput v-model="testUser" class="w-full" autocomplete="off" /></UFormField>
        <UButton color="neutral" variant="outline" icon="i-lucide-plug-zap" :loading="testing" :disabled="!f.urls || !f.baseDn" :label="t('ldap.test')" @click="runTest" />
        <UButton type="submit" :loading="busy" :label="t('common.save')" />
      </div>
    </form>
  </UCard>
</template>
