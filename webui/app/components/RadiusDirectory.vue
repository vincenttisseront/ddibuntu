<script setup lang="ts">
// Accès réseau — annuaire Active Directory du service RADIUS (0.13.1, itération 2). Liaison LDAPS en LECTURE SEULE avec un compte de service :
// réglages, test de liaison serveur par serveur, vérification d'un compte (état + groupes directs et imbriqués) et recherche de groupes.
// Rien n'est écrit dans l'annuaire ; le mot de passe de liaison est chiffré côté serveur et n'est jamais renvoyé. Les règles d'accès viennent ensuite.
const { t } = useT(); const api = useApi(); const toast = useToast(); const fmt = useFmt()

// ---- Réglages ----
const f = reactive({ urls: '', baseDn: '', bindDn: '', bindPassword: '', clearPassword: false, tlsRejectUnauthorized: true, caPem: '' })
const pwSet = ref(false), loaded = ref(false), saving = ref(false), testing = ref(false), error = ref(''), test = ref<any>(null)
const urlList = () => f.urls.split(/\s+/).filter(Boolean)
const complete = computed(() => urlList().length > 0 && !!f.baseDn.trim() && !!f.bindDn.trim() && (pwSet.value ? !f.clearPassword : !!f.bindPassword))
async function load() {
  try {
    const r: any = await api.call('GET', '/radius/directory', undefined, { silent: true })
    Object.assign(f, { urls: r.urls.join('\n'), baseDn: r.baseDn, bindDn: r.bindDn, bindPassword: '', clearPassword: false, tlsRejectUnauthorized: r.tlsRejectUnauthorized, caPem: r.caPem ?? '' })
    pwSet.value = !!r.bindPasswordSet
  } catch (e: any) { error.value = e?.info?.message ?? t('err.internal') } finally { loaded.value = true }
}
async function save(quiet = false): Promise<boolean> {
  saving.value = true; error.value = ''
  try {
    const b: any = { urls: urlList(), baseDn: f.baseDn.trim(), bindDn: f.bindDn.trim(), tlsRejectUnauthorized: f.tlsRejectUnauthorized, clearPassword: f.clearPassword }
    if (f.bindPassword) b.bindPassword = f.bindPassword
    if (f.caPem.trim()) b.caPem = f.caPem.trim() + '\n'
    await api.call('PUT', '/radius/directory', b, { silent: true })
    if (!quiet) toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' })
    await load(); return true
  } catch (e: any) { error.value = e?.info?.message ?? t('err.internal'); return false } finally { saving.value = false }
}
async function runTest() {   // enregistre puis teste : le serveur teste toujours les réglages ENREGISTRÉS
  testing.value = true; test.value = null
  try { if (await save(true)) test.value = await api.call('POST', '/radius/directory/test', {}, { silent: true }) }
  catch (e: any) { error.value = e?.info?.message ?? t('err.internal') } finally { testing.value = false }
}

// ---- Vérification d'un compte ----
const kind = ref<'user' | 'computer'>('user'), name = ref(''), looking = ref(false), lookErr = ref(''), account = ref<any>(null)
const kinds = computed(() => [{ label: t('radius.dir.kind_user'), value: 'user' }, { label: t('radius.dir.kind_computer'), value: 'computer' }])
async function lookup() {
  if (!name.value.trim() || looking.value) return
  looking.value = true; lookErr.value = ''; account.value = null
  try { account.value = await api.call('POST', '/radius/directory/lookup', { kind: kind.value, name: name.value.trim() }, { silent: true }) }
  catch (e: any) { lookErr.value = e?.info?.message ?? t('err.internal') } finally { looking.value = false }
}
const stateBadges = computed(() => {
  const s = account.value?.state
  if (!s) return []
  return [
    s.reasons.includes('unreadable') ? { key: 'unreadable', color: 'warning', icon: 'i-lucide-eye-off' } : s.enabled ? { key: 'enabled', color: 'success', icon: 'i-lucide-circle-check' } : { key: 'disabled', color: 'error', icon: 'i-lucide-ban' },
    s.locked ? { key: 'locked', color: 'error', icon: 'i-lucide-lock' } : { key: 'unlocked', color: 'neutral', icon: 'i-lucide-lock-open' },
    s.expired ? { key: 'expired', color: 'error', icon: 'i-lucide-calendar-x' } : { key: 'valid', color: 'neutral', icon: 'i-lucide-calendar-check' },
  ]
})
const expiry = computed(() => { const s = account.value?.state; return !s || s.expiresAt === null ? t('radius.dir.never') : fmt.dateTime(s.expiresAt) })

// ---- Recherche de groupes ----
const gq = ref(''), searching = ref(false), gErr = ref(''), found = ref<any>(null)
async function searchGroups() {
  const q = gq.value.trim()
  if (q.length < 2 || searching.value) return
  searching.value = true; gErr.value = ''; found.value = null
  try { found.value = await api.call('GET', `/radius/directory/groups?q=${encodeURIComponent(q)}`, undefined, { silent: true }) }
  catch (e: any) { gErr.value = e?.info?.message ?? t('err.internal') } finally { searching.value = false }
}
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
onMounted(load)
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('radius.dir.intro') }}</p>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-network" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.dir.conn_title') }}</h2><UBadge color="neutral" variant="subtle" icon="i-lucide-eye" :label="t('radius.dir.read_only')" class="ml-auto" /></div></template>
      <form class="flex flex-col gap-4" @submit.prevent="save()">
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" data-test="dir-error" />
        <div class="grid gap-4 md:grid-cols-2">
          <UFormField :label="t('radius.dir.urls')" :help="t('radius.dir.urls_help')" required><UTextarea v-model="f.urls" :rows="2" class="w-full font-mono" placeholder="ldaps://dc1.exemple.fr&#10;ldaps://dc2.exemple.fr" data-test="dir-urls" /></UFormField>
          <UFormField :label="t('radius.dir.base_dn')" :help="t('radius.dir.base_dn_help')" required><UInput v-model="f.baseDn" class="w-full font-mono" placeholder="DC=exemple,DC=fr" autocomplete="off" data-test="dir-basedn" /></UFormField>
          <UFormField :label="t('radius.dir.bind_dn')" :help="t('radius.dir.bind_dn_help')" required><UInput v-model="f.bindDn" class="w-full font-mono" placeholder="svc-radius@exemple.fr" autocomplete="off" data-test="dir-binddn" /></UFormField>
          <UFormField :label="t('radius.dir.bind_pw')" :help="pwSet && !f.clearPassword ? t('radius.dir.pw_set') : t('radius.dir.pw_none')">
            <UInput v-model="f.bindPassword" type="password" autocomplete="new-password" class="w-full" :disabled="f.clearPassword" data-test="dir-pw" />
            <UCheckbox v-if="pwSet" v-model="f.clearPassword" :label="t('radius.dir.pw_clear')" class="mt-2" data-test="dir-pw-clear" />
          </UFormField>
        </div>
        <div class="grid gap-4 md:grid-cols-2">
          <div class="flex flex-col gap-2">
            <USwitch v-model="f.tlsRejectUnauthorized" :label="t('radius.dir.tls_verify')" data-test="dir-tls" />
            <UAlert v-if="!f.tlsRejectUnauthorized" color="warning" variant="subtle" icon="i-lucide-shield-alert" :title="t('radius.dir.tls_off_title')" :description="t('radius.dir.tls_off_body')" data-test="dir-tls-warn" />
          </div>
          <UFormField :label="t('radius.dir.ca')" :help="t('radius.dir.ca_help')"><UTextarea v-model="f.caPem" :rows="3" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" data-test="dir-ca" /></UFormField>
        </div>
        <UAlert color="neutral" variant="subtle" icon="i-lucide-info" :description="t('radius.dir.lockout_note')" />
        <template v-if="test">
          <UAlert :color="test.ok ? 'success' : 'warning'" variant="subtle" :icon="test.ok ? 'i-lucide-circle-check' : 'i-lucide-triangle-alert'" :title="test.ok ? t('radius.dir.test_ok') : t('radius.dir.test_ko')" data-test="dir-test-result">
            <template #description>
              <ul class="text-sm flex flex-col gap-1 mt-1">
                <li v-for="a in test.attempts" :key="a.server" class="flex flex-wrap items-center gap-2" data-test="dir-attempt">
                  <UIcon :name="a.ok ? 'i-lucide-check' : 'i-lucide-x'" class="size-4" /><code>{{ a.server }}</code>
                  <span>{{ a.ok ? t('radius.dir.attempt_ok') : t(`radius.dir.reason.${a.reason}`) }}</span>
                </li>
              </ul>
            </template>
          </UAlert>
        </template>
        <div class="flex flex-wrap justify-end gap-2">
          <UButton color="neutral" variant="outline" icon="i-lucide-plug-zap" :loading="testing" :disabled="!complete || saving" :label="t('radius.dir.test')" data-test="dir-test" @click="runTest" />
          <UButton type="submit" :loading="saving && !testing" :disabled="testing" :label="t('common.save')" data-test="dir-save" />
        </div>
      </form>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-user-search" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.dir.lookup_title') }}</h2></div><p class="text-sm text-muted mt-1">{{ t('radius.dir.lookup_desc') }}</p></template>
      <form class="flex flex-col gap-4" @submit.prevent="lookup">
        <div class="flex flex-wrap items-end gap-3">
          <UFormField :label="t('radius.dir.kind')"><URadioGroup v-model="kind" :items="kinds" orientation="horizontal" data-test="dir-kind" /></UFormField>
          <UFormField :label="kind === 'user' ? t('radius.dir.name_user') : t('radius.dir.name_computer')" class="flex-1 min-w-56"><UInput v-model="name" class="w-full font-mono" autocomplete="off" :placeholder="kind === 'user' ? 'alice  /  alice@exemple.fr' : 'PC001  /  pc001.exemple.fr'" data-test="dir-name" /></UFormField>
          <UButton type="submit" icon="i-lucide-search" :loading="looking" :disabled="!name.trim()" :label="t('radius.dir.check')" data-test="dir-lookup" />
        </div>
        <UAlert v-if="lookErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="lookErr" role="alert" data-test="dir-lookup-error" />
        <UAlert v-else-if="account && !account.found" color="warning" variant="subtle" icon="i-lucide-search-x" :title="account.ambiguous ? t('radius.dir.ambiguous') : t('radius.dir.not_found')" data-test="dir-notfound" />
        <div v-else-if="account?.found" class="flex flex-col gap-4" data-test="dir-account">
          <div class="flex flex-wrap items-center gap-2">
            <UBadge :color="account.state.usable ? 'success' : 'error'" variant="solid" :icon="account.state.usable ? 'i-lucide-badge-check' : 'i-lucide-badge-x'" :label="account.state.usable ? t('radius.dir.usable') : t('radius.dir.unusable')" data-test="dir-usable" />
            <UBadge v-for="b in stateBadges" :key="b.key" :color="(b.color as any)" variant="subtle" :icon="b.icon" :label="t(`radius.dir.st.${b.key}`)" :data-test="`dir-st-${b.key}`" />
          </div>
          <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <div><dt class="text-muted">{{ t('radius.dir.f_display') }}</dt><dd>{{ account.displayName || '—' }}</dd></div>
            <div><dt class="text-muted">{{ t('radius.dir.f_sam') }}</dt><dd class="font-mono">{{ account.sam }}</dd></div>
            <div v-if="account.upn"><dt class="text-muted">{{ t('radius.dir.f_upn') }}</dt><dd class="font-mono">{{ account.upn }}</dd></div>
            <div v-if="account.dnsHostName"><dt class="text-muted">{{ t('radius.dir.f_dns') }}</dt><dd class="font-mono">{{ account.dnsHostName }}</dd></div>
            <div><dt class="text-muted">{{ t('radius.dir.f_expires') }}</dt><dd>{{ expiry }}</dd></div>
            <div><dt class="text-muted">{{ t('radius.dir.f_server') }}</dt><dd class="font-mono">{{ account.server }}</dd></div>
            <div class="sm:col-span-2"><dt class="text-muted">{{ t('radius.dir.f_dn') }}</dt><dd class="font-mono break-all">{{ account.dn }}</dd></div>
          </dl>
          <div>
            <h3 class="text-sm font-medium mb-1">{{ t('radius.dir.groups') }} <span class="text-muted font-normal">({{ account.groups.length }})</span></h3>
            <p v-if="!account.groups.length" class="text-sm text-muted">{{ t('radius.dir.groups_none') }}</p>
            <ul v-else class="flex flex-col divide-y divide-default border border-default rounded-md text-sm" data-test="dir-groups">
              <li v-for="g in account.groups" :key="g.dn" class="flex flex-wrap items-center gap-2 px-3 py-1.5" data-test="dir-group">
                <span class="font-mono">{{ g.name }}</span>
                <UBadge :color="g.direct ? 'primary' : 'neutral'" variant="subtle" size="sm" :label="g.direct ? t('radius.dir.direct') : t('radius.dir.nested')" />
                <span class="text-xs text-dimmed font-mono break-all ml-auto">{{ g.dn }}</span>
              </li>
            </ul>
            <UAlert v-if="account.groupsTruncated" color="warning" variant="subtle" icon="i-lucide-list-end" :title="t('radius.dir.groups_truncated')" class="mt-2" data-test="dir-groups-truncated" />
            <p class="text-xs text-dimmed mt-2">{{ t('radius.dir.primary_note') }}</p>
          </div>
        </div>
      </form>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-users" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.dir.g_title') }}</h2></div><p class="text-sm text-muted mt-1">{{ t('radius.dir.g_desc') }}</p></template>
      <form class="flex flex-col gap-3" @submit.prevent="searchGroups">
        <div class="flex flex-wrap items-end gap-3">
          <UFormField :label="t('radius.dir.g_q')" :help="t('radius.dir.g_q_help')" class="flex-1 min-w-56"><UInput v-model="gq" class="w-full font-mono" autocomplete="off" placeholder="wifi" data-test="dir-gq" /></UFormField>
          <UButton type="submit" icon="i-lucide-search" :loading="searching" :disabled="gq.trim().length < 2" :label="t('common.search')" data-test="dir-gsearch" />
        </div>
        <UAlert v-if="gErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="gErr" role="alert" data-test="dir-g-error" />
        <template v-else-if="found">
          <p v-if="!found.groups.length" class="text-sm text-muted" data-test="dir-g-none">{{ t('radius.dir.g_none') }}</p>
          <ul v-else class="flex flex-col divide-y divide-default border border-default rounded-md text-sm" data-test="dir-g-list">
            <li v-for="g in found.groups" :key="g.dn" class="flex flex-wrap items-center gap-2 px-3 py-1.5" data-test="dir-g-item">
              <span class="font-mono font-medium">{{ g.name }}</span><span v-if="g.description" class="text-muted">{{ g.description }}</span>
              <span class="text-xs text-dimmed font-mono break-all ml-auto">{{ g.dn }}</span>
              <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-copy" :aria-label="t('radius.dir.copy_dn')" :title="t('radius.dir.copy_dn')" @click="copy(g.dn)" />
            </li>
          </ul>
          <UAlert v-if="found.truncated" color="warning" variant="subtle" icon="i-lucide-list-end" :title="t('radius.dir.g_truncated')" data-test="dir-g-truncated" />
        </template>
      </form>
    </UCard>
  </div>
</template>
