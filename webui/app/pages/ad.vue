<script setup lang="ts">
// Active Directory : Kerberos / GSS-TSIG (mises à jour DNS sécurisées) et redirecteurs conditionnels.
// La console ne détient ni le domaine officiel ni le keytab : elle dépose une demande que root (ddibuntu-ad) revalide, puis relit son état.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const { isAdmin, canWrite } = useRole()
const info = ref<any>(null), loading = ref(true), error = ref('')
async function load(silent = false) {
  try { info.value = await api.call('GET', '/ad/kerberos', undefined, { silent }); error.value = '' }
  catch (e: any) { if (!silent) error.value = e.info?.message ?? t('err.internal') }
  finally { loading.value = false }
}
onMounted(() => load())
const st = computed(() => info.value?.state ?? null)
const kt = computed(() => st.value?.keytab ?? null)
const fmt = useFmt()
const when = (s?: number | null) => (s ? fmt.dateTime(s * 1000) : '—')

// ---- Demandes à root : on attend son résultat (traitement asynchrone, quelques secondes) ----
const working = ref('')
async function request(kind: string, call: () => Promise<any>, okMsg: string) {
  error.value = ''; working.value = kind
  try {
    const acc = await call()
    let res: any = null
    for (let i = 0; i < 40 && !res; i++) {
      await new Promise((r) => setTimeout(r, 1500)); await load(true)
      const r = info.value?.result
      if (r && r.at >= acc.requestedAt && !info.value?.pending) res = r
    }
    if (!res) toast.add({ title: t('ad.krb.timeout'), color: 'warning', icon: 'i-lucide-clock-alert' })
    else toast.add({ title: res.ok ? okMsg : t('ad.krb.failed'), description: res.ok ? undefined : res.message, color: res.ok ? 'success' : 'error', icon: res.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
    return !!res?.ok
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal'); return false }
  finally { working.value = ''; void load(true) }
}

// Domaine Kerberos
const cfgOpen = ref(false), cfgRealm = ref(''), cfgKdcs = ref('')
function openConfig() { cfgRealm.value = st.value?.realm ?? ''; cfgKdcs.value = (st.value?.kdcs ?? []).join('\n'); cfgOpen.value = true }
async function saveConfig() {
  const kdcs = cfgKdcs.value.split(/[\s,;]+/).filter(Boolean)
  const ok = await request('config', () => api.call('PUT', '/ad/kerberos/config', { realm: cfgRealm.value.trim().toUpperCase(), kdcs }, { busy: true }), t('ad.krb.config_done'))
  if (ok) cfgOpen.value = false
}
// Keytab (secret) : lu dans le navigateur, envoyé une fois, jamais affiché ni renvoyé
const ktOpen = ref(false), ktFile = ref<File | null>(null)
function pickKeytab(e: Event) { ktFile.value = (e.target as HTMLInputElement).files?.[0] ?? null }
async function saveKeytab() {
  if (!ktFile.value) return
  if (ktFile.value.size > 65536) { error.value = t('err.invalid_keytab'); return }
  const buf = new Uint8Array(await ktFile.value.arrayBuffer())
  let bin = ''; for (const b of buf) bin += String.fromCharCode(b)
  const ok = await request('keytab', () => api.call('PUT', '/ad/kerberos/keytab', { keytab: btoa(bin) }, { busy: true }), t('ad.krb.keytab_done'))
  if (ok) { ktOpen.value = false; ktFile.value = null }
}
const testKrb = () => request('test', () => api.call('POST', '/ad/kerberos/test', {}, { busy: true }), t('ad.krb.test_ok'))
async function removeKrb() {
  if (!(await ask(t('ad.krb.remove_title'), t('ad.krb.remove_body', { n: info.value?.secureZones?.length ?? 0 }), true))) return
  await request('remove', () => api.call('DELETE', '/ad/kerberos', undefined, { busy: true }), t('ad.krb.remove_done'))
}
const ktState = computed(() => (!st.value?.configured ? 'none' : kt.value?.present ? 'ok' : 'missing'))

// ---- Redirecteurs conditionnels ----
const fwDomain = ref(''), fwServers = ref(''), fwBusy = ref(''), fwCheck = ref<any>(null)
const fwList = () => fwServers.value.split(/[\s,;]+/).filter(Boolean)
async function checkForwarders() {
  error.value = ''; fwBusy.value = 'check'; fwCheck.value = null
  try { fwCheck.value = await api.call('POST', '/ad/forwarders/check', { domain: fwDomain.value.trim(), servers: fwList() }, { busy: true }) }
  catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { fwBusy.value = '' }
}
async function applyForwarders() {
  if (fwCheck.value && !fwCheck.value.adDetected && !(await ask(t('ad.fw.noad_title'), t('ad.fw.noad_body'), false))) return
  error.value = ''; fwBusy.value = 'apply'
  try {
    const r = await api.call('POST', '/ad/forwarders/apply', { domain: fwDomain.value.trim(), servers: fwList() }, { busy: true })
    toast.add({ title: r.created ? t('ad.fw.created') : t('ad.fw.updated'), description: t('ad.fw.deploy_hint'), color: 'success', icon: 'i-lucide-check' })
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { fwBusy.value = '' }
}
</script>

<template>
  <div class="flex flex-col gap-4 max-w-5xl">
    <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" />
    <div v-if="loading" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader" class="animate-spin" />{{ t('cluster.loading') }}</div>
    <template v-else>
      <UCard>
        <template #header>
          <div class="flex items-center justify-between gap-2">
            <span class="font-medium">{{ t('ad.krb.title') }}</span>
            <span v-if="working" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader" class="animate-spin" />{{ t('ad.krb.working') }}</span>
          </div>
        </template>
        <p class="text-sm text-muted mb-3">{{ t('ad.krb.intro') }}</p>
        <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt class="text-muted">{{ t('ad.krb.realm') }}</dt>
          <dd><span v-if="st?.configured" class="font-mono">{{ st.realm }}</span><span v-else class="text-muted">{{ t('ad.krb.not_configured') }}</span></dd>
          <dt class="text-muted">{{ t('ad.krb.kdcs') }}</dt>
          <dd><span v-if="st?.kdcs?.length" class="font-mono">{{ st.kdcs.join(', ') }}</span><span v-else class="text-muted">{{ st?.configured ? t('ad.krb.kdc_dns') : '—' }}</span></dd>
          <dt class="text-muted">{{ t('ad.krb.keytab') }}</dt>
          <dd>
            <UBadge :color="ktState === 'ok' ? 'success' : ktState === 'missing' ? 'warning' : 'neutral'" variant="subtle" :label="t(`ad.krb.kt.${ktState}`)" />
          </dd>
          <template v-if="kt?.present">
            <dt class="text-muted">{{ t('ad.krb.principals') }}</dt>
            <dd class="font-mono break-all"><div v-for="p in kt.principals" :key="p">{{ p }} <span class="text-muted">(kvno {{ kt.kvno[p] }})</span></div></dd>
            <dt class="text-muted">{{ t('ad.krb.enctypes') }}</dt><dd class="font-mono">{{ kt.enctypes.join(', ') }}</dd>
            <dt class="text-muted">{{ t('ad.krb.installed') }}</dt><dd>{{ when(kt.mtime) }}</dd>
          </template>
          <template v-if="info?.sync">
            <dt class="text-muted">{{ t('ad.krb.sync') }}</dt>
            <dd class="flex items-center gap-2 flex-wrap">
              <UBadge :color="info.sync.state === 'failed' ? 'error' : 'success'" variant="subtle" :label="t(`ad.krb.sync_${info.sync.state}`)" />
              <span class="text-muted text-xs">{{ when(info.sync.at) }}<template v-if="info.sync.state === 'failed' && info.sync.message"> · {{ info.sync.message }}</template></span>
            </dd>
          </template>
          <dt class="text-muted">{{ t('ad.krb.zones') }}</dt>
          <dd><span v-if="info?.secureZones?.length" class="font-mono">{{ info.secureZones.map((z: any) => z.name).join(', ') }}</span><span v-else class="text-muted">{{ t('ad.krb.zones_none') }}</span></dd>
        </dl>
        <div v-if="isAdmin" class="flex flex-wrap gap-2 mt-4">
          <UButton size="sm" icon="i-lucide-settings-2" :label="t('ad.krb.configure')" :disabled="!!working" @click="openConfig" />
          <UButton size="sm" color="neutral" variant="outline" icon="i-lucide-key-round" :label="t('ad.krb.install_keytab')" :disabled="!!working || !st?.configured" @click="ktOpen = true" />
          <UButton size="sm" color="neutral" variant="outline" icon="i-lucide-plug-zap" :label="t('ad.krb.test')" :loading="working === 'test'" :disabled="!!working || ktState !== 'ok'" @click="testKrb" />
          <UButton size="sm" color="error" variant="outline" icon="i-lucide-trash-2" :label="t('ad.krb.remove')" :disabled="!!working || !st?.configured" @click="removeKrb" />
        </div>
        <p v-else class="text-xs text-muted mt-3">{{ t('ad.krb.admin_only') }}</p>
        <details class="mt-4 text-sm">
          <summary class="cursor-pointer text-muted">{{ t('ad.krb.howto_title') }}</summary>
          <p class="mt-2 text-muted">{{ t('ad.krb.howto') }}</p>
          <pre class="mt-2 p-2 rounded bg-elevated text-xs overflow-x-auto">ktpass -princ DNS/ddi1.corp.local@CORP.LOCAL -mapuser ddi1-dns$ -pass * ^
  -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -out dns.keytab</pre>
          <p class="mt-2 text-muted">{{ t('ad.krb.howto_zone') }}</p>
        </details>
      </UCard>

      <UCard>
        <template #header><span class="font-medium">{{ t('ad.fw.title') }}</span></template>
        <p class="text-sm text-muted mb-3">{{ t('ad.fw.intro') }}</p>
        <div class="grid gap-3 md:grid-cols-2">
          <UFormField :label="t('ad.fw.domain')" :hint="t('ad.fw.domain_hint')"><UInput v-model="fwDomain" class="w-full font-mono" placeholder="corp.local" :disabled="!canWrite" /></UFormField>
          <UFormField :label="t('ad.fw.servers')" :hint="t('ad.fw.servers_hint')"><UInput v-model="fwServers" class="w-full font-mono" placeholder="10.0.0.10, 10.0.0.11" :disabled="!canWrite" /></UFormField>
        </div>
        <div v-if="canWrite" class="flex flex-wrap gap-2 mt-3">
          <UButton size="sm" color="neutral" variant="outline" icon="i-lucide-search-check" :label="t('ad.fw.check')" :loading="fwBusy === 'check'" :disabled="!!fwBusy || !fwDomain || !fwList().length" @click="checkForwarders" />
          <UButton size="sm" icon="i-lucide-corner-down-right" :label="t('ad.fw.apply')" :loading="fwBusy === 'apply'" :disabled="!!fwBusy || !fwDomain || !fwList().length" @click="applyForwarders" />
        </div>
        <div v-if="fwCheck" class="mt-4">
          <UAlert :color="fwCheck.adDetected ? 'success' : 'warning'" variant="subtle" :icon="fwCheck.adDetected ? 'i-lucide-check' : 'i-lucide-triangle-alert'" :title="fwCheck.adDetected ? t('ad.fw.detected') : t('ad.fw.not_detected')" />
          <table class="w-full text-sm mt-3">
            <thead><tr class="text-left text-muted"><th class="py-1 pr-4">{{ t('ad.fw.server') }}</th><th class="pr-4">SOA</th><th class="pr-4">LDAP</th><th class="pr-4">Kerberos</th><th>ms</th></tr></thead>
            <tbody>
              <tr v-for="r in fwCheck.results" :key="r.server" class="border-t border-default">
                <td class="py-1.5 pr-4 font-mono">{{ r.server }}</td>
                <td class="pr-4"><UBadge v-if="r.soa" color="success" variant="subtle" :label="r.soa.mname" /><UBadge v-else color="error" variant="subtle" :label="r.error || t('ad.fw.no_answer')" /></td>
                <td class="pr-4 font-mono">{{ r.ldap.length ? r.ldap.join(', ') : '—' }}</td>
                <td class="pr-4 font-mono">{{ r.kerberos.length ? r.kerberos.join(', ') : '—' }}</td>
                <td class="font-mono">{{ r.ms }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </UCard>
    </template>

    <UModal v-model:open="cfgOpen" :title="t('ad.krb.configure')" :description="t('ad.krb.config_desc')">
      <template #body>
        <div class="flex flex-col gap-3">
          <UFormField :label="t('ad.krb.realm')" :hint="t('ad.krb.realm_hint')"><UInput v-model="cfgRealm" class="w-full font-mono" placeholder="CORP.LOCAL" /></UFormField>
          <UFormField :label="t('ad.krb.kdcs')" :hint="t('ad.krb.kdcs_hint')"><UTextarea v-model="cfgKdcs" :rows="3" class="w-full font-mono" placeholder="dc1.corp.local&#10;dc2.corp.local" /></UFormField>
        </div>
      </template>
      <template #footer>
        <div class="flex justify-end gap-2 w-full">
          <UButton color="neutral" variant="outline" :label="t('common.cancel')" :disabled="working === 'config'" @click="cfgOpen = false" />
          <UButton :label="t('common.save')" :loading="working === 'config'" :disabled="!cfgRealm.trim() || working === 'config'" @click="saveConfig" />
        </div>
      </template>
    </UModal>
    <UModal v-model:open="ktOpen" :title="t('ad.krb.install_keytab')" :description="t('ad.krb.keytab_desc')">
      <template #body>
        <UFormField :label="t('ad.krb.keytab_file')" :hint="t('ad.krb.keytab_hint')"><input type="file" class="block w-full text-sm" :aria-label="t('ad.krb.keytab_file')" @change="pickKeytab"></UFormField>
      </template>
      <template #footer>
        <div class="flex justify-end gap-2 w-full">
          <UButton color="neutral" variant="outline" :label="t('common.cancel')" :disabled="working === 'keytab'" @click="ktOpen = false" />
          <UButton :label="t('ad.krb.install')" :loading="working === 'keytab'" :disabled="!ktFile || working === 'keytab'" @click="saveKeytab" />
        </div>
      </template>
    </UModal>
  </div>
</template>
