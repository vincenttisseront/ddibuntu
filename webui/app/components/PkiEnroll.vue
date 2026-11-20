<script setup lang="ts">
// Postes du domaine (0.18.0) : la PKI du DDI émet le certificat EAP-TLS de chaque poste. Le poste génère sa clé, s'authentifie en Kerberos avec son compte machine
// et reçoit son certificat ; la console ne voit que la demande. Cette page règle le service, dépose le keytab (chiffré en base, jamais renvoyé), donne le script à déployer par GPO
// et montre l'activité. Les certificats émis se listent dans « Certificats » (profil « machine »).
const props = defineProps<{ status: any; waiting: boolean }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()

const data = ref<any>(null), err = ref(''), saving = ref(false), loaded = ref(false), keytabBusy = ref(false)
const f = reactive({ enabled: false, ca: '', host: '', groupDn: '', minIntervalSec: 300, maxPerDay: 6, maxPerMinute: 30 })
const errOf = (e: any) => e?.info?.message ?? t('err.internal')
const ready = computed(() => props.status?.state === 'healthy')

// Commandes de création du compte de service et d'export du keytab : le nom de la console vient du formulaire, le domaine est déduit du DN du groupe
const SVC = 'svc-ddi-enroll'
const cmdHost = computed(() => f.host.trim().toLowerCase() || 'ddi.example.org')
const cmdDomain = computed(() => [...f.groupDn.matchAll(/(?:^|,)\s*DC=([^,]+)/gi)].map((m) => m[1]!.trim().toLowerCase()).join('.') || 'example.org')
const cmdRealm = computed(() => cmdDomain.value.toUpperCase())
const cmdBaseDn = computed(() => cmdDomain.value.split('.').map((x) => `DC=${x}`).join(','))
const cmdWindows = computed(() => [
  `# ${t('enroll.cmd_c_create')}`,
  `New-ADUser -Name ${SVC} -SamAccountName ${SVC} -AccountPassword (Read-Host -AsSecureString 'Mot de passe temporaire') -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true`,
  `# ${t('enroll.cmd_c_aes')}`,
  `Set-ADUser ${SVC} -KerberosEncryptionType AES128,AES256`,
  `# ${t('enroll.cmd_c_spn')}`,
  `setspn -S HTTP/${cmdHost.value} ${SVC}`,
  `# ${t('enroll.cmd_c_export_win')}`,
  `ktpass /out C:\\Temp\\ddi-enroll.keytab /princ HTTP/${cmdHost.value}@${cmdRealm.value} /mapuser ${SVC}@${cmdDomain.value} /mapop set /ptype KRB5_NT_PRINCIPAL /crypto AES256-SHA1 +rndpass -setupn`,
].join('\n'))
const cmdSamba = computed(() => [
  `# ${t('enroll.cmd_c_create')}`,
  `samba-tool user create ${SVC} "$(openssl rand -base64 24)"`,
  `samba-tool spn add HTTP/${cmdHost.value} ${SVC}`,
  `# ${t('enroll.cmd_c_aes_samba')}`,
  `ldapmodify -H ldaps://dc1.${cmdDomain.value} -D administrator@${cmdDomain.value} -W <<'EOF'`,
  `dn: CN=${SVC},CN=Users,${cmdBaseDn.value}`,
  `changetype: modify`,
  `replace: msDS-SupportedEncryptionTypes`,
  `msDS-SupportedEncryptionTypes: 24`,
  `EOF`,
  `samba-tool user setpassword ${SVC} --newpassword="$(openssl rand -base64 24)"`,
  `# ${t('enroll.cmd_c_export_samba')}`,
  `samba-tool domain exportkeytab ddi-enroll.keytab --principal=HTTP/${cmdHost.value}@${cmdRealm.value}`,
  `# ${t('enroll.cmd_c_check')}`,
  `klist -ke ddi-enroll.keytab`,
].join('\n'))
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success', icon: 'i-lucide-check' }) } catch { /* presse-papiers indisponible : le texte reste sélectionnable */ } }
const kt = computed(() => data.value?.keytab ?? null)
const issuers = computed<string[]>(() => data.value?.issuers ?? [])
const lim = computed(() => data.value?.limits ?? { minInterval: { min: 30, max: 86400 }, perDay: { min: 1, max: 50 }, perMinute: { min: 1, max: 600 } })
const complete = computed(() => !!f.ca && !!f.host.trim() && !!f.groupDn.trim() && !!kt.value)
const recent = computed<any[]>(() => data.value?.recent ?? [])

async function load(initForm = false) {
  try {
    const r: any = await api.call('GET', '/enroll', undefined, { silent: true })
    data.value = r
    if (initForm || !loaded.value) Object.assign(f, r.settings)   // le formulaire ne se réécrit jamais pendant la saisie
    err.value = ''
  } catch (e: any) { err.value = errOf(e) } finally { loaded.value = true }
}
const body = (enabled: boolean) => ({ enabled, ca: f.ca, host: f.host.trim().toLowerCase(), groupDn: f.groupDn.trim(), minIntervalSec: f.minIntervalSec, maxPerDay: f.maxPerDay, maxPerMinute: f.maxPerMinute })
async function save(enabled = f.enabled) {
  saving.value = true; err.value = ''
  try { await api.call('PUT', '/enroll/config', body(enabled), { silent: true }); toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await load(true) }
  catch (e: any) { err.value = errOf(e) } finally { saving.value = false }
}
async function toggle(on: boolean) {
  if (!on && !(await ask(t('enroll.disable_title'), t('enroll.disable_body'), true))) return
  await save(on)
}
async function pickKeytab(ev: Event) {
  const file = (ev.target as HTMLInputElement).files?.[0]
  ;(ev.target as HTMLInputElement).value = ''
  if (!file) return
  if (file.size > 60000) { err.value = t('err.invalid_keytab'); return }
  keytabBusy.value = true; err.value = ''
  try {
    const bytes = new Uint8Array(await file.arrayBuffer())
    let bin = ''; for (const b of bytes) bin += String.fromCharCode(b)
    await api.call('PUT', '/enroll/keytab', { keytab: btoa(bin) }, { silent: true })
    toast.add({ title: t('enroll.keytab_saved'), color: 'success', icon: 'i-lucide-check' }); await load()
  } catch (e: any) { err.value = errOf(e) } finally { keytabBusy.value = false }
}
async function dropKeytab() {
  if (!(await ask(t('enroll.keytab_remove_title'), t('enroll.keytab_remove_body'), true))) return
  keytabBusy.value = true
  try { await api.call('DELETE', '/enroll/keytab'); await load(true) } catch (e: any) { err.value = errOf(e) } finally { keytabBusy.value = false }
}
const when = (v: string) => fmt.dateTime(v)
const reasonText = (r: any) => {
  if (r.action === 'enroll.issued') return t('enroll.ev_issued', { serial: String(r.detail?.serial ?? '').slice(-8) })
  const k = `err.${r.detail?.reason}`, v = t(k)
  return v === k ? String(r.detail?.reason ?? '') : v   // une raison sans traduction s'affiche telle quelle
}

onMounted(() => load())
</script>

<template>
  <div class="flex flex-col gap-4" data-test="pki-enroll">
    <p class="text-sm text-muted">{{ t('enroll.intro') }}</p>
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-circle-alert" :description="err" data-test="enroll-error" />

    <UCard>
      <template #header><span class="font-medium">{{ t('enroll.step_keytab') }}</span></template>
      <p class="text-sm text-muted mb-2">{{ t('enroll.keytab_help') }}</p>
      <details class="mb-3 rounded-md border border-default" data-test="enroll-cmds">
        <summary class="cursor-pointer px-3 py-2 text-sm font-medium">{{ t('enroll.cmd_title') }}</summary>
        <div class="flex flex-col gap-3 px-3 pb-3">
          <p class="text-xs text-muted">{{ t('enroll.cmd_note', { host: cmdHost, realm: cmdRealm }) }}</p>
          <div v-for="b in [{ k: 'win', title: t('enroll.cmd_win'), text: cmdWindows }, { k: 'samba', title: t('enroll.cmd_samba'), text: cmdSamba }]" :key="b.k">
            <div class="mb-1 flex items-center justify-between"><span class="text-sm">{{ b.title }}</span>
              <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-copy" :label="t('common.copy')" :data-test="`enroll-cmd-copy-${b.k}`" @click="copy(b.text)" /></div>
            <pre class="overflow-x-auto rounded-md bg-elevated p-3 text-xs" :data-test="`enroll-cmd-${b.k}`">{{ b.text }}</pre>
          </div>
        </div>
      </details>
      <div v-if="kt" class="text-sm mb-2" data-test="enroll-keytab">
        <div v-for="p in kt.principals" :key="p" class="font-mono">{{ p }}<span class="text-muted"> · kvno {{ kt.kvno[p] }}</span></div>
        <UAlert v-if="kt.problem" color="warning" variant="subtle" :description="t(`err.enroll_${kt.problem}`)" class="mt-2" />
      </div>
      <p v-else class="text-sm mb-2" data-test="enroll-no-keytab">{{ t('enroll.keytab_none') }}</p>
      <div class="flex gap-2 items-center">
        <label class="inline-flex"><input type="file" class="hidden" accept=".keytab,.kt,application/octet-stream" data-test="enroll-keytab-file" @change="pickKeytab">
          <span class="inline-flex items-center gap-1 rounded-md border border-default px-3 py-1.5 text-sm cursor-pointer hover:bg-elevated"><UIcon name="i-lucide-upload" />{{ t(kt ? 'enroll.keytab_replace' : 'enroll.keytab_upload') }}</span>
        </label>
        <UButton v-if="kt" color="error" variant="ghost" icon="i-lucide-trash-2" :loading="keytabBusy" :label="t('common.delete')" data-test="enroll-keytab-del" @click="dropKeytab" />
      </div>
    </UCard>

    <UCard>
      <template #header><span class="font-medium">{{ t('enroll.step_settings') }}</span></template>
      <div class="grid gap-3 md:grid-cols-2">
        <UFormField :label="t('enroll.host')" :help="t('enroll.host_help')"><UInput v-model="f.host" class="w-full" placeholder="ddi.example.org" data-test="enroll-host" /></UFormField>
        <UFormField :label="t('enroll.ca')" :help="t('enroll.ca_help')"><USelect v-model="f.ca" :items="issuers" class="w-full" :placeholder="t('enroll.ca_pick')" data-test="enroll-ca" /></UFormField>
        <UFormField :label="t('enroll.group')" :help="t('enroll.group_help')" class="md:col-span-2"><UInput v-model="f.groupDn" class="w-full font-mono" placeholder="CN=DDI-Enrolement-Postes,OU=Groupes,DC=example,DC=org" data-test="enroll-group" /></UFormField>
        <UFormField :label="t('enroll.min_interval')" :help="t('enroll.min_interval_help')"><UInput v-model.number="f.minIntervalSec" type="number" :min="lim.minInterval.min" :max="lim.minInterval.max" class="w-full" data-test="enroll-interval" /></UFormField>
        <UFormField :label="t('enroll.per_day')"><UInput v-model.number="f.maxPerDay" type="number" :min="lim.perDay.min" :max="lim.perDay.max" class="w-full" data-test="enroll-perday" /></UFormField>
        <UFormField :label="t('enroll.per_minute')" :help="t('enroll.per_minute_help')"><UInput v-model.number="f.maxPerMinute" type="number" :min="lim.perMinute.min" :max="lim.perMinute.max" class="w-full" data-test="enroll-perminute" /></UFormField>
      </div>
      <div class="flex flex-wrap items-center gap-3 mt-4">
        <USwitch :model-value="f.enabled" :label="t('enroll.enable')" :disabled="saving || !ready || (!f.enabled && !complete)" data-test="enroll-enable" @update:model-value="toggle" />
        <UButton :loading="saving" :disabled="!ready || props.waiting" :label="t('common.save')" icon="i-lucide-save" data-test="enroll-save" @click="save()" />
        <span v-if="!complete" class="text-sm text-muted">{{ t('enroll.incomplete') }}</span>
      </div>
    </UCard>

    <UCard>
      <template #header><span class="font-medium">{{ t('enroll.step_script') }}</span></template>
      <p class="text-sm text-muted mb-2">{{ t('enroll.script_help') }}</p>
      <UButton :href="'/api/enroll/script'" download="enroll.ps1" icon="i-lucide-download" :disabled="!f.host || !f.ca" :label="t('enroll.script_download')" data-test="enroll-script" />
    </UCard>

    <UCard>
      <template #header>
        <div class="flex items-center justify-between"><span class="font-medium">{{ t('enroll.activity') }}</span>
          <span class="text-sm text-muted" data-test="enroll-24h">{{ t('enroll.last24h', { ok: data?.last24h?.issued ?? 0, ko: data?.last24h?.refused ?? 0 }) }}</span></div>
      </template>
      <p v-if="!recent.length" class="text-sm text-muted">{{ t('enroll.no_activity') }}</p>
      <table v-else class="w-full text-sm" data-test="enroll-recent">
        <thead class="sr-only">
          <tr><th scope="col">{{ t('enroll.col_when') }}</th><th scope="col">{{ t('enroll.col_machine') }}</th><th scope="col">{{ t('enroll.col_result') }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="(r, i) in recent" :key="i" class="border-t border-default">
            <td class="py-1 pr-3 whitespace-nowrap text-muted">{{ when(r.at) }}</td>
            <td class="py-1 pr-3 font-mono">{{ r.machine }}</td>
            <td class="py-1"><UBadge :color="r.action === 'enroll.issued' ? 'success' : 'warning'" variant="subtle" :label="reasonText(r)" /></td>
          </tr>
        </tbody>
      </table>
    </UCard>
  </div>
</template>
