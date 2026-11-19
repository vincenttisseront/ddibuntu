<script setup lang="ts">
// SCEP de la PKI du DDI (0.14.8) : activation de l'alias, préenregistrement des équipements (nom, profil, noms alternatifs + défi à usage unique), nouveau défi, annulation.
// EJBCA Community n'a que le mode « autorité » : l'équipement est préenregistré ici, puis s'inscrit seul avec SA clé. Le défi est fabriqué par la console, remis à root dans un
// fichier secret et rendu UNE seule fois ci-dessous : il n'est ni stocké ni journalisé (la PKI n'en garde qu'une empreinte).
const props = defineProps<{ status: any; waiting: boolean }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()

const meta = ref<any>(null), data = ref<any>(null), err = ref(''), loading = ref(false), busy = ref('')
const ready = computed(() => props.status?.state === 'healthy')
const scep = computed(() => data.value?.scep ?? null)
const enabled = computed(() => scep.value?.enabled === true)
const issuers = computed<any[]>(() => data.value?.issuers ?? [])
const rsaIssuers = computed(() => issuers.value.filter((x) => x.rsa))
const profiles = computed<any[]>(() => meta.value?.profiles ?? [])
const offers = computed<any[]>(() => [...(scep.value?.offers ?? [])].sort((a, b) => b.modifiedAt - a.modifiedAt || a.cn.localeCompare(b.cn)))
const errOf = (e: any) => e?.info?.message ?? t('err.internal')
const detailOf = (e: any) => (e?.info?.detail ? `${errOf(e)} ${e.info.detail}` : errOf(e))
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
const when = (sec: number | null) => (sec ? fmt.dateTime(sec * 1000) : '—')
const dateOnly = (iso: string) => (iso ? fmt.dateTime(Date.parse(iso)) : '—')

async function load() {
  loading.value = true
  try { data.value = await api.call('GET', '/pki/scep', undefined, { silent: true }); err.value = '' } catch (e: any) { err.value = errOf(e) } finally { loading.value = false }
}
// ---- Activation ----
async function toggle(on: boolean) {
  if (locked.value) return
  if (!on && !(await ask(t('pki.scep.disable_title'), t('pki.scep.disable_body'), true))) return
  busy.value = on ? 'enable' : 'disable'; err.value = ''
  try { await api.call('POST', `/pki/scep/${on ? 'enable' : 'disable'}`, {}); toast.add({ title: t(on ? 'pki.scep.enable_done' : 'pki.scep.disable_done'), color: 'success' }); await load() }
  catch (e: any) { err.value = detailOf(e) } finally { busy.value = '' }
}

// ---- Préenregistrement ----
const SAN_KEYS = ['dns', 'ip', 'mail', 'upn'] as const
const emptyOffer = () => ({ open: false, ca: '', profile: 'network', cn: '', cnAuto: '', dnsAuto: '', upnAuto: '', o: '', ou: '', c: 'FR', dns: '', ip: '', mail: '', upn: '', err: '', busy: false,
  done: null as null | { cn: string; ca: string; profile: string; challenge: string; offerDays: number; url: string; rearm: boolean } })
const off = reactive(emptyOffer())
const locked = computed(() => !ready.value || props.waiting || !!busy.value || off.busy)
const profile = computed(() => profiles.value.find((p) => p.key === off.profile))
const allowed = (k: string) => !!profile.value?.allowed.includes(k)
const list_ = (s: string) => [...new Set(s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean))]
const sans = computed(() => Object.fromEntries(SAN_KEYS.map((k) => [k, allowed(k) ? list_(off[k]) : []])) as Record<(typeof SAN_KEYS)[number], string[]>)
const sanOk = computed(() => !!profile.value && profile.value.needAny.some((k: string) => sans.value[k as (typeof SAN_KEYS)[number]].length > 0))
const needText = computed(() => (profile.value?.needAny ?? []).map((k: string) => t(`pki.cert.san_${k}`)).join(' / '))
const CN_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/
const cnOk = computed(() => CN_RE.test(off.cn.trim()) && !['ejbca', 'superadmin'].includes(off.cn.trim().toLowerCase()) && !off.cn.trim().toLowerCase().startsWith('ddi-')
  && !offers.value.some((o) => o.cn.toLowerCase() === off.cn.trim().toLowerCase()))
const offerOk = computed(() => !!off.ca && cnOk.value && sanOk.value)
const profileItems = computed(() => profiles.value.map((p) => ({ value: p.key, label: `${t(`pki.cert.profile.${p.key}`)} — ${t('pki.cert.days', { n: p.days })}` })))
// Nom proposé (0.14.14) d'après le profil, le domaine du DDI et le premier numéro libre ; il suit le profil tant que l'utilisateur n'a pas écrit dans le champ.
const autoCn = () => suggestCertName(t(`pki.name.${['server', 'machine', 'user', 'network'].includes(off.profile) ? off.profile : 'other'}`), domainOf(props.status?.hostname), off.profile !== 'user', offers.value.map((o) => o.cn))
function refreshCn() { const was = off.cn === off.cnAuto; off.cnAuto = autoCn(); if (was) off.cn = off.cnAuto }
function openOffer() { Object.assign(off, emptyOffer(), { open: true, ca: rsaIssuers.value[0]?.name ?? '' }); refreshCn() }
function refreshSans() {
  const a = suggestSans(off.profile, off.cn, domainOf(props.status?.hostname))
  if (off.dns === off.dnsAuto) off.dns = a.dns
  if (off.upn === off.upnAuto) off.upn = a.upn
  off.dnsAuto = a.dns; off.upnAuto = a.upn
}
watch(() => [off.cn, off.profile], () => { if (off.open) refreshSans() })
watch(() => off.profile, () => { if (off.open) refreshCn() })
async function submitOffer() {
  off.busy = true; off.err = ''
  try {
    const r = await api.call('POST', '/pki/scep/offers', { ca: off.ca, profile: off.profile, cn: off.cn.trim(), o: off.o.trim() || undefined, ou: off.ou.trim() || undefined, c: off.c.trim().toUpperCase() || undefined,
      dns: sans.value.dns, ip: sans.value.ip, mail: sans.value.mail, upn: sans.value.upn })
    off.done = { cn: r.cn, ca: r.ca, profile: r.profile, challenge: r.challenge, offerDays: r.offerDays, url: r.url, rearm: false }
    await load()
  } catch (e: any) { off.err = detailOf(e) } finally { off.busy = false }
}
// le défi ne survit pas à la fermeture de la fenêtre
watch(() => off.open, (v) => { if (!v) off.done = null })

// ---- Nouveau défi, annulation ----
async function rearm(o: any) {
  if (locked.value) return
  if (!(await ask(t('pki.scep.rearm_title', { cn: o.cn }), t('pki.scep.rearm_body'), false))) return
  busy.value = `rearm-${o.cn}`; err.value = ''
  try {
    const r = await api.call('POST', `/pki/scep/offers/${encodeURIComponent(o.cn)}/rearm`, {})
    Object.assign(off, emptyOffer(), { open: true, done: { cn: r.cn, ca: r.ca, profile: r.profile, challenge: r.challenge, offerDays: r.offerDays, url: r.url, rearm: true } })
    await load()
  } catch (e: any) { err.value = detailOf(e) } finally { busy.value = '' }
}
async function cancel(o: any) {
  if (locked.value) return
  if (!(await ask(t('pki.scep.cancel_title', { cn: o.cn }), t('pki.scep.cancel_body'), true))) return
  busy.value = `cancel-${o.cn}`; err.value = ''
  try { await api.call('DELETE', `/pki/scep/offers/${encodeURIComponent(o.cn)}`); toast.add({ title: t('pki.scep.cancel_done'), color: 'success' }); await load() }
  catch (e: any) { err.value = detailOf(e) } finally { busy.value = '' }
}

const STATE_COLOR: Record<string, string> = { waiting: 'info', issued: 'success', expired: 'neutral', failed: 'error', revoked: 'error', other: 'neutral' }
const sanText = (s: string) => s.replace(/dNSName=/g, 'DNS:').replace(/iPAddress=/g, 'IP:').replace(/rfc822Name=/g, 'mail:').replace(/UPN=|upn=/g, 'UPN:')
const caItem = (name: string) => issuers.value.find((x) => x.name === name)

let timer: ReturnType<typeof setInterval> | undefined
onMounted(async () => {
  try { meta.value = await api.call('GET', '/pki/certs/meta', undefined, { silent: true }) } catch (e: any) { err.value = errOf(e) }
  await load()
  timer = setInterval(() => { if (!off.open && !busy.value) void load() }, 15_000)   // une inscription se voit sans recharger la page
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
defineExpose({ load })
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('pki.scep.intro') }}</p>
    <UAlert v-if="!ready" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.ca.not_ready')" role="status" data-test="pki-scep-notready" />
    <p v-if="err" class="text-sm text-error" role="alert" data-test="pki-scep-error">{{ err }}</p>

    <!-- Alias -->
    <UCard>
      <div class="flex flex-wrap items-center gap-3">
        <h3 class="font-medium">{{ t('pki.scep.alias_title') }}</h3>
        <UBadge :color="enabled ? 'success' : 'neutral'" variant="subtle" :label="t(enabled ? 'pki.scep.enabled' : 'pki.scep.disabled')" data-test="pki-scep-state" />
        <div class="ml-auto flex gap-2">
          <UButton v-if="!enabled" icon="i-lucide-power" :label="t('pki.scep.enable')" :loading="busy === 'enable'" :disabled="locked || !data" data-test="pki-scep-enable" @click="toggle(true)" />
          <UButton v-else icon="i-lucide-power-off" color="neutral" variant="outline" :label="t('pki.scep.disable')" :loading="busy === 'disable'" :disabled="locked" data-test="pki-scep-disable" @click="toggle(false)" />
          <UButton icon="i-lucide-refresh-cw" color="neutral" variant="ghost" :label="t('common.refresh')" :loading="loading" data-test="pki-scep-refresh" @click="load" />
        </div>
      </div>
      <div v-if="enabled && scep?.url" class="mt-3 flex flex-col gap-1">
        <span class="text-sm text-muted">{{ t('pki.scep.url') }}</span>
        <div class="flex items-center gap-2">
          <code class="text-sm break-all" data-test="pki-scep-url">{{ scep.url }}</code>
          <UButton size="xs" icon="i-lucide-copy" color="neutral" variant="ghost" :aria-label="t('common.copy')" @click="copy(scep.url)" />
        </div>
        <span class="text-xs text-muted">{{ t('pki.scep.url_help', { port: scep.port }) }}</span>
      </div>
      <p v-else-if="data && !enabled" class="mt-2 text-sm text-muted" data-test="pki-scep-hint">{{ t('pki.scep.disabled_hint') }}</p>
      <p class="mt-3 text-xs text-muted">{{ t('pki.scep.limits') }}</p>
    </UCard>

    <!-- Autorités utilisables -->
    <UAlert v-if="data && ready && !rsaIssuers.length" color="info" variant="subtle" icon="i-lucide-info" :title="t('pki.scep.no_rsa')" role="status" data-test="pki-scep-norsa">
      <template #description><a href="#cas" class="underline">{{ t('pki.cert.no_issuer_link') }}</a></template>
    </UAlert>
    <UCard v-else-if="enabled && rsaIssuers.length">
      <h3 class="font-medium mb-1">{{ t('pki.scep.ca_title') }}</h3>
      <p class="text-xs text-muted mb-2">{{ t('pki.scep.ca_help') }}</p>
      <ul class="flex flex-col gap-2">
        <li v-for="ca in rsaIssuers" :key="ca.name" class="text-sm" :data-test="`pki-scep-ca-${ca.name}`">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-medium">{{ ca.name }}</span><span class="text-xs text-muted">RSA {{ ca.keyBits }}</span>
            <UButton v-if="ca.certUrl" size="xs" icon="i-lucide-download" color="neutral" variant="ghost" :label="t('pki.cert.dl_cert')" :href="`/api${ca.certUrl}`" :download="`${ca.name}.pem`" external />
          </div>
          <div v-if="ca.sha256" class="text-xs text-muted font-mono break-all">SHA-256 {{ ca.sha256 }}</div>
        </li>
      </ul>
    </UCard>

    <!-- Équipements -->
    <div class="flex flex-wrap gap-2">
      <UButton icon="i-lucide-plus" :label="t('pki.scep.offer')" :disabled="locked || !enabled || !rsaIssuers.length" data-test="pki-scep-offer" @click="openOffer" />
    </div>
    <UCard>
      <p v-if="data && !offers.length" class="text-sm text-muted" data-test="pki-scep-empty">{{ t('pki.scep.empty') }}</p>
      <div v-else-if="offers.length" class="overflow-x-auto">
        <table class="w-full text-sm" data-test="pki-scep-table"><caption class="sr-only">{{ t('pki.tab_scep') }}</caption>
          <thead><tr class="text-left text-muted">
            <th class="py-1 pr-3 font-normal">{{ t('pki.scep.col_name') }}</th><th class="py-1 pr-3 font-normal">{{ t('pki.cert.col_profile') }}</th>
            <th class="py-1 pr-3 font-normal">{{ t('pki.cert.col_state') }}</th><th />
          </tr></thead>
          <tbody>
            <tr v-for="o in offers" :key="o.cn" class="border-t border-default align-top" :data-test="`pki-scep-row-${o.cn}`">
              <td class="py-2 pr-3">
                <div class="font-medium break-all" data-test="pki-scep-cn">{{ o.cn }}</div>
                <div v-if="o.san" class="text-xs text-muted font-mono break-all">{{ sanText(o.san) }}</div>
                <div class="text-xs text-dimmed">{{ o.ca }}</div>
              </td>
              <td class="py-2 pr-3 whitespace-nowrap">{{ o.profile ? t(`pki.cert.profile.${o.profile}`) : '—' }}</td>
              <td class="py-2 pr-3">
                <UBadge :color="(STATE_COLOR[o.state] as any)" variant="subtle" :label="t(`pki.scep.state.${o.state}`)" data-test="pki-scep-row-state" />
                <div v-if="o.state === 'waiting'" class="text-xs text-muted">{{ t('pki.scep.expires', { date: when(o.expiresAt) }) }}</div>
                <div v-else-if="o.state === 'expired'" class="text-xs text-muted">{{ t('pki.scep.expired_on', { date: when(o.expiresAt ?? o.modifiedAt) }) }}</div>
                <div v-else-if="o.cert" class="text-xs text-muted">{{ t(o.cert.revoked ? 'pki.scep.cert_revoked' : 'pki.scep.cert_until', { date: dateOnly(o.cert.notAfter) }) }}<span class="font-mono"> · {{ o.cert.serial }}</span></div>
              </td>
              <td class="py-2 text-right whitespace-nowrap">
                <UButton size="xs" icon="i-lucide-key-round" color="neutral" variant="ghost" :label="t('pki.scep.rearm')" :loading="busy === `rearm-${o.cn}`" :disabled="locked || !enabled" :data-test="`pki-scep-rearm-${o.cn}`" @click="rearm(o)" />
                <UButton size="xs" icon="i-lucide-x" color="error" variant="ghost" :label="t('pki.scep.cancel')" :loading="busy === `cancel-${o.cn}`" :disabled="locked" :data-test="`pki-scep-cancel-${o.cn}`" @click="cancel(o)" />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="offers.length" class="text-xs text-muted mt-3" data-test="pki-scep-total">{{ t('pki.scep.total', { n: offers.length }) }}</p>
    </UCard>

    <!-- Préenregistrement et défi -->
    <UModal v-model:open="off.open" :title="t(off.done ? 'pki.scep.challenge_title' : 'pki.scep.offer')" :description="off.done ? '' : t('pki.scep.offer_desc')" :dismissible="!off.busy">
      <template #body>
        <div v-if="off.done" class="flex flex-col gap-3" data-test="pki-scep-done">
          <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.scep.challenge_warn', { days: off.done.offerDays })" role="status" />
          <p class="text-sm">{{ t('pki.scep.challenge_for', { cn: off.done.cn, ca: off.done.ca, profile: t(`pki.cert.profile.${off.done.profile}`) }) }}</p>
          <div class="flex items-center gap-2">
            <code class="flex-1 text-lg tracking-widest font-mono break-all select-all rounded bg-elevated px-3 py-2" data-test="pki-scep-challenge">{{ off.done.challenge }}</code>
            <UButton icon="i-lucide-copy" color="neutral" variant="outline" :label="t('common.copy')" data-test="pki-scep-challenge-copy" @click="copy(off.done.challenge)" />
          </div>
          <div class="text-sm flex flex-col gap-1">
            <span class="text-muted">{{ t('pki.scep.url') }}</span>
            <div class="flex items-center gap-2"><code class="text-xs break-all">{{ off.done.url }}</code><UButton size="xs" icon="i-lucide-copy" color="neutral" variant="ghost" :aria-label="t('common.copy')" @click="copy(off.done.url)" /></div>
          </div>
          <p class="text-xs text-muted">{{ t('pki.scep.howto', { cn: off.done.cn }) }}</p>
          <div class="flex justify-end"><UButton :label="t('common.close')" data-test="pki-scep-done-close" @click="off.open = false" /></div>
        </div>
        <form v-else class="flex flex-col gap-3" @submit.prevent="submitOffer">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <UFormField :label="t('pki.cert.col_ca')"><USelect v-model="off.ca" :items="rsaIssuers.map((x) => x.name)" class="w-full" data-test="pki-scep-ca" /></UFormField>
            <UFormField :label="t('pki.cert.col_profile')"><USelect v-model="off.profile" :items="profileItems" class="w-full" data-test="pki-scep-profile" /></UFormField>
          </div>
          <UFormField :label="t('pki.scep.cn')" :help="t('pki.scep.cn_help')" :error="off.cn && !cnOk ? t('pki.scep.cn_invalid') : undefined">
            <UInput v-model="off.cn" class="w-full" maxlength="63" data-test="pki-scep-cn-input" />
          </UFormField>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <UFormField :label="t('pki.ca.o')"><UInput v-model="off.o" class="w-full" maxlength="64" /></UFormField>
            <UFormField :label="t('pki.ca.ou')"><UInput v-model="off.ou" class="w-full" maxlength="64" /></UFormField>
            <UFormField :label="t('pki.ca.c')"><UInput v-model="off.c" class="w-full font-mono" maxlength="2" placeholder="FR" /></UFormField>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <UFormField v-for="k in SAN_KEYS.filter((x) => allowed(x))" :key="k" :label="t(`pki.cert.san_${k}`)" :help="t('pki.cert.san_help', { max: meta?.sanMax?.[k] ?? 8 })">
              <UTextarea v-model="off[k]" :rows="2" class="w-full font-mono text-xs" :data-test="`pki-scep-san-${k}`" />
            </UFormField>
          </div>
          <p v-if="!sanOk" class="text-xs text-warning" data-test="pki-scep-san-need">{{ t('pki.cert.san_need', { what: needText }) }}</p>
          <p v-if="off.busy" class="text-xs text-muted" role="status">{{ t('pki.scep.working') }}</p>
          <UAlert v-if="off.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="off.err" role="alert" data-test="pki-scep-offer-error" />
          <div class="flex justify-end gap-2">
            <UButton type="button" color="neutral" variant="outline" :label="t('common.cancel')" :disabled="off.busy" @click="off.open = false" />
            <UButton type="submit" :loading="off.busy" :disabled="!offerOk || locked" :label="t('pki.scep.offer_go')" data-test="pki-scep-offer-go" />
          </div>
        </form>
      </template>
    </UModal>
  </div>
</template>
