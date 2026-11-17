<script setup lang="ts">
// Certificats de la PKI du DDI (0.14.3) : liste lue dans la base d'EJBCA (lecture seule), recherche et filtres, export CSV, téléchargement, révocation, émission
// depuis une demande de certificat (la clé reste chez le demandeur) ou avec une clé fabriquée par la console puis remise dans un PKCS#12 (jamais stockée).
// La console ne signe rien : root revalide la demande et parle à EJBCA ; ici on attend simplement sa réponse (quelques secondes).
const props = defineProps<{ status: any; waiting: boolean }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const fmt = useFmt()

const meta = ref<any>(null), list = ref<any>(null), err = ref(''), loading = ref(false)
const ready = computed(() => props.status?.state === 'healthy')
const issuers = computed<string[]>(() => list.value?.issuers ?? [])
const rows = computed<any[]>(() => list.value?.rows ?? [])
const profiles = computed<any[]>(() => meta.value?.profiles ?? [])
const errOf = (e: any) => e?.info?.message ?? t('err.internal')
const detailOf = (e: any) => (e?.info?.detail ? `${errOf(e)} ${e.info.detail}` : errOf(e))
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }

// ---- Liste, recherche, filtres ----
const PAGE = 50
const f = reactive({ q: '', ca: '', profile: '', state: '', expiring: '' })
const offset = ref(0)
const query = computed(() => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(f)) if (v) p.set(k, v)
  return p.toString()
})
async function load() {
  loading.value = true
  try {
    list.value = await api.call('GET', `/pki/certs?${query.value}${query.value ? '&' : ''}limit=${PAGE}&offset=${offset.value}`, undefined, { silent: true }); err.value = ''
  } catch (e: any) { err.value = errOf(e) } finally { loading.value = false }
}
let timer: ReturnType<typeof setTimeout> | undefined
watch(() => f.q, () => { if (timer) clearTimeout(timer); timer = setTimeout(() => { offset.value = 0; load() }, 300) })
watch(() => [f.ca, f.profile, f.state, f.expiring], () => { offset.value = 0; load() })
const total = computed(() => list.value?.total ?? 0)
const from = computed(() => (total.value ? offset.value + 1 : 0)), to = computed(() => Math.min(offset.value + PAGE, total.value))
const go = (d: number) => { offset.value = Math.max(0, offset.value + d * PAGE); load() }
const csvHref = computed(() => `/api/pki/certs.csv${query.value ? '?' + query.value : ''}`)
const ALL = '__all'
const caItems = computed(() => [{ value: ALL, label: t('pki.cert.f_all_ca') }, ...issuers.value.map((n) => ({ value: n, label: n }))])
const profItems = computed(() => [{ value: ALL, label: t('pki.cert.f_all_profiles') }, ...profiles.value.map((p) => ({ value: p.key, label: t(`pki.cert.profile.${p.key}`) })), { value: 'other', label: t('pki.cert.profile.other') }])
const stateItems = computed(() => [{ value: ALL, label: t('pki.cert.f_all_states') }, ...['active', 'revoked', 'expired'].map((s) => ({ value: s, label: t(`pki.cert.state.${s}`) }))])
const expItems = computed(() => [{ value: ALL, label: t('pki.cert.f_any_expiry') }, ...[30, 60, 90, 365].map((d) => ({ value: String(d), label: t('pki.cert.f_expiring', { n: d }) }))])
const sel = (k: 'ca' | 'profile' | 'state' | 'expiring') => computed({ get: () => f[k] || ALL, set: (v: string) => { f[k] = v === ALL ? '' : v } })
const selCa = sel('ca'), selProfile = sel('profile'), selState = sel('state'), selExp = sel('expiring')

// ---- Présentation ----
const STATE_COLOR: Record<string, string> = { active: 'success', revoked: 'error', expired: 'neutral' }
const daysLeft = (iso: string) => Math.floor((Date.parse(iso) - Date.now()) / 86400_000)
const dateOnly = (iso: string | null) => (iso ? fmt.dateTime(Date.parse(iso)) : '—')
const cnOf = (dn: string) => (dn.match(/(?:^|,)CN=((?:\\.|[^,\\])*)/)?.[1] ?? dn).replace(/\\(.)/g, '$1')
const sanText = (s: string) => s.replace(/dNSName=/g, 'DNS:').replace(/iPAddress=/g, 'IP:').replace(/rfc822Name=/g, 'mail:').replace(/UPN=|upn=/g, 'UPN:')
const dl = (r: any, k: 'cert' | 'chain') => `/api/pki/certs/${r.fingerprint}/${k}.pem`
const dlName = (r: any, k: 'cert' | 'chain') => `${cnOf(r.subject).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 40) || 'certificat'}-${String(r.serial).slice(-8)}.${k === 'cert' ? 'pem' : 'chain.pem'}`

// ---- Émission ----
const SAN_KEYS = ['dns', 'ip', 'mail', 'upn'] as const
const emptyIssue = () => ({ open: false, mode: 'csr' as 'csr' | 'p12', ca: '', profile: 'machine', cn: '', o: '', ou: '', c: 'FR', dns: '', ip: '', mail: '', upn: '', pem: '', alg: 'ecp256', password: '', show: false, compat: false,
  err: '', busy: false, done: null as null | { id: string; serial: string; notAfter: string; subject: string; certificate: string; chain: string; file?: string } })
const iss = reactive(emptyIssue())
const files = reactive<{ csr: File | null }>({ csr: null })
const profile = computed(() => profiles.value.find((p) => p.key === iss.profile))
const allowed = (k: string) => !!profile.value?.allowed.includes(k)
const list_ = (s: string) => [...new Set(s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean))]
const sans = computed(() => Object.fromEntries(SAN_KEYS.map((k) => [k, allowed(k) ? list_(iss[k]) : []])) as Record<(typeof SAN_KEYS)[number], string[]>)
const sanOk = computed(() => !!profile.value && profile.value.needAny.some((k: string) => sans.value[k as (typeof SAN_KEYS)[number]].length > 0))
const needText = computed(() => (profile.value?.needAny ?? []).map((k: string) => t(`pki.cert.san_${k}`)).join(' / '))
const issueOk = computed(() => !!iss.ca && !!iss.cn.trim() && sanOk.value && (iss.mode === 'csr' ? !!iss.pem.trim() || !!files.csr : iss.password.length >= 8))
const profileItems = computed(() => profiles.value.map((p) => ({ value: p.key, label: `${t(`pki.cert.profile.${p.key}`)} — ${t('pki.cert.days', { n: p.days })}` })))
const algItems = [{ value: 'ecp256', label: 'ECDSA P-256' }, { value: 'ecp384', label: 'ECDSA P-384' }, { value: 'rsa2048', label: 'RSA 2048' }, { value: 'rsa3072', label: 'RSA 3072' }]
function openIssue(mode: 'csr' | 'p12') {
  Object.assign(iss, emptyIssue(), { open: true, mode, ca: issuers.value.length === 1 ? issuers.value[0] : f.ca || issuers.value[0] || '' }); files.csr = null
}
function pickCsr(ev: Event) { files.csr = (ev.target as HTMLInputElement).files?.[0] ?? null }
async function csrBlob(): Promise<{ pem: string } | { der: string }> {
  if (!files.csr) return { pem: iss.pem }
  if (files.csr.size > 16384) throw Object.assign(new Error('pki_bad_file'), { info: { message: t('err.pki_bad_file') } })
  const u = new Uint8Array(await files.csr.arrayBuffer())
  if (new TextDecoder().decode(u.subarray(0, 10)).startsWith('-----BEGIN')) return { pem: new TextDecoder().decode(u) }
  let s = ''
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000))
  return { der: btoa(s) }
}
const baseBody = () => ({ ca: iss.ca, profile: iss.profile, cn: iss.cn.trim(), o: iss.o.trim() || undefined, ou: iss.ou.trim() || undefined, c: iss.c.trim().toUpperCase() || undefined,
  dns: sans.value.dns, ip: sans.value.ip, mail: sans.value.mail, upn: sans.value.upn })
function genPassword() {   // 20 caractères sans ambiguïté (ni 0/O ni 1/l/I), tirés du générateur du navigateur
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_+=', u = new Uint32Array(20)
  crypto.getRandomValues(u)
  iss.password = Array.from(u, (x) => A[x % A.length]).join(''); iss.show = true
}
function saveBlob(b: Blob, name: string) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = name; document.body.appendChild(a); a.click(); a.remove()
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000)
}
const text = (s: string) => new Blob([s], { type: 'application/x-pem-file' })
async function submitIssue() {
  iss.busy = true; iss.err = ''
  try {
    if (iss.mode === 'csr') {
      const r = await api.call('POST', '/pki/certs/csr', { ...baseBody(), csr: await csrBlob() })
      iss.done = { id: r.id, serial: r.serial, notAfter: r.notAfter, subject: r.subject, certificate: r.certificate, chain: r.chain }
    } else {
      const r = await fetch('/api/pki/certs/p12', { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': api.csrf.value }, body: JSON.stringify({ ...baseBody(), alg: iss.alg, password: iss.password, compat: iss.compat }) })
      if (!r.ok) throw Object.assign(new Error('p12'), { info: api.describe({ statusCode: r.status, data: await r.json().catch(() => null) }) })
      const name = /filename="([^"]+)"/.exec(r.headers.get('content-disposition') ?? '')?.[1] ?? 'certificat.p12'
      saveBlob(await r.blob(), name)
      iss.done = { id: r.headers.get('x-pki-id') ?? '', serial: r.headers.get('x-pki-serial') ?? '', notAfter: '', subject: iss.cn.trim(), certificate: '', chain: '', file: name }
      iss.password = ''; iss.show = false
    }
    await load()
  } catch (e: any) { iss.err = detailOf(e) } finally { iss.busy = false }
}

// ---- Révocation ----
const rv = reactive({ open: false, row: null as any, reason: '1', err: '', busy: false })
const reasonItems = computed(() => (meta.value?.reasons ?? [0, 1, 3, 4, 5]).map((n: number) => ({ value: String(n), label: t(`pki.cert.reason.${n}`) })))
function openRevoke(r: any) { Object.assign(rv, { open: true, row: r, reason: '1', err: '', busy: false }) }
async function revoke() {
  rv.busy = true; rv.err = ''
  try { await api.call('POST', `/pki/certs/${rv.row.fingerprint}/revoke`, { reason: Number(rv.reason) }); rv.open = false; toast.add({ title: t('pki.cert.revoked_done'), color: 'success' }); await load() }
  catch (e: any) { rv.err = detailOf(e) } finally { rv.busy = false }
}
const locked = computed(() => !ready.value || props.waiting || iss.busy || rv.busy)

onMounted(async () => { try { meta.value = await api.call('GET', '/pki/certs/meta', undefined, { silent: true }) } catch (e: any) { err.value = errOf(e) } await load() })
onBeforeUnmount(() => { if (timer) clearTimeout(timer) })
defineExpose({ load })
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('pki.cert.intro') }}</p>
    <UAlert v-if="!ready" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.ca.not_ready')" role="status" data-test="pki-cert-notready" />
    <UAlert v-else-if="list && !issuers.length" color="info" variant="subtle" icon="i-lucide-info" :title="t('pki.cert.no_issuer')" role="status" data-test="pki-cert-noissuer">
      <template #description><a href="#cas" class="underline">{{ t('pki.cert.no_issuer_link') }}</a></template>
    </UAlert>
    <p v-if="err" class="text-sm text-error" role="alert" data-test="pki-cert-error">{{ err }}</p>

    <div class="flex flex-wrap gap-2">
      <UButton icon="i-lucide-file-plus-2" :label="t('pki.cert.issue_csr')" :disabled="locked || !issuers.length" data-test="pki-cert-issue-csr" @click="openIssue('csr')" />
      <UButton icon="i-lucide-package" color="neutral" variant="outline" :label="t('pki.cert.issue_p12')" :disabled="locked || !issuers.length" data-test="pki-cert-issue-p12" @click="openIssue('p12')" />
      <UButton icon="i-lucide-download" color="neutral" variant="ghost" :label="t('pki.cert.csv')" :href="csvHref" download="certificats-pki.csv" external :disabled="!total" data-test="pki-cert-csv" />
      <UButton icon="i-lucide-refresh-cw" color="neutral" variant="ghost" :label="t('common.refresh')" :loading="loading" data-test="pki-cert-refresh" @click="load" />
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2">
      <UInput v-model="f.q" icon="i-lucide-search" class="lg:col-span-2" :placeholder="t('pki.cert.search')" :aria-label="t('pki.cert.search')" data-test="pki-cert-q" />
      <USelect v-model="selCa" :items="caItems" class="w-full" :aria-label="t('pki.cert.col_ca')" data-test="pki-cert-f-ca" />
      <USelect v-model="selProfile" :items="profItems" class="w-full" :aria-label="t('pki.cert.col_profile')" data-test="pki-cert-f-profile" />
      <USelect v-model="selState" :items="stateItems" class="w-full" :aria-label="t('pki.cert.col_state')" data-test="pki-cert-f-state" />
      <USelect v-model="selExp" :items="expItems" class="w-full" :aria-label="t('pki.cert.col_end')" data-test="pki-cert-f-exp" />
    </div>

    <UCard>
      <p v-if="list && !rows.length" class="text-sm text-muted" data-test="pki-cert-empty">{{ t(query ? 'pki.cert.empty_filtered' : 'pki.cert.empty') }}</p>
      <div v-else-if="rows.length" class="overflow-x-auto">
        <table class="w-full text-sm" data-test="pki-cert-table"><caption class="sr-only">{{ t('pki.tab_certs') }}</caption>
          <thead><tr class="text-left text-muted">
            <th class="py-1 pr-3 font-normal">{{ t('pki.cert.col_subject') }}</th><th class="py-1 pr-3 font-normal">{{ t('pki.cert.col_profile') }}</th><th class="py-1 pr-3 font-normal">{{ t('pki.cert.col_end') }}</th>
            <th class="py-1 pr-3 font-normal">{{ t('pki.cert.col_state') }}</th><th class="py-1 pr-3 font-normal">{{ t('pki.cert.col_serial') }}</th><th />
          </tr></thead>
          <tbody>
            <tr v-for="r in rows" :key="r.fingerprint" class="border-t border-default align-top" :data-test="`pki-cert-row-${r.fingerprint}`">
              <td class="py-2 pr-3">
                <div class="font-medium break-all" data-test="pki-cert-cn">{{ cnOf(r.subject) }}</div>
                <div v-if="r.san" class="text-xs text-muted font-mono break-all">{{ sanText(r.san) }}</div>
                <div class="text-xs text-dimmed">{{ r.ca }}</div>
              </td>
              <td class="py-2 pr-3 whitespace-nowrap">{{ t(`pki.cert.profile.${r.profile}`) }}</td>
              <td class="py-2 pr-3 whitespace-nowrap">{{ dateOnly(r.notAfter) }}
                <div v-if="r.state === 'active' && daysLeft(r.notAfter) < 60" class="text-xs text-warning">{{ t('pki.cert.days_left', { n: daysLeft(r.notAfter) }) }}</div></td>
              <td class="py-2 pr-3 whitespace-nowrap">
                <UBadge :color="(STATE_COLOR[r.state] as any)" variant="subtle" :label="t(`pki.cert.state.${r.state}`)" data-test="pki-cert-state" />
                <div v-if="r.state === 'revoked'" class="text-xs text-muted">{{ dateOnly(r.revokedAt) }}<template v-if="r.reason !== null && r.reason >= 0"> · {{ t(`pki.cert.reason.${r.reason}`) }}</template></div>
              </td>
              <td class="py-2 pr-3 font-mono text-xs break-all">{{ r.serial }}</td>
              <td class="py-2 text-right whitespace-nowrap">
                <UButton size="xs" icon="i-lucide-download" color="neutral" variant="ghost" :label="t('pki.cert.dl_cert')" :href="dl(r, 'cert')" :download="dlName(r, 'cert')" external :data-test="`pki-cert-dl-${r.fingerprint}`" />
                <UButton size="xs" icon="i-lucide-link" color="neutral" variant="ghost" :label="t('pki.cert.dl_chain')" :href="dl(r, 'chain')" :download="dlName(r, 'chain')" external />
                <UButton v-if="r.state !== 'revoked'" size="xs" icon="i-lucide-ban" color="error" variant="ghost" :label="t('pki.cert.revoke')" :disabled="locked" :data-test="`pki-cert-revoke-${r.fingerprint}`" @click="openRevoke(r)" />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="total > PAGE" class="flex items-center justify-between gap-2 mt-3 text-sm">
        <span class="text-muted" data-test="pki-cert-range">{{ t('pki.cert.range', { a: from, b: to, n: total }) }}</span>
        <div class="flex gap-2">
          <UButton size="xs" color="neutral" variant="outline" icon="i-lucide-chevron-left" :label="t('common.previous')" :disabled="offset === 0 || loading" data-test="pki-cert-prev" @click="go(-1)" />
          <UButton size="xs" color="neutral" variant="outline" trailing-icon="i-lucide-chevron-right" :label="t('common.next')" :disabled="offset + PAGE >= total || loading" data-test="pki-cert-next" @click="go(1)" />
        </div>
      </div>
      <p v-else-if="total" class="text-xs text-muted mt-3" data-test="pki-cert-range">{{ t('pki.cert.total', { n: total }) }}</p>
    </UCard>

    <!-- Émission -->
    <UModal v-model:open="iss.open" :title="t(iss.mode === 'csr' ? 'pki.cert.issue_csr' : 'pki.cert.issue_p12')" :description="t(iss.mode === 'csr' ? 'pki.cert.csr_desc' : 'pki.cert.p12_desc')" :dismissible="!iss.busy">
      <template #body>
        <div v-if="iss.done" class="flex flex-col gap-3" data-test="pki-cert-done">
          <UAlert color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('pki.cert.issued')" :description="t('pki.cert.issued_info', { serial: iss.done.serial })" role="status" />
          <p v-if="iss.done.file" class="text-sm">{{ t('pki.cert.p12_saved', { file: iss.done.file }) }}</p>
          <template v-else>
            <UTextarea :model-value="iss.done.certificate" readonly :rows="7" class="w-full font-mono text-xs" data-test="pki-cert-result-pem" />
            <div class="flex flex-wrap gap-2">
              <UButton size="sm" icon="i-lucide-copy" color="neutral" variant="outline" :label="t('common.copy')" @click="copy(iss.done.certificate)" />
              <UButton size="sm" icon="i-lucide-download" color="neutral" variant="outline" :label="t('pki.cert.dl_cert')" data-test="pki-cert-result-dl" @click="saveBlob(text(iss.done.certificate), `${cnOf(iss.done.subject).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 40) || 'certificat'}.pem`)" />
              <UButton size="sm" icon="i-lucide-link" color="neutral" variant="outline" :label="t('pki.cert.dl_chain')" @click="saveBlob(text(iss.done.certificate + iss.done.chain), 'chaine.pem')" />
            </div>
          </template>
          <div class="flex justify-end"><UButton :label="t('common.close')" @click="iss.open = false" /></div>
        </div>
        <form v-else class="flex flex-col gap-3" @submit.prevent="submitIssue">
          <UAlert v-if="iss.mode === 'p12'" color="info" variant="subtle" icon="i-lucide-key-round" :title="t('pki.cert.p12_key_title')" :description="t('pki.cert.p12_key_body')" />
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <UFormField :label="t('pki.cert.col_ca')"><USelect v-model="iss.ca" :items="issuers" class="w-full" data-test="pki-cert-ca" /></UFormField>
            <UFormField :label="t('pki.cert.col_profile')"><USelect v-model="iss.profile" :items="profileItems" class="w-full" data-test="pki-cert-profile" /></UFormField>
          </div>
          <UFormField :label="t('pki.cert.cn')" :help="t('pki.cert.cn_help')"><UInput v-model="iss.cn" class="w-full" maxlength="64" data-test="pki-cert-cn-input" /></UFormField>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <UFormField :label="t('pki.ca.o')"><UInput v-model="iss.o" class="w-full" maxlength="64" /></UFormField>
            <UFormField :label="t('pki.ca.ou')"><UInput v-model="iss.ou" class="w-full" maxlength="64" /></UFormField>
            <UFormField :label="t('pki.ca.c')"><UInput v-model="iss.c" class="w-full font-mono" maxlength="2" placeholder="FR" /></UFormField>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <UFormField v-for="k in SAN_KEYS.filter((x) => allowed(x))" :key="k" :label="t(`pki.cert.san_${k}`)" :help="t('pki.cert.san_help', { max: meta?.sanMax?.[k] ?? 8 })">
              <UTextarea v-model="iss[k]" :rows="2" class="w-full font-mono text-xs" :data-test="`pki-cert-san-${k}`" />
            </UFormField>
          </div>
          <p v-if="!sanOk" class="text-xs text-warning" data-test="pki-cert-san-need">{{ t('pki.cert.san_need', { what: needText }) }}</p>
          <template v-if="iss.mode === 'csr'">
            <UFormField :label="t('pki.cert.csr_pem')" :help="t('pki.cert.csr_help')"><UTextarea v-model="iss.pem" :rows="6" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE REQUEST-----" data-test="pki-cert-csr" /></UFormField>
            <UFormField :label="t('pki.ca.or_file')"><input type="file" accept=".csr,.pem,.req,.der" class="text-sm" data-test="pki-cert-csr-file" @change="pickCsr"></UFormField>
          </template>
          <template v-else>
            <UFormField :label="t('pki.ca.alg')"><USelect v-model="iss.alg" :items="algItems" class="w-full sm:w-1/2" data-test="pki-cert-alg" /></UFormField>
            <UFormField :label="t('pki.cert.p12_password')" :help="t('pki.cert.p12_password_help')">
              <div class="flex gap-1">
                <UInput v-model="iss.password" :type="iss.show ? 'text' : 'password'" autocomplete="new-password" class="flex-1 font-mono" maxlength="128" data-test="pki-cert-password" />
                <UButton type="button" icon="i-lucide-dices" color="neutral" variant="outline" :label="t('pki.cert.gen_password')" data-test="pki-cert-genpw" @click="genPassword" />
                <UButton type="button" :icon="iss.show ? 'i-lucide-eye-off' : 'i-lucide-eye'" color="neutral" variant="ghost" :aria-label="t('pki.cert.show_password')" @click="iss.show = !iss.show" />
                <UButton type="button" icon="i-lucide-copy" color="neutral" variant="ghost" :aria-label="t('common.copy')" :disabled="!iss.password" @click="copy(iss.password)" />
              </div>
            </UFormField>
            <USwitch v-model="iss.compat" :label="t('pki.cert.p12_compat')" :description="t('pki.cert.p12_compat_help')" data-test="pki-cert-compat" />
          </template>
          <p v-if="iss.busy" class="text-xs text-muted" role="status">{{ t('pki.cert.working') }}</p>
          <UAlert v-if="iss.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="iss.err" role="alert" data-test="pki-cert-issue-error" />
          <div class="flex justify-end gap-2">
            <UButton type="button" color="neutral" variant="outline" :label="t('common.cancel')" :disabled="iss.busy" @click="iss.open = false" />
            <UButton type="submit" :loading="iss.busy" :disabled="!issueOk || locked" :label="t(iss.mode === 'csr' ? 'pki.cert.issue_go' : 'pki.cert.issue_p12_go')" data-test="pki-cert-issue-go" />
          </div>
        </form>
      </template>
    </UModal>

    <!-- Révocation -->
    <UModal v-model:open="rv.open" :title="t('pki.cert.revoke')" :description="t('pki.cert.revoke_desc', { cn: rv.row ? cnOf(rv.row.subject) : '' })" :dismissible="!rv.busy">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="revoke">
          <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.cert.revoke_warn')" />
          <UFormField :label="t('pki.cert.reason_label')"><USelect v-model="rv.reason" :items="reasonItems" class="w-full" data-test="pki-cert-reason" /></UFormField>
          <UAlert v-if="rv.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="rv.err" role="alert" data-test="pki-cert-revoke-error" />
          <div class="flex justify-end gap-2">
            <UButton type="button" color="neutral" variant="outline" :label="t('common.cancel')" :disabled="rv.busy" @click="rv.open = false" />
            <UButton type="submit" color="error" :loading="rv.busy" :disabled="locked && !rv.busy" :label="t('pki.cert.revoke')" data-test="pki-cert-revoke-go" />
          </div>
        </form>
      </template>
    </UModal>
  </div>
</template>
