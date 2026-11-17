<script setup lang="ts">
// Accès réseau — certificats EAP-TLS du service RADIUS (0.13.2, itération 3) : autorités de confiance (racine + intermédiaires), certificat et clé du serveur
// RADIUS (demande CSR à faire signer, ou import PEM / PKCS#12), révocation par CRL (adresse + téléchargement horaire, ou fichier), et vérification à blanc
// d'un certificat client. La console valide pour guider ; root REVALIDE tout au déploiement. Les clés et mots de passe ne sont jamais renvoyés.
const props = defineProps<{ eap: any | null }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()

const view = ref<any>(null), loadErr = ref('')
const ddi = ref<any>(null)   // ce que la PKI du DDI propose (0.14.3) ; absent = pas de carte
async function load() {
  try { view.value = await api.call('GET', '/radius/pki', undefined, { silent: true }); loadErr.value = '' } catch (e: any) { loadErr.value = e?.info?.message ?? t('err.internal') }
  try { ddi.value = await api.call('GET', '/radius/pki/ddi', undefined, { silent: true }) } catch { ddi.value = null }
}
const rd = computed(() => view.value?.readiness ?? { ready: false, empty: true, problems: [], warnings: [] })
const caName = (id?: string) => view.value?.cas.find((c: any) => c.id === id)?.name ?? ''
const problemText = (p: { code: string; ref?: string }) => t(`radius.pki.p.${p.code}`, { name: caName(p.ref) })
const GROUPS: Record<string, string[]> = { trust: ['no_ca', 'no_root', 'ca_chain', 'ca_expired'], server: ['no_server', 'server_expired', 'server_usage', 'server_chain'], crl: ['crl_missing', 'crl_expired'] }
const checklist = computed(() => {
  const v = view.value
  if (!v) return []
  const by = (g: string) => rd.value.problems.filter((p: any) => GROUPS[g]!.includes(p.code))
  const warn = (codes: string[]) => rd.value.warnings.filter((p: any) => codes.includes(p.code))
  return [
    { key: 'trust', icon: 'i-lucide-link', problems: by('trust'), warnings: warn(['ca_expiring']), ok: v.cas.length > 0 },
    { key: 'server', icon: 'i-lucide-server-cog', problems: by('server'), warnings: warn(['server_expiring']), ok: !!v.server },
    { key: 'crl', icon: 'i-lucide-ban', problems: v.checkCrl ? by('crl') : [], warnings: v.checkCrl ? warn(['crl_expiring']) : [], ok: v.checkCrl && v.cas.length > 0, off: !v.checkCrl },
  ]
})
const readyBadge = computed(() => rd.value.ready ? { color: 'success', label: t('radius.pki.ready') } : rd.value.empty ? { color: 'neutral', label: t('radius.pki.empty') } : { color: 'warning', label: t('radius.pki.incomplete') })

// ---- Utilitaires ----
async function readB64(f: File): Promise<string> {
  const u = new Uint8Array(await f.arrayBuffer()); let s = ''
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000))
  return btoa(s)
}
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
const errOf = (e: any) => e?.info?.message ?? t('err.internal')
const day = (ms: number | null | undefined) => (ms ? fmt.dateTime(ms) : '—')
const daysLeft = (ms: number) => Math.floor((ms - Date.now()) / 86400_000)
const files = reactive<Record<string, File | null>>({})
function pick(k: string, ev: Event) { files[k] = (ev.target as HTMLInputElement).files?.[0] ?? null }

// ---- Options ----
const optBusy = ref(false)
async function setCheckCrl(v: boolean) {
  if (optBusy.value) return
  optBusy.value = true
  try { await api.call('PUT', '/radius/pki/options', { checkCrl: v }); await load() } catch { /* message déjà affiché */ await load() } finally { optBusy.value = false }
}

// ---- Autorités ----
const caM = reactive({ open: false, pem: '', name: '', busy: false, err: '' })
function openAddCa() { Object.assign(caM, { open: true, pem: '', name: '', busy: false, err: '' }); files.ca = null }
async function addCa() {
  caM.busy = true; caM.err = ''
  try {
    const b: any = { name: caM.name.trim() || undefined }
    if (files.ca) b.dataBase64 = await readB64(files.ca); else b.pem = caM.pem
    const r: any = await api.call('POST', '/radius/pki/cas', b, { silent: true })
    view.value = r.view; caM.open = false
    toast.add({ title: t('radius.pki.ca_added', { n: r.added, s: r.skipped }), color: 'success', icon: 'i-lucide-check' })
  } catch (e: any) { caM.err = errOf(e) } finally { caM.busy = false }
}
async function delCa(c: any) {
  if (!(await ask(t('radius.pki.ca_del_title'), t('radius.pki.ca_del_body', { name: c.name }), true))) return
  try { await api.call('DELETE', `/radius/pki/cas/${c.id}`); await load() } catch { /* message déjà affiché */ }
}
const crlM = reactive({ open: false, id: '', url: '', busy: '' as '' | 'save' | 'fetch' | 'upload', err: '', ok: '' })
const crlCa = computed(() => view.value?.cas.find((c: any) => c.id === crlM.id) ?? null)
function openCrl(c: any) { Object.assign(crlM, { open: true, id: c.id, url: c.crlUrl ?? '', busy: '', err: '', ok: '' }); files.crl = null }
const pushText = (p: string) => (p === 'pushed' ? t('radius.pki.crl_pushed') : p === 'pending' ? t('radius.pki.crl_push_pending') : '')
async function saveCrlUrl() {
  crlM.busy = 'save'; crlM.err = ''; crlM.ok = ''
  try { await api.call('PUT', `/radius/pki/cas/${crlM.id}`, { crlUrl: crlM.url.trim() || null }, { silent: true }); await load(); crlM.ok = t('common.saved') } catch (e: any) { crlM.err = errOf(e) } finally { crlM.busy = '' }
}
async function fetchCrl() {
  crlM.busy = 'fetch'; crlM.err = ''; crlM.ok = ''
  try {
    if ((crlCa.value?.crlUrl ?? '') !== crlM.url.trim()) await api.call('PUT', `/radius/pki/cas/${crlM.id}`, { crlUrl: crlM.url.trim() || null }, { silent: true })
    const r: any = await api.call('POST', `/radius/pki/cas/${crlM.id}/crl/refresh`, {}, { silent: true })
    crlM.ok = [r.changed ? t('radius.pki.crl_new', { n: r.revoked }) : t('radius.pki.crl_same'), pushText(r.push)].filter(Boolean).join(' ')
  } catch (e: any) { crlM.err = errOf(e) } finally { crlM.busy = ''; await load() }
}
async function uploadCrl() {
  if (!files.crl) return
  crlM.busy = 'upload'; crlM.err = ''; crlM.ok = ''
  try {
    const r: any = await api.call('POST', `/radius/pki/cas/${crlM.id}/crl`, { dataBase64: await readB64(files.crl) }, { silent: true })
    crlM.ok = [r.changed ? t('radius.pki.crl_new', { n: r.revoked }) : t('radius.pki.crl_same'), pushText(r.push)].filter(Boolean).join(' ')
  } catch (e: any) { crlM.err = errOf(e) } finally { crlM.busy = ''; await load() }
}
const crlState = (c: any) => {
  if (!c.crl) return { color: c.issuing ? 'warning' : 'neutral', key: c.issuing ? 'none' : 'optional' }
  if (c.crl.nextUpdate <= Date.now()) return { color: 'error', key: 'expired' }
  return { color: 'success', key: 'ok' }
}

// ---- Certificat du serveur ----
const csrM = reactive({ open: false, cn: '', sans: '', keyType: 'rsa2048', busy: false, err: '' })
const KEYS = computed(() => [{ label: t('radius.pki.kt_rsa2048'), value: 'rsa2048' }, { label: t('radius.pki.kt_rsa3072'), value: 'rsa3072' }, { label: t('radius.pki.kt_ec256'), value: 'ec256' }])
function openCsr() { Object.assign(csrM, { open: true, cn: '', sans: '', keyType: 'rsa2048', busy: false, err: '' }) }
async function makeCsr() {
  csrM.busy = true; csrM.err = ''
  try {
    await api.call('POST', '/radius/pki/server/csr', { cn: csrM.cn.trim(), sans: csrM.sans.split(/[\s,;]+/).filter(Boolean), keyType: csrM.keyType }, { silent: true })
    csrM.open = false; await load()
  } catch (e: any) { csrM.err = errOf(e) } finally { csrM.busy = false }
}
const signM = reactive({ open: false, pem: '', busy: false, err: '' })
function openSign() { Object.assign(signM, { open: true, pem: '', busy: false, err: '' }); files.sign = null }
async function sendSigned() {
  signM.busy = true; signM.err = ''
  try {
    const b: any = files.sign ? { dataBase64: await readB64(files.sign) } : { pem: signM.pem }
    const r: any = await api.call('POST', '/radius/pki/server/cert', b, { silent: true })
    view.value = r.view; signM.open = false; toast.add({ title: t('radius.pki.server_saved'), color: 'success', icon: 'i-lucide-check' })
  } catch (e: any) { signM.err = errOf(e) } finally { signM.busy = false }
}
async function cancelCsr() {
  if (!(await ask(t('radius.pki.csr_cancel_title'), t('radius.pki.csr_cancel_body'), true))) return
  try { await api.call('DELETE', '/radius/pki/server/pending'); await load() } catch { /* message déjà affiché */ }
}
const impM = reactive({ open: false, mode: 'pem' as 'pem' | 'p12', pem: '', key: '', keyPassword: '', p12Password: '', busy: false, err: '' })
const MODES = computed(() => [{ label: t('radius.pki.imp_pem'), value: 'pem' }, { label: t('radius.pki.imp_p12'), value: 'p12' }])
function openImport() { Object.assign(impM, { open: true, mode: 'pem', pem: '', key: '', keyPassword: '', p12Password: '', busy: false, err: '' }); files.impCert = null; files.impKey = null; files.p12 = null }
async function doImport() {
  impM.busy = true; impM.err = ''
  try {
    const b: any = {}
    if (impM.mode === 'p12') { if (!files.p12) throw new Error('x'); b.p12Base64 = await readB64(files.p12); b.p12Password = impM.p12Password }
    else {
      if (files.impCert) b.certBase64 = await readB64(files.impCert); else b.pem = impM.pem
      b.key = files.impKey ? await files.impKey.text() : impM.key
      if (impM.keyPassword) b.keyPassword = impM.keyPassword
    }
    const r: any = await api.call('POST', '/radius/pki/server/import', b, { silent: true })
    view.value = r.view; impM.open = false; impM.key = ''; impM.keyPassword = ''; impM.p12Password = ''
    toast.add({ title: t('radius.pki.server_saved'), color: 'success', icon: 'i-lucide-check' })
  } catch (e: any) { impM.err = e?.info ? errOf(e) : t('radius.pki.imp_missing') } finally { impM.busy = false }
}
async function delServer() {
  if (!(await ask(t('radius.pki.server_del_title'), t('radius.pki.server_del_body'), true))) return
  try { await api.call('DELETE', '/radius/pki/server'); await load() } catch { /* message déjà affiché */ }
}

// ---- PKI du DDI (0.14.3) : confiance en une autorité du DDI, certificat du serveur émis par elle ----
const ddiBusy = ref(''), ddiErr = ref('')
async function ddiTrust(name: string) {
  ddiBusy.value = `trust:${name}`; ddiErr.value = ''
  try {
    const r: any = await api.call('POST', '/radius/pki/ddi/trust', { ca: name }, { silent: true })
    view.value = r.view
    toast.add({ title: t('radius.pki.ddi_trusted_done', { n: r.added, crl: r.crl.loaded }), color: 'success', icon: 'i-lucide-check' })
    await load()
  } catch (e: any) { ddiErr.value = errOf(e) } finally { ddiBusy.value = '' }
}
const dsv = reactive({ open: false, ca: '', cn: '', dns: '', ip: '', alg: 'ecp256', busy: false, err: '' })
const DDI_ALGS = [{ value: 'ecp256', label: 'ECDSA P-256' }, { value: 'rsa2048', label: 'RSA 2048' }, { value: 'rsa3072', label: 'RSA 3072' }]
const lines = (v: string) => [...new Set(v.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean))]
const dsvOk = computed(() => !!dsv.ca && !!dsv.cn.trim() && lines(dsv.dns).length > 0)
function openDdiServer() {
  const first = ddi.value?.issuers?.find((i: any) => i.trusted) ?? ddi.value?.issuers?.[0]
  Object.assign(dsv, { open: true, ca: first?.name ?? '', cn: '', dns: '', ip: '', alg: 'ecp256', busy: false, err: '' })
}
async function ddiServer() {
  dsv.busy = true; dsv.err = ''
  try {
    const r: any = await api.call('POST', '/radius/pki/ddi/server', { ca: dsv.ca, cn: dsv.cn.trim(), dns: lines(dsv.dns), ip: lines(dsv.ip), alg: dsv.alg }, { silent: true })
    view.value = r.view; dsv.open = false
    toast.add({ title: t('radius.pki.ddi_issued', { serial: r.serial }), color: 'success', icon: 'i-lucide-check' })
  } catch (e: any) { dsv.err = e?.info?.detail ? `${errOf(e)} ${e.info.detail}` : errOf(e) } finally { dsv.busy = false }
}

// ---- Vérification d'un certificat client ----
const chk = reactive({ pem: '', directory: true, busy: false, err: '' }), chkRes = ref<any>(null)
async function checkClient() {
  chk.busy = true; chk.err = ''; chkRes.value = null
  try {
    const b: any = { directory: chk.directory }
    if (files.chk) b.dataBase64 = await readB64(files.chk); else b.pem = chk.pem
    chkRes.value = await api.call('POST', '/radius/pki/check-client', b, { silent: true })
  } catch (e: any) { chk.err = errOf(e) } finally { chk.busy = false }
}
const accountMsg = computed(() => { const a = chkRes.value?.account; return a && !a.checked ? t(a.reason === 'no_identity' ? 'radius.pki.chk_no_identity' : `err.${a.reason}`) : '' })
onMounted(load)
defineExpose({ load })
watch(() => props.eap, () => { void load() })
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('radius.pki.intro') }}</p>
    <UAlert v-if="loadErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="loadErr" role="alert" />

    <template v-if="view">
      <!-- Disponibilité -->
      <UCard data-test="pki-ready">
        <template #header>
          <div class="flex items-center gap-2"><UIcon name="i-lucide-shield-check" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.pki.ready_title') }}</h2>
            <UBadge :color="(readyBadge.color as any)" variant="subtle" :label="readyBadge.label" class="ml-auto" data-test="pki-ready-badge" /></div>
        </template>
        <ul class="flex flex-col gap-3 text-sm">
          <li v-for="c in checklist" :key="c.key" class="flex gap-3" :data-test="`pki-check-${c.key}`">
            <UIcon :name="c.problems.length ? 'i-lucide-circle-x' : c.off ? 'i-lucide-circle-slash' : c.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-dashed'" class="size-5 shrink-0 mt-0.5" :class="c.problems.length ? 'text-error' : c.off ? 'text-warning' : c.ok ? 'text-success' : 'text-muted'" />
            <div class="flex flex-col gap-0.5">
              <span class="font-medium">{{ t(`radius.pki.c_${c.key}`) }}</span>
              <span v-if="c.off" class="text-warning">{{ t('radius.pki.crl_off') }}</span>
              <span v-for="p in c.problems" :key="p.code + (p.ref ?? '')" class="text-error" data-test="pki-problem">{{ problemText(p) }}</span>
              <span v-for="p in c.warnings" :key="'w' + p.code + (p.ref ?? '')" class="text-warning" data-test="pki-warning">{{ problemText(p) }}</span>
              <span v-if="!c.problems.length && !c.warnings.length && !c.off" class="text-muted">{{ t(`radius.pki.c_${c.key}_ok`) }}</span>
            </div>
          </li>
        </ul>
        <div class="mt-4 text-sm" data-test="pki-deployed">
          <template v-if="props.eap?.enabled"><UBadge color="success" variant="subtle" icon="i-lucide-badge-check" :label="t('radius.pki.deployed')" />
            <span class="text-muted ml-2">{{ t('radius.pki.deployed_detail', { cas: props.eap.cas, crls: props.eap.crls.length, exp: day(props.eap.server?.notAfter) }) }}</span></template>
          <UBadge v-else color="neutral" variant="subtle" icon="i-lucide-badge-minus" :label="t('radius.pki.not_deployed')" />
        </div>
        <UAlert color="info" variant="subtle" icon="i-lucide-info" class="mt-3" :title="t('radius.pki.rules_title')" :description="t('radius.pki.rules_body')" data-test="pki-rules-note" />
      </UCard>

      <!-- PKI du DDI -->
      <UCard v-if="ddi?.installed" data-test="pki-ddi">
        <template #header>
          <div class="flex items-center gap-2"><UIcon name="i-lucide-badge-check" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.pki.ddi_title') }}</h2></div>
          <p class="text-sm text-muted mt-1">{{ t('radius.pki.ddi_desc') }}</p>
        </template>
        <UAlert v-if="!ddi.ready" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.ca.not_ready')" role="status" class="mb-3" data-test="pki-ddi-notready" />
        <p v-if="!ddi.issuers.length" class="text-sm text-muted" data-test="pki-ddi-none">{{ t('radius.pki.ddi_none') }} <NuxtLink to="/pki#cas" class="text-primary underline">{{ t('radius.pki.ddi_none_link') }}</NuxtLink></p>
        <ul v-else class="flex flex-col divide-y divide-default border border-default rounded-md text-sm" data-test="pki-ddi-list">
          <li v-for="i in ddi.issuers" :key="i.name" class="flex flex-wrap items-center gap-2 px-3 py-2" :data-test="`pki-ddi-${i.name}`">
            <div class="flex flex-col gap-0.5 min-w-0">
              <span class="font-medium font-mono">{{ i.name }}</span>
              <span class="text-xs text-muted font-mono break-all">{{ i.dn }}</span>
              <span v-if="!i.hasCrl" class="text-xs text-warning" data-test="pki-ddi-nocrl">{{ t('radius.pki.ddi_no_crl') }}</span>
            </div>
            <UBadge class="ml-auto" :color="i.trusted ? 'success' : 'neutral'" variant="subtle" :label="t(i.trusted ? 'radius.pki.ddi_trusted' : 'radius.pki.ddi_not_trusted')" data-test="pki-ddi-state" />
            <UButton size="xs" :color="i.trusted ? 'neutral' : 'primary'" :variant="i.trusted ? 'outline' : 'solid'" :icon="i.trusted ? 'i-lucide-refresh-cw' : 'i-lucide-link'" :label="t(i.trusted ? 'radius.pki.ddi_refresh' : 'radius.pki.ddi_trust')"
              :loading="ddiBusy === `trust:${i.name}`" :disabled="!!ddiBusy || !ddi.ready" :data-test="`pki-ddi-trust-${i.name}`" @click="ddiTrust(i.name)" />
          </li>
        </ul>
        <p v-if="ddiErr" class="text-sm text-error mt-2" role="alert" data-test="pki-ddi-error">{{ ddiErr }}</p>
        <div v-if="ddi.issuers.length" class="mt-3 flex flex-wrap items-center gap-2">
          <UButton icon="i-lucide-server-cog" color="neutral" variant="outline" :label="t('radius.pki.ddi_server_btn')" :disabled="!!ddiBusy || !ddi.ready" data-test="pki-ddi-server-open" @click="openDdiServer" />
          <span class="text-xs text-dimmed">{{ t('radius.pki.ddi_server_hint') }}</span>
        </div>
      </UCard>

      <!-- Autorités -->
      <UCard>
        <template #header>
          <div class="flex items-center gap-2"><UIcon name="i-lucide-link" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.pki.ca_title') }}</h2>
            <UButton class="ml-auto" size="sm" icon="i-lucide-plus" :label="t('radius.pki.ca_add')" data-test="pki-ca-add" @click="openAddCa" /></div>
          <p class="text-sm text-muted mt-1">{{ t('radius.pki.ca_desc') }}</p>
        </template>
        <p v-if="!view.cas.length" class="text-sm text-muted" data-test="pki-ca-none">{{ t('radius.pki.ca_none') }}</p>
        <ul v-else class="flex flex-col divide-y divide-default border border-default rounded-md text-sm" data-test="pki-ca-list">
          <li v-for="c in view.cas" :key="c.id" class="flex flex-col gap-1.5 px-3 py-2" data-test="pki-ca">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-medium">{{ c.name }}</span>
              <UBadge v-if="c.root" color="primary" variant="subtle" size="sm" :label="t('radius.pki.root')" />
              <UBadge v-else color="neutral" variant="subtle" size="sm" :label="t('radius.pki.inter')" />
              <UBadge v-if="c.issuing" color="neutral" variant="outline" size="sm" :label="t('radius.pki.issuing')" />
              <UBadge v-if="c.ddi" color="primary" variant="outline" size="sm" icon="i-lucide-badge-check" :label="t('radius.pki.ddi_badge')" data-test="pki-ca-ddi" />
              <UBadge v-if="c.expired" color="error" variant="subtle" size="sm" :label="t('radius.pki.expired')" />
              <UBadge v-else-if="!c.chainOk" color="warning" variant="subtle" size="sm" icon="i-lucide-unlink" :label="t('radius.pki.chain_broken')" data-test="pki-ca-broken" />
              <span class="ml-auto flex gap-1">
                <UButton size="xs" color="neutral" variant="outline" icon="i-lucide-ban" :label="t('radius.pki.crl_btn')" :data-test="`pki-ca-crl-${c.name}`" @click="openCrl(c)" />
                <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" :title="t('common.delete')" :data-test="`pki-ca-del-${c.name}`" @click="delCa(c)" />
              </span>
            </div>
            <div class="text-xs text-muted font-mono break-all">{{ c.info.subject }}</div>
            <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
              <span>{{ t('radius.pki.valid_until', { d: day(c.info.notAfter) }) }}</span>
              <span class="flex items-center gap-1"><UBadge :color="(crlState(c).color as any)" variant="subtle" size="sm" :label="t(`radius.pki.crl_${crlState(c).key}`)" data-test="pki-ca-crlstate" />
                <template v-if="c.crl">{{ t('radius.pki.crl_detail', { n: c.crl.revoked, d: day(c.crl.nextUpdate) }) }}</template></span>
              <span v-if="c.crlError" class="text-error" data-test="pki-ca-crlerror">{{ t('radius.pki.crl_error', { e: t(`err.radius_pki_${c.crlError.code}`) }) }}</span>
            </div>
          </li>
        </ul>
        <div class="mt-4 flex flex-col gap-2">
          <USwitch :model-value="view.checkCrl" :disabled="optBusy" :label="t('radius.pki.check_crl')" data-test="pki-checkcrl" @update:model-value="setCheckCrl" />
          <UAlert v-if="!view.checkCrl" color="warning" variant="subtle" icon="i-lucide-shield-alert" :title="t('radius.pki.check_crl_off_title')" :description="t('radius.pki.check_crl_off_body')" data-test="pki-checkcrl-warn" />
          <p v-else class="text-xs text-dimmed">{{ t('radius.pki.check_crl_note') }}</p>
        </div>
      </UCard>

      <!-- Serveur -->
      <UCard>
        <template #header>
          <div class="flex items-center gap-2"><UIcon name="i-lucide-server-cog" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.pki.server_title') }}</h2></div>
          <p class="text-sm text-muted mt-1">{{ t('radius.pki.server_desc') }}</p>
        </template>
        <div v-if="view.server" class="flex flex-col gap-3" data-test="pki-server">
          <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <div class="sm:col-span-2"><dt class="text-muted">{{ t('radius.pki.f_subject') }}</dt><dd class="font-mono break-all">{{ view.server.subject }}</dd></div>
            <div><dt class="text-muted">{{ t('radius.pki.f_issuer') }}</dt><dd class="font-mono break-all">{{ view.server.issuer }}</dd></div>
            <div><dt class="text-muted">{{ t('radius.pki.f_expires') }}</dt><dd :class="daysLeft(view.server.notAfter) < 30 ? 'text-warning' : ''">{{ day(view.server.notAfter) }} <span class="text-muted">({{ t('radius.pki.days_left', { n: daysLeft(view.server.notAfter) }) }})</span></dd></div>
            <div><dt class="text-muted">{{ t('radius.pki.f_key') }}</dt><dd>{{ view.server.keyType.toUpperCase() }}{{ view.server.keyBits ? ' ' + view.server.keyBits : '' }}</dd></div>
            <div><dt class="text-muted">{{ t('radius.pki.f_chain') }}</dt><dd><UBadge :color="view.server.chainOk ? 'success' : 'warning'" variant="subtle" :label="view.server.chainOk ? t('radius.pki.chain_ok') : t('radius.pki.chain_broken')" /></dd></div>
            <div v-if="view.server.sans.length" class="sm:col-span-2"><dt class="text-muted">{{ t('radius.pki.f_sans') }}</dt><dd class="font-mono break-all">{{ view.server.sans.join(', ') }}</dd></div>
            <div class="sm:col-span-2"><dt class="text-muted">{{ t('radius.pki.f_fp') }}</dt><dd class="font-mono text-xs break-all">{{ view.server.fingerprint }}</dd></div>
          </dl>
          <div class="flex flex-wrap gap-2">
            <UButton color="neutral" variant="outline" icon="i-lucide-file-signature" :label="t('radius.pki.csr_new')" data-test="pki-csr-open" @click="openCsr" />
            <UButton color="neutral" variant="outline" icon="i-lucide-upload" :label="t('radius.pki.import')" data-test="pki-import-open" @click="openImport" />
            <UButton color="error" variant="ghost" icon="i-lucide-trash-2" :label="t('common.delete')" data-test="pki-server-del" @click="delServer" />
          </div>
        </div>
        <div v-else class="flex flex-col gap-3">
          <p class="text-sm text-muted" data-test="pki-server-none">{{ t('radius.pki.server_none') }}</p>
          <div class="flex flex-wrap gap-2">
            <UButton icon="i-lucide-file-signature" :label="t('radius.pki.csr_new')" data-test="pki-csr-open" @click="openCsr" />
            <UButton color="neutral" variant="outline" icon="i-lucide-upload" :label="t('radius.pki.import')" data-test="pki-import-open" @click="openImport" />
          </div>
        </div>

        <div v-if="view.pending" class="mt-4 flex flex-col gap-2 border border-default rounded-md p-3" data-test="pki-pending">
          <div class="flex flex-wrap items-center gap-2"><UBadge color="info" variant="subtle" icon="i-lucide-hourglass" :label="t('radius.pki.pending')" />
            <span class="text-sm">{{ t('radius.pki.pending_detail', { cn: view.pending.cn, d: day(view.pending.createdAt) }) }}</span></div>
          <p class="text-sm text-muted">{{ t('radius.pki.pending_help') }}</p>
          <UTextarea :model-value="view.pending.csrPem" readonly :rows="6" class="w-full font-mono text-xs" data-test="pki-csr-pem" />
          <div class="flex flex-wrap gap-2">
            <UButton size="sm" color="neutral" variant="outline" icon="i-lucide-copy" :label="t('common.copy')" data-test="pki-csr-copy" @click="copy(view.pending.csrPem)" />
            <UButton size="sm" icon="i-lucide-file-check" :label="t('radius.pki.sign_paste')" data-test="pki-sign-open" @click="openSign" />
            <UButton size="sm" color="error" variant="ghost" icon="i-lucide-x" :label="t('radius.pki.csr_cancel')" data-test="pki-csr-cancel" @click="cancelCsr" />
          </div>
        </div>
        <UAlert color="neutral" variant="subtle" icon="i-lucide-lightbulb" class="mt-4" :title="t('radius.pki.adcs_title')" :description="t('radius.pki.adcs_body')" data-test="pki-adcs-hint" />
      </UCard>

      <!-- Vérification d'un certificat client -->
      <UCard>
        <template #header>
          <div class="flex items-center gap-2"><UIcon name="i-lucide-badge-check" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.pki.chk_title') }}</h2></div>
          <p class="text-sm text-muted mt-1">{{ t('radius.pki.chk_desc') }}</p>
        </template>
        <form class="flex flex-col gap-3" @submit.prevent="checkClient">
          <UFormField :label="t('radius.pki.chk_pem')" :help="t('radius.pki.chk_help')"><UTextarea v-model="chk.pem" :rows="4" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" data-test="pki-chk-pem" /></UFormField>
          <div class="flex flex-wrap items-center gap-3">
            <input type="file" accept=".pem,.crt,.cer,.der,.p7b" class="text-sm" :aria-label="t('radius.pki.file')" data-test="pki-chk-file" @change="pick('chk', $event)">
            <UCheckbox v-model="chk.directory" :label="t('radius.pki.chk_dir')" data-test="pki-chk-dir" />
            <UButton type="submit" class="ml-auto" icon="i-lucide-search-check" :loading="chk.busy" :disabled="!chk.pem.trim() && !files.chk" :label="t('radius.pki.chk_run')" data-test="pki-chk-run" />
          </div>
          <UAlert v-if="chk.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="chk.err" role="alert" data-test="pki-chk-error" />
        </form>
        <div v-if="chkRes" class="mt-4 flex flex-col gap-3" data-test="pki-chk-result">
          <div class="flex flex-wrap items-center gap-2">
            <UBadge :color="chkRes.ok ? 'success' : 'error'" variant="solid" :icon="chkRes.ok ? 'i-lucide-badge-check' : 'i-lucide-badge-x'" :label="chkRes.ok ? t('radius.pki.chk_ok') : t('radius.pki.chk_ko')" data-test="pki-chk-verdict" />
            <span v-if="!chkRes.ok" class="text-sm text-error" data-test="pki-chk-reason">{{ t(`radius.pki.chk_code.${chkRes.chain.code}`) }}</span>
            <UBadge color="neutral" variant="subtle" :label="t(`radius.pki.rev.${chkRes.revocation}`)" data-test="pki-chk-rev" />
            <UBadge v-if="!chkRes.identity.clientAuth" color="warning" variant="subtle" :label="t('radius.pki.chk_noeku')" />
          </div>
          <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <div class="sm:col-span-2"><dt class="text-muted">{{ t('radius.pki.f_subject') }}</dt><dd class="font-mono break-all">{{ chkRes.identity.subject }}</dd></div>
            <div><dt class="text-muted">{{ t('radius.pki.f_issuer') }}</dt><dd class="font-mono break-all">{{ chkRes.identity.issuer }}</dd></div>
            <div><dt class="text-muted">{{ t('radius.pki.f_expires') }}</dt><dd>{{ day(chkRes.identity.notAfter) }}</dd></div>
            <div v-if="chkRes.identity.upn"><dt class="text-muted">UPN</dt><dd class="font-mono" data-test="pki-chk-upn">{{ chkRes.identity.upn }}</dd></div>
            <div v-if="chkRes.identity.dns.length"><dt class="text-muted">DNS</dt><dd class="font-mono break-all">{{ chkRes.identity.dns.join(', ') }}</dd></div>
            <div v-if="chkRes.identity.email.length"><dt class="text-muted">{{ t('radius.pki.f_email') }}</dt><dd class="font-mono break-all">{{ chkRes.identity.email.join(', ') }}</dd></div>
            <div v-if="chkRes.identity.crlUrls.length" class="sm:col-span-2"><dt class="text-muted">{{ t('radius.pki.f_cdp') }}</dt><dd class="font-mono text-xs break-all" data-test="pki-chk-cdp">{{ chkRes.identity.crlUrls.join('  ·  ') }}</dd></div>
          </dl>
          <template v-if="chkRes.account">
            <UAlert v-if="!chkRes.account.checked" color="warning" variant="subtle" icon="i-lucide-network" :title="accountMsg" data-test="pki-chk-acc-skip" />
            <UAlert v-else-if="!chkRes.account.found" color="warning" variant="subtle" icon="i-lucide-search-x" :title="chkRes.account.ambiguous ? t('radius.dir.ambiguous') : t('radius.dir.not_found')" data-test="pki-chk-acc-none" />
            <div v-else class="border border-default rounded-md p-3 text-sm flex flex-col gap-2" data-test="pki-chk-account">
              <div class="flex flex-wrap items-center gap-2"><UBadge :color="chkRes.account.state.usable ? 'success' : 'error'" variant="subtle" :label="chkRes.account.state.usable ? t('radius.dir.usable') : t('radius.dir.unusable')" />
                <span class="font-mono">{{ chkRes.account.sam }}</span><span class="text-muted">{{ chkRes.account.displayName }}</span></div>
              <div class="text-muted">{{ t('radius.dir.groups') }} ({{ chkRes.account.groups.length }}) : <span class="font-mono">{{ chkRes.account.groups.map((g: any) => g.name).join(', ') || '—' }}</span></div>
            </div>
          </template>
        </div>
      </UCard>
    </template>

    <!-- Ajouter une autorité -->
    <UModal v-model:open="caM.open" :title="t('radius.pki.ca_add')" :description="t('radius.pki.ca_add_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="addCa">
          <UFormField :label="t('radius.pki.pem_label')"><UTextarea v-model="caM.pem" :rows="8" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" data-test="pki-ca-pem" /></UFormField>
          <UFormField :label="t('radius.pki.or_file')" :help="t('radius.pki.file_help')"><input type="file" accept=".pem,.crt,.cer,.der,.p7b" class="text-sm" data-test="pki-ca-file" @change="pick('ca', $event)"></UFormField>
          <UFormField :label="t('radius.pki.ca_name')" :help="t('radius.pki.ca_name_help')"><UInput v-model="caM.name" class="w-full" maxlength="80" data-test="pki-ca-name" /></UFormField>
          <UAlert v-if="caM.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="caM.err" role="alert" data-test="pki-ca-error" />
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="caM.open = false" /><UButton type="submit" :loading="caM.busy" :disabled="!caM.pem.trim() && !files.ca" :label="t('radius.pki.ca_add')" data-test="pki-ca-submit" /></div>
        </form>
      </template>
    </UModal>

    <!-- CRL d'une autorité -->
    <UModal v-model:open="crlM.open" :title="t('radius.pki.crl_title', { name: crlCa?.name ?? '' })" :description="t('radius.pki.crl_desc')">
      <template #body>
        <div class="flex flex-col gap-4">
          <div v-if="crlCa?.crl" class="text-sm text-muted" data-test="pki-crl-current">{{ t('radius.pki.crl_current', { n: crlCa.crl.revoked, a: day(crlCa.crl.thisUpdate), b: day(crlCa.crl.nextUpdate), src: t(`radius.pki.src_${crlCa.crl.source}`) }) }}</div>
          <UFormField :label="t('radius.pki.crl_url')" :help="t('radius.pki.crl_url_help')"><UInput v-model="crlM.url" class="w-full font-mono" placeholder="http://pki.exemple.fr/CertEnroll/ca.crl" autocomplete="off" data-test="pki-crl-url" /></UFormField>
          <div class="flex flex-wrap gap-2">
            <UButton color="neutral" variant="outline" :loading="crlM.busy === 'save'" :disabled="!!crlM.busy" :label="t('common.save')" data-test="pki-crl-save" @click="saveCrlUrl" />
            <UButton icon="i-lucide-download" :loading="crlM.busy === 'fetch'" :disabled="!crlM.url.trim() || (!!crlM.busy && crlM.busy !== 'fetch')" :label="t('radius.pki.crl_fetch')" data-test="pki-crl-fetch" @click="fetchCrl" />
          </div>
          <UFormField :label="t('radius.pki.crl_file')" :help="t('radius.pki.crl_file_help')"><input type="file" accept=".crl,.pem,.der" class="text-sm" data-test="pki-crl-file" @change="pick('crl', $event)"></UFormField>
          <div><UButton color="neutral" variant="outline" icon="i-lucide-upload" :loading="crlM.busy === 'upload'" :disabled="!files.crl || (!!crlM.busy && crlM.busy !== 'upload')" :label="t('radius.pki.crl_send')" data-test="pki-crl-upload" @click="uploadCrl" /></div>
          <UAlert v-if="crlM.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="crlM.err" role="alert" data-test="pki-crl-error" />
          <UAlert v-if="crlM.ok" color="success" variant="subtle" icon="i-lucide-circle-check" :title="crlM.ok" role="status" data-test="pki-crl-ok" />
          <p class="text-xs text-dimmed">{{ t('radius.pki.crl_note') }}</p>
          <div class="flex justify-end"><UButton color="neutral" variant="outline" :label="t('common.close')" @click="crlM.open = false" /></div>
        </div>
      </template>
    </UModal>

    <!-- Demande de certificat (CSR) -->
    <UModal v-model:open="csrM.open" :title="t('radius.pki.csr_new')" :description="t('radius.pki.csr_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="makeCsr">
          <UFormField :label="t('radius.pki.csr_cn')" :help="t('radius.pki.csr_cn_help')" required><UInput v-model="csrM.cn" class="w-full font-mono" placeholder="radius.exemple.fr" autocomplete="off" data-test="pki-csr-cn" /></UFormField>
          <UFormField :label="t('radius.pki.csr_sans')" :help="t('radius.pki.csr_sans_help')"><UTextarea v-model="csrM.sans" :rows="2" class="w-full font-mono" placeholder="radius2.exemple.fr" data-test="pki-csr-sans" /></UFormField>
          <UFormField :label="t('radius.pki.csr_kt')"><URadioGroup v-model="csrM.keyType" :items="KEYS" data-test="pki-csr-kt" /></UFormField>
          <UAlert v-if="csrM.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="csrM.err" role="alert" data-test="pki-csr-error" />
          <p class="text-xs text-dimmed">{{ t('radius.pki.csr_note') }}</p>
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="csrM.open = false" /><UButton type="submit" :loading="csrM.busy" :disabled="!csrM.cn.trim()" :label="t('radius.pki.csr_make')" data-test="pki-csr-submit" /></div>
        </form>
      </template>
    </UModal>

    <!-- Certificat signé -->
    <UModal v-model:open="signM.open" :title="t('radius.pki.sign_paste')" :description="t('radius.pki.sign_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="sendSigned">
          <UFormField :label="t('radius.pki.pem_label')"><UTextarea v-model="signM.pem" :rows="8" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" data-test="pki-sign-pem" /></UFormField>
          <UFormField :label="t('radius.pki.or_file')" :help="t('radius.pki.file_help')"><input type="file" accept=".pem,.crt,.cer,.der,.p7b" class="text-sm" data-test="pki-sign-file" @change="pick('sign', $event)"></UFormField>
          <UAlert v-if="signM.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="signM.err" role="alert" data-test="pki-sign-error" />
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="signM.open = false" /><UButton type="submit" :loading="signM.busy" :disabled="!signM.pem.trim() && !files.sign" :label="t('radius.pki.sign_send')" data-test="pki-sign-submit" /></div>
        </form>
      </template>
    </UModal>

    <!-- Importer certificat + clé -->
    <UModal v-model:open="impM.open" :title="t('radius.pki.import')" :description="t('radius.pki.imp_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="doImport">
          <URadioGroup v-model="impM.mode" :items="MODES" orientation="horizontal" data-test="pki-imp-mode" />
          <template v-if="impM.mode === 'pem'">
            <UFormField :label="t('radius.pki.imp_cert')"><UTextarea v-model="impM.pem" :rows="5" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" data-test="pki-imp-pem" /></UFormField>
            <UFormField :label="t('radius.pki.or_file')"><input type="file" accept=".pem,.crt,.cer,.der,.p7b" class="text-sm" data-test="pki-imp-certfile" @change="pick('impCert', $event)"></UFormField>
            <UFormField :label="t('radius.pki.imp_key')" :help="t('radius.pki.imp_key_help')"><UTextarea v-model="impM.key" :rows="5" class="w-full font-mono text-xs" placeholder="-----BEGIN PRIVATE KEY-----" autocomplete="off" data-test="pki-imp-key" /></UFormField>
            <UFormField :label="t('radius.pki.or_file')"><input type="file" accept=".key,.pem" class="text-sm" data-test="pki-imp-keyfile" @change="pick('impKey', $event)"></UFormField>
            <UFormField :label="t('radius.pki.imp_keypw')" :help="t('radius.pki.imp_keypw_help')"><UInput v-model="impM.keyPassword" type="password" class="w-full" autocomplete="new-password" data-test="pki-imp-keypw" /></UFormField>
          </template>
          <template v-else>
            <UFormField :label="t('radius.pki.imp_p12file')"><input type="file" accept=".p12,.pfx" class="text-sm" data-test="pki-imp-p12" @change="pick('p12', $event)"></UFormField>
            <UFormField :label="t('radius.pki.imp_p12pw')"><UInput v-model="impM.p12Password" type="password" class="w-full" autocomplete="new-password" data-test="pki-imp-p12pw" /></UFormField>
          </template>
          <UAlert color="neutral" variant="subtle" icon="i-lucide-lock" :description="t('radius.pki.imp_note')" />
          <UAlert v-if="impM.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="impM.err" role="alert" data-test="pki-imp-error" />
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="impM.open = false" /><UButton type="submit" :loading="impM.busy" :label="t('radius.pki.import')" data-test="pki-imp-submit" /></div>
        </form>
      </template>
    </UModal>

    <!-- Certificat du serveur émis par la PKI du DDI -->
    <UModal v-model:open="dsv.open" :title="t('radius.pki.ddi_server_title')" :description="t('radius.pki.ddi_server_desc')" :dismissible="!dsv.busy">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="ddiServer">
          <UAlert v-if="view?.server" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('radius.pki.ddi_replace_title')" :description="t('radius.pki.ddi_replace_hint')" data-test="pki-ddi-replace-warn" />
          <UFormField :label="t('pki.ca.name')"><USelect v-model="dsv.ca" :items="(ddi?.issuers ?? []).map((x: any) => x.name)" class="w-full" data-test="pki-ddi-ca" /></UFormField>
          <UFormField :label="t('pki.cert.cn')" :help="t('radius.pki.ddi_cn_help')"><UInput v-model="dsv.cn" class="w-full" maxlength="64" placeholder="radius.lab.test" data-test="pki-ddi-cn" /></UFormField>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <UFormField :label="t('pki.cert.san_dns')" :help="t('pki.cert.san_help', { max: 8 })"><UTextarea v-model="dsv.dns" :rows="3" class="w-full font-mono text-xs" data-test="pki-ddi-dns" /></UFormField>
            <UFormField :label="t('pki.cert.san_ip')" :help="t('pki.cert.san_help', { max: 4 })"><UTextarea v-model="dsv.ip" :rows="3" class="w-full font-mono text-xs" data-test="pki-ddi-ip" /></UFormField>
          </div>
          <UFormField :label="t('pki.ca.alg')"><USelect v-model="dsv.alg" :items="DDI_ALGS" class="w-full sm:w-1/2" data-test="pki-ddi-alg" /></UFormField>
          <p v-if="dsv.busy" class="text-xs text-muted" role="status">{{ t('pki.cert.working') }}</p>
          <UAlert v-if="dsv.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="dsv.err" role="alert" data-test="pki-ddi-server-error" />
          <div class="flex justify-end gap-2">
            <UButton type="button" color="neutral" variant="outline" :label="t('common.cancel')" :disabled="dsv.busy" @click="dsv.open = false" />
            <UButton type="submit" :loading="dsv.busy" :disabled="!dsvOk" :label="t('pki.cert.issue_go')" data-test="pki-ddi-issue" />
          </div>
        </form>
      </template>
    </UModal>
  </div>
</template>
