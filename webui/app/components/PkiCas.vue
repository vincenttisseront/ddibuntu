<script setup lang="ts">
// Autorités de la PKI du DDI (0.14.1) : liste (lue dans ce que root publie), création d'une racine de laboratoire ou d'une émettrice (signée par une racine du
// DDI ou par une racine HORS LIGNE), import du certificat signé, CRL. La console ne touche à aucune clé : elle dépose des demandes que root revalide.
const props = defineProps<{ status: any; waiting: boolean; settle: () => Promise<void>; result?: { at: number; action: string; ok: boolean; message: string } | null }>()
const emit = defineEmits<{ (e: 'changed'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const fmt = useFmt()

const data = ref<any>(null), busy = ref(''), err = ref('')
const cas = computed<any[]>(() => data.value?.cas ?? [])
const byName = computed<Record<string, any>>(() => Object.fromEntries(cas.value.map((c) => [c.name, c])))
const ready = computed(() => props.status?.state === 'healthy')
const locked = computed(() => props.waiting || !!busy.value)
// Dernier résultat de root pour une action sur les autorités, tant qu'il est récent : sans lui, un fichier PKCS#12 refusé (mauvais mot de passe, chaîne incomplète…) ne dirait rien
const lastResult = computed(() => (props.result && props.result.action.startsWith('ca_') && Date.now() / 1000 - props.result.at < 900 ? props.result : null))
async function load() { try { data.value = await api.call('GET', '/pki/cas', undefined, { silent: true }) } catch (e: any) { err.value = e?.info?.message ?? '' } }
async function done() { await props.settle(); await load(); emit('changed') }
const errOf = (e: any) => e?.info?.message ?? t('err.internal')
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }

// ---- Lecture d'un fichier choisi (certificat ou CRL : PEM en texte, DER en base64) ----
async function fileBlob(f: File): Promise<{ pem: string } | { der: string }> {
  const u = new Uint8Array(await f.arrayBuffer())
  const head = new TextDecoder().decode(u.subarray(0, 12))
  if (head.startsWith('-----BEGIN')) return { pem: new TextDecoder().decode(u) }
  let s = ''
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000))
  return { der: btoa(s) }
}
const files = reactive<Record<string, File | null>>({})
function pick(k: string, ev: Event) { files[k] = (ev.target as HTMLInputElement).files?.[0] ?? null }
async function blobOf(pem: string, k: string) { return files[k] ? fileBlob(files[k]!) : { pem } }

// ---- Présentation ----
const stateColor = (s: string) => (s === 'active' ? 'success' : s === 'waiting' ? 'warning' : 'neutral')
const dateOnly = (iso: string) => (iso ? fmt.dateTime(Date.parse(iso)) : '—')
const daysLeft = (iso: string) => Math.floor((Date.parse(iso) - Date.now()) / 86400_000)
const keyText = (c: any) => (c.keyAlg === 'EC' ? `ECDSA ${c.curve || c.keyBits}` : c.keyAlg ? `${c.keyAlg} ${c.keyBits}` : '—')
function warnings(c: any): string[] {
  const w: string[] = []
  if (c.notAfter && c.state !== 'waiting') { const d = daysLeft(c.notAfter); if (d < 0) w.push(t('pki.ca.expired')); else if (d < 90) w.push(t('pki.ca.expiring', { n: d })) }
  if (c.crl?.nextUpdate) {
    const left = Date.parse(c.crl.nextUpdate) - Date.now()
    if (left < 0) w.push(t(c.kind === 'extroot' ? 'pki.ca.rootcrl_expired' : 'pki.ca.crl_expired'))
    else if (left < 86400_000 * (c.kind === 'extroot' ? 14 : 1)) w.push(t(c.kind === 'extroot' ? 'pki.ca.rootcrl_soon' : 'pki.ca.crl_soon'))
  }
  return w
}
// Vue en arbre (0.14.13) : la hiérarchie à gauche (racine → émettrices), le détail complet de l'autorité choisie à droite
const rows = computed(() => pkiTreeRows<any>(cas.value))
const pickedName = ref('')
const selected = computed(() => byName.value[pickedName.value] ?? rows.value[0]?.ca ?? null)
const kindIcon = (k: string) => (k === 'root' ? 'i-lucide-shield-check' : k === 'extroot' ? 'i-lucide-shield-off' : k === 'issuing' ? 'i-lucide-stamp' : 'i-lucide-shield-question')
const signSnippet = (c: any) => {
  const x = byName.value[c.extRoot]
  return ["cat > ca.ext <<'EOF'", 'basicConstraints=critical,CA:TRUE,pathlen:0', 'keyUsage=critical,keyCertSign,cRLSign', 'subjectKeyIdentifier=hash', 'authorityKeyIdentifier=keyid',
    `crlDistributionPoints=URI:${x?.crlUrl || t('pki.ca.root_crl_url')}`, `authorityInfoAccess=caIssuers;URI:${x?.certUrl || t('pki.ca.root_cert_url')}`, 'EOF',
    `openssl x509 -req -in ${c.name}.csr -CA racine.pem -CAkey racine.key -CAcreateserial -days 1825 -sha256 -extfile ca.ext -out ${c.name}.crt`].join('\n')
}
const dl = (c: any, k: 'cert' | 'chain' | 'csr' | 'crl') => `/api/pki/cas/${encodeURIComponent(c.name)}/${k}`
const dlName = (c: any, k: string) => ({ cert: `${c.name}.pem`, chain: `${c.name}.chain.pem`, csr: `${c.name}.csr`, crl: `${c.name}.crl` } as Record<string, string>)[k]

// ---- Création ----
const ALGS = [{ value: 'rsa3072', label: 'RSA 3072' }, { value: 'rsa4096', label: 'RSA 4096' }, { value: 'ecp256', label: 'ECDSA P-256' }, { value: 'ecp384', label: 'ECDSA P-384' }]
const cr = reactive({ open: false, kind: 'issuing' as 'root' | 'issuing', name: '', cn: '', o: '', ou: '', c: 'FR', alg: 'rsa3072', days: 1825, signedBy: 'external', chain: '', err: '', busy: false })
function openCreate(kind: 'root' | 'issuing') {
  // Nom et CN proposés (0.14.14) : DDI-Issuing-1 / « DDI Issuing CA 1 », au premier numéro libre ; à remplacer librement
  Object.assign(cr, { open: true, kind, ...suggestCaNames(kind, cas.value.map((c) => c.name)), o: '', ou: '', c: 'FR', alg: 'rsa3072', days: kind === 'root' ? 3650 : 1825, signedBy: 'external', chain: '', err: '', busy: false })
  files.chain = null
}
const signerItems = computed(() => [{ value: 'external', label: t('pki.ca.signer_external') }, ...(data.value?.signers ?? []).map((n: string) => ({ value: n, label: t('pki.ca.signer_ddi', { name: n }) }))])
const crValid = computed(() => !!cr.name.trim() && !!cr.cn.trim() && (cr.kind === 'root' || cr.signedBy !== 'external' || !!cr.chain.trim() || !!files.chain))
async function createCa() {
  cr.busy = true; cr.err = ''
  try {
    const dn = { cn: cr.cn.trim(), o: cr.o.trim(), ou: cr.ou.trim(), c: cr.c.trim().toUpperCase() }
    if (cr.kind === 'root') await api.call('POST', '/pki/cas/root', { name: cr.name.trim(), alg: cr.alg, days: Number(cr.days), ...dn })
    else await api.call('POST', '/pki/cas/issuing', { name: cr.name.trim(), alg: cr.alg, days: Number(cr.days), ...dn, signedBy: cr.signedBy,
      ...(cr.signedBy === 'external' ? { chain: await blobOf(cr.chain, 'chain') } : {}) })
    cr.open = false; toast.add({ title: t('pki.sent'), color: 'success' }); await done()
  } catch (e: any) { cr.err = errOf(e) } finally { cr.busy = false }
}

// ---- Reprise d'une autorité existante (PKCS#12) : le fichier et son mot de passe ne sont gardés que le temps de la requête, puis effacés de l'écran ----
const pk = reactive({ open: false, name: '', file: null as File | null, password: '', confirm: '', err: '', busy: false })
function openP12() { Object.assign(pk, { open: true, name: suggestImportName(cas.value.map((c) => c.name)), file: null, password: '', confirm: '', err: '', busy: false }) }
function pickP12(ev: Event) { pk.file = (ev.target as HTMLInputElement).files?.[0] ?? null }
const pkValid = computed(() => !!pk.name.trim() && !!pk.file && !!pk.password && pk.confirm.trim() === pk.name.trim())
async function importP12() {
  pk.busy = true; pk.err = ''
  try {
    const u = new Uint8Array(await pk.file!.arrayBuffer())
    let s = ''
    for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000))
    await api.call('POST', '/pki/cas/p12', { name: pk.name.trim(), p12: btoa(s), password: pk.password, confirm: pk.confirm.trim() })
    pk.open = false; toast.add({ title: t('pki.sent'), color: 'success' }); await done()
  } catch (e: any) { pk.err = errOf(e) } finally { pk.busy = false; pk.password = ''; pk.file = null }
}

// ---- Import du certificat signé / CRL de la racine hors ligne ----
const im = reactive({ open: false, ca: null as any, pem: '', err: '', busy: false })
function openImport(c: any) { Object.assign(im, { open: true, ca: c, pem: '', err: '', busy: false }); files.cert = null }
async function importCert() {
  im.busy = true; im.err = ''
  try { await api.call('POST', `/pki/cas/${encodeURIComponent(im.ca.name)}/import`, { certificate: await blobOf(im.pem, 'cert') }); im.open = false; toast.add({ title: t('pki.sent'), color: 'success' }); await done() }
  catch (e: any) { im.err = errOf(e) } finally { im.busy = false }
}
const rc = reactive({ open: false, ca: null as any, pem: '', err: '', busy: false })
function openRootCrl(c: any) { Object.assign(rc, { open: true, ca: c, pem: '', err: '', busy: false }); files.crl = null }
async function rootCrl() {
  rc.busy = true; rc.err = ''
  try { await api.call('POST', `/pki/cas/${encodeURIComponent(rc.ca.name)}/rootcrl`, { crl: await blobOf(rc.pem, 'crl') }); rc.open = false; toast.add({ title: t('pki.sent'), color: 'success' }); await done() }
  catch (e: any) { rc.err = errOf(e) } finally { rc.busy = false }
}
async function renewCrl(c: any) {
  busy.value = `crl:${c.name}`; err.value = ''
  try { await api.call('POST', `/pki/cas/${encodeURIComponent(c.name)}/crl`, {}); toast.add({ title: t('pki.sent'), color: 'success' }); await done() }
  catch (e: any) { err.value = errOf(e) } finally { busy.value = '' }
}
onMounted(load)
defineExpose({ load })
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('pki.ca.intro') }}</p>
    <UAlert v-if="!ready" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.ca.not_ready')" role="status" data-test="pki-ca-notready" />
    <UAlert v-if="status && status.installed && !status.recovery" color="warning" variant="subtle" icon="i-lucide-archive-restore" :title="t('pki.ca.no_recovery_title')" :description="t('pki.ca.no_recovery_body')" :actions="[{ label: t('pki.ca.no_recovery_go'), color: 'warning', variant: 'outline', to: '/pki#recovery' }]" data-test="pki-ca-norecovery" />
    <p v-if="err" class="text-sm text-error" role="alert" data-test="pki-ca-error">{{ err }}</p>
    <UAlert v-if="lastResult && !lastResult.ok" color="error" variant="subtle" icon="i-lucide-circle-x" :title="lastResult.message" :description="`${t('radius.last')} ${fmt.dateTime(lastResult.at * 1000)}`" role="alert" data-test="pki-ca-result-error" />
    <p v-else-if="lastResult" class="text-xs text-muted" role="status" data-test="pki-ca-result">{{ t('radius.last') }} {{ fmt.dateTime(lastResult.at * 1000) }} — ✔ {{ lastResult.message }}</p>

    <div class="flex flex-wrap gap-2">
      <UButton icon="i-lucide-plus" :label="t('pki.ca.add_issuing')" :disabled="!ready || locked" data-test="pki-ca-add-issuing" @click="openCreate('issuing')" />
      <UButton icon="i-lucide-flask-conical" color="neutral" variant="outline" :label="t('pki.ca.add_root')" :disabled="!ready || locked" data-test="pki-ca-add-root" @click="openCreate('root')" />
      <UButton icon="i-lucide-file-key" color="neutral" variant="outline" :label="t('pki.ca.add_p12')" :disabled="!ready || locked" data-test="pki-ca-add-p12" @click="openP12" />
    </div>

    <p v-if="!cas.length" class="text-sm text-muted" data-test="pki-ca-empty">{{ t('pki.ca.empty') }}</p>
    <div v-if="cas.length" class="grid grid-cols-1 lg:grid-cols-[20rem_minmax(0,1fr)] gap-4 items-start">
    <nav class="flex flex-col gap-1 rounded-lg border border-default p-2 lg:sticky lg:top-2" :aria-label="t('pki.ca.tree')" data-test="pki-ca-tree">
      <button v-for="r in rows" :key="r.ca.name" type="button" :data-test="`pki-ca-node-${r.ca.name}`" :aria-current="selected?.name === r.ca.name ? 'true' : undefined"
        class="flex items-center gap-1 rounded-md px-2 py-1.5 text-left text-sm hover:bg-elevated focus-visible:outline-2 focus-visible:outline-primary" :class="selected?.name === r.ca.name ? 'bg-elevated ring-1 ring-primary' : ''"
        @click="pickedName = r.ca.name">
        <span v-for="(g, i) in r.guides" :key="i" class="inline-block w-4 shrink-0 self-stretch" :class="g ? 'border-l border-default' : ''" aria-hidden="true" />
        <span v-if="r.depth" class="inline-block w-3 shrink-0 self-center border-t border-default -ml-0" aria-hidden="true" />
        <UIcon :name="kindIcon(r.ca.kind)" class="size-4 shrink-0" :class="r.ca.state === 'active' ? 'text-success' : r.ca.state === 'waiting' ? 'text-warning' : 'text-muted'" />
        <span class="flex min-w-0 flex-1 flex-col">
          <span class="truncate font-mono font-medium">{{ r.ca.name }}</span>
          <span class="truncate text-xs text-muted">{{ t(`pki.ca.kind.${r.ca.kind}`) }}<template v-if="r.ca.state !== 'active'"> · <span class="text-warning">{{ t(`pki.ca.state.${r.ca.state}`) }}</span></template><template v-else-if="r.ca.notAfter"> · → {{ r.ca.notAfter.slice(0, 10) }}</template></span>
        </span>
        <UIcon v-if="warnings(r.ca).length" name="i-lucide-triangle-alert" class="size-4 shrink-0 text-warning" :aria-label="t('pki.ca.has_warning')" data-test="pki-ca-node-warn" />
      </button>
    </nav>
    <template v-if="selected">
    <UCard v-for="c in [selected]" :key="c.name" :data-test="`pki-ca-${c.name}`">
      <template #header>
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="font-medium font-mono break-all">{{ c.name }}</span>
          <div class="flex gap-2">
            <UBadge color="neutral" variant="subtle" :label="t(`pki.ca.kind.${c.kind}`)" />
            <UBadge v-if="c.imported" color="warning" variant="subtle" :label="t('pki.ca.imported')" data-test="pki-ca-imported-badge" />
            <UBadge :color="(stateColor(c.state) as any)" variant="subtle" :label="t(`pki.ca.state.${c.state}`)" data-test="pki-ca-state" />
          </div>
        </div>
      </template>
      <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-sm">
        <div class="sm:col-span-2"><dt class="text-muted">{{ t('pki.ca.dn') }}</dt><dd class="font-mono break-all">{{ c.dn || '—' }}</dd></div>
        <div v-if="c.issuer && !c.selfSigned" class="sm:col-span-2"><dt class="text-muted">{{ t('pki.ca.issuer') }}</dt><dd class="font-mono break-all">{{ c.issuer }}</dd></div>
        <div v-if="c.notAfter"><dt class="text-muted">{{ t('pki.ca.validity') }}</dt><dd>{{ dateOnly(c.notBefore) }} → {{ dateOnly(c.notAfter) }}</dd></div>
        <div v-if="c.keyAlg"><dt class="text-muted">{{ t('pki.ca.key') }}</dt><dd class="font-mono">{{ keyText(c) }} · {{ c.sigAlg }}</dd></div>
        <div v-if="c.signedBy && c.kind !== 'extroot'"><dt class="text-muted">{{ t('pki.ca.signed_by') }}</dt><dd class="font-mono">{{ c.signedBy === 'self' ? t('pki.ca.self_signed') : c.signedBy === 'external' ? (c.extRoot || t('pki.ca.signer_external')) : c.signedBy }}</dd></div>
        <div v-if="c.sha256"><dt class="text-muted">{{ t('pki.ca.sha') }}</dt><dd class="font-mono break-all text-xs">{{ c.sha256 }}</dd></div>
        <div v-if="c.state !== 'waiting' && c.kind !== 'unknown'"><dt class="text-muted">{{ t('pki.ca.crl') }}</dt>
          <dd v-if="c.crl">{{ t('pki.ca.crl_info', { n: c.crl.number, a: dateOnly(c.crl.thisUpdate), b: dateOnly(c.crl.nextUpdate) }) }}</dd><dd v-else class="text-muted">{{ t('pki.ca.crl_none') }}</dd></div>
        <div v-if="c.crlUrl && c.state !== 'waiting'" class="sm:col-span-2"><dt class="text-muted">{{ t('pki.ca.crl_url') }}</dt>
          <dd class="flex gap-2 items-center"><code class="break-all text-xs flex-1">{{ c.crlUrl }}</code><UButton size="xs" icon="i-lucide-copy" color="neutral" variant="ghost" :aria-label="t('common.copy')" @click="copy(c.crlUrl)" /></dd></div>
      </dl>
      <div v-if="c.state !== 'waiting' && c.kind !== 'unknown'" class="mt-3 flex flex-wrap items-center gap-2 text-sm" :data-test="`pki-ca-ad-${c.name}`">
        <span class="text-muted">{{ t('pki.ad.card') }}</span>
        <template v-if="c.publication">
          <UBadge :color="(c.publication.state === 'published' && c.publication.current ? 'success' : c.publication.state === 'pending' ? 'info' : c.publication.state === 'withdrawn' ? 'neutral' : c.publication.state === 'published' ? 'info' : 'warning')" variant="subtle" :label="t(`pki.ad.st.${c.publication.state === 'published' && !c.publication.current ? 'pending' : c.publication.state}`)" data-test="pki-ca-ad-state" />
          <span v-if="c.publication.reason && ['failed', 'conflict', 'drift'].includes(c.publication.state)" class="text-muted">{{ t(`pki.ad.reason.${c.publication.reason}`) }}</span>
        </template>
        <template v-else-if="data?.adEnabled"><UBadge color="info" variant="subtle" :label="t('pki.ad.st.pending')" data-test="pki-ca-ad-state" /></template>
        <template v-else><span class="text-muted" data-test="pki-ca-ad-off">{{ t('pki.ad.card_off') }}</span><a href="#ad" class="text-primary underline" data-test="pki-ca-ad-link">{{ t('pki.ad.card_off_link') }}</a></template>
      </div>
      <UAlert v-if="c.imported" class="mt-3" color="info" variant="subtle" icon="i-lucide-file-key" :title="t('pki.ca.imported_note')" data-test="pki-ca-imported" />
      <UAlert v-if="c.kind === 'root' && c.selfSigned" class="mt-3" color="info" variant="subtle" icon="i-lucide-flask-conical" :title="t('pki.ca.lab_root')" data-test="pki-ca-lab" />
      <UAlert v-for="(w, i) in warnings(c)" :key="i" class="mt-3" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="w" data-test="pki-ca-warn" />

      <div v-if="c.state === 'waiting'" class="mt-3 flex flex-col gap-2" data-test="pki-ca-sign">
        <p class="text-sm font-medium">{{ t('pki.ca.sign_title') }}</p>
        <ol class="list-decimal ml-5 text-sm text-muted flex flex-col gap-1"><li>{{ t('pki.ca.sign_1') }}</li><li>{{ t('pki.ca.sign_2') }}</li><li>{{ t('pki.ca.sign_3') }}</li></ol>
        <div class="relative"><pre class="text-xs font-mono bg-elevated rounded p-3 overflow-x-auto" data-test="pki-ca-snippet">{{ signSnippet(c) }}</pre>
          <UButton class="absolute top-1 right-1" size="xs" icon="i-lucide-copy" color="neutral" variant="ghost" :aria-label="t('common.copy')" @click="copy(signSnippet(c))" /></div>
        <p class="text-xs text-dimmed">{{ t('pki.ca.sign_hint') }}</p>
      </div>

      <div class="flex flex-wrap gap-2 mt-4">
        <UButton v-if="c.files.csr" size="sm" icon="i-lucide-download" color="neutral" variant="outline" :label="t('pki.ca.dl_csr')" :href="dl(c, 'csr')" :download="dlName(c, 'csr')" external data-test="pki-ca-dl-csr" />
        <UButton v-if="c.state === 'waiting'" size="sm" icon="i-lucide-upload" :label="t('pki.ca.import')" :disabled="!ready || locked" data-test="pki-ca-import" @click="openImport(c)" />
        <UButton v-if="c.files.cert" size="sm" icon="i-lucide-download" color="neutral" variant="outline" :label="t('pki.ca.dl_cert')" :href="dl(c, 'cert')" :download="dlName(c, 'cert')" external data-test="pki-ca-dl-cert" />
        <UButton v-if="c.files.chain" size="sm" icon="i-lucide-download" color="neutral" variant="outline" :label="t('pki.ca.dl_chain')" :href="dl(c, 'chain')" :download="dlName(c, 'chain')" external data-test="pki-ca-dl-chain" />
        <UButton v-if="c.files.crl" size="sm" icon="i-lucide-download" color="neutral" variant="outline" :label="t('pki.ca.dl_crl')" :href="dl(c, 'crl')" :download="dlName(c, 'crl')" external data-test="pki-ca-dl-crl" />
        <UButton v-if="c.state === 'active' && (c.kind === 'root' || c.kind === 'issuing') && c.managed" size="sm" icon="i-lucide-refresh-cw" color="neutral" variant="ghost" :label="t('pki.ca.renew_crl')"
          :loading="busy === `crl:${c.name}`" :disabled="!ready || locked" data-test="pki-ca-renew" @click="renewCrl(c)" />
        <UButton v-if="c.kind === 'extroot'" size="sm" icon="i-lucide-upload" color="neutral" variant="outline" :label="t('pki.ca.rootcrl')" :disabled="!ready || locked" data-test="pki-ca-rootcrl" @click="openRootCrl(c)" />
      </div>
    </UCard>
    </template>
    </div>

    <!-- Création -->
    <UModal v-model:open="cr.open" :title="cr.kind === 'root' ? t('pki.ca.add_root') : t('pki.ca.add_issuing')" :description="cr.kind === 'root' ? t('pki.ca.root_desc') : t('pki.ca.issuing_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="createCa">
          <UAlert v-if="cr.kind === 'root'" color="warning" variant="subtle" icon="i-lucide-flask-conical" :title="t('pki.ca.root_warn')" />
          <UFormField :label="t('pki.ca.name')" :help="t('pki.ca.name_help')"><UInput v-model="cr.name" class="w-full font-mono" maxlength="48" placeholder="DDI-Issuing-1" data-test="pki-ca-name" /></UFormField>
          <UFormField :label="t('pki.ca.cn')" :help="t('pki.ca.dn_help')"><UInput v-model="cr.cn" class="w-full" maxlength="64" placeholder="DDI Issuing CA 1" data-test="pki-ca-cn" /></UFormField>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <UFormField :label="t('pki.ca.o')"><UInput v-model="cr.o" class="w-full" maxlength="64" data-test="pki-ca-o" /></UFormField>
            <UFormField :label="t('pki.ca.ou')"><UInput v-model="cr.ou" class="w-full" maxlength="64" data-test="pki-ca-ou" /></UFormField>
            <UFormField :label="t('pki.ca.c')"><UInput v-model="cr.c" class="w-full font-mono" maxlength="2" placeholder="FR" data-test="pki-ca-c" /></UFormField>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <UFormField :label="t('pki.ca.alg')"><USelect v-model="cr.alg" :items="ALGS" class="w-full" data-test="pki-ca-alg" /></UFormField>
            <UFormField :label="t('pki.ca.days')" :help="cr.kind === 'root' ? t('pki.ca.days_root') : t('pki.ca.days_issuing')"><UInput v-model.number="cr.days" type="number" :min="365" :max="cr.kind === 'root' ? 7305 : 3650" class="w-full" data-test="pki-ca-days" /></UFormField>
          </div>
          <template v-if="cr.kind === 'issuing'">
            <UFormField :label="t('pki.ca.signer')"><USelect v-model="cr.signedBy" :items="signerItems" class="w-full" data-test="pki-ca-signer" /></UFormField>
            <template v-if="cr.signedBy === 'external'">
              <!-- 0.14.12 : sans racine hors ligne à coller, la seule issue est une racine du DDI : on le dit et on y mène -->
              <UAlert v-if="!(data?.signers ?? []).length" color="info" variant="subtle" icon="i-lucide-info" :title="t('pki.ca.no_root_title')" :description="t('pki.ca.no_root_body')"
                :actions="[{ label: t('pki.ca.no_root_go'), color: 'info', variant: 'outline', onClick: () => { cr.open = false; nextTick(() => openCreate('root')) } }]" data-test="pki-ca-no-root" />
              <UFormField :label="t('pki.ca.chain')" :help="t('pki.ca.chain_help')"><UTextarea v-model="cr.chain" :rows="6" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" data-test="pki-ca-chain" /></UFormField>
              <UFormField :label="t('pki.ca.or_file')"><input type="file" accept=".pem,.crt,.cer,.der,.p7b" class="text-sm" data-test="pki-ca-chain-file" @change="pick('chain', $event)"></UFormField>
            </template>
            <p v-else class="text-xs text-dimmed">{{ t('pki.ca.signer_ddi_hint') }}</p>
          </template>
          <UAlert v-if="cr.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="cr.err" role="alert" data-test="pki-ca-create-error" />
          <div class="flex justify-end gap-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="cr.open = false" />
            <UButton type="submit" :loading="cr.busy" :disabled="!crValid" :label="t('pki.ca.create')" data-test="pki-ca-create" />
          </div>
        </form>
      </template>
    </UModal>

    <!-- Reprise d'une autorité existante (PKCS#12) -->
    <UModal v-model:open="pk.open" :title="t('pki.ca.p12_title')" :description="t('pki.ca.p12_desc')">
      <template #body>
        <form class="flex flex-col gap-3" autocomplete="off" @submit.prevent="importP12">
          <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('pki.ca.p12_warn')" data-test="pki-ca-p12-warn" />
          <p class="text-xs text-dimmed">{{ t('pki.ca.p12_limits') }}</p>
          <UFormField :label="t('pki.ca.name')" :help="t('pki.ca.name_help')"><UInput v-model="pk.name" class="w-full font-mono" maxlength="48" placeholder="Ancienne-Emettrice" data-test="pki-ca-p12-name" /></UFormField>
          <UFormField :label="t('pki.ca.p12_file')"><input type="file" accept=".p12,.pfx" class="text-sm" data-test="pki-ca-p12-file" @change="pickP12"></UFormField>
          <UFormField :label="t('pki.ca.p12_password')"><UInput v-model="pk.password" type="password" autocomplete="new-password" class="w-full" maxlength="128" data-test="pki-ca-p12-password" /></UFormField>
          <UFormField :label="t('pki.ca.p12_confirm')"><UInput v-model="pk.confirm" class="w-full font-mono" maxlength="48" autocomplete="off" data-test="pki-ca-p12-confirm" /></UFormField>
          <UAlert v-if="pk.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="pk.err" role="alert" data-test="pki-ca-p12-error" />
          <div class="flex justify-end gap-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="pk.open = false" />
            <UButton type="submit" :loading="pk.busy" :disabled="!pkValid" :label="t('pki.ca.p12_go')" data-test="pki-ca-p12-go" />
          </div>
        </form>
      </template>
    </UModal>

    <!-- Import du certificat signé -->
    <UModal v-model:open="im.open" :title="t('pki.ca.import_title', { name: im.ca?.name ?? '' })" :description="t('pki.ca.import_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="importCert">
          <UFormField :label="t('pki.ca.pem')"><UTextarea v-model="im.pem" :rows="8" class="w-full font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" data-test="pki-ca-import-pem" /></UFormField>
          <UFormField :label="t('pki.ca.or_file')"><input type="file" accept=".pem,.crt,.cer,.der" class="text-sm" data-test="pki-ca-import-file" @change="pick('cert', $event)"></UFormField>
          <UAlert v-if="im.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="im.err" role="alert" data-test="pki-ca-import-error" />
          <div class="flex justify-end gap-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="im.open = false" />
            <UButton type="submit" :loading="im.busy" :disabled="!im.pem.trim() && !files.cert" :label="t('pki.ca.import')" data-test="pki-ca-import-go" />
          </div>
        </form>
      </template>
    </UModal>

    <!-- CRL de la racine hors ligne -->
    <UModal v-model:open="rc.open" :title="t('pki.ca.rootcrl_title', { name: rc.ca?.name ?? '' })" :description="t('pki.ca.rootcrl_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="rootCrl">
          <UFormField :label="t('pki.ca.crl_pem')"><UTextarea v-model="rc.pem" :rows="6" class="w-full font-mono text-xs" placeholder="-----BEGIN X509 CRL-----" data-test="pki-ca-rootcrl-pem" /></UFormField>
          <UFormField :label="t('pki.ca.or_file')"><input type="file" accept=".crl,.pem,.der" class="text-sm" data-test="pki-ca-rootcrl-file" @change="pick('crl', $event)"></UFormField>
          <UAlert v-if="rc.err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="rc.err" role="alert" data-test="pki-ca-rootcrl-error" />
          <div class="flex justify-end gap-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="rc.open = false" />
            <UButton type="submit" :loading="rc.busy" :disabled="!rc.pem.trim() && !files.crl" :label="t('pki.ca.rootcrl')" data-test="pki-ca-rootcrl-go" />
          </div>
        </form>
      </template>
    </UModal>
  </div>
</template>
