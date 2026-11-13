<script setup lang="ts">
// Assistants du cluster : « Créer un cluster » et « Rejoindre un cluster » (nœud hors cluster) ; « Ajouter un nœud » (nœud porteur de l'autorité).
// La console ne fait que déposer des demandes ; root les revalide. Aucune boîte système ; un spinner accompagne toute attente.
const props = defineProps<{ st: any; setup: any; result: any }>()
const emit = defineEmits<{ (e: 'reload'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { csrf } = api

type Mode = 'init' | 'join' | 'add'
const mode = ref<Mode | null>(null), busy = ref(false), err = ref(''), step = ref<'form' | 'done'>('form')
const open = computed({ get: () => mode.value !== null, set: (v: boolean) => { if (!v && !busy.value) close() } })
const addrs = computed<any[]>(() => props.setup?.addresses ?? [])
const hostname = computed(() => props.setup?.hostname ?? '')
const missing = computed<string[]>(() => props.setup?.missing ?? [])
const installCmd = computed(() => `sudo ${props.setup?.install ?? 'apt install patroni etcd-server etcd-client python3-psycopg2 gnupg'}`)

// ---- création
const ini = reactive({ cluster: 'ddibuntu', node: '', ip: '', net: '', vip: '', vipIface: '', vrid: '', confirm: '' })
// ---- rattachement
const jn = reactive({ pass: '', confirm: '', file: null as File | null })
// ---- ajout d'un nœud
const add = reactive({ name: '', ip: '', role: 'data' as 'data' | 'witness' })
const secret = ref(''), created = ref('')

const nameOk = (v: string) => /^[a-z][a-z0-9-]{1,30}$/.test(v)
const ipOk = (v: string) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v)
const initOk = computed(() => nameOk(ini.cluster) && nameOk(ini.node) && ipOk(ini.ip) && ini.confirm === ini.node && (!ini.net || /^[0-9.]+\/\d{1,2}$/.test(ini.net)) && ((!ini.vip && !ini.vipIface) || (ipOk(ini.vip) && !!ini.vipIface)) && (!ini.vrid || (+ini.vrid >= 1 && +ini.vrid <= 255)))
const joinOk = computed(() => !!jn.file && /^[A-Za-z0-9]{24,64}$/.test(jn.pass) && jn.confirm === hostname.value)
const addOk = computed(() => nameOk(add.name) && ipOk(add.ip))

function begin(m: Mode) {
  err.value = ''; step.value = 'form'; secret.value = ''; created.value = ''
  if (m === 'init') {
    Object.assign(ini, { cluster: 'ddibuntu', node: nameOk(hostname.value) ? hostname.value : '', ip: addrs.value[0]?.address ?? '', net: '', vip: '', vipIface: addrs.value[0]?.iface ?? '', vrid: '', confirm: '' })
  } else if (m === 'join') Object.assign(jn, { pass: '', confirm: '', file: null })
  else Object.assign(add, { name: '', ip: '', role: 'data' })
  mode.value = m
}
function close() { if (mode.value === 'add' && created.value) api.call('DELETE', `/cluster/bundle/${created.value}`, undefined, { silent: true }).catch(() => {}); mode.value = null; created.value = ''; secret.value = '' }

// root traite en tâche de fond : on attend son résultat (création et rattachement : jusqu'à quelques minutes). La console peut redémarrer pendant ce temps.
async function sessionGone(): Promise<boolean> {
  try { const m: any = await $fetch('/api/auth/me'); return !m?.user } catch { return false }   // injoignable (redémarrage) : on réessaie
}
async function waitResult(action: string, node: string, before: number, tries = 180): Promise<any> {
  for (let i = 0; i < tries; i++) {
    await new Promise((r) => setTimeout(r, 2000)); emit('reload'); await new Promise((r) => setTimeout(r, 1000))
    const r = props.result
    if (r && r.at > before && r.action === action && (!node || r.candidate === node)) return r
    // rattachement : la base locale est remplacée par celle du cluster, donc notre session n'existe plus et le résultat ne peut plus être lu.
    // Session invalidée (ou console arrêtée/redémarrée) = le rattachement a eu lieu : on ne laisse pas attendre le délai complet.
    if (action === 'join' && i >= 2 && (await sessionGone())) return { ok: true, at: Date.now(), action, message: t('cluster.w.join.session_gone') }
  }
  return null
}
async function run(kind: Mode, call: () => Promise<any>, node = '') {
  busy.value = true; err.value = ''
  const before = props.result?.at ?? 0
  try {
    const out = await call()
    const r = await waitResult(kind === 'add' ? 'bundle' : kind, node, before)
    if (!r) { err.value = t('cluster.op.timeout'); return }
    if (!r.ok) { err.value = r.message; return }
    if (kind === 'add') { secret.value = out.passphrase; created.value = node; step.value = 'done' }
    else { toast.add({ title: t(`cluster.w.${kind}.done`), description: r.message, color: 'success', icon: 'i-lucide-check' }); mode.value = null; if (kind === 'join') setTimeout(() => { window.location.href = '/login' }, 15000) }
  } catch (e: any) { err.value = e.info?.message ?? t('err.internal') }
  finally { busy.value = false; emit('reload') }
}
const submitInit = () => run('init', () => api.call('POST', '/cluster/init', { cluster: ini.cluster, node: ini.node, ip: ini.ip, ...(ini.net ? { net: ini.net } : {}), ...(ini.vip ? { vip: ini.vip, vipIface: ini.vipIface } : {}), ...(ini.vrid ? { vrid: +ini.vrid } : {}), confirm: ini.confirm }, { busy: true }), ini.node)
async function submitJoin() {
  const buf = new Uint8Array(await jn.file!.arrayBuffer()); let bin = ''; for (const b of buf) bin += String.fromCharCode(b)
  return run('join', () => api.call('POST', '/cluster/join', { bundle: btoa(bin), pass: jn.pass, confirm: jn.confirm }, { busy: true }))
}
const submitAdd = () => run('add', () => api.call('POST', '/cluster/bundle', { name: add.name, ip: add.ip, role: add.role }, { busy: true }), add.name)
function pick(e: Event) { jn.file = (e.target as HTMLInputElement).files?.[0] ?? null }
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
void csrf
defineExpose({ begin })
</script>

<template>
  <UModal v-model:open="open" :dismissible="!busy" :title="mode ? t(`cluster.w.${mode}.title`) : ''" :description="mode ? t(`cluster.w.${mode}.desc`) : ''">
    <template #body>
      <div v-if="mode === 'init'" class="flex flex-col gap-3">
        <div class="grid sm:grid-cols-2 gap-3">
          <UFormField :label="t('cluster.w.cluster_name')"><UInput v-model="ini.cluster" class="w-full" :disabled="busy" /></UFormField>
          <UFormField :label="t('cluster.w.node_name')"><UInput v-model="ini.node" class="w-full" :disabled="busy" /></UFormField>
          <UFormField :label="t('cluster.w.node_ip')">
            <USelectMenu v-if="addrs.length" v-model="ini.ip" class="w-full" :items="addrs.map((a: any) => a.address)" :disabled="busy" />
            <UInput v-else v-model="ini.ip" class="w-full" :disabled="busy" />
          </UFormField>
          <UFormField :label="t('cluster.w.net')" :hint="t('cluster.w.optional')"><UInput v-model="ini.net" class="w-full" placeholder="10.10.0.0/24" :disabled="busy" /></UFormField>
          <UFormField :label="t('cluster.w.vip')" :hint="t('cluster.w.optional')"><UInput v-model="ini.vip" class="w-full" placeholder="192.0.2.10" :disabled="busy" /></UFormField>
          <UFormField :label="t('cluster.w.vip_iface')"><USelectMenu v-if="addrs.length" v-model="ini.vipIface" class="w-full" :items="[...new Set(addrs.map((a: any) => a.iface))]" :disabled="busy || !ini.vip" /><UInput v-else v-model="ini.vipIface" class="w-full" placeholder="ens18" :disabled="busy || !ini.vip" /></UFormField>
        </div>
        <UAlert v-if="missing.length" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('cluster.w.missing', { list: missing.join(', ') })" :description="installCmd" />
        <UAlert color="info" variant="subtle" icon="i-lucide-info" :title="t('cluster.w.init.note')" />
        <label class="text-sm">{{ t('cluster.op.type', { v: ini.node || '…' }) }}<UInput v-model="ini.confirm" class="w-full mt-1" autocomplete="off" :disabled="busy" /></label>
      </div>

      <div v-else-if="mode === 'join'" class="flex flex-col gap-3">
        <UAlert v-if="missing.length" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('cluster.w.missing', { list: missing.join(', ') })" :description="installCmd" />
        <UAlert color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('cluster.w.join.warn_title')" :description="t('cluster.w.join.warn_desc')" />
        <UFormField :label="t('cluster.w.join.file')"><input type="file" class="block w-full text-sm" :aria-label="t('cluster.w.join.file')" :disabled="busy" @change="pick"></UFormField>
        <UFormField :label="t('cluster.w.join.pass')"><UInput v-model="jn.pass" class="w-full" type="password" autocomplete="off" :disabled="busy" /></UFormField>
        <label class="text-sm">{{ t('cluster.op.type', { v: hostname }) }}<UInput v-model="jn.confirm" class="w-full mt-1" autocomplete="off" :disabled="busy" /></label>
      </div>

      <div v-else-if="mode === 'add' && step === 'form'" class="flex flex-col gap-3">
        <div class="grid sm:grid-cols-2 gap-3">
          <UFormField :label="t('cluster.w.node_name')"><UInput v-model="add.name" class="w-full" :disabled="busy" /></UFormField>
          <UFormField :label="t('cluster.w.node_ip')"><UInput v-model="add.ip" class="w-full" placeholder="10.10.0.2" :disabled="busy" /></UFormField>
        </div>
        <UFormField :label="t('cluster.w.add.role')">
          <URadioGroup v-model="add.role" :items="[{ value: 'data', label: t('cluster.w.add.role_data') }, { value: 'witness', label: t('cluster.w.add.role_witness') }]" :disabled="busy" />
        </UFormField>
        <UAlert color="info" variant="subtle" icon="i-lucide-info" :title="t('cluster.w.add.note')" />
      </div>

      <div v-else-if="mode === 'add'" class="flex flex-col gap-3">
        <UAlert color="success" variant="subtle" icon="i-lucide-check" :title="t('cluster.w.add.ready', { n: created })" />
        <div>
          <div class="text-sm font-medium mb-1">{{ t('cluster.w.add.pass') }}</div>
          <div class="flex gap-2"><code class="flex-1 rounded bg-elevated px-2 py-1.5 text-sm break-all select-all">{{ secret }}</code><UButton color="neutral" variant="outline" icon="i-lucide-copy" :aria-label="t('common.copy')" @click="copy(secret)" /></div>
          <p class="text-xs text-warning mt-1">{{ t('cluster.w.add.pass_once') }}</p>
        </div>
        <UButton :href="`/api/cluster/bundle/${created}`" :download="`ddibuntu-${created}.bundle`" external icon="i-lucide-download" :label="t('cluster.w.add.download')" class="self-start" />
        <ol class="list-decimal pl-5 text-sm text-muted space-y-1"><li>{{ t('cluster.w.add.s1') }}</li><li>{{ t('cluster.w.add.s2') }}</li><li>{{ t('cluster.w.add.s3') }}</li></ol>
        <p class="text-xs text-muted">{{ t('cluster.w.add.expire') }}</p>
      </div>

      <UAlert v-if="err" class="mt-3" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" />
      <div v-if="busy" class="flex items-center gap-2 text-sm text-muted mt-3"><UIcon name="i-lucide-loader" class="animate-spin" />{{ t(`cluster.w.${mode}.running`) }}</div>
    </template>
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <template v-if="mode === 'add' && step === 'done'"><UButton :label="t('cluster.w.add.finish')" @click="close" /></template>
        <template v-else>
          <UButton color="neutral" variant="outline" :label="t('common.cancel')" :disabled="busy" @click="close" />
          <UButton v-if="mode === 'init'" :label="t('cluster.w.init.go')" :disabled="!initOk || busy || missing.length > 0" :loading="busy" @click="submitInit" />
          <UButton v-else-if="mode === 'join'" color="error" :label="t('cluster.w.join.go')" :disabled="!joinOk || busy || missing.length > 0" :loading="busy" @click="submitJoin" />
          <UButton v-else :label="t('cluster.w.add.go')" :disabled="!addOk || busy" :loading="busy" @click="submitAdd" />
        </template>
      </div>
    </template>
  </UModal>
</template>
