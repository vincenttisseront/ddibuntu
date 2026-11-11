<script setup lang="ts">
// Réglages du cluster : adresse virtuelle et réseau dédié (communs à tous les nœuds, publiés une fois dans etcd), certificats de ce nœud et adresse de ce nœud.
// La console ne fait que déposer des demandes (validées de nouveau par root) ; chaque attente affiche un spinner, chaque confirmation est une boîte maison.
const props = defineProps<{ st: any; result: any; local: any }>()
const emit = defineEmits<{ (e: 'reload'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const { isAdmin } = useRole(); const fmt = useFmt()

const settings = computed(() => props.st?.settings ?? null)
const pub = computed(() => settings.value?.published ?? null)
const app = computed(() => settings.value?.applied ?? null)
const syncing = computed(() => !!pub.value && !!app.value && pub.value.rev > app.value.rev)
const pki = computed(() => props.st?.pki ?? null)
const isData = computed(() => props.st?.nodeRole === 'data')
const canAct = computed(() => isAdmin.value && isData.value && !props.st?.stale)
const isLeader = computed(() => props.st?.localRole === 'leader')
const me = computed(() => (props.st?.nodes ?? []).find((n: any) => n.name === props.st?.node))
const addrs = computed<any[]>(() => props.local?.addresses ?? [])
const ifaces = computed<string[]>(() => [...new Set(addrs.value.map((a: any) => a.iface))] as string[])

const ipOk = (v: string) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v)
const cidrOk = (v: string) => { const m = v.match(/^([0-9.]+)\/(\d{1,2})$/); return !!m && ipOk(m[1]!) && Number(m[2]) <= 32 }
const ifaceOk = (v: string) => /^[a-z][a-z0-9._-]{0,14}$/.test(v)
const dayColor = (d: number) => (d <= 7 ? 'error' : d <= 30 ? 'warning' : 'success') as any

type Kind = 'set-vip' | 'clear-vip' | 'vip-iface' | 'set-net' | 'change-ip'
const kind = ref<Kind | null>(null), busy = ref(false), err = ref(''), renewing = ref(false)
const f = reactive({ vip: '', iface: '', vrid: '', net: '', ip: '', confirm: '' })
const open = computed({ get: () => kind.value !== null, set: (v: boolean) => { if (!v && !busy.value) kind.value = null } })
const expected = computed(() => (kind.value === 'change-ip' ? props.st?.node : props.st?.cluster) ?? '')
const needsConfirm = computed(() => kind.value !== null && kind.value !== 'vip-iface')
const valid = computed(() => {
  switch (kind.value) {
    case 'set-vip': return cidrOk(f.vip) && ifaceOk(f.iface) && (!f.vrid || (/^\d{1,3}$/.test(f.vrid) && Number(f.vrid) >= 1 && Number(f.vrid) <= 255)) && f.confirm === expected.value
    case 'clear-vip': return f.confirm === expected.value
    case 'vip-iface': return ifaceOk(f.iface)
    case 'set-net': return cidrOk(f.net) && f.confirm === expected.value
    case 'change-ip': return ipOk(f.ip) && f.ip !== me.value?.ip && f.confirm === expected.value
    default: return false
  }
})
function begin(k: Kind) {
  err.value = ''
  Object.assign(f, { vip: app.value?.vip ?? '', iface: app.value?.iface ?? ifaces.value[0] ?? '', vrid: app.value?.vrid && app.value.vip ? String(app.value.vrid) : '', net: app.value?.net ?? '', ip: '', confirm: '' })
  if (k === 'set-vip' && !app.value?.vip) f.vip = ''
  kind.value = k
}
function payload(): Record<string, unknown> {
  switch (kind.value) {
    case 'set-vip': return { action: 'set-vip', vip: f.vip, iface: f.iface, ...(f.vrid ? { vrid: Number(f.vrid) } : {}), confirm: f.confirm }
    case 'clear-vip': return { action: 'clear-vip', confirm: f.confirm }
    case 'vip-iface': return { action: 'vip-iface', iface: f.iface }
    case 'set-net': return { action: 'set-net', net: f.net, confirm: f.confirm }
    default: return { action: 'change-ip', ip: f.ip, confirm: f.confirm }
  }
}
// root traite la demande en tâche de fond : on attend son résultat (un changement d'adresse peut durer plusieurs minutes : l'autorité signe, etcd redémarre)
async function waitResult(action: string, before: number, tries: number): Promise<any> {
  for (let i = 0; i < tries; i++) {
    await new Promise((r) => setTimeout(r, 2000)); emit('reload'); await new Promise((r) => setTimeout(r, 1000))
    const r = props.result
    if (r && r.at > before && r.action === action) return r
  }
  return null
}
async function submit(k: string, body: Record<string, unknown>, tries: number): Promise<{ ok: boolean; message: string } | null> {
  const before = props.result?.at ?? 0
  await api.call('POST', '/cluster/action', body, { busy: true })
  return waitResult(k, before, tries)
}
async function go() {
  const k = kind.value; if (!k || !valid.value) return
  busy.value = true; err.value = ''
  try {
    const r = await submit(k, payload(), k === 'change-ip' ? 200 : 60)
    if (!r) { err.value = t('cluster.op.timeout'); return }
    if (!r.ok) { err.value = r.message; return }
    toast.add({ title: t(`cluster.set.${k}.done`), description: r.message, color: 'success', icon: 'i-lucide-check' }); kind.value = null
  } catch (e: any) { err.value = e.info?.message ?? t('err.internal') }
  finally { busy.value = false; emit('reload') }
}
async function renew() {
  if (!(await ask(t('cluster.set.renew.title'), t('cluster.set.renew.body'), false))) return
  renewing.value = true
  try {
    const r = await submit('renew-cert', { action: 'renew-cert' }, 60)
    if (!r) toast.add({ title: t('cluster.op.timeout'), color: 'warning', icon: 'i-lucide-clock-alert' })
    else toast.add({ title: r.ok ? t('cluster.set.renew.done') : t('cluster.op.failed'), description: r.message, color: r.ok ? 'success' : 'error', icon: r.ok ? 'i-lucide-check' : 'i-lucide-triangle-alert' })
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) }
  finally { renewing.value = false; emit('reload') }
}
defineExpose({ begin })
</script>

<template>
  <div class="grid gap-4 lg:grid-cols-2">
    <UCard>
      <template #header>
        <div class="flex items-center justify-between gap-2">
          <span class="font-medium">{{ t('cluster.set.title') }}</span>
          <UBadge v-if="settings" :color="syncing ? 'warning' : 'success'" variant="subtle" :label="syncing ? t('cluster.set.syncing', { a: app?.rev ?? 0, p: pub?.rev ?? 0 }) : t('cluster.set.aligned', { r: app?.rev ?? 0 })" />
        </div>
      </template>
      <p v-if="!settings" class="text-sm text-muted">{{ t('cluster.set.unavailable') }}</p>
      <template v-else>
        <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt class="text-muted">{{ t('cluster.vip') }}</dt>
          <dd><span v-if="pub ? pub.vip : app?.vip" class="font-mono">{{ pub ? pub.vip : app?.vip }}</span><span v-else class="text-muted">{{ t('cluster.vip_none') }}</span></dd>
          <dt class="text-muted">{{ t('cluster.set.vrid') }}</dt><dd class="font-mono">{{ pub ? pub.vrid : app?.vrid }}</dd>
          <dt class="text-muted">{{ t('cluster.set.iface') }}</dt><dd class="font-mono">{{ app?.iface || '—' }}</dd>
          <dt class="text-muted">{{ t('cluster.set.net') }}</dt><dd class="font-mono">{{ app?.net || '—' }}</dd>
        </dl>
        <UAlert v-if="syncing" class="mt-3" color="warning" variant="subtle" icon="i-lucide-clock-alert" :title="t('cluster.set.syncing_title')" :description="t('cluster.set.syncing_desc')" />
        <p class="text-xs text-muted mt-3">{{ t('cluster.set.hint') }}</p>
        <div v-if="canAct" class="flex flex-wrap gap-2 mt-3">
          <UButton size="sm" icon="i-lucide-network" :label="app?.vip ? t('cluster.set.vip_change') : t('cluster.set.vip_set')" @click="begin('set-vip')" />
          <UButton v-if="app?.vip" size="sm" color="neutral" variant="outline" icon="i-lucide-cable" :label="t('cluster.set.iface_change')" @click="begin('vip-iface')" />
          <UButton v-if="app?.vip" size="sm" color="error" variant="outline" icon="i-lucide-circle-slash" :label="t('cluster.set.vip_clear')" @click="begin('clear-vip')" />
          <UButton size="sm" color="neutral" variant="outline" icon="i-lucide-route" :label="t('cluster.set.net_change')" @click="begin('set-net')" />
        </div>
      </template>
    </UCard>

    <UCard>
      <template #header><span class="font-medium">{{ t('cluster.pki.title') }}</span></template>
      <p v-if="!pki" class="text-sm text-muted">{{ t('cluster.set.unavailable') }}</p>
      <template v-else>
        <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt class="text-muted">{{ t('cluster.pki.node') }}</dt>
          <dd class="flex flex-wrap items-center gap-2"><UBadge :color="dayColor(pki.node.daysLeft)" variant="subtle" :label="t('cluster.pki.days', { n: pki.node.daysLeft })" /><span class="text-muted">{{ pki.node.notAfter ? fmt.dateTime(pki.node.notAfter * 1000) : '' }}</span></dd>
          <dt class="text-muted">{{ t('cluster.pki.serial') }}</dt><dd class="font-mono break-all">{{ pki.node.serial || '—' }}</dd>
          <dt class="text-muted">{{ t('cluster.pki.ca') }}</dt>
          <dd class="flex flex-wrap items-center gap-2"><UBadge :color="dayColor(pki.ca.daysLeft)" variant="subtle" :label="t('cluster.pki.days', { n: pki.ca.daysLeft })" /></dd>
          <dt class="text-muted">{{ t('cluster.pki.auto') }}</dt><dd>{{ t('cluster.pki.auto_val', { n: pki.renewDays }) }}</dd>
          <dt v-if="pki.pending" class="text-muted">{{ t('cluster.pki.request') }}</dt>
          <dd v-if="pki.pending" class="flex items-center gap-2"><UIcon name="i-lucide-loader" class="animate-spin" /><span>{{ t('cluster.pki.pending') }}</span></dd>
        </dl>
        <p class="text-xs text-muted mt-3">{{ t('cluster.pki.hint') }}</p>
        <div v-if="canAct" class="mt-3"><UButton size="sm" icon="i-lucide-refresh-cw" :label="t('cluster.set.renew.btn')" :loading="renewing" :disabled="pki.pending || renewing" @click="renew" /></div>
      </template>
    </UCard>

    <UCard class="lg:col-span-2">
      <template #header><span class="font-medium">{{ t('cluster.ip.title') }}</span></template>
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt class="text-muted">{{ t('cluster.name') }}</dt><dd class="font-mono">{{ st.node }}</dd>
        <dt class="text-muted">{{ t('cluster.address') }}</dt><dd class="font-mono">{{ me?.ip || '—' }}</dd>
      </dl>
      <p class="text-xs text-muted mt-3">{{ t('cluster.ip.hint') }}</p>
      <UAlert v-if="isLeader" class="mt-3" color="info" variant="subtle" icon="i-lucide-info" :title="t('cluster.ip.leader_title')" :description="t('cluster.ip.leader_desc')" />
      <div v-if="canAct" class="mt-3"><UButton size="sm" color="warning" variant="outline" icon="i-lucide-map-pin-pen" :label="t('cluster.ip.btn')" :disabled="isLeader" @click="begin('change-ip')" /></div>
    </UCard>
  </div>

  <UModal v-model:open="open" :title="kind ? t(`cluster.set.${kind}.title`) : ''" :description="kind ? t(`cluster.set.${kind}.desc`) : ''" :dismissible="!busy">
    <template #body>
      <div v-if="kind" class="flex flex-col gap-3">
        <template v-if="kind === 'set-vip'">
          <UFormField :label="t('cluster.set.vip_label')" :hint="t('cluster.set.cidr_hint')"><UInput v-model="f.vip" class="w-full" placeholder="192.0.2.10/24" autocomplete="off" :disabled="busy" /></UFormField>
          <div class="grid sm:grid-cols-2 gap-3">
            <UFormField :label="t('cluster.set.iface_label')">
              <USelectMenu v-if="ifaces.length" v-model="f.iface" class="w-full" :items="ifaces" :disabled="busy" />
              <UInput v-else v-model="f.iface" class="w-full" placeholder="ens18" :disabled="busy" />
            </UFormField>
            <UFormField :label="t('cluster.set.vrid')" :hint="t('cluster.w.optional')"><UInput v-model="f.vrid" class="w-full" placeholder="51" inputmode="numeric" :disabled="busy" /></UFormField>
          </div>
        </template>
        <UFormField v-else-if="kind === 'vip-iface'" :label="t('cluster.set.iface_label')">
          <USelectMenu v-if="ifaces.length" v-model="f.iface" class="w-full" :items="ifaces" :disabled="busy" />
          <UInput v-else v-model="f.iface" class="w-full" placeholder="ens18" :disabled="busy" />
        </UFormField>
        <UFormField v-else-if="kind === 'set-net'" :label="t('cluster.set.net_label')" :hint="t('cluster.set.cidr_hint')"><UInput v-model="f.net" class="w-full" placeholder="10.10.0.0/24" autocomplete="off" :disabled="busy" /></UFormField>
        <template v-else-if="kind === 'change-ip'">
          <UFormField :label="t('cluster.ip.new')" :hint="t('cluster.ip.new_hint', { a: me?.ip ?? '' })"><UInput v-model="f.ip" class="w-full" placeholder="10.10.0.12" autocomplete="off" :disabled="busy" /></UFormField>
          <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('cluster.ip.warn_title')" :description="t('cluster.ip.warn_desc')" />
        </template>
        <UAlert v-if="kind === 'clear-vip'" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('cluster.set.clear.warn')" />
        <label v-if="needsConfirm" class="text-sm">{{ t('cluster.op.type', { v: expected }) }}
          <UInput v-model="f.confirm" class="w-full mt-1" autocomplete="off" :disabled="busy" @keyup.enter="go" />
        </label>
        <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" />
        <div v-if="busy" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader" class="animate-spin" />{{ kind === 'change-ip' ? t('cluster.ip.running') : t('cluster.op.running') }}</div>
      </div>
    </template>
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton color="neutral" variant="outline" :label="t('common.cancel')" :disabled="busy" @click="kind = null" />
        <UButton :label="t('common.confirm')" :disabled="!valid || busy" :loading="busy" @click="go" />
      </div>
    </template>
  </UModal>
</template>
