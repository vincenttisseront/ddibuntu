<script setup lang="ts">
// Accès réseau — règles d'accès du service RADIUS (0.13.3, itération 4). Une liste ORDONNÉE : la première règle qui correspond décide, sinon refus.
// Une règle relie des conditions (type de compte, groupes AD — imbriqués compris —, clients, usages, SSID) à une décision (accepter avec VLAN / pool /
// durée / attributs, ou refuser). L'état du compte (désactivé, verrouillé, expiré) refuse AVANT toute règle. La simulation joue la liste ENREGISTRÉE
// sur un vrai compte de l'annuaire avant de publier ; le déploiement se fait par « Déployer » (onglet Service).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()
const emit = defineEmits<{ changed: [] }>()

const view = ref<any>(null), loadErr = ref(''), busyId = ref<number | null>(null), clients = ref<any[]>([])
async function load() {
  try { view.value = await api.call('GET', '/radius/rules', undefined, { silent: true }); loadErr.value = '' } catch (e: any) { loadErr.value = e?.info?.message ?? t('err.internal') }
  try { clients.value = ((await api.call('GET', '/radius/clients', undefined, { silent: true })) as any).items } catch { /* la liste des clients n'est qu'une aide à la saisie */ }
}
const items = computed<any[]>(() => view.value?.items ?? [])
const numberOf = (r: any): number | null => view.value?.numbers?.[r.id] ?? null
const warningsOf = (r: any) => (view.value?.warnings ?? []).filter((w: any) => w.rule !== undefined && w.rule === numberOf(r))
const clientItems = computed(() => clients.value.map((c) => ({ label: `${c.name} (${t(`radius.u.${c.usage}`)})${c.enabled ? '' : ' — ' + t('common.disabled')}`, value: c.name })))
const USAGES = ['wifi', 'vpn', 'switch', 'other']
const VENDOR = ['Aruba-User-Role', 'Fortinet-Group-Name', 'Cisco-AVPair', 'Reply-Message']

// ---- Ordre ----
async function move(r: any, delta: -1 | 1) {
  const i = items.value.findIndex((x) => x.id === r.id), j = i + delta
  if (j < 0 || j >= items.value.length || busyId.value !== null) return
  const ids = items.value.map((x) => x.id); [ids[i], ids[j]] = [ids[j], ids[i]]
  busyId.value = r.id
  try { await api.call('PUT', '/radius/rules-order', { ids }); await load(); emit('changed') } catch { await load() } finally { busyId.value = null }
}
async function toggle(r: any) {
  if (busyId.value !== null) return
  busyId.value = r.id
  try { await api.call('PUT', `/radius/rules/${r.id}`, bodyOf(r, { enabled: !r.enabled })); await load(); emit('changed') } catch { await load() } finally { busyId.value = null }
}
async function remove(r: any) {
  if (!(await ask(t('radius.rules.del_title'), t('radius.rules.del_body', { name: r.name }), true))) return
  busyId.value = r.id
  try { await api.call('DELETE', `/radius/rules/${r.id}`); await load(); emit('changed') } catch { /* message déjà affiché */ } finally { busyId.value = null }
}
/** Corps d'une requête PUT/POST à partir d'une règle de la liste (conds + reply → champs plats de l'API). */
function bodyOf(r: any, over: Record<string, unknown> = {}) {
  return { name: r.name, enabled: r.enabled, action: r.action, kind: r.conds.kind, groups: r.conds.groups, clients: r.conds.clients, usages: r.conds.usages, ssids: r.conds.ssids, reply: r.reply, comment: r.comment, ...over }
}

// ---- Éditeur ----
const edit = reactive({ open: false, id: 0 as number, saving: false, error: '' })
const f = reactive({ name: '', enabled: true, action: 'accept', kind: 'any', groups: [] as Array<{ dn: string; name: string }>, clients: [] as string[], usages: [] as string[], ssids: '',
  vlan: '', pool: '', minutes: '', filterId: '', attrs: [] as Array<{ name: string; value: string }>, comment: '' })
function openEdit(r: any | null) {
  edit.id = r?.id ?? 0; edit.error = ''
  Object.assign(f, r ? { name: r.name, enabled: r.enabled, action: r.action, kind: r.conds.kind ?? 'any', groups: r.conds.groups.map((g: any) => ({ ...g })), clients: [...r.conds.clients], usages: [...r.conds.usages],
    ssids: r.conds.ssids.join('\n'), vlan: r.reply.vlan ? String(r.reply.vlan) : '', pool: r.reply.pool ?? '', minutes: r.reply.sessionTimeout ? String(Math.round(r.reply.sessionTimeout / 60)) : '', filterId: r.reply.filterId ?? '',
    attrs: (r.reply.attrs ?? []).map((a: any) => ({ ...a })), comment: r.comment ?? '' }
    : { name: '', enabled: true, action: 'accept', kind: 'any', groups: [], clients: [], usages: [], ssids: '', vlan: '', pool: '', minutes: '', filterId: '', attrs: [], comment: '' })
  gq.value = ''; found.value = null; gErr.value = ''; dnManual.value = ''
  edit.open = true
}
const actions = computed(() => [{ label: t('radius.rules.accept'), value: 'accept' }, { label: t('radius.rules.reject'), value: 'reject' }])
const kinds = computed(() => [{ label: t('radius.rules.kind_any'), value: 'any' }, { label: t('radius.dir.kind_user'), value: 'user' }, { label: t('radius.dir.kind_computer'), value: 'computer' }])
const usageChoices = computed(() => USAGES.map((v) => ({ label: t(`radius.u.${v}`), value: v })))
const vendorChoices = computed(() => VENDOR.filter((v) => !f.attrs.some((a) => a.name === v)).map((v) => ({ label: v, value: v })))
const newAttr = ref('')
function addAttr() { if (newAttr.value && !f.attrs.some((a) => a.name === newAttr.value)) f.attrs.push({ name: newAttr.value, value: BLANK }); newAttr.value = BLANK }
function payload() {
  const reply: Record<string, unknown> = {}
  if (f.action === 'accept') {
    if (f.vlan.trim()) reply.vlan = Number(f.vlan)
    if (f.pool.trim()) reply.pool = f.pool.trim()
    if (f.minutes.trim()) reply.sessionTimeout = Math.round(Number(f.minutes) * 60)
    if (f.filterId.trim()) reply.filterId = f.filterId.trim()
    const attrs = f.attrs.filter((a) => a.value.trim()).map((a) => ({ name: a.name, value: a.value.trim() }))
    if (attrs.length) reply.attrs = attrs
  }
  return { name: f.name.trim(), enabled: f.enabled, action: f.action, kind: f.kind === 'any' ? null : f.kind, groups: f.groups, clients: f.clients, usages: f.usages,
    ssids: f.ssids.split('\n').map((s) => s.trim()).filter(Boolean), reply, comment: f.comment.trim() || null }
}
async function save() {
  if (edit.saving || !f.name.trim()) return
  edit.saving = true; edit.error = ''
  try {
    if (edit.id) await api.call('PUT', `/radius/rules/${edit.id}`, payload(), { silent: true }); else await api.call('POST', '/radius/rules', payload(), { silent: true })
    edit.open = false; toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await load(); emit('changed')
  } catch (e: any) { edit.error = e?.info?.message ?? t('err.internal') } finally { edit.saving = false }
}
// sélecteur de groupes : recherche dans l'annuaire (ou DN saisi à la main si l'annuaire n'est pas joignable)
const gq = ref(''), searching = ref(false), gErr = ref(''), found = ref<any>(null), dnManual = ref('')
async function searchGroups() {
  const q = gq.value.trim()
  if (q.length < 2 || searching.value) return
  searching.value = true; gErr.value = ''; found.value = null
  try { found.value = await api.call('GET', `/radius/directory/groups?q=${encodeURIComponent(q)}`, undefined, { silent: true }) } catch (e: any) { gErr.value = e?.info?.message ?? t('err.internal') } finally { searching.value = false }
}
const hasGroup = (dn: string) => f.groups.some((g) => g.dn.toLowerCase() === dn.toLowerCase())
function addGroup(dn: string, name: string) { if (dn && !hasGroup(dn)) f.groups.push({ dn, name }) }
// MÊME motif que la console serveur et que root (GROUP_DN_RE) : un test unitaire vérifie l'identité des trois
const DN_OK = /^(?:[^\x00-\x1f\x7f"$%{}`\\]|\\[,+<>;=# \\]){3,512}$/
const dnBad = computed(() => { const d = dnManual.value.trim(); return d.includes('=') && !DN_OK.test(d) })
function addManual() { const dn = dnManual.value.trim(); if (dn.includes('=') && DN_OK.test(dn)) { addGroup(dn, ''); dnManual.value = '' } }

// ---- Simulation ----
const BLANK = ''   // texte vide ; jamais comme valeur d'un item de sélecteur (Reka UI échoue, voir unit-iter34)
const sim = reactive({ kind: 'user', name: '', clientId: 0 as number, ssid: '', running: false, error: '', res: null as any })
const simKinds = computed(() => [{ label: t('radius.dir.kind_user'), value: 'user' }, { label: t('radius.dir.kind_computer'), value: 'computer' }])
const simClients = computed(() => [{ label: t('radius.rules.sim_any_client'), value: 0 }, ...clients.value.filter((c) => c.enabled).map((c) => ({ label: `${c.name} (${t(`radius.u.${c.usage}`)})`, value: c.id }))])
async function simulate() {
  if (sim.running || !sim.name.trim()) return
  sim.running = true; sim.error = ''; sim.res = null
  try { sim.res = await api.call('POST', '/radius/rules/simulate', { kind: sim.kind, name: sim.name.trim(), clientId: sim.clientId ? Number(sim.clientId) : null, ssid: sim.ssid.trim() || null }, { silent: true }) }
  catch (e: any) { sim.error = e?.info?.message ?? t('err.internal') } finally { sim.running = false }
}
const ruleName = (n: number | null) => items.value.find((r) => numberOf(r) === n)?.name ?? ''
const condText = (c: any) => {
  const want = Array.isArray(c.wanted) ? c.wanted.map((w: string) => (c.type === 'groups' ? w.split(',')[0]!.replace(/^CN=/i, '') : w)).join(' | ') : ''
  const got = Array.isArray(c.got) ? (c.got.length ? c.got.map((w: string) => w.split(',')[0]!.replace(/^CN=/i, '')).join(', ') : t('radius.rules.none')) : c.got ?? t('radius.rules.none')
  return `${t(`radius.rules.cond_${c.type}`)} : ${want} ← ${got}`
}
function reasonText(r: any) { return r.code === 'rule_accept' || r.code === 'rule_reject' ? t(`radius.rules.res.${r.code}`, { n: r.rule, name: ruleName(r.rule) }) : t(`radius.rules.res.${r.code}`) }
const problemsText = computed(() => (view.value?.problems ?? []).map((p: string) => t(`radius.rules.problem.${p}`)))
const replyText = (r: any) => {
  const a: string[] = []
  if (r.reply?.vlan) a.push(`VLAN ${r.reply.vlan}`)
  if (r.reply?.pool) a.push(`pool ${r.reply.pool}`)
  if (r.reply?.sessionTimeout) a.push(t('radius.rules.timeout_short', { m: Math.round(r.reply.sessionTimeout / 60) }))
  if (r.reply?.filterId) a.push(`Filter-Id ${r.reply.filterId}`)
  for (const x of r.reply?.attrs ?? []) a.push(`${x.name} = ${x.value}`)
  return a
}
onMounted(load)
defineExpose({ load })
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted">{{ t('radius.rules.intro') }}</p>
    <UAlert v-if="loadErr" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="loadErr" role="alert" />

    <UAlert v-if="view?.pending" color="info" variant="subtle" icon="i-lucide-rocket" :title="t('radius.rules.pending_title')" :description="t('radius.rules.pending_body')" data-test="rules-pending" />
    <UAlert v-if="view && view.active && problemsText.length" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('radius.rules.problems_title')" data-test="rules-problems">
      <template #description><ul class="list-disc pl-5 text-sm"><li v-for="p in problemsText" :key="p">{{ p }}</li></ul></template>
    </UAlert>
    <UAlert v-if="view && !items.length" color="neutral" variant="subtle" icon="i-lucide-shield-ban" :title="t('radius.rules.empty_title')" :description="t('radius.rules.empty_body')" data-test="rules-empty" />

    <UCard>
      <template #header>
        <div class="flex flex-wrap items-center gap-2">
          <UIcon name="i-lucide-list-ordered" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.rules.list_title') }}</h2>
          <UBadge v-if="view" color="neutral" variant="subtle" :label="t('radius.rules.count', { n: view.active, total: items.length })" />
          <div class="flex-1" />
          <UButton icon="i-lucide-plus" :label="t('radius.rules.add')" :disabled="!!view && items.length >= view.max" data-test="rule-add" @click="openEdit(null)" />
        </div>
      </template>
      <ol v-if="items.length" class="flex flex-col divide-y divide-default" data-test="rules-list">
        <li v-for="(r, i) in items" :key="r.id" class="flex flex-wrap items-start gap-3 py-3" :class="r.enabled ? '' : 'opacity-60'" data-test="rule-row">
          <span class="inline-flex items-center justify-center size-7 rounded-full bg-elevated text-sm font-mono shrink-0" :title="numberOf(r) ? t('radius.rules.number_hint') : t('radius.rules.inactive')" data-test="rule-n">{{ numberOf(r) ?? '—' }}</span>
          <div class="flex-1 min-w-64 flex flex-col gap-1">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-medium" data-test="rule-name">{{ r.name }}</span>
              <UBadge :color="r.action === 'accept' ? 'success' : 'error'" variant="subtle" :icon="r.action === 'accept' ? 'i-lucide-check' : 'i-lucide-ban'" :label="t(`radius.rules.${r.action}`)" data-test="rule-action" />
              <UBadge v-if="!r.enabled" color="neutral" variant="subtle" :label="t('radius.rules.disabled')" />
            </div>
            <div class="flex flex-wrap gap-1.5 text-xs" data-test="rule-conds">
              <UBadge v-if="r.conds.kind" color="neutral" variant="outline" size="sm" :label="t(`radius.dir.kind_${r.conds.kind}`)" />
              <UBadge v-for="g in r.conds.groups" :key="g.dn" color="primary" variant="subtle" size="sm" icon="i-lucide-users" :label="g.name" :title="g.dn" />
              <UBadge v-for="c in r.conds.clients" :key="c" color="neutral" variant="subtle" size="sm" icon="i-lucide-router" :label="c" :class="(view?.unknown ?? []).some((u: any) => u.id === r.id && u.names.includes(c)) ? 'line-through' : ''" />
              <UBadge v-for="u in r.conds.usages" :key="u" color="neutral" variant="subtle" size="sm" :label="t(`radius.u.${u}`)" />
              <UBadge v-for="s in r.conds.ssids" :key="s" color="neutral" variant="subtle" size="sm" icon="i-lucide-wifi" :label="s" />
              <span v-if="!r.conds.kind && !r.conds.groups.length && !r.conds.clients.length && !r.conds.usages.length && !r.conds.ssids.length" class="text-muted">{{ t('radius.rules.cond_none') }}</span>
            </div>
            <div v-if="r.action === 'accept' && replyText(r).length" class="flex flex-wrap gap-1.5 text-xs" data-test="rule-reply"><UBadge v-for="x in replyText(r)" :key="x" color="success" variant="outline" size="sm" :label="x" /></div>
            <p v-if="r.comment" class="text-xs text-muted">{{ r.comment }}</p>
            <ul v-if="warningsOf(r).length" class="text-xs text-warning flex flex-col gap-0.5" data-test="rule-warnings">
              <li v-for="w in warningsOf(r)" :key="w.code + (w.by ?? '')" class="flex items-center gap-1"><UIcon name="i-lucide-triangle-alert" class="size-3.5" />{{ t(`radius.rules.warn.${w.code}`, { by: w.by ?? '', names: (w.names ?? []).join(', ') }) }}</li>
            </ul>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <USwitch :model-value="r.enabled" :disabled="busyId !== null" :aria-label="t('common.enabled')" data-test="rule-toggle" @update:model-value="toggle(r)" />
            <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-arrow-up" :aria-label="t('radius.rules.up')" :title="t('radius.rules.up')" :disabled="i === 0 || busyId !== null" :loading="busyId === r.id" data-test="rule-up" @click="move(r, -1)" />
            <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-arrow-down" :aria-label="t('radius.rules.down')" :title="t('radius.rules.down')" :disabled="i === items.length - 1 || busyId !== null" data-test="rule-down" @click="move(r, 1)" />
            <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-pencil" :aria-label="t('common.edit')" :title="t('common.edit')" :disabled="busyId !== null" data-test="rule-edit" @click="openEdit(r)" />
            <UButton size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" :title="t('common.delete')" :disabled="busyId !== null" data-test="rule-delete" @click="remove(r)" />
          </div>
        </li>
      </ol>
      <p v-if="items.length" class="text-xs text-dimmed mt-3">{{ t('radius.rules.default_note') }}</p>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-flask-conical" class="size-5 text-primary" /><h2 class="font-semibold">{{ t('radius.rules.sim_title') }}</h2></div><p class="text-sm text-muted mt-1">{{ t('radius.rules.sim_desc') }}</p></template>
      <form class="flex flex-col gap-4" @submit.prevent="simulate">
        <div class="flex flex-wrap items-end gap-3">
          <UFormField :label="t('radius.dir.kind')"><URadioGroup v-model="sim.kind" :items="simKinds" orientation="horizontal" data-test="sim-kind" /></UFormField>
          <UFormField :label="sim.kind === 'user' ? t('radius.rules.sim_upn') : t('radius.rules.sim_dns')" class="flex-1 min-w-56"><UInput v-model="sim.name" class="w-full font-mono" autocomplete="off" :placeholder="sim.kind === 'user' ? 'alice@exemple.fr' : 'pc001.exemple.fr'" data-test="sim-name" /></UFormField>
        </div>
        <div class="flex flex-wrap items-end gap-3">
          <UFormField :label="t('radius.rules.sim_client')" class="min-w-56"><USelect v-model="sim.clientId" :items="simClients" value-key="value" class="w-full" data-test="sim-client" /></UFormField>
          <UFormField :label="t('radius.rules.sim_ssid')" :help="t('radius.rules.sim_ssid_help')" class="min-w-48"><UInput v-model="sim.ssid" class="w-full" autocomplete="off" data-test="sim-ssid" /></UFormField>
          <UButton type="submit" icon="i-lucide-play" :loading="sim.running" :disabled="!sim.name.trim()" :label="t('radius.rules.simulate')" data-test="sim-run" />
        </div>
        <UAlert v-if="sim.error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="sim.error" role="alert" data-test="sim-error" />
        <div v-if="sim.res" class="flex flex-col gap-3" data-test="sim-result">
          <UAlert :color="sim.res.decision === 'accept' ? 'success' : 'error'" variant="subtle" :icon="sim.res.decision === 'accept' ? 'i-lucide-circle-check' : 'i-lucide-circle-x'" :title="t(`radius.rules.decision_${sim.res.decision}`)" :description="reasonText(sim.res)" data-test="sim-decision" />
          <UAlert v-if="sim.res.directoryError" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t(`err.${sim.res.directoryError}`)" />
          <div v-if="sim.res.reply?.length">
            <h3 class="text-sm font-medium mb-1">{{ t('radius.rules.sim_reply') }}</h3>
            <ul class="flex flex-col divide-y divide-default border border-default rounded-md text-sm font-mono" data-test="sim-reply"><li v-for="a in sim.res.reply" :key="a.name" class="flex gap-3 px-3 py-1"><span class="text-muted">{{ a.name }}</span><span>{{ a.value }}</span></li></ul>
          </div>
          <div v-if="sim.res.trace?.length">
            <h3 class="text-sm font-medium mb-1">{{ t('radius.rules.sim_trace') }}</h3>
            <ol class="flex flex-col gap-1 text-sm" data-test="sim-trace">
              <li v-for="x in sim.res.trace" :key="x.n" class="border border-default rounded-md px-3 py-1.5" :class="x.matched ? 'border-success' : ''">
                <div class="flex items-center gap-2"><UIcon :name="x.matched ? 'i-lucide-check' : 'i-lucide-x'" class="size-4" :class="x.matched ? 'text-success' : 'text-muted'" /><span class="font-mono">{{ x.n }}</span><span>{{ ruleName(x.n) }}</span><UBadge v-if="x.never" color="warning" variant="subtle" size="sm" :label="t('radius.rules.never')" /></div>
                <ul class="text-xs text-muted pl-6"><li v-for="c in x.conds" :key="c.type" :class="c.ok ? '' : 'text-error'">{{ c.ok ? '✔' : '✖' }} {{ condText(c) }}</li></ul>
              </li>
            </ol>
          </div>
          <div v-if="sim.res.account">
            <h3 class="text-sm font-medium mb-1">{{ sim.res.account.displayName }} <span class="text-muted font-normal">— {{ t('radius.dir.groups') }} ({{ sim.res.account.groups.length }})</span></h3>
            <p v-if="sim.res.account.groupsTruncated" class="text-xs text-warning">{{ t('radius.dir.groups_truncated') }}</p>
            <div class="flex flex-wrap gap-1.5"><UBadge v-for="g in sim.res.account.groups" :key="g.dn" color="neutral" variant="subtle" size="sm" :label="g.name" :title="g.dn" /></div>
            <p class="text-xs text-dimmed mt-2">{{ sim.res.account.state.expiresAt ? t('radius.rules.sim_expires', { d: fmt.dateTime(sim.res.account.state.expiresAt) }) : '' }}</p>
          </div>
          <p class="text-xs text-dimmed">{{ t('radius.rules.sim_note') }}</p>
        </div>
      </form>
    </UCard>

    <UModal v-model:open="edit.open" :title="edit.id ? t('radius.rules.edit_title') : t('radius.rules.new_title')" :description="t('radius.rules.edit_desc')" :ui="{ content: 'max-w-3xl' }">
      <template #body>
        <form class="flex flex-col gap-4" @submit.prevent="save">
          <UAlert v-if="edit.error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="edit.error" role="alert" data-test="rule-error" />
          <div class="grid gap-4 md:grid-cols-2">
            <UFormField :label="t('common.name')" required><UInput v-model="f.name" class="w-full" maxlength="80" autocomplete="off" data-test="rule-f-name" /></UFormField>
            <UFormField :label="t('radius.rules.f_action')"><URadioGroup v-model="f.action" :items="actions" orientation="horizontal" data-test="rule-f-action" /></UFormField>
          </div>

          <fieldset class="flex flex-col gap-3 border border-default rounded-md p-3">
            <legend class="text-sm font-medium px-1">{{ t('radius.rules.f_conds') }}</legend>
            <p class="text-xs text-muted">{{ t('radius.rules.f_conds_help') }}</p>
            <UFormField :label="t('radius.rules.f_kind')"><URadioGroup v-model="f.kind" :items="kinds" orientation="horizontal" data-test="rule-f-kind" /></UFormField>
            <UFormField :label="t('radius.rules.f_groups')" :help="t('radius.rules.f_groups_help')">
              <div class="flex flex-col gap-2">
                <div v-if="f.groups.length" class="flex flex-wrap gap-1.5" data-test="rule-f-groups">
                  <UBadge v-for="(g, i) in f.groups" :key="g.dn" color="primary" variant="subtle" icon="i-lucide-users" :title="g.dn"><span>{{ g.name }}</span><button type="button" class="ml-1" :aria-label="t('common.delete')" @click="f.groups.splice(i, 1)">×</button></UBadge>
                </div>
                <div class="flex gap-2"><UInput v-model="gq" class="flex-1" :placeholder="t('radius.rules.g_search')" autocomplete="off" data-test="rule-g-q" @keydown.enter.prevent="searchGroups" /><UButton type="button" color="neutral" variant="outline" icon="i-lucide-search" :loading="searching" :disabled="gq.trim().length < 2" :label="t('common.search')" data-test="rule-g-search" @click="searchGroups" /></div>
                <UAlert v-if="gErr" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="gErr" />
                <ul v-if="found?.groups?.length" class="flex flex-col divide-y divide-default border border-default rounded-md text-sm max-h-48 overflow-auto" data-test="rule-g-found">
                  <li v-for="g in found.groups" :key="g.dn" class="flex items-center gap-2 px-3 py-1"><span class="font-mono">{{ g.name }}</span><span class="text-xs text-dimmed truncate">{{ g.description }}</span><UButton type="button" size="xs" class="ml-auto" color="neutral" variant="outline" :disabled="hasGroup(g.dn) || g.usable === false" :title="g.usable === false ? t('radius.rules.g_unusable') : undefined" :label="hasGroup(g.dn) ? t('radius.rules.g_added') : t('radius.rules.g_add')" @click="addGroup(g.dn, g.name)" /><UBadge v-if="g.usable === false" color="warning" variant="subtle" size="sm" icon="i-lucide-triangle-alert" :label="t('radius.rules.g_unusable_short')" :title="t('radius.rules.g_unusable')" data-test="rule-g-unusable" /></li>
                </ul>
                <p v-else-if="found" class="text-sm text-muted">{{ t('radius.dir.g_none') }}</p>
                <div class="flex gap-2"><UInput v-model="dnManual" class="flex-1 font-mono" placeholder="CN=grp-wifi,CN=Users,DC=exemple,DC=fr" autocomplete="off" data-test="rule-g-dn" @keydown.enter.prevent="addManual" /><UButton type="button" color="neutral" variant="outline" :disabled="!dnManual.includes('=') || dnBad" :label="t('radius.rules.g_add_dn')" @click="addManual" /></div>
                <p v-if="dnBad" class="text-xs text-warning" data-test="rule-g-dn-bad">{{ t('radius.rules.g_dn_bad') }}</p>
              </div>
            </UFormField>
            <div class="grid gap-4 md:grid-cols-2">
              <UFormField :label="t('radius.rules.f_clients')" :help="t('radius.rules.f_clients_help')"><USelectMenu v-model="f.clients" :items="clientItems" value-key="value" multiple class="w-full" :placeholder="t('radius.rules.any_client')" data-test="rule-f-clients" /></UFormField>
              <UFormField :label="t('radius.rules.f_usages')" :help="t('radius.rules.f_usages_help')"><USelectMenu v-model="f.usages" :items="usageChoices" value-key="value" multiple class="w-full" :placeholder="t('radius.rules.any_usage')" data-test="rule-f-usages" /></UFormField>
            </div>
            <UFormField :label="t('radius.rules.f_ssids')" :help="t('radius.rules.f_ssids_help')"><UTextarea v-model="f.ssids" :rows="2" class="w-full font-mono" placeholder="Corp Wifi" data-test="rule-f-ssids" /></UFormField>
          </fieldset>

          <fieldset v-if="f.action === 'accept'" class="flex flex-col gap-3 border border-default rounded-md p-3" data-test="rule-f-reply">
            <legend class="text-sm font-medium px-1">{{ t('radius.rules.f_reply') }}</legend>
            <p class="text-xs text-muted">{{ t('radius.rules.f_reply_help') }}</p>
            <div class="grid gap-4 md:grid-cols-2">
              <UFormField :label="t('radius.rules.f_vlan')" :help="t('radius.rules.f_vlan_help')"><UInput v-model="f.vlan" type="number" min="1" max="4094" class="w-full" data-test="rule-f-vlan" /></UFormField>
              <UFormField :label="t('radius.rules.f_pool')" :help="t('radius.rules.f_pool_help')"><UInput v-model="f.pool" class="w-full font-mono" autocomplete="off" data-test="rule-f-pool" /></UFormField>
              <UFormField :label="t('radius.rules.f_timeout')" :help="t('radius.rules.f_timeout_help')"><UInput v-model="f.minutes" type="number" min="1" max="43200" class="w-full" data-test="rule-f-timeout" /></UFormField>
              <UFormField :label="t('radius.rules.f_filter')" :help="t('radius.rules.f_filter_help')"><UInput v-model="f.filterId" class="w-full font-mono" autocomplete="off" data-test="rule-f-filter" /></UFormField>
            </div>
            <div class="flex flex-col gap-2">
              <span class="text-sm font-medium">{{ t('radius.rules.f_attrs') }}</span>
              <div v-for="(a, i) in f.attrs" :key="a.name" class="flex gap-2 items-center"><code class="text-sm w-48 shrink-0">{{ a.name }}</code><UInput v-model="a.value" class="flex-1 font-mono" autocomplete="off" /><UButton type="button" size="xs" color="neutral" variant="ghost" icon="i-lucide-x" :aria-label="t('common.delete')" @click="f.attrs.splice(i, 1)" /></div>
              <div v-if="vendorChoices.length" class="flex gap-2"><USelect v-model="newAttr" :items="vendorChoices" value-key="value" class="w-64" :placeholder="t('radius.rules.f_attr_add')" data-test="rule-f-attr" @update:model-value="addAttr" /></div>
            </div>
          </fieldset>
          <UAlert v-else color="neutral" variant="subtle" icon="i-lucide-info" :description="t('radius.rules.reject_note')" />

          <div class="grid gap-4 md:grid-cols-2">
            <UFormField :label="t('common.description')"><UInput v-model="f.comment" class="w-full" maxlength="500" data-test="rule-f-comment" /></UFormField>
            <UFormField :label="t('common.enabled')" :help="t('radius.rules.f_enabled_help')"><USwitch v-model="f.enabled" data-test="rule-f-enabled" /></UFormField>
          </div>
          <div class="flex justify-end gap-2">
            <UButton type="button" color="neutral" variant="outline" :label="t('common.cancel')" :disabled="edit.saving" @click="edit.open = false" />
            <UButton type="submit" :loading="edit.saving" :disabled="!f.name.trim()" :label="t('common.save')" data-test="rule-save" />
          </div>
        </form>
      </template>
    </UModal>
  </div>
</template>
