<script setup lang="ts">
// Assistant d'import NetBox : connexion (jeton jamais conservé sauf demande), périmètre, aperçu sans écriture, import avec point de restauration.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const emit = defineEmits<{ (e: 'changed'): void }>()
const step = ref(0), busy = ref(false), error = ref(''), done = ref(false)
const steps = computed(() => [{ id: 'conn', label: t('nbw.s_conn') }, { id: 'scope', label: t('nbw.s_scope') }, { id: 'preview', label: t('nbw.s_preview') }, { id: 'apply', label: t('nbw.s_apply') }])
const fail = (e: any) => { const u = e.info?.upstream; error.value = (e.info?.message ?? t('err.internal')) + (u ? ' ' + t('nbw.upstream', { s: u.status, d: u.detail || '—' }) : '') }
const f = reactive<any>({ url: '', token: '', tlsVerify: true, caPem: '', rememberToken: false, include: { vlans: true, prefixes: true, addresses: true }, mode: 'add', prune: false, includeContainers: false })
const { data: saved } = useFetch<any>('/api/netbox/settings', { server: false })
watch(saved, (s) => { if (s?.url) { for (const k of ['url', 'tlsVerify', 'caPem', 'include', 'mode', 'prune', 'includeContainers']) if (s[k] !== undefined) f[k] = s[k]; f.rememberToken = s.tokenSet } }, { immediate: true })
const test = ref<any>(null), plan = ref<any>(null), result = ref<any>(null)
const body = () => ({ url: f.url.trim(), tlsVerify: f.tlsVerify, caPem: f.caPem || undefined, include: f.include, mode: f.mode, prune: f.prune, includeContainers: f.includeContainers, token: f.token.trim() || undefined })
async function runTest() { busy.value = true; error.value = ''; test.value = null; try { test.value = await api.call('POST', '/netbox/test', { url: f.url.trim(), tlsVerify: f.tlsVerify, caPem: f.caPem || undefined, token: f.token.trim() || undefined }) } catch (e: any) { fail(e) } finally { busy.value = false } }
async function saveSettings() { try { await api.call('PUT', '/netbox/settings', { ...body(), token: undefined, ...(f.rememberToken && f.token ? { token: f.token } : {}), rememberToken: f.rememberToken }); toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }) } catch (e: any) { fail(e) } }
async function preview() { busy.value = true; error.value = ''; plan.value = null; try { plan.value = await api.call('POST', '/netbox/preview', body()) } catch (e: any) { fail(e) } finally { busy.value = false } }
async function apply() {
  if (!(await ask(t('nbw.apply'), t('nbw.apply_confirm'), false))) return
  busy.value = true; error.value = ''
  try { result.value = await api.call('POST', '/netbox/commit', { planId: plan.value.planId }); done.value = true; emit('changed'); toast.add({ title: t('import.done'), color: 'success', icon: 'i-lucide-check' }) } catch (e: any) { fail(e) } finally { busy.value = false }
}
async function undo() {
  if (!(await ask(t('restore.restore'), t('restore.undo_confirm'), true))) return
  try { await api.call('POST', `/snapshots/${result.value.snapshotId}/restore`, {}); emit('changed'); toast.add({ title: t('restore.done'), color: 'success', icon: 'i-lucide-check' }); result.value = null; done.value = false; step.value = 0 } catch (e: any) { fail(e) }
}
const KINDS = ['vlans', 'subnets', 'addresses']
const COLS = ['created', 'updated', 'unchanged', 'kept_manual', 'existing']
const canNext = computed(() => [!!f.url.trim() && (!!f.token || !!saved.value?.tokenSet) && !!test.value?.ok, f.include.vlans || f.include.prefixes || f.include.addresses, !!plan.value, !done.value][step.value] ?? false)
const stats = (r: any) => r?.stats ?? r
</script>

<template>
  <WizardShell v-model="step" :steps="steps" :can-next="canNext" :busy="busy" :finish-label="t('nbw.apply')" :hide-footer="done" @finish="apply">
    <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" class="mb-3" />
    <template #conn>
      <UCard><form class="flex flex-col gap-3" @submit.prevent="runTest">
        <p class="text-sm text-muted">{{ t('nbw.conn_desc') }}</p>
        <UFormField :label="t('nbw.url')" :help="t('nbw.url_hint')"><UInput v-model="f.url" class="w-full font-mono" placeholder="https://netbox.example.com" /></UFormField>
        <UFormField :label="t('nbw.token')" :help="saved?.tokenSet ? t('nbw.token_saved') : t('nbw.token_hint')"><UInput v-model="f.token" type="password" autocomplete="off" class="w-full font-mono" /></UFormField>
        <USwitch v-model="f.rememberToken" :label="t('nbw.remember')" />
        <USwitch v-model="f.tlsVerify" :label="t('ad.tls_verify')" />
        <UFormField v-if="f.tlsVerify" :label="t('ad.ca')" :help="t('ad.ca_hint')"><UTextarea v-model="f.caPem" :rows="3" class="w-full font-mono text-xs" /></UFormField>
        <UAlert v-else color="warning" variant="subtle" icon="i-lucide-shield-alert" :title="t('nbw.tls_off')" />
        <div class="flex gap-2"><UButton type="submit" icon="i-lucide-plug-zap" :loading="busy" :label="t('ad.test_do')" /><UButton color="neutral" variant="outline" icon="i-lucide-save" :label="t('nbw.save')" :disabled="!f.url" @click="saveSettings" /></div>
        <UAlert v-if="test" color="success" variant="subtle" icon="i-lucide-check" :title="t('nbw.ok', { v: test.version })" />
      </form></UCard>
    </template>
    <template #scope>
      <UCard><div class="flex flex-col gap-3 text-sm">
        <p class="text-muted">{{ t('nbw.scope_desc') }}</p>
        <USwitch v-model="f.include.vlans" label="VLAN" /><USwitch v-model="f.include.prefixes" :label="t('nbw.prefixes')" /><USwitch v-model="f.include.addresses" :label="t('nbw.addresses')" /><USwitch v-model="f.includeContainers" :label="t('nbw.containers')" />
        <UFormField :label="t('import.mode')" :help="t(`nbw.mode_${f.mode}_hint`)"><USelect v-model="f.mode" :items="['add', 'sync', 'sync_overwrite'].map((v) => ({ label: t(`nbw.mode_${v}`), value: v }))" class="w-full" /></UFormField>
        <USwitch v-if="f.mode !== 'add'" v-model="f.prune" :label="t('nbw.prune')" />
      </div></UCard>
    </template>
    <template #preview>
      <UCard><div class="flex flex-col gap-3 text-sm">
        <p class="text-muted">{{ t('nbw.preview_desc') }}</p>
        <div><UButton icon="i-lucide-search-check" :loading="busy" :label="t('import.analyse')" @click="preview" /></div>
        <template v-if="plan">
          <p class="num">{{ t('nbw.fetched', { v: plan.fetched.vlans, p: plan.fetched.prefixes, a: plan.fetched.addresses }) }}</p>
          <table class="w-full max-w-xl"><caption class="sr-only">{{ t('nbw.s_preview') }}</caption>
            <thead><tr class="text-muted"><th scope="col" class="text-start p-1" /><th v-for="c in COLS" :key="c" scope="col" class="p-1">{{ t(`nbw.c_${c}`) }}</th></tr></thead>
            <tbody><tr v-for="k in KINDS" :key="k" class="border-t border-default"><th scope="row" class="text-start p-1">{{ t(`nbw.k_${k}`) }}</th><td v-for="c in COLS" :key="c" class="p-1 text-center num">{{ plan.stats[k][c] ?? 0 }}</td></tr></tbody></table>
          <p v-if="plan.stats.pruned.vlans + plan.stats.pruned.addresses" class="text-warning num">{{ t('nbw.will_prune', { n: plan.stats.pruned.vlans + plan.stats.pruned.addresses }) }}</p>
          <p v-if="plan.stats.addresses.no_subnet" class="text-muted num">{{ t('nbw.no_subnet', { n: plan.stats.addresses.no_subnet }) }}</p>
          <p v-if="plan.stats.stale_subnets" class="text-muted num">{{ t('nbw.stale', { n: plan.stats.stale_subnets }) }}</p>
          <p v-if="Object.keys(plan.stats.skipped ?? {}).length" class="text-xs text-muted">{{ t('nbw.skipped') }} : {{ Object.entries(plan.stats.skipped).filter(([, n]) => Number(n) > 0).map(([k, n]) => `${t(`nbw.skip.${k}`)} ${n}`).join(' · ') }}</p>
        </template>
      </div></UCard>
    </template>
    <template #apply>
      <UCard><div class="flex flex-col gap-3 text-sm">
        <template v-if="!done"><p>{{ t('nbw.apply_desc') }}</p><UAlert color="info" variant="subtle" icon="i-lucide-undo-2" :title="t('restore.auto_point')" /></template>
        <template v-else>
          <UAlert color="success" variant="subtle" icon="i-lucide-check" :title="t('import.done')" />
          <p class="num">{{ KINDS.map((k) => `${t(`nbw.k_${k}`)} : +${stats(result)[k].created} / ~${stats(result)[k].updated}`).join(' · ') }}</p>
          <div class="flex gap-2"><UButton color="neutral" variant="outline" icon="i-lucide-undo-2" :label="t('restore.undo')" @click="undo" /><UButton to="/ipam#subnets" color="neutral" variant="ghost" :label="t('nbw.see_ipam')" /></div>
          <UAlert color="warning" variant="subtle" icon="i-lucide-rocket" :title="t('adw.deploy_hint')" />
        </template>
      </div></UCard>
    </template>
  </WizardShell>
</template>
