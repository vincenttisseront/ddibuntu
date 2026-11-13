<script setup lang="ts">
// Vue unifiée d'une adresse : noms (A/AAAA), PTR et alias (CNAME) gérés depuis l'IP (0.9.53).
const props = defineProps<{ address: { id: number; ip: string; hostname?: string | null } | null; canWrite: boolean }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ changed: [] }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const data = ref<any>(null), loading = ref(false), busy = ref(false), err = ref('')
const nf = reactive({ name: '', zone_id: 0, target: '', ttl: '' as string | number, comment: '' })
const hostZone = ref(0)
const edit = reactive<{ id: number; name: string; ttl: string | number; comment: string; disabled: boolean; target: string } | null>({} as any)
const editing = ref(0)

async function load() {
  if (!props.address) return
  loading.value = true; err.value = ''
  try { data.value = await api.call('GET', `/ipam/addresses/${props.address.id}/dns`, undefined, { silent: true }) }
  catch (e: any) { data.value = null; err.value = e?.info?.message ?? t('err.internal') } finally { loading.value = false }
}
watch(open, (o) => { if (o) { Object.assign(nf, { name: '', zone_id: 0, target: '', ttl: '', comment: '' }); editing.value = 0; hostZone.value = 0; void load() } })
const hosts = computed<any[]>(() => data.value?.hosts ?? [])
const targets = computed(() => [...hosts.value.map((h) => h.fqdn), ...(data.value?.aliases ?? []).map((a: any) => a.fqdn)])
const targetOptions = computed(() => targets.value.map((x: string) => ({ label: x, value: x })))
const zoneOptions = computed(() => [{ label: t('addrdns.zone_auto'), value: 0 }, ...(data.value?.zones ?? []).map((z: any) => ({ label: z.name + (z.viewName ? ` (${z.viewName})` : ''), value: z.id }))])
const hostZoneOptions = computed(() => (data.value?.hostZones ?? []).map((z: any) => ({ label: z.name, value: z.id })))
const ttlNum = (v: string | number) => (v === '' || v === null ? null : Number(v))
const ttlOk = (v: string | number) => v === '' || (Number.isInteger(Number(v)) && Number(v) >= 0 && Number(v) <= 2147483647)

async function run(fn: () => Promise<void>) {
  busy.value = true; err.value = ''
  try { await fn(); emit('changed') } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = false }
}
const createHost = () => run(async () => { await api.call('POST', `/ipam/addresses/${props.address!.id}/dns`, { zone_id: hostZone.value }, { silent: true }); toast.add({ title: t('addrdns.host_created'), color: 'success', icon: 'i-lucide-check' }); await load() })
const addAlias = () => run(async () => {
  const body: any = { name: nf.name }
  if (nf.zone_id) body.zone_id = nf.zone_id
  if (nf.target) body.target = nf.target
  if (nf.ttl !== '') body.ttl = ttlNum(nf.ttl)
  if (nf.comment) body.comment = nf.comment
  await api.call('POST', `/ipam/addresses/${props.address!.id}/aliases`, body, { silent: true })
  toast.add({ title: t('addrdns.created'), color: 'success', icon: 'i-lucide-check' }); nf.name = ''; nf.comment = ''; await load()
})
function startEdit(a: any) { editing.value = a.id; Object.assign(edit!, { id: a.id, name: a.name, ttl: a.ttl ?? '', comment: a.comment ?? '', disabled: a.disabled, target: a.target }) }
const saveEdit = () => run(async () => {
  const a = (data.value.aliases as any[]).find((x) => x.id === editing.value)
  const body: any = { ttl: ttlNum(edit!.ttl), comment: edit!.comment || null, disabled: edit!.disabled }
  if (edit!.name !== a.name) body.name = edit!.name
  if (edit!.target !== a.target) body.target = edit!.target
  await api.call('PUT', `/ipam/addresses/${props.address!.id}/aliases/${editing.value}`, body, { silent: true })
  editing.value = 0; toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await load()
})
async function removeAlias(a: any) {
  const deps = (data.value.aliases as any[]).filter((x) => x.depth > a.depth && x.id !== a.id).length   // approximation d'affichage ; le serveur tranche
  const direct = (data.value.aliases as any[]).some((x) => x.target === a.fqdn)
  const cascade = direct && deps > 0
  if (!(await ask(t('common.delete'), cascade ? t('addrdns.delete_cascade', { name: a.fqdn }) : t('common.delete_confirm', { name: a.fqdn })))) return
  await run(async () => { await api.call('DELETE', `/ipam/addresses/${props.address!.id}/aliases/${a.id}${cascade ? '?cascade=1' : ''}`, undefined, { silent: true }); toast.add({ title: t('addrdns.deleted'), color: 'success', icon: 'i-lucide-check' }); await load() })
}
const aliases = computed<any[]>(() => data.value?.aliases ?? [])
</script>

<template>
  <UModal v-model:open="open" :title="t('addrdns.title', { ip: address?.ip ?? '' })" :description="t('addrdns.desc')" :ui="{ content: 'sm:max-w-3xl' }">
    <template #body>
      <div v-if="loading && !data" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader-circle" class="animate-spin" />{{ t('common.loading') }}</div>
      <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" class="mb-3" role="alert" />
      <div v-if="data" class="flex flex-col gap-4 text-sm">
        <section>
          <h3 class="font-medium mb-1">{{ t('addrdns.names') }}</h3>
          <ul v-if="hosts.length" class="flex flex-col gap-1">
            <li v-for="h in hosts" :key="h.id" class="flex flex-wrap items-center gap-2"><UIcon name="i-lucide-server" class="size-4 text-muted" /><span class="font-mono">{{ h.fqdn }}</span><UBadge size="sm" variant="subtle" color="neutral" :label="h.type" /><UBadge v-if="h.viewName" size="sm" variant="subtle" color="info" :label="h.viewName" /></li>
          </ul>
          <div v-else class="flex flex-col gap-2">
            <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('addrdns.no_host')" :description="data.hostname ? t('addrdns.no_host_hint', { name: data.hostname }) : t('addrdns.no_hostname')" />
            <div v-if="canWrite && data.hostname" class="flex flex-wrap items-end gap-2">
              <UFormField :label="t('addrdns.create_in')"><USelect v-model="hostZone" :items="hostZoneOptions" class="w-64" :placeholder="t('addrdns.pick_zone')" /></UFormField>
              <UButton icon="i-lucide-plus" :label="t('addrdns.create_host')" :disabled="!hostZone" :loading="busy" @click="createHost" />
            </div>
          </div>
          <p v-if="data.ptr.length" class="mt-2 text-xs text-muted"><span class="font-medium">PTR</span> · <span class="font-mono">{{ data.ptr.map((p: any) => `${p.fqdn} → ${p.target}`).join(' ; ') }}</span></p>
        </section>

        <section v-if="hosts.length">
          <h3 class="font-medium mb-1">{{ t('addrdns.aliases') }} <span class="text-muted font-normal">({{ aliases.length }})</span></h3>
          <p v-if="!aliases.length" class="text-muted">{{ t('addrdns.none') }}</p>
          <ul v-else class="flex flex-col divide-y divide-default rounded border border-default">
            <li v-for="a in aliases" :key="a.id" class="p-2" :style="{ paddingInlineStart: (0.5 + (a.depth - 1) * 1.25) + 'rem' }" :data-test="'alias-' + a.fqdn">
              <div v-if="editing !== a.id" class="flex flex-wrap items-center gap-2">
                <UIcon :name="a.depth > 1 ? 'i-lucide-corner-down-right' : 'i-lucide-link'" class="size-4 text-muted" />
                <span class="font-mono" :class="a.disabled ? 'line-through text-muted' : ''">{{ a.fqdn }}</span>
                <span class="text-xs text-muted">→ <span class="font-mono">{{ a.target }}</span></span>
                <UBadge v-if="a.ttl !== null" size="sm" variant="subtle" color="neutral" :label="'TTL ' + a.ttl" />
                <UBadge v-if="a.disabled" size="sm" variant="subtle" color="warning" :label="t('addrdns.disabled')" />
                <UBadge v-if="a.protected" size="sm" variant="subtle" color="info" :label="t('addrdns.protected')" />
                <span v-if="a.comment" class="text-xs text-muted truncate max-w-48" :title="a.comment">{{ a.comment }}</span>
                <span v-if="canWrite" class="ms-auto flex gap-1">
                  <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-pencil" :aria-label="t('common.edit')" @click="startEdit(a)" />
                  <UButton size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="t('common.delete')" @click="removeAlias(a)" />
                </span>
              </div>
              <form v-else class="flex flex-wrap items-end gap-2" @submit.prevent="saveEdit">
                <UFormField :label="t('common.name')"><UInput v-model="edit!.name" class="w-44 font-mono" /></UFormField>
                <UFormField :label="t('addrdns.target')"><USelect v-model="edit!.target" :items="targetOptions.filter((o) => o.value !== a.fqdn)" class="w-56" /></UFormField>
                <UFormField label="TTL" :error="ttlOk(edit!.ttl) ? undefined : t('addrdns.ttl_bad')"><UInput v-model="edit!.ttl" inputmode="numeric" class="w-24" placeholder="—" /></UFormField>
                <UFormField :label="t('common.description')"><UInput v-model="edit!.comment" class="w-44" /></UFormField>
                <UCheckbox v-model="edit!.disabled" :label="t('addrdns.disabled')" class="pb-2" />
                <div class="flex gap-1 pb-0.5"><UButton type="submit" size="sm" :loading="busy" :disabled="!ttlOk(edit!.ttl)" :label="t('common.save')" /><UButton size="sm" color="neutral" variant="outline" :label="t('common.cancel')" @click="editing = 0" /></div>
              </form>
            </li>
          </ul>

          <form v-if="canWrite" class="mt-3 flex flex-wrap items-end gap-2" @submit.prevent="addAlias">
            <UFormField :label="t('addrdns.new_alias')" ><UInput v-model="nf.name" class="w-56 font-mono" :placeholder="t('addrdns.name_help')" data-test="alias-name" /></UFormField>
            <UFormField :label="t('addrdns.zone')"><USelect v-model="nf.zone_id" :items="zoneOptions" class="w-52" /></UFormField>
            <UFormField v-if="targets.length > 1" :label="t('addrdns.target')"><USelect v-model="nf.target" :items="targetOptions" class="w-56" :placeholder="t('addrdns.target_ph')" /></UFormField>
            <UFormField label="TTL" :error="ttlOk(nf.ttl) ? undefined : t('addrdns.ttl_bad')"><UInput v-model="nf.ttl" inputmode="numeric" class="w-24" placeholder="—" /></UFormField>
            <UButton type="submit" icon="i-lucide-plus" :label="t('addrdns.add')" :loading="busy" :disabled="!nf.name.trim() || !ttlOk(nf.ttl) || (hosts.length > 1 && !nf.target)" data-test="alias-add" />
          </form>
          <p v-if="canWrite" class="mt-2 text-xs text-dimmed">{{ t('addrdns.deploy_hint') }}</p>
        </section>
      </div>
      <div class="flex justify-end mt-4"><UButton color="neutral" variant="outline" :label="t('common.close')" @click="open = false" /></div>
    </template>
  </UModal>
</template>
