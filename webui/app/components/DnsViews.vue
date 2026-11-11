<script setup lang="ts">
// Vues DNS (0.9.6) : une vue répond selon l'adresse du client (et, au besoin, celle du serveur interrogé). Les vues sont évaluées dans l'ordre :
// la première dont la liste correspond sert le client. Dès qu'une vue existe, toute zone appartient à une vue.
const props = defineProps<{ looseZones: number }>()
const emit = defineEmits<{ (e: 'changed'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const { isAdmin } = useRole()
const { data, refresh } = useFetch<any>('/api/dns/views', { server: false })
const items = computed<any[]>(() => data.value?.items ?? [])
const uncovered = computed<string[]>(() => data.value?.uncovered ?? [])
const shadowed = computed<string[]>(() => data.value?.shadowed ?? [])
const busy = ref(false), error = ref(''), open = ref(false)
const f = reactive<any>({ id: 0, name: '', clients: '', dests: '', recursion: true, comment: '' })
const split = (v: string) => String(v ?? '').split(/[,\s]+/).filter(Boolean)
const adopt = computed(() => !f.id && !items.value.length && props.looseZones > 0)

function edit(v?: any) {
  error.value = ''
  Object.assign(f, v ? { id: v.id, name: v.name, clients: v.match_clients.join(', '), dests: v.match_destinations.join(', '), recursion: v.recursion, comment: v.comment ?? '' }
    : { id: 0, name: '', clients: '', dests: '', recursion: true, comment: '' })
  open.value = true
}
async function save() {
  busy.value = true; error.value = ''
  const body = { name: f.name.trim().toLowerCase(), match_clients: split(f.clients), match_destinations: split(f.dests), recursion: f.recursion, comment: f.comment || null }
  try {
    if (f.id) await api.call('PUT', `/dns/views/${f.id}`, body)
    else await api.call('POST', '/dns/views', { ...body, adopt_zones: adopt.value })
    open.value = false; toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' }); await refresh(); emit('changed')
  } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function remove(v: any) {
  if (!(await ask(t('dnsv.delete'), t('dnsv.delete_confirm', { n: v.name }), true))) return
  busy.value = true
  try {
    try { await api.call('DELETE', `/dns/views/${v.id}`) } catch (e: any) {
      if (e.info?.code !== 'view_last_with_zones') throw e
      // dernière vue : ses zones redeviennent des zones ordinaires, ce qui se confirme à part
      if (!(await ask(t('dnsv.delete'), t('dnsv.last_confirm', { n: v.zones }), true))) return
      await api.call('DELETE', `/dns/views/${v.id}?force=1`)
    }
    toast.add({ title: t('dnsv.deleted'), color: 'success', icon: 'i-lucide-check' }); await refresh(); emit('changed')
  } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { busy.value = false }
}
async function move(i: number, d: -1 | 1) {
  const ids = items.value.map((v) => v.id), j = i + d
  if (j < 0 || j >= ids.length) return
  ;[ids[i], ids[j]] = [ids[j]!, ids[i]!]
  busy.value = true
  try { await api.call('POST', '/dns/views/order', { ids }); await refresh() } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { busy.value = false }
}
</script>

<template>
  <div class="flex flex-col gap-3">
    <p class="text-sm text-muted max-w-3xl">{{ t('dnsv.intro') }}</p>
    <UAlert v-if="uncovered.length" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="t('dnsv.uncovered', { ip: uncovered.join(', ') })" />
    <UAlert v-if="shadowed.length" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('dnsv.shadowed', { n: shadowed.join(', ') })" />
    <UAlert v-if="items.length" color="neutral" variant="subtle" icon="i-lucide-info" :title="t('dnsv.refused_note')" />
    <div class="flex justify-end"><UButton v-if="isAdmin" icon="i-lucide-plus" :label="t('dnsv.add')" :disabled="items.length >= (data?.max ?? 16)" @click="edit()" /></div>
    <div v-if="!items.length" class="text-sm text-muted border border-default rounded-md p-4">{{ t('dnsv.none') }}</div>
    <div v-else class="overflow-x-auto border border-default rounded-md">
      <table class="w-full text-sm">
        <thead class="bg-elevated text-left"><tr>
          <th class="p-2 w-24">{{ t('dnsv.order') }}</th><th class="p-2">{{ t('common.name') }}</th><th class="p-2">{{ t('dnsv.clients') }}</th><th class="p-2">{{ t('dnsv.dests') }}</th>
          <th class="p-2">{{ t('dnsv.recursion') }}</th><th class="p-2 text-right">{{ t('dnsv.zones') }}</th><th class="p-2" />
        </tr></thead>
        <tbody>
          <tr v-for="(v, i) in items" :key="v.id" class="border-t border-default">
            <td class="p-2 whitespace-nowrap">
              <span class="num mr-2">{{ i + 1 }}</span>
              <UButton v-if="isAdmin" icon="i-lucide-arrow-up" size="xs" color="neutral" variant="ghost" :disabled="i === 0 || busy" :aria-label="t('dnsv.up')" @click="move(i, -1)" />
              <UButton v-if="isAdmin" icon="i-lucide-arrow-down" size="xs" color="neutral" variant="ghost" :disabled="i === items.length - 1 || busy" :aria-label="t('dnsv.down')" @click="move(i, 1)" />
            </td>
            <td class="p-2 font-mono font-medium">{{ v.name }}<div v-if="v.comment" class="text-xs text-muted font-sans font-normal">{{ v.comment }}</div></td>
            <td class="p-2 font-mono">{{ v.match_clients.join(', ') }}</td>
            <td class="p-2 font-mono">{{ v.match_destinations.join(', ') || '—' }}</td>
            <td class="p-2"><UBadge :color="v.recursion ? 'success' : 'neutral'" variant="subtle" :label="v.recursion ? t('common.yes') : t('common.no')" /></td>
            <td class="p-2 text-right num">{{ v.zones }}</td>
            <td class="p-2 text-right whitespace-nowrap">
              <UButton v-if="isAdmin" icon="i-lucide-pencil" size="xs" color="neutral" variant="ghost" :aria-label="t('common.edit')" @click="edit(v)" />
              <UButton v-if="isAdmin" icon="i-lucide-trash-2" size="xs" color="error" variant="ghost" :aria-label="t('common.delete')" :disabled="busy" @click="remove(v)" />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <UModal v-model:open="open" :title="f.id ? t('dnsv.edit') : t('dnsv.add')" :description="t('dnsv.form_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="save">
          <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" />
          <UAlert v-if="adopt" color="warning" variant="subtle" icon="i-lucide-info" :title="t('dnsv.adopt', { n: looseZones })" />
          <UFormField :label="t('common.name')" required :help="t('dnsv.name_hint')"><UInput v-model="f.name" class="w-full font-mono" placeholder="interne" /></UFormField>
          <UFormField :label="t('dnsv.clients')" required :help="t('dnsv.clients_hint')"><UInput v-model="f.clients" class="w-full font-mono" placeholder="10.0.0.0/8, 192.168.0.0/16, localhost" /></UFormField>
          <UFormField :label="t('dnsv.dests')" :help="t('dnsv.dests_hint')"><UInput v-model="f.dests" class="w-full font-mono" /></UFormField>
          <UFormField :label="t('dnsv.recursion')" :help="t('dnsv.recursion_hint')"><USwitch v-model="f.recursion" /></UFormField>
          <UFormField :label="t('common.description')"><UInput v-model="f.comment" class="w-full" /></UFormField>
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="open = false" /><UButton type="submit" :loading="busy" :label="t('common.save')" /></div>
        </form>
      </template>
    </UModal>
  </div>
</template>
