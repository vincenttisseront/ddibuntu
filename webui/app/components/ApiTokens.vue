<script setup lang="ts">
// Jetons d'API : création (secret affiché une seule fois), liste, révocation par boîte de dialogue maison.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { data, refresh } = await useFetch<any>('/api/tokens')
const f = reactive({ name: '', role: 'viewer', expiresDays: 90 as number | null })
const open = ref(false), busy = ref(false), secret = ref(''), err = ref('')
const roles = computed(() => ['viewer', 'operator'].map((v) => ({ label: t(`system.role.${v}`), value: v })))
const expiries = computed(() => [{ label: t('tok.exp_30'), value: 30 }, { label: t('tok.exp_90'), value: 90 }, { label: t('tok.exp_365'), value: 365 }, { label: t('tok.exp_never'), value: null as any }])
const fmt = (v: string | null) => (v ? new Date(v).toLocaleString() : '—')
const nameOk = computed(() => /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(f.name))
function begin() { Object.assign(f, { name: '', role: 'viewer', expiresDays: 90 }); secret.value = ''; err.value = ''; open.value = true }
async function create() {
  busy.value = true; err.value = ''
  try { const r: any = await api.call('POST', '/tokens', { name: f.name, role: f.role, expiresDays: f.expiresDays }, { busy: true }); secret.value = r.token; await refresh() }
  catch (e: any) { err.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
async function revoke(row: any) {
  if (!(await ask(t('tok.revoke'), t('tok.revoke_confirm', { name: row.name })))) return
  try { await api.call('DELETE', `/tokens/${row.id}`); toast.add({ title: t('tok.revoked'), color: 'success', icon: 'i-lucide-check' }); await refresh() }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) }
}
async function copy(v: string) { try { await navigator.clipboard.writeText(v); toast.add({ title: t('common.copied'), color: 'success' }) } catch { /* presse-papiers indisponible */ } }
const curl = computed(() => `curl -k -H "Authorization: Bearer ${secret.value}" ${typeof window !== 'undefined' ? window.location.origin : ''}/api/ipam/spaces`)
</script>

<template>
  <div class="flex flex-col gap-3">
    <UAlert color="neutral" variant="subtle" icon="i-lucide-key-round" :description="t('tok.intro')" />
    <div class="flex gap-2">
      <UButton icon="i-lucide-plus" :label="t('tok.new')" @click="begin" data-test="tok-new" />
      <UButton icon="i-lucide-book-open" color="neutral" variant="outline" :label="t('tok.openapi')" to="/api/openapi.json" target="_blank" />
    </div>
    <div class="overflow-x-auto"><table class="w-full text-sm">
      <thead><tr class="text-left text-muted"><th class="py-1 pe-3">{{ t('common.name') }}</th><th class="pe-3">{{ t('tok.prefix') }}</th><th class="pe-3">{{ t('tok.role') }}</th><th class="pe-3">{{ t('tok.created') }}</th><th class="pe-3">{{ t('tok.expires') }}</th><th class="pe-3">{{ t('tok.last_used') }}</th><th class="pe-3">{{ t('common.status') }}</th><th /></tr></thead>
      <tbody>
        <tr v-for="r in data?.items ?? []" :key="r.id" class="border-t border-default">
          <td class="py-1 pe-3 font-mono">{{ r.name }}</td><td class="pe-3 font-mono">{{ r.prefix }}…</td><td class="pe-3">{{ t(`system.role.${r.role}`) }}</td>
          <td class="pe-3">{{ fmt(r.created_at) }}</td><td class="pe-3">{{ r.expires_at ? fmt(r.expires_at) : t('tok.exp_never') }}</td><td class="pe-3">{{ fmt(r.last_used_at) }}</td>
          <td class="pe-3"><UBadge size="sm" variant="subtle" :color="r.active ? 'success' : 'neutral'" :label="r.revoked_at ? t('tok.st_revoked') : r.active ? t('tok.st_active') : t('tok.st_expired')" /></td>
          <td><UButton v-if="r.active" size="xs" color="error" variant="ghost" icon="i-lucide-ban" :label="t('tok.revoke')" @click="revoke(r)" /></td>
        </tr>
        <tr v-if="!(data?.items ?? []).length"><td colspan="8" class="py-3 text-muted">{{ t('tok.none') }}</td></tr>
      </tbody>
    </table></div>

    <UModal v-model:open="open" :dismissible="!busy" :title="t('tok.new')" :description="t('tok.new_desc')">
      <template #body>
        <div v-if="!secret" class="flex flex-col gap-3">
          <UFormField :label="t('common.name')" :hint="t('tok.name_hint')"><UInput v-model="f.name" class="w-full" :disabled="busy" data-test="tok-name" /></UFormField>
          <UFormField :label="t('tok.role')" :hint="t('tok.role_hint')"><USelect v-model="f.role" :items="roles" class="w-full" :disabled="busy" /></UFormField>
          <UFormField :label="t('tok.expires')"><USelect v-model="f.expiresDays" :items="expiries" class="w-full" :disabled="busy" /></UFormField>
          <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" />
        </div>
        <div v-else class="flex flex-col gap-3">
          <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('tok.once')" />
          <div class="flex gap-2 items-center"><code class="flex-1 break-all text-sm" data-test="tok-secret">{{ secret }}</code><UButton size="xs" icon="i-lucide-copy" color="neutral" variant="outline" :label="t('common.copy')" @click="copy(secret)" /></div>
          <p class="text-xs text-muted">{{ t('tok.example') }}</p><pre class="text-xs whitespace-pre-wrap break-all">{{ curl }}</pre>
        </div>
      </template>
      <template #footer>
        <div class="flex justify-end gap-2 w-full">
          <UButton color="neutral" variant="outline" :label="secret ? t('common.close') : t('common.cancel')" :disabled="busy" @click="open = false" />
          <UButton v-if="!secret" :label="t('tok.create')" :loading="busy" :disabled="!nameOk" @click="create" data-test="tok-create" />
        </div>
      </template>
    </UModal>
  </div>
</template>
