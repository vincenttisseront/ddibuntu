<script setup lang="ts">
// Contrôle de cohérence DNS ↔ IPAM (0.10.1) : constats, score par zone, correction en un clic (après récapitulatif).
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm()
const { canWrite } = useRole()
const rep = ref<any>(null), loading = ref(true), fixing = ref(false), err = ref('')
const sel = ref<string[]>([]), kind = ref('all')
const KIND = computed<Record<string, string>>(() => ({ orphan_ptr: t('dnshealth.kind.orphan_ptr'), a_no_ptr: t('dnshealth.kind.a_no_ptr'), a_no_ipam: t('dnshealth.kind.a_no_ipam'), ip_no_name: t('dnshealth.kind.ip_no_name'), dangling_cname: t('dnshealth.kind.dangling_cname') }))
const FIX = computed<Record<string, string>>(() => ({ delete: t('dnshealth.fix.delete'), create_ptr: t('dnshealth.fix.create_ptr'), create_address: t('dnshealth.fix.create_address'), create_a: t('dnshealth.fix.create_a'), disable: t('dnshealth.fix.disable') }))
async function load() {
  loading.value = true; err.value = ''
  try { rep.value = await api.call('GET', '/dns/health', undefined, { silent: true }); sel.value = sel.value.filter((k) => rep.value.findings.some((f: any) => f.key === k)) }
  catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { loading.value = false }
}
const shown = computed(() => (rep.value?.findings ?? []).filter((f: any) => kind.value === 'all' || f.kind === kind.value))
const fixableShown = computed(() => shown.value.filter((f: any) => f.fixable))
const kindItems = computed(() => [{ label: t('dnshealth.all'), value: 'all' }, ...Object.keys(KIND.value).map((k) => ({ label: `${KIND.value[k]} (${rep.value?.counts?.[k] ?? 0})`, value: k }))])
const color = (s: number) => (s >= 95 ? 'success' : s >= 75 ? 'warning' : 'error')
function toggle(k: string, on: boolean) { sel.value = on ? [...new Set([...sel.value, k])] : sel.value.filter((x) => x !== k) }
function toggleAll(on: boolean) { sel.value = on ? fixableShown.value.map((f: any) => f.key) : [] }
async function fix() {
  const items = (rep.value?.findings ?? []).filter((f: any) => sel.value.includes(f.key))
  if (!items.length) return
  const lines = items.slice(0, 8).map((f: any) => `• ${FIX.value[f.fix]} : ${f.name}`).join('\n') + (items.length > 8 ? `\n… +${items.length - 8}` : '')
  if (!(await ask(t('dnshealth.confirm.title'), `${t('dnshealth.confirm.msg', { n: items.length })}\n${lines}`, false))) return
  fixing.value = true; err.value = ''
  try {
    const r = await api.call('POST', '/dns/health/fix', { keys: sel.value })
    rep.value = r.report; sel.value = []
    toast.add({ title: t('dnshealth.fixed', { n: r.done, g: r.gone, u: r.unfixable }), color: 'success' })
  } catch (e: any) { err.value = e?.info?.message ?? t('err.internal'); await load() } finally { fixing.value = false }
}
await load()
</script>

<template>
  <div class="flex flex-col gap-4">
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <div v-if="loading && !rep" class="flex items-center gap-2 text-muted"><UIcon name="i-lucide-loader-circle" class="size-4 animate-spin" />{{ t('common.loading') }}</div>
    <template v-if="rep">
      <div class="flex flex-wrap items-center gap-3">
        <UBadge :color="color(rep.score)" variant="subtle" size="lg" :label="t('dnshealth.score', { n: rep.score })" data-test="health-score" />
        <span class="text-sm text-muted">{{ t('dnshealth.summary', { n: rep.findings.length }) }}</span>
        <UButton class="ml-auto" color="neutral" variant="outline" icon="i-lucide-refresh-cw" :label="t('dnshealth.recheck')" :loading="loading" @click="load" />
      </div>
      <div v-if="rep.zones.length" class="flex flex-wrap gap-2" :aria-label="t('dnshealth.zones')">
        <UBadge v-for="z in rep.zones" :key="z.zone_id" :color="color(z.score)" variant="outline" :label="`${z.zone} · ${z.score}`" :title="t('dnshealth.zone_tip', { r: z.records, i: z.issues })" />
      </div>
      <UAlert v-if="!rep.findings.length" color="success" variant="subtle" icon="i-lucide-badge-check" :title="t('dnshealth.clean')" />
      <template v-else>
        <div class="flex flex-wrap items-center gap-3">
          <USelect v-model="kind" :items="kindItems" class="w-72" :aria-label="t('common.type')" />
          <UButton v-if="canWrite" icon="i-lucide-wrench" :label="t('dnshealth.fix_sel', { n: sel.length })" :disabled="!sel.length" :loading="fixing" data-test="health-fix" @click="fix" />
        </div>
        <div class="overflow-x-auto rounded-md border border-default">
          <table class="w-full text-sm">
            <thead class="text-left text-muted"><tr>
              <th class="p-2 w-8"><UCheckbox v-if="canWrite" :model-value="fixableShown.length > 0 && fixableShown.every((f: any) => sel.includes(f.key))" :aria-label="t('dnshealth.all')" @update:model-value="(v: any) => toggleAll(!!v)" /></th>
              <th class="p-2">{{ t('common.type') }}</th><th class="p-2">{{ t('common.name') }}</th><th class="p-2">{{ t('dns.zone') }}</th><th class="p-2">{{ t('dnshealth.detail') }}</th><th class="p-2">{{ t('dnshealth.action') }}</th>
            </tr></thead>
            <tbody>
              <tr v-for="f in shown" :key="f.key" class="border-t border-default">
                <td class="p-2"><UCheckbox v-if="canWrite && f.fixable" :model-value="sel.includes(f.key)" :aria-label="f.name" @update:model-value="(v: any) => toggle(f.key, !!v)" /></td>
                <td class="p-2 whitespace-nowrap">{{ KIND[f.kind] }}</td>
                <td class="p-2 font-mono">{{ f.name }}</td>
                <td class="p-2 font-mono">{{ f.zone ?? '—' }}</td>
                <td class="p-2 text-muted">{{ f.detail }}</td>
                <td class="p-2 whitespace-nowrap">{{ f.fixable ? FIX[f.fix] : t('dnshealth.manual') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </template>
  </div>
</template>
