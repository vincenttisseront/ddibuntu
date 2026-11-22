<script setup lang="ts">
// Accès réseau — journal des authentifications de CE nœud (0.14.18) : qui s'est authentifié, par quel équipement, avec quel certificat, quelle règle a
// décidé, pourquoi un refus. Lecture seule du fichier écrit par FreeRADIUS (voir server/utils/radius-journal.ts) ; l'explication d'un motif
// et ce qu'il faut vérifier sont affichés en clair sous la ligne.
const { t } = useT(); const api = useApi(); const fmt = useFmt()

interface Ev {
  at: number; kind: 'accept' | 'reject' | 'diag'; user: string; client: string; nas: string; mac: string; called: string; nasId: string
  subject: string; issuer: string; serial: string; expires: string; upn: string; dns: string; identity: string; decision: string; reason: string; why: string; selftest: boolean
}
interface Res { available: boolean; events: Ev[]; counts: { accept: number; reject: number; diag: number }; reasons: { why: string; n: number }[]; truncated: boolean }

// pas de valeur vide : un item de sélecteur ne peut pas valoir ''
const kind = ref<'all' | 'accept' | 'reject' | 'diag'>('all')
const minutes = ref(1440), q = ref(''), selftest = ref(false), auto = ref(true)
const data = ref<Res | null>(null), err = ref(''), loading = ref(false), open = ref<string | null>(null)
const kinds = computed(() => [{ label: t('radius.journal.kind_all'), value: 'all' }, { label: t('radius.journal.kind_accept'), value: 'accept' }, { label: t('radius.journal.kind_reject'), value: 'reject' }, { label: t('radius.journal.kind_diag'), value: 'diag' }])
const periods = computed(() => [{ label: t('radius.journal.p_1h'), value: 60 }, { label: t('radius.journal.p_24h'), value: 1440 }, { label: t('radius.journal.p_7d'), value: 10080 }, { label: t('radius.journal.p_all'), value: 0 }])

async function load() {
  loading.value = true
  try {
    const p = new URLSearchParams({ limit: '300' })
    if (kind.value !== 'all') p.set('kind', kind.value)
    if (minutes.value) p.set('minutes', String(minutes.value))
    if (q.value.trim()) p.set('q', q.value.trim().slice(0, 100))
    if (selftest.value) p.set('selftest', '1')
    data.value = await api.call('GET', `/radius/events?${p}`, undefined, { silent: true }); err.value = ''
  } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { loading.value = false }
}
let timer: ReturnType<typeof setInterval> | undefined, typing: ReturnType<typeof setTimeout> | undefined
watch([kind, minutes, selftest], () => { void load() })
watch(q, () => { clearTimeout(typing); typing = setTimeout(() => { void load() }, 350) })
onMounted(() => { timer = setInterval(() => { if (auto.value && !document.hidden) void load() }, 10_000) })
onBeforeUnmount(() => { clearInterval(timer); clearTimeout(typing) })
await load()

const key = (e: Ev, i: number) => `${e.at}:${e.kind}:${i}`
const who = (e: Ev) => e.identity ? e.identity.replace(/^(user|computer):/, '') : e.upn || e.dns || e.user || '—'
const whoKind = (e: Ev) => e.identity.startsWith('computer:') ? t('radius.journal.computer') : e.identity.startsWith('user:') ? t('radius.journal.user') : ''
const ssid = (e: Ev) => /^(?:[0-9A-Fa-f]{2}[-:.]?){5}[0-9A-Fa-f]{2}:(.+)$/.exec(e.called)?.[1] ?? ''
const nasText = (e: Ev) => e.client ? `${e.client}${e.nas ? ` (${e.nas})` : ''}` : e.nas || '—'
const certText = (e: Ev) => e.subject.replace(/^\/?CN=/, '') || '—'
const why = (e: Ev) => (e.kind === 'accept' ? e.decision || t('radius.journal.res_accept') : t(`radius.journal.why_${e.why}`))
const badge = (e: Ev) => (e.kind === 'accept' ? 'success' : e.kind === 'reject' ? 'error' : 'warning')
const reasonLabel = (w: string) => t(`radius.journal.why_${w}`)
</script>

<template>
  <div class="flex flex-col gap-3" data-test="radius-journal">
    <p class="text-sm text-muted">{{ t('radius.journal.intro') }}</p>
    <UAlert v-if="data && !data.available" color="info" variant="subtle" icon="i-lucide-file-clock" :title="t('radius.journal.absent')" data-test="radius-journal-absent" />

    <div class="flex flex-wrap items-end gap-3">
      <UFormField :label="t('radius.journal.f_kind')"><USelect v-model="kind" :items="kinds" class="w-40" data-test="radius-journal-kind" /></UFormField>
      <UFormField :label="t('radius.journal.f_period')"><USelect v-model="minutes" :items="periods" class="w-40" data-test="radius-journal-period" /></UFormField>
      <UFormField :label="t('common.search')" class="grow min-w-56"><UInput v-model="q" class="w-full" :placeholder="t('radius.journal.f_search')" data-test="radius-journal-q" /></UFormField>
      <UCheckbox v-model="selftest" :label="t('radius.journal.f_selftest')" />
      <UCheckbox v-model="auto" :label="t('radius.journal.f_auto')" />
      <UButton icon="i-lucide-refresh-cw" color="neutral" variant="outline" :label="t('radius.journal.refresh')" :loading="loading" @click="load" />
    </div>

    <p v-if="data" class="text-sm" data-test="radius-journal-summary">
      {{ t('radius.journal.summary', { ok: data.counts.accept, ko: data.counts.reject, diag: data.counts.diag }) }}
      <template v-if="data.reasons.length"> — <UBadge v-for="r in data.reasons.slice(0, 4)" :key="r.why" size="sm" color="neutral" variant="subtle" class="me-1" :label="`${reasonLabel(r.why)} · ${r.n}`" /></template>
    </p>
    <AiExplain v-if="data?.available" use="radius_summary" :payload="{ minutes: minutes || 10080 }" :label="t('ai.radius_summary')" />
    <p v-if="err" class="text-sm text-error" role="alert">{{ err }}</p>

    <div class="overflow-x-auto">
      <table class="w-full text-sm" data-test="radius-journal-table">
        <thead><tr class="text-left text-muted">
          <th class="py-1 pe-3">{{ t('radius.journal.col_time') }}</th><th class="pe-3">{{ t('radius.journal.col_result') }}</th><th class="pe-3">{{ t('radius.journal.col_who') }}</th>
          <th class="pe-3">{{ t('radius.journal.col_mac') }}</th><th class="pe-3">{{ t('radius.journal.col_nas') }}</th><th class="pe-3">{{ t('radius.journal.col_cert') }}</th><th>{{ t('radius.journal.col_why') }}</th>
        </tr></thead>
        <tbody>
          <template v-for="(e, i) in data?.events ?? []" :key="key(e, i)">
            <tr class="border-t border-default align-top cursor-pointer hover:bg-elevated/50" data-test="radius-journal-row" tabindex="0" :aria-expanded="open === key(e, i)"
                @click="open = open === key(e, i) ? null : key(e, i)" @keydown.enter="open = open === key(e, i) ? null : key(e, i)">
              <td class="py-1 pe-3 whitespace-nowrap">{{ fmt.dateTime(e.at) }}</td>
              <td class="pe-3"><UBadge size="sm" variant="subtle" :color="(badge(e) as any)" :label="t(`radius.journal.res_${e.kind}`)" /><UBadge v-if="e.selftest" size="sm" color="neutral" variant="outline" class="ms-1" :label="t('radius.journal.test')" /></td>
              <td class="pe-3"><span class="font-mono break-all">{{ who(e) }}</span><span v-if="whoKind(e)" class="text-dimmed text-xs"> · {{ whoKind(e) }}</span></td>
              <td class="pe-3 font-mono whitespace-nowrap">{{ e.mac || '—' }}</td>
              <td class="pe-3"><span class="font-mono">{{ nasText(e) }}</span><span v-if="ssid(e)" class="text-dimmed text-xs"> · {{ ssid(e) }}</span></td>
              <td class="pe-3 font-mono break-all">{{ certText(e) }}</td>
              <td :class="e.kind === 'accept' ? '' : 'text-muted'">{{ why(e) }}</td>
            </tr>
            <tr v-if="open === key(e, i)" class="bg-elevated/40" data-test="radius-journal-detail">
              <td colspan="7" class="px-3 py-2">
                <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-xs">
                  <div v-if="e.kind !== 'accept'" class="sm:col-span-2 text-sm"><strong>{{ reasonLabel(e.why) }}.</strong> {{ t(`radius.journal.hint_${e.why}`) }}</div>
                  <div v-if="e.reason"><dt class="inline text-muted">{{ t('radius.journal.d_reason') }} : </dt><dd class="inline font-mono break-all">{{ e.reason }}</dd></div>
                  <div v-if="e.user"><dt class="inline text-muted">{{ t('radius.journal.d_presented') }} : </dt><dd class="inline font-mono break-all">{{ e.user }}</dd></div>
                  <div v-if="e.subject"><dt class="inline text-muted">{{ t('radius.journal.d_subject') }} : </dt><dd class="inline font-mono break-all">{{ e.subject }}</dd></div>
                  <div v-if="e.issuer"><dt class="inline text-muted">{{ t('radius.journal.d_issuer') }} : </dt><dd class="inline font-mono break-all">{{ e.issuer }}</dd></div>
                  <div v-if="e.serial"><dt class="inline text-muted">{{ t('radius.journal.d_serial') }} : </dt><dd class="inline font-mono">{{ e.serial }}</dd></div>
                  <div v-if="e.expires"><dt class="inline text-muted">{{ t('radius.journal.d_expires') }} : </dt><dd class="inline font-mono">{{ e.expires }}</dd></div>
                  <div v-if="e.upn"><dt class="inline text-muted">UPN : </dt><dd class="inline font-mono break-all">{{ e.upn }}</dd></div>
                  <div v-if="e.dns"><dt class="inline text-muted">DNS : </dt><dd class="inline font-mono break-all">{{ e.dns }}</dd></div>
                  <div v-if="e.decision"><dt class="inline text-muted">{{ t('radius.journal.d_rule') }} : </dt><dd class="inline">{{ e.decision }}</dd></div>
                  <div v-if="e.called"><dt class="inline text-muted">{{ t('radius.journal.d_called') }} : </dt><dd class="inline font-mono break-all">{{ e.called }}</dd></div>
                  <div v-if="e.nasId"><dt class="inline text-muted">NAS-Identifier : </dt><dd class="inline font-mono break-all">{{ e.nasId }}</dd></div>
                </dl>
                <AiExplain class="mt-2" use="radius" :payload="{ at: e.at, kind: e.kind, mac: e.mac, user: e.user }" />
              </td>
            </tr>
          </template>
          <tr v-if="data && !(data.events ?? []).length"><td colspan="7" class="py-3 text-muted" data-test="radius-journal-none">{{ t('radius.journal.none') }}</td></tr>
        </tbody>
      </table>
    </div>
    <p v-if="data?.truncated" class="text-xs text-dimmed">{{ t('radius.journal.truncated') }}</p>
    <p class="text-xs text-dimmed">{{ t('radius.node_note') }}</p>
  </div>
</template>
