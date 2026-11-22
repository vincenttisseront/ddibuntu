<script setup lang="ts">
// Journal d'audit : tableau dense ; un clic sur une ligne ouvre le détail dans un panneau à droite de la page
const { t } = useT()
const te = (k: string) => t(k) !== k   // clé connue du catalogue ?
const { dateTime } = useFmt()
const q = ref('')
const query = computed(() => ({ limit: 500, ...(q.value ? { q: q.value } : {}) }))
const { data, pending, refresh } = await useFetch<any>('/api/audit', { query, watch: [query] })
const rows = computed<any[]>(() => data.value?.items ?? [])

const reasonOf = (r: any): string => (r.detail && typeof r.detail === 'object' && typeof r.detail.reason === 'string' ? r.detail.reason : '')
const reasonLabel = (code: string) => (code && te(`audit.reason.${code}`) ? t(`audit.reason.${code}`) : code)
const cols = computed(() => [
  { key: 'at', label: t('common.date'), fmt: (v: any) => dateTime(v), width: '11rem' },
  { key: 'username', label: t('system.user') },
  { key: 'action', label: t('system.action'), kind: 'mono' as const },
  { key: 'entity', label: t('system.entity') },
  { key: 'entity_id', label: 'ID', kind: 'mono' as const },
  { key: 'summary', label: t('audit.summary'), fmt: (_v: any, r: any) => reasonLabel(reasonOf(r)) },
  { key: 'ip', label: 'IP', kind: 'mono' as const },
])
// « summary » n'existe pas dans la ligne : DenseTable lit la clé, la mise en forme (fmt) reçoit la ligne entière
const tableRows = computed(() => rows.value.map((r) => ({ ...r, summary: reasonOf(r) })))

const open = ref(false)
const sel = ref<any | null>(null)
const raw = ref(false)
function show(r: any) { sel.value = r; raw.value = false; open.value = true }

const detail = computed<Record<string, any>>(() => (sel.value?.detail && typeof sel.value.detail === 'object' ? sel.value.detail : {}))
const fmtVal = (v: any): string => (v === null || v === undefined ? '—' : typeof v === 'object' ? JSON.stringify(v) : String(v))
// Valeurs des méthodes essayées (« tried ») : « LDAP : compte non trouvé »
const triedLines = computed<string[]>(() => (Array.isArray(detail.value.tried) ? detail.value.tried : []).map((x: any) => `${t(`audit.via.${x?.via}`)} : ${reasonLabel(String(x?.result ?? ''))}`))
const fields = computed(() => Object.entries(detail.value).filter(([k]) => !['tried', 'reason'].includes(k)))
</script>

<template>
  <div class="flex flex-col gap-3">
    <div class="flex gap-2 items-center">
      <UInput v-model="q" icon="i-lucide-search" size="sm" class="w-72" :placeholder="t('common.search')" :aria-label="t('common.search')" />
      <UButton size="sm" color="neutral" variant="ghost" icon="i-lucide-refresh-cw" :loading="pending" :aria-label="t('audit.refresh')" @click="() => refresh()" />
      <span class="text-xs text-muted">{{ t('audit.hint') }}</span>
    </div>
    <DenseTable :rows="tableRows" :columns="cols" export-name="audit" :loading="pending" :row-class="() => 'cursor-pointer'" data-test="audit-table" @row-click="show" />

    <USlideover v-model:open="open" side="right" :title="sel?.action" :description="sel ? dateTime(sel.at) : ''" :ui="{ content: 'max-w-lg' }">
      <template #body>
        <div v-if="sel" class="flex flex-col gap-4 text-sm" data-test="audit-detail">
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
            <dt class="text-muted">{{ t('common.date') }}</dt><dd class="num">{{ dateTime(sel.at) }}</dd>
            <dt class="text-muted">{{ t('system.user') }}</dt><dd>{{ sel.username || '—' }}</dd>
            <dt class="text-muted">{{ t('system.action') }}</dt><dd class="font-mono">{{ sel.action }}</dd>
            <dt class="text-muted">{{ t('system.entity') }}</dt><dd>{{ sel.entity || '—' }}<template v-if="sel.entity_id"> · <span class="font-mono">{{ sel.entity_id }}</span></template></dd>
            <dt class="text-muted">IP</dt><dd class="font-mono">{{ sel.ip || '—' }}</dd>
            <dt class="text-muted">#</dt><dd class="font-mono">{{ sel.id }}</dd>
          </dl>

          <UAlert v-if="reasonOf(sel)" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="reasonLabel(reasonOf(sel))" :description="te(`audit.why.${reasonOf(sel)}`) ? t(`audit.why.${reasonOf(sel)}`) : undefined" data-test="audit-reason" />

          <div v-if="triedLines.length"><div class="text-muted mb-1">{{ t('audit.tried') }}</div>
            <ul class="list-disc pl-5"><li v-for="(l, i) in triedLines" :key="i">{{ l }}</li></ul></div>

          <div v-if="fields.length"><div class="text-muted mb-1">{{ t('audit.detail') }}</div>
            <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1"><template v-for="[k, v] in fields" :key="k"><dt class="font-mono text-xs text-muted">{{ k }}</dt><dd class="break-all">{{ fmtVal(v) }}</dd></template></dl></div>
          <p v-else-if="!triedLines.length && !reasonOf(sel)" class="text-muted">{{ t('audit.no_detail') }}</p>

          <AiExplain use="audit" :payload="{ id: sel.id }" />

          <div><UButton size="xs" variant="ghost" color="neutral" :icon="raw ? 'i-lucide-chevron-down' : 'i-lucide-chevron-right'" :label="t('audit.raw')" @click="raw = !raw" />
            <pre v-if="raw" class="mt-1 text-xs whitespace-pre-wrap break-all font-mono bg-elevated rounded p-2 max-h-80 overflow-auto">{{ JSON.stringify(sel.detail, null, 2) ?? 'null' }}</pre></div>
        </div>
      </template>
    </USlideover>
  </div>
</template>
