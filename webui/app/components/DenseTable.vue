<script setup lang="ts">
// Tableau dense façon console IPAM : ligne de filtres par colonne, tri, sélection multiple, arborescence repliable,
// compteur de résultats et export CSV de la vue filtrée. Les données sont fournies déjà chargées (filtrage côté client).
export interface DCol {
  key: string; label: string; kind?: 'text' | 'mono' | 'num' | 'badge' | 'progress' | 'bool'; trans?: string
  width?: string; nofilter?: boolean; nosort?: boolean; fmt?: (v: any, row: any) => string; hidden?: boolean
}
const props = defineProps<{ rows: any[]; columns: DCol[]; selectable?: boolean; tree?: boolean; exportName?: string; loading?: boolean; rowClass?: (row: any) => string }>()
const selected = defineModel<number[]>('selected', { default: () => [] })
const emit = defineEmits<{ (e: 'row-click', row: any): void; (e: 'visible', rows: any[]): void }>()
const { t } = useT()

const cols = computed(() => props.columns.filter((c) => !c.hidden))
const filters = reactive<Record<string, string>>({})
const sort = ref<{ key: string; dir: 1 | -1 } | null>(null)
const collapsed = ref<Set<number>>(new Set())

const getPath = (o: any, p: string) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), o)
const text = (c: DCol, row: any): string => {
  const v = getPath(row, c.key)
  if (c.fmt) return c.fmt(v, row)
  if (v == null) return ''
  if (c.kind === 'bool') return v ? t('common.yes') : t('common.no')
  if (c.kind === 'badge' && c.trans) return t(`${c.trans}.${v}`)
  if (c.kind === 'progress') return `${v}%`
  return String(v)
}
const filtering = computed(() => Object.values(filters).some((v) => v.trim() !== ''))
const flat = computed(() => filtering.value || !!sort.value || !props.tree)

const visible = computed(() => {
  let r = props.rows
  if (filtering.value) {
    const active = cols.value.filter((c) => (filters[c.key] ?? '').trim() !== '')
    r = r.filter((row) => active.every((c) => text(c, row).toLowerCase().includes(filters[c.key]!.trim().toLowerCase())))
  }
  if (sort.value) {
    const { key, dir } = sort.value, c = cols.value.find((x) => x.key === key)!
    const num = c.kind === 'num' || c.kind === 'progress'
    r = [...r].sort((a, b) => {
      const x = getPath(a, key), y = getPath(b, key)
      if (x == null && y == null) return 0
      if (x == null) return 1
      if (y == null) return -1
      return (num ? Number(x) - Number(y) : String(x).localeCompare(String(y), undefined, { numeric: true })) * dir
    })
  } else if (props.tree && !filtering.value) {
    const byId = new Map<number, any>(props.rows.map((x) => [x.id, x]))
    r = r.filter((row) => { let p = row.parent_id ? byId.get(row.parent_id) : null, g = 0; while (p && g++ < 64) { if (collapsed.value.has(p.id)) return false; p = p.parent_id ? byId.get(p.parent_id) : null } return true })
  }
  return r
})
watch(visible, (v) => emit('visible', v), { immediate: true })

function toggleSort(c: DCol) {
  if (c.nosort) return
  const s = sort.value
  sort.value = !s || s.key !== c.key ? { key: c.key, dir: 1 } : s.dir === 1 ? { key: c.key, dir: -1 } : null
}
function toggle(id: number) { const s = new Set(collapsed.value); if (s.has(id)) s.delete(id); else s.add(id); collapsed.value = s }
function expandAll() { collapsed.value = new Set() }
function collapseAll() { collapsed.value = new Set(props.rows.filter((r) => r.children > 0).map((r) => r.id)) }
function clearFilters() { for (const k of Object.keys(filters)) filters[k] = '' }
defineExpose({ expandAll, collapseAll, clearFilters, visible })

const allSelected = computed(() => visible.value.length > 0 && visible.value.every((r) => selected.value.includes(r.id)))
function toggleAll() { selected.value = allSelected.value ? selected.value.filter((id) => !visible.value.some((r) => r.id === id)) : [...new Set([...selected.value, ...visible.value.map((r) => r.id)])] }
function toggleOne(id: number) { selected.value = selected.value.includes(id) ? selected.value.filter((x) => x !== id) : [...selected.value, id] }

// Export CSV de la vue (neutralise l'injection de formule dans un tableur)
const q = (s: string) => (/^[=+\-@]/.test(s) ? `"'${s.replace(/"/g, '""')}"` : /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s)
function exportCsv() {
  const head = cols.value.map((c) => q(c.label)).join(',')
  const body = visible.value.map((r) => cols.value.map((c) => q(text(c, r))).join(','))
  const blob = new Blob(['﻿' + [head, ...body].join('\n') + '\n'], { type: 'text/csv;charset=utf-8' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `${props.exportName ?? 'export'}.csv`; a.click(); URL.revokeObjectURL(a.href)
}
const pctColor = (v: number) => (v >= 90 ? 'bg-error' : v >= 75 ? 'bg-warning' : 'bg-primary')
</script>

<template>
  <div class="flex flex-col gap-2 min-h-0">
    <div class="flex items-center gap-2 flex-wrap text-sm">
      <slot name="toolbar" :visible="visible" />
      <div class="flex-1" />
      <UButton v-if="filtering" size="xs" color="neutral" variant="ghost" icon="i-lucide-filter-x" :label="t('ipam.clear_filters')" @click="clearFilters" />
      <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-download" :label="t('ipam.export_view')" :disabled="!visible.length" @click="exportCsv" />
    </div>
    <div class="overflow-auto max-h-[calc(100vh-18rem)] rounded-md border border-default">
      <table class="w-full text-xs border-collapse">
        <thead class="sticky top-0 z-10 bg-elevated">
          <tr>
            <th v-if="selectable" class="w-8 px-2 py-1.5 text-center"><input type="checkbox" :checked="allSelected" :aria-label="t('ipam.select_all')" @change="toggleAll"></th>
            <th v-for="c in cols" :key="c.key" class="px-2 py-1.5 text-left font-medium whitespace-nowrap" :style="c.width ? { width: c.width } : undefined"
              :aria-sort="sort?.key === c.key ? (sort.dir === 1 ? 'ascending' : 'descending') : undefined">
              <button type="button" class="inline-flex items-center gap-1 select-none" :class="c.nosort ? 'cursor-default' : 'hover:text-highlighted'" @click="toggleSort(c)">
                {{ c.label }}
                <UIcon v-if="sort?.key === c.key" :name="sort.dir === 1 ? 'i-lucide-arrow-up' : 'i-lucide-arrow-down'" class="size-3" />
              </button>
            </th>
            <th v-if="$slots.actions" class="w-px" />
          </tr>
          <tr class="border-b border-default">
            <th v-if="selectable" />
            <th v-for="c in cols" :key="c.key + '-f'" class="px-1 pb-1.5">
              <input v-if="!c.nofilter" v-model="filters[c.key]" type="search" :aria-label="`${t('ipam.filter')} ${c.label}`" class="w-full min-w-14 rounded border border-default bg-default px-1.5 py-0.5 text-xs font-normal">
            </th>
            <th v-if="$slots.actions" />
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in visible" :key="r.id" class="border-b border-default/60 hover:bg-elevated/60" :class="[selected.includes(r.id) ? 'bg-primary/10' : '', rowClass?.(r) ?? '']" @click="emit('row-click', r)">
            <td v-if="selectable" class="px-2 py-1 text-center" @click.stop><input type="checkbox" :checked="selected.includes(r.id)" :aria-label="t('ipam.select_row')" @change="toggleOne(r.id)"></td>
            <td v-for="(c, ci) in cols" :key="c.key" class="px-2 py-1 align-middle whitespace-nowrap" :class="c.kind === 'num' ? 'text-right tabular-nums' : ''">
              <slot :name="`cell-${c.key}`" :row="r" :col="c">
                <span v-if="ci === 0 && tree && !flat" class="inline-flex items-center gap-1" :style="{ paddingLeft: `${(r.depth ?? 0) * 14}px` }">
                  <button v-if="r.children > 0" type="button" class="p-0.5 -ml-1 rounded hover:bg-accented" :aria-label="collapsed.has(r.id) ? t('ipam.expand') : t('ipam.collapse')" :aria-expanded="!collapsed.has(r.id)" @click.stop="toggle(r.id)">
                    <UIcon :name="collapsed.has(r.id) ? 'i-lucide-chevron-right' : 'i-lucide-chevron-down'" class="size-3.5" />
                  </button>
                  <span v-else class="w-4" />
                  <UIcon :name="r.kind === 'container' ? 'i-lucide-folder' : 'i-lucide-network'" class="size-3.5 text-muted shrink-0" />
                  <span class="font-mono">{{ text(c, r) }}</span>
                </span>
                <template v-else>
                  <UBadge v-if="c.kind === 'badge' && getPath(r, c.key)" variant="subtle" color="neutral" size="sm" :label="text(c, r)" />
                  <UBadge v-else-if="c.kind === 'bool'" variant="subtle" size="sm" :color="getPath(r, c.key) ? 'success' : 'neutral'" :label="text(c, r)" />
                  <span v-else-if="c.kind === 'progress'" class="flex items-center gap-1.5 min-w-24">
                    <template v-if="getPath(r, c.key) == null"><span class="text-muted">—</span></template>
                    <template v-else>
                      <span class="relative h-1.5 w-14 rounded-full bg-accented overflow-hidden" role="img" :aria-label="`${c.label} ${getPath(r, c.key)}%`"><span class="absolute inset-y-0 left-0 rounded-full" :class="pctColor(getPath(r, c.key))" :style="{ width: `${Math.min(100, getPath(r, c.key))}%` }" /></span>
                      <span class="tabular-nums w-10 text-right">{{ getPath(r, c.key) }}%</span>
                    </template>
                  </span>
                  <span v-else :class="c.kind === 'mono' ? 'font-mono break-all' : ''">{{ text(c, r) }}</span>
                </template>
              </slot>
            </td>
            <td v-if="$slots.actions" class="px-1 py-0.5 whitespace-nowrap" @click.stop><div class="flex justify-end gap-0.5"><slot name="actions" :row="r" /></div></td>
          </tr>
        </tbody>
      </table>
      <p v-if="!loading && !visible.length" class="p-6 text-center text-sm text-muted">{{ t('common.empty') }}</p>
    </div>
    <div class="flex items-center gap-3 text-xs text-muted">
      <span aria-live="polite">{{ t('ipam.results', { n: visible.length }) }}<template v-if="filtering && visible.length !== rows.length"> / {{ rows.length }}</template></span>
      <span v-if="selectable && selected.length">· {{ t('ipam.selected', { n: selected.length }) }}</span>
      <slot name="footer" />
    </div>
  </div>
</template>
