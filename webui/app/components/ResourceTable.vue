<script setup lang="ts">
// Panneau CRUD générique : tableau + formulaire de création/modification + suppression confirmée.
import { h, resolveComponent } from 'vue'
const { dateTime } = useFmt()

export interface Col { key: string; label: string; kind?: 'text' | 'mono' | 'badge' | 'bool' | 'list' | 'date' | 'progress' | 'num'; trans?: string; fmt?: (v: any, row: any) => string }
export interface Field {
  key: string; label: string; type: 'text' | 'number' | 'select' | 'textarea' | 'switch' | 'list' | 'password'
  required?: boolean; options?: Array<{ label: string; value: string | number }>; createOnly?: boolean; editHidden?: boolean
  hint?: string | ((state: any) => string); placeholder?: string; default?: any; rows?: number; mono?: boolean
}
const props = defineProps<{
  endpoint: string; columns: Col[]; fields?: Field[]; canWrite?: boolean; createUrl?: string
  updateUrl?: (row: any) => string; deleteUrl?: (row: any) => string; query?: Record<string, any>
  createLabel?: string; searchable?: boolean; transform?: (body: any, editing: boolean) => any; deleteName?: (row: any) => string; hideEdit?: boolean; itemsKey?: string
}>()
const emit = defineEmits<{ (e: 'changed'): void }>()
const slots = useSlots()
const { t } = useT()
const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

const q = ref('')
const query = computed(() => ({ ...(props.query ?? {}), ...(props.searchable && q.value ? { q: q.value } : {}) }))
const { data, pending, refresh } = await useFetch<any>(() => '/api' + props.endpoint, { query, watch: [query] })
const rows = computed<any[]>(() => (data.value?.[props.itemsKey ?? 'items'] ?? []))
defineExpose({ refresh })

const getPath = (o: any, p: string) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), o)
const setPath = (o: any, p: string, v: any) => { const ks = p.split('.'); let c = o; ks.slice(0, -1).forEach((k) => { c = c[k] ??= {} }); c[ks[ks.length - 1]!] = v }

// ---- Formulaire ----
const open = ref(false)
const editing = ref<any | null>(null)
const state = reactive<Record<string, any>>({})
const error = ref<{ message: string; issues: Array<{ path: string; message: string }> } | null>(null)
const busy = ref(false)
const visible = computed(() => (props.fields ?? []).filter((f) => !(editing.value ? f.createOnly || f.editHidden : false)))

function init(row: any | null) {
  for (const k of Object.keys(state)) delete state[k]
  for (const f of props.fields ?? []) {
    let v = row ? getPath(row, f.key) : f.default
    if (f.type === 'list') v = Array.isArray(v) ? v.join(', ') : (v ?? '')
    if (f.type === 'switch') v = !!v
    if (f.type === 'password') v = ''
    setPath(state, f.key, v ?? (f.type === 'number' ? null : ''))
  }
  error.value = null
}
function openCreate() { editing.value = null; init(null); open.value = true }
function openEdit(row: any) { editing.value = row; init(row); open.value = true }
function build() {
  const out: Record<string, any> = {}
  for (const f of visible.value) {
    let v = getPath(state, f.key)
    if (f.type === 'list') v = String(v ?? '').split(/[,\s]+/).map((s) => s.trim()).filter(Boolean)
    else if (f.type === 'number') v = v === '' || v === null || v === undefined ? null : Number(v)
    else if (f.type === 'text' || f.type === 'textarea') v = typeof v === 'string' && v.trim() === '' && !f.required ? null : v
    else if (f.type === 'password' && !v) continue
    setPath(out, f.key, v)
  }
  return out
}
async function submit() {
  busy.value = true; error.value = null
  try {
    const body = props.transform ? props.transform(build(), !!editing.value) : build()
    if (editing.value) await api.call('PUT', props.updateUrl!(editing.value), body)
    else await api.call('POST', props.createUrl!, body)
    open.value = false
    toast.add({ title: t('common.saved'), color: 'success', icon: 'i-lucide-check' })
    await refresh(); emit('changed')
  } catch (e: any) { error.value = e.info ?? { message: t('err.internal'), issues: [] } } finally { busy.value = false }
}
async function remove(row: any) {
  const name = props.deleteName?.(row) ?? ''
  if (!(await ask(t('common.delete'), t('common.delete_confirm', { name })))) return
  try { await api.call('DELETE', props.deleteUrl!(row)); toast.add({ title: t('common.deleted'), color: 'success', icon: 'i-lucide-check' }); await refresh(); emit('changed') }
  catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error', icon: 'i-lucide-triangle-alert' }) }
}

// ---- Colonnes ----
const UBadge = resolveComponent('UBadge'), UButton = resolveComponent('UButton'), UProgress = resolveComponent('UProgress')
const cols = computed(() => {
  const out: any[] = props.columns.map((c) => ({
    accessorKey: c.key, header: c.label,
    cell: ({ row }: any) => {
      const v = getPath(row.original, c.key)
      switch (c.kind) {
        case 'bool': return h(UBadge, { color: v ? 'success' : 'neutral', variant: 'subtle', label: v ? t('common.yes') : t('common.no') })
        case 'badge': return v == null || v === '' ? '' : h(UBadge, { variant: 'subtle', color: 'neutral', label: c.trans ? t(`${c.trans}.${v}`) : String(v) })
        case 'mono': return h('span', { class: 'font-mono text-xs break-all' }, v == null ? '' : String(v))
        case 'num': return h('span', { class: 'num' }, v == null ? '' : String(v))
        case 'list': return h('span', { class: 'font-mono text-xs' }, Array.isArray(v) ? v.join(', ') : '')
        case 'date': return v ? dateTime(v) : ''
        case 'progress': return v == null ? '—' : h('div', { class: 'flex items-center gap-2 min-w-28' }, [h(UProgress, { modelValue: v, max: 100, size: 'sm', color: v >= 80 ? 'warning' : 'primary', 'aria-label': c.label }), h('span', { class: 'num text-xs w-10 text-right' }, `${v}%`)])
        default: return c.fmt ? c.fmt(v, row.original) : v == null ? '' : String(v)
      }
    },
  }))
  if (props.canWrite || slots.actions) out.push({
    id: 'actions', header: '',
    cell: ({ row }: any) => h('div', { class: 'flex gap-1 justify-end' }, [
      ...((slots.actions?.({ row: row.original }) as any[]) ?? []),
      ...(props.canWrite && props.updateUrl && !props.hideEdit ? [h(UButton, { icon: 'i-lucide-pencil', size: 'xs', color: 'neutral', variant: 'ghost', 'aria-label': t('common.edit'), onClick: () => openEdit(row.original) })] : []),
      ...(props.canWrite && props.deleteUrl ? [h(UButton, { icon: 'i-lucide-trash-2', size: 'xs', color: 'error', variant: 'ghost', 'aria-label': t('common.delete'), onClick: () => remove(row.original) })] : []),
    ]),
  })
  return out
})
const hint = (f: Field) => (typeof f.hint === 'function' ? f.hint(state) : f.hint)
</script>

<template>
  <div class="flex flex-col gap-3 min-h-0">
    <div class="flex items-center gap-2 flex-wrap">
      <UInput v-if="searchable" v-model="q" icon="i-lucide-search" :placeholder="t('common.search')" :aria-label="t('common.search')" class="w-64" />
      <slot name="toolbar" />
      <div class="flex-1" />
      <UButton v-if="canWrite && createUrl" icon="i-lucide-plus" :label="createLabel ?? t('common.add')" @click="openCreate" />
    </div>
    <div class="overflow-auto max-h-[calc(100vh-17rem)] rounded-md border border-default">
      <UTable :data="rows" :columns="cols" :loading="pending" sticky class="min-w-full" />
      <p v-if="!pending && !rows.length" class="p-6 text-center text-sm text-muted">{{ t('common.empty') }}</p>
    </div>

    <UModal v-model:open="open" :title="editing ? t('common.edit') : (createLabel ?? t('common.add'))" :description="t('common.form_desc')">
      <template #body>
        <form class="flex flex-col gap-3" @submit.prevent="submit">
          <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error.message">
            <template v-if="error.issues?.length" #description><ul class="list-disc ps-4"><li v-for="i in error.issues" :key="i.path + i.message">{{ i.path }} : {{ i.message }}</li></ul></template>
          </UAlert>
          <UFormField v-for="f in visible" :key="f.key" :label="f.label" :required="f.required" :help="hint(f)">
            <USwitch v-if="f.type === 'switch'" :model-value="getPath(state, f.key)" @update:model-value="setPath(state, f.key, $event)" />
            <USelect v-else-if="f.type === 'select'" :model-value="getPath(state, f.key)" :items="f.options ?? []" class="w-full" @update:model-value="setPath(state, f.key, $event)" />
            <UTextarea v-else-if="f.type === 'textarea'" :model-value="getPath(state, f.key)" :rows="f.rows ?? 3" class="w-full" :class="f.mono ? 'font-mono' : ''" :placeholder="f.placeholder" @update:model-value="setPath(state, f.key, $event)" />
            <UInput v-else :model-value="getPath(state, f.key)" :type="f.type === 'password' ? 'password' : f.type === 'number' ? 'number' : 'text'" class="w-full" :placeholder="f.placeholder" :autocomplete="f.type === 'password' ? 'new-password' : 'off'" @update:model-value="setPath(state, f.key, $event)" />
          </UFormField>
          <div class="flex justify-end gap-2 pt-2">
            <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="open = false" />
            <UButton type="submit" :loading="busy" :label="t('common.save')" />
          </div>
        </form>
      </template>
    </UModal>
  </div>
</template>
