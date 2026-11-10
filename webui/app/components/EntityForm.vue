<script setup lang="ts">
// Fenêtre de création/modification générique (mêmes champs que ResourceTable) : le parent fournit la fonction d'envoi.
import type { Field } from './ResourceTable.vue'
const props = defineProps<{ title: string; fields: Field[]; row?: any | null; submit: (body: any) => Promise<void> }>()
const open = defineModel<boolean>('open', { default: false })
const { t } = useT()
const state = reactive<Record<string, any>>({})
const error = ref<{ message: string; issues: Array<{ path: string; message: string }> } | null>(null)
const busy = ref(false)
const editing = computed(() => !!props.row)
const visible = computed(() => props.fields.filter((f) => !(editing.value ? f.createOnly || f.editHidden : false)))

function init() {
  for (const k of Object.keys(state)) delete state[k]
  for (const f of props.fields) {
    let v = props.row ? props.row[f.key] : f.default
    if (f.type === 'list') v = Array.isArray(v) ? v.join(', ') : (v ?? '')
    if (f.type === 'switch') v = !!v
    state[f.key] = v ?? (f.type === 'number' ? null : '')
  }
  error.value = null
}
watch(open, (o) => { if (o) init() }, { immediate: true })

function build() {
  const out: Record<string, any> = {}
  for (const f of visible.value) {
    let v = state[f.key]
    if (f.type === 'list') v = String(v ?? '').split(/[,\s]+/).map((s) => s.trim()).filter(Boolean)
    else if (f.type === 'number') v = v === '' || v === null || v === undefined ? null : Number(v)
    else if (f.type === 'text' || f.type === 'textarea') v = typeof v === 'string' && v.trim() === '' && !f.required ? null : v
    out[f.key] = v
  }
  return out
}
async function go() {
  busy.value = true; error.value = null
  try { await props.submit(build()); open.value = false }
  catch (e: any) { error.value = e.info ?? { message: t('err.internal'), issues: [] } }
  finally { busy.value = false }
}
const hint = (f: Field) => (typeof f.hint === 'function' ? f.hint(state) : f.hint)
</script>

<template>
  <UModal v-model:open="open" :title="title" :description="t('common.form_desc')">
    <template #body>
      <form class="flex flex-col gap-3" @submit.prevent="go">
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error.message">
          <template v-if="error.issues?.length" #description><ul class="list-disc ps-4"><li v-for="i in error.issues" :key="i.path + i.message">{{ i.path }} : {{ i.message }}</li></ul></template>
        </UAlert>
        <UFormField v-for="f in visible" :key="f.key" :label="f.label" :required="f.required" :help="hint(f)">
          <USwitch v-if="f.type === 'switch'" v-model="state[f.key]" />
          <USelect v-else-if="f.type === 'select'" v-model="state[f.key]" :items="f.options ?? []" class="w-full" />
          <UTextarea v-else-if="f.type === 'textarea'" v-model="state[f.key]" :rows="f.rows ?? 3" class="w-full" :class="f.mono ? 'font-mono' : ''" :placeholder="f.placeholder" />
          <UInput v-else v-model="state[f.key]" :type="f.type === 'number' ? 'number' : 'text'" class="w-full" :class="f.mono ? 'font-mono' : ''" :placeholder="f.placeholder" autocomplete="off" />
        </UFormField>
        <div class="flex justify-end gap-2 pt-2">
          <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="open = false" />
          <UButton type="submit" :loading="busy" :label="t('common.save')" />
        </div>
      </form>
    </template>
  </UModal>
</template>
