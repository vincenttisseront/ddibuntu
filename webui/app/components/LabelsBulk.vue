<script setup lang="ts">
// Pose / retrait de labels sur une sélection d'objets du même type (réseaux, adresses…)
const props = defineProps<{ kind: 'subnet' | 'address' | 'vlan' | 'space'; ids: number[] }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ (e: 'done'): void }>()
const { t } = useT(); const api = useApi(); const toast = useToast(); const { refresh } = useLabels()
const add = ref<string[]>([]), remove = ref<string[]>([]), busy = ref(false), err = ref('')
watch(open, (o) => { if (o) { add.value = []; remove.value = []; err.value = '' } })
async function go() {
  busy.value = true; err.value = ''
  try {
    const r: any = await api.call('POST', '/ipam/labels/assign', { kind: props.kind, ids: props.ids, add: add.value, remove: remove.value }, { silent: true })
    toast.add({ title: t('label.assigned', { n: r.updated }), color: 'success', icon: 'i-lucide-check' })
    open.value = false; await refresh(); emit('done')
  } catch (e: any) { err.value = e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
</script>

<template>
  <UModal v-model:open="open" :title="t('label.bulk_title', { n: ids.length })" :description="t('label.bulk_desc')">
    <template #body>
      <form class="flex flex-col gap-3" @submit.prevent="go">
        <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" />
        <UFormField :label="t('label.add')"><LabelsInput v-model="add" :aria-label="t('label.add')" /></UFormField>
        <UFormField :label="t('label.remove')"><LabelsInput v-model="remove" :aria-label="t('label.remove')" /></UFormField>
        <div class="flex justify-end gap-2 pt-2">
          <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="open = false" />
          <UButton type="submit" :loading="busy" :disabled="!add.length && !remove.length" :label="t('label.apply')" />
        </div>
      </form>
    </template>
  </UModal>
</template>
