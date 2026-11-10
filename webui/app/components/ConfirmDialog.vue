<script setup lang="ts">
// Boîte de dialogue maison : jamais de fenêtre système (confirm/alert).
const { t } = useT()
const { state } = useConfirm()
function answer(v: boolean) { const r = state.value.resolve; state.value = { ...state.value, open: false, resolve: null }; r?.(v) }
watch(() => state.value.open, (o) => { if (!o && state.value.resolve) answer(false) })
</script>

<template>
  <UModal v-model:open="state.open" :title="state.title" :description="state.message">
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="answer(false)" />
        <UButton :color="state.danger ? 'error' : 'primary'" :label="t('common.confirm')" @click="answer(true)" />
      </div>
    </template>
  </UModal>
</template>
