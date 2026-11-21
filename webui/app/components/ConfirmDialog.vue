<script setup lang="ts">
// Boîte de dialogue maison : jamais de fenêtre système (confirm/alert).
const { t } = useT()
const { state } = useConfirm()
function answer(v: boolean) { const r = state.value.resolve; state.value = { ...state.value, open: false, resolve: null }; r?.(v) }
watch(() => state.value.open, (o) => { if (!o && state.value.resolve) answer(false) })
</script>

<template>
  <!-- z-[60] : la confirmation doit passer devant toute fenêtre déjà ouverte (liste des alias, formulaires) : à même niveau, c'est l'ordre d'insertion dans la page qui décide -->
  <UModal v-model:open="state.open" :title="state.title" :description="state.message" :ui="{ overlay: 'z-[60]', content: 'z-[60]' }">
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="answer(false)" />
        <UButton :color="state.danger ? 'error' : 'primary'" :label="t('common.confirm')" @click="answer(true)" />
      </div>
    </template>
  </UModal>
</template>
