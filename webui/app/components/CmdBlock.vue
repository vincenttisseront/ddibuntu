<script setup lang="ts">
// Bloc de commandes à copier (0.18.3) : un titre, le texte dans un <pre>, un bouton « Copier ». `test` donne les data-test (« enroll-deploy-<test> » et « enroll-deploy-copy-<test> »).
const props = defineProps<{ title: string; text: string; test: string }>()
const { t } = useT(); const toast = useToast()
async function copy() { try { await navigator.clipboard.writeText(props.text); toast.add({ title: t('common.copied'), color: 'success', icon: 'i-lucide-check' }) } catch { /* presse-papiers indisponible : le texte reste sélectionnable */ } }
</script>

<template>
  <div>
    <div class="mb-1 flex items-center justify-between"><span class="text-sm">{{ title }}</span>
      <UButton size="xs" color="neutral" variant="ghost" icon="i-lucide-copy" :label="t('common.copy')" :data-test="`enroll-deploy-copy-${test}`" @click="copy" /></div>
    <pre class="overflow-x-auto rounded-md bg-elevated p-3 text-xs" :data-test="`enroll-deploy-${test}`">{{ text }}</pre>
  </div>
</template>
