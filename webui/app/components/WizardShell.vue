<script setup lang="ts">
// Cadre commun des assistants : étapes numérotées (étape courante annoncée aux lecteurs d'écran), retour, suite, fin.
const props = defineProps<{ steps: Array<{ id: string; label: string }>; canNext?: boolean; busy?: boolean; finishLabel?: string; hideFooter?: boolean }>()
const step = defineModel<number>({ default: 0 })
const emit = defineEmits<{ finish: [] }>()
const { t } = useT()
const last = computed(() => step.value === props.steps.length - 1)
</script>

<template>
  <div class="flex flex-col gap-4">
    <ol class="flex flex-wrap gap-2" :aria-label="t('wizard.steps')">
      <li v-for="(s, i) in steps" :key="s.id" :aria-current="i === step ? 'step' : undefined" class="flex items-center gap-2 rounded-full border px-3 py-1 text-sm"
        :class="i === step ? 'border-primary text-primary font-medium' : i < step ? 'border-default text-muted' : 'border-default text-dimmed'">
        <UIcon v-if="i < step" name="i-lucide-check" class="size-4" /><span v-else class="num font-semibold">{{ i + 1 }}</span><span>{{ s.label }}</span>
      </li>
    </ol>
    <slot />   <!-- contenu commun à toutes les étapes (message d'erreur de l'assistant) -->
    <section :aria-label="steps[step]?.label"><slot :name="steps[step]!.id" /></section>
    <div v-if="!hideFooter" class="flex justify-between">
      <UButton color="neutral" variant="outline" icon="i-lucide-arrow-left" :label="t('wizard.back')" :disabled="step === 0 || busy" @click="step--" />
      <UButton v-if="!last" trailing-icon="i-lucide-arrow-right" :label="t('wizard.next')" :disabled="!canNext || busy" @click="step++" />
      <UButton v-else icon="i-lucide-check" :label="finishLabel ?? t('wizard.finish')" :disabled="!canNext" :loading="busy" @click="emit('finish')" />
    </div>
  </div>
</template>
