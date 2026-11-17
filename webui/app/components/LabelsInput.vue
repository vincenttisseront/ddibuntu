<script setup lang="ts">
// Saisie de labels : on tape puis Entrée (ou virgule) ; les labels existants du catalogue sont proposés d'un clic.
const model = defineModel<string[]>({ default: () => [] })
defineProps<{ placeholder?: string; ariaLabel?: string }>()
const { t } = useT()
const { items, colorOf } = useLabels()
const norm = (s: string) => s.normalize('NFC').trim().replace(/\s+/g, ' ').toLowerCase()
const value = computed({
  get: () => model.value ?? [],
  set: (v: string[]) => { model.value = [...new Set(v.map(norm).filter(Boolean))] },
})
const suggestions = computed(() => items.value.map((l: any) => l.name as string).filter((n) => !value.value.includes(n)).slice(0, 12))
const add = (n: string) => { value.value = [...value.value, n] }
</script>

<template>
  <div class="flex flex-col gap-1.5">
    <UInputTags v-model="value" class="w-full" :placeholder="placeholder ?? t('label.input_ph')" :aria-label="ariaLabel ?? t('label.title')" add-on-paste :max="20" />
    <div v-if="suggestions.length" class="flex flex-wrap items-center gap-1">
      <span class="text-xs text-muted">{{ t('label.suggest') }}</span>
      <button v-for="n in suggestions" :key="n" type="button" class="rounded-full border border-default px-1.5 py-px text-xs hover:bg-elevated" :style="{ color: colorOf(n) }" @click="add(n)">+ {{ n }}</button>
    </div>
  </div>
</template>
