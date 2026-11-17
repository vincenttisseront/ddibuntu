<script setup lang="ts">
// Pastilles de labels colorées (couleur du catalogue, sinon couleur stable dérivée du nom)
const props = defineProps<{ labels?: string[] | null; max?: number; color?: string }>()
const { colorOf } = useLabels()
const shown = computed(() => (props.labels ?? []).slice(0, props.max ?? 6))
const extra = computed(() => Math.max(0, (props.labels?.length ?? 0) - shown.value.length))
const style = (n: string) => { const c = props.color || colorOf(n); return { color: c, borderColor: `color-mix(in srgb, ${c} 45%, transparent)`, backgroundColor: `color-mix(in srgb, ${c} 14%, transparent)` } }
</script>

<template>
  <span v-if="shown.length" class="inline-flex flex-wrap items-center gap-1">
    <span v-for="l in shown" :key="l" class="inline-block rounded-full border px-1.5 py-px text-xs font-medium leading-4" :style="style(l)">{{ l }}</span>
    <span v-if="extra" class="text-xs text-muted">+{{ extra }}</span>
  </span>
</template>
