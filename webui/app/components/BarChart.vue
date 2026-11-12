<script setup lang="ts">
// Barres horizontales en SVG, valeurs au survol (<title>), tableau équivalent pour les lecteurs d'écran.
const props = defineProps<{ items: Array<{ label: string; value: number; display?: string; warn?: boolean }>; max?: number; label: string }>()
const top = computed(() => props.max ?? Math.max(1, ...props.items.map((i) => i.value)))
const rowH = 26
</script>

<template>
  <div>
    <svg role="img" :aria-label="label" :viewBox="`0 0 400 ${Math.max(items.length, 1) * rowH}`" class="w-full max-w-[400px]" preserveAspectRatio="xMinYMin meet">
      <g v-for="(it, i) in items" :key="it.label" :transform="`translate(0 ${i * rowH})`">
        <title>{{ it.label }} : {{ it.display ?? it.value }}</title>
        <text x="0" y="16" class="fill-current text-xs font-mono" style="font-size: 11px">{{ it.label.length > 17 ? it.label.slice(0, 16) + '…' : it.label }}</text>
        <rect x="116" y="4" width="110" height="14" rx="3" class="fill-current text-neutral-200 dark:text-neutral-700" />
        <rect x="116" y="4" :width="Math.max(2, (110 * it.value) / top)" height="14" rx="3" :class="it.warn ? 'fill-current text-amber-500' : 'fill-current text-brand-500'" />
        <text x="234" y="16" class="fill-current num" style="font-size: 11px">{{ it.display ?? it.value }}</text>
      </g>
    </svg>
    <table class="sr-only">
      <caption>{{ label }}</caption>
      <tbody><tr v-for="it in items" :key="it.label"><th scope="row">{{ it.label }}</th><td>{{ it.display ?? it.value }}</td></tr></tbody>
    </table>
  </div>
</template>
