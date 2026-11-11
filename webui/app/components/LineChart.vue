<script setup lang="ts">
// Courbes SVG : intervalle fixe (les trous sont comblés par des zéros), points isolés dessinés, valeurs au survol.
const props = defineProps<{ series: Array<{ name: string; color: string; points: Array<{ t: number; v: number }> }>; binMs: number; from: number; to: number; label: string }>()
const W = 600, H = 180, L = 36, B = 22
const bins = computed(() => { const n = Math.max(1, Math.round((props.to - props.from) / props.binMs)); return Array.from({ length: n + 1 }, (_, i) => props.from + i * props.binMs) })
const filled = computed(() => props.series.map((s) => {
  const m = new Map(s.points.map((p) => [Math.floor(p.t / props.binMs) * props.binMs, p.v]))
  return { ...s, pts: bins.value.map((b) => ({ t: b, v: m.get(Math.floor(b / props.binMs) * props.binMs) ?? 0 })) }
}))
const maxV = computed(() => Math.max(1, ...filled.value.flatMap((s) => s.pts.map((p) => p.v))))
const x = (i: number) => L + (i * (W - L - 8)) / Math.max(1, bins.value.length - 1)
const y = (v: number) => H - B - (v * (H - B - 8)) / maxV.value
const path = (pts: Array<{ v: number }>) => pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(p.v).toFixed(1)}`).join(' ')
// l'heure dépend de la langue et du fuseau du navigateur : rien n'est écrit côté serveur (évite un écart d'hydratation)
const mounted = ref(false); onMounted(() => { mounted.value = true })
const fmt = (ms: number) => (mounted.value ? new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '')
</script>

<template>
  <div>
    <svg role="img" :aria-label="label" :viewBox="`0 0 ${W} ${H}`" class="w-full">
      <line :x1="L" :y1="H - B" :x2="W - 8" :y2="H - B" class="stroke-current text-neutral-300 dark:text-neutral-600" />
      <line :x1="L" :y1="8" :x2="L" :y2="H - B" class="stroke-current text-neutral-300 dark:text-neutral-600" />
      <text :x="L - 4" y="14" text-anchor="end" class="fill-current num" style="font-size: 10px">{{ maxV }}</text>
      <text :x="L - 4" :y="H - B" text-anchor="end" class="fill-current num" style="font-size: 10px">0</text>
      <text :x="L" :y="H - 4" class="fill-current num" style="font-size: 10px">{{ fmt(from) }}</text>
      <text :x="W - 8" :y="H - 4" text-anchor="end" class="fill-current num" style="font-size: 10px">{{ fmt(to) }}</text>
      <g v-for="s in filled" :key="s.name">
        <path :d="path(s.pts)" fill="none" :stroke="s.color" stroke-width="2" stroke-linejoin="round" />
        <circle v-for="(p, i) in s.pts.filter((q) => q.v > 0)" :key="i" :cx="x(s.pts.indexOf(p))" :cy="y(p.v)" r="3" :fill="s.color"><title>{{ s.name }} · {{ fmt(p.t) }} : {{ p.v }}</title></circle>
      </g>
    </svg>
    <ul class="flex gap-4 text-xs mt-1"><li v-for="s in series" :key="s.name" class="flex items-center gap-1"><span class="inline-block size-3 rounded-sm" :style="{ background: s.color }" />{{ s.name }}</li></ul>
    <table class="sr-only">
      <caption>{{ label }}</caption>
      <thead><tr><th>{{ fmt(from) }}</th><th v-for="s in series" :key="s.name">{{ s.name }}</th></tr></thead>
      <tbody><tr v-for="(b, i) in bins" :key="b"><th scope="row">{{ fmt(b) }}</th><td v-for="s in filled" :key="s.name">{{ s.pts[i]?.v }}</td></tr></tbody>
    </table>
  </div>
</template>
