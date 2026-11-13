<script setup lang="ts">
// Grille d'occupation d'un réseau IPv4 (jusqu'à /16) : une case par adresse, rendue sur un canevas.
// Le tableau des adresses reste la vue accessible au clavier ; la grille ajoute le coup d'œil et le clic vers l'adresse.
const props = defineProps<{ subnetId: number; refreshKey?: number }>()
const emit = defineEmits<{ pick: [info: { ip: string; state: string; item: { hostname: string | null; mac: string | null } | null }] }>()
const { t } = useT(); const api = useApi()

const STATES = ['u', 'd', 'r', 'g', 'i', 'v', 'o', 'p', '.', 'n', 'b'] as const
const COLORS: Record<string, string> = { u: '#2563eb', d: '#0d9488', r: '#9333ea', g: '#d97706', i: '#64748b', v: '#db2777', n: '#334155', b: '#334155', o: 'rgba(13,148,136,.32)', p: 'rgba(37,99,235,.24)', '.': 'rgba(128,128,128,.16)' }

// Replié par défaut (une ligne de résumé) : le tableau des adresses reste l'objet principal de la page ; le choix est mémorisé par navigateur.
const KEY = 'ddi.grid.open'
const open = ref(false)
try { open.value = localStorage.getItem(KEY) === '1' } catch { /* stockage indisponible : replié */ }
const toggle = () => { open.value = !open.value; try { localStorage.setItem(KEY, open.value ? '1' : '0') } catch { /* sans mémoire */ } }
const map = ref<any>(null), err = ref(''), loading = ref(false)
const canvas = ref<HTMLCanvasElement | null>(null)
const hover = ref<number>(-1)
let seq = 0
async function load() {
  const my = ++seq
  loading.value = true; err.value = ''
  try { const m = await api.call('GET', `/ipam/subnets/${props.subnetId}/map`, undefined, { silent: true }); if (my === seq) map.value = m }
  catch (e: any) { if (my === seq) { map.value = null; err.value = e?.info?.code === 'map_too_large' || e?.info?.code === 'map_unsupported_family' ? t(`err.${e.info.code}`) : t('err.internal') } }
  finally { if (my === seq) loading.value = false }
}
watch(() => [props.subnetId, props.refreshKey], load, { immediate: true })

const size = computed<number>(() => map.value?.size ?? 0)
const cols = computed(() => (size.value <= 64 ? 8 : size.value <= 256 ? 16 : size.value <= 1024 ? 32 : 256))
const cell = computed(() => (cols.value <= 16 ? 22 : cols.value <= 32 ? 14 : 4))
const gap = computed(() => (cell.value >= 14 ? 2 : 0))
const rows = computed(() => Math.ceil(size.value / cols.value))
const byOffset = computed(() => { const m = new Map<number, { hostname: string | null; mac: string | null }>(); for (const [o, h, mac] of map.value?.items ?? []) m.set(o, { hostname: h, mac }); return m })

function ipAt(o: number): string {
  const p = String(map.value.base).split('.').map(Number); let n = ((p[0]! * 256 + p[1]!) * 256 + p[2]!) * 256 + p[3]! + o
  const out = [0, 0, 0, 0]; for (let i = 3; i >= 0; i--) { out[i] = n % 256; n = Math.floor(n / 256) }
  return out.join('.')
}
const stateAt = (o: number) => (map.value?.cells?.[o] as string | undefined) ?? '.'

function draw() {
  const cv = canvas.value; if (!cv || !map.value) return
  const dpr = Math.max(1, Math.min(3, window.devicePixelRatio || 1)), step = cell.value
  const w = cols.value * step, h = rows.value * step
  cv.width = w * dpr; cv.height = h * dpr; cv.style.width = w + 'px'; cv.style.height = h + 'px'
  const g = cv.getContext('2d'); if (!g) return
  g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h)
  const cells: string = map.value.cells
  for (let i = 0; i < cells.length; i++) {
    g.fillStyle = COLORS[cells[i]!] ?? COLORS['.']!
    g.fillRect((i % cols.value) * step, Math.floor(i / cols.value) * step, step - gap.value, step - gap.value)
  }
  if (hover.value >= 0) { g.strokeStyle = document.documentElement.classList.contains('dark') ? '#f8fafc' : '#0f172a'; g.lineWidth = 2; g.strokeRect((hover.value % cols.value) * step + 1, Math.floor(hover.value / cols.value) * step + 1, step - gap.value - 2, step - gap.value - 2) }
}
watch([map, hover], () => nextTick(draw), { flush: 'post' })
onMounted(() => nextTick(draw))
watch(open, () => nextTick(draw), { flush: 'post' })

function offsetOf(ev: MouseEvent): number {
  const r = (ev.currentTarget as HTMLCanvasElement).getBoundingClientRect()
  const x = Math.floor((ev.clientX - r.left) / cell.value), y = Math.floor((ev.clientY - r.top) / cell.value)
  if (x < 0 || x >= cols.value || y < 0) return -1
  const o = y * cols.value + x
  return o < size.value ? o : -1
}
const info = computed(() => {
  if (hover.value < 0 || !map.value) return null
  const o = hover.value, it = byOffset.value.get(o)
  return { ip: ipAt(o), state: stateAt(o), hostname: it?.hostname ?? null, mac: it?.mac ?? null }
})
function click(ev: MouseEvent) {
  const o = offsetOf(ev); if (o < 0 || !map.value) return
  const it = byOffset.value.get(o) ?? null
  emit('pick', { ip: ipAt(o), state: stateAt(o), item: it })
}
const legend = computed(() => STATES.filter((s) => (map.value?.counts?.[s] ?? 0) > 0 && s !== 'b').map((s) => ({ s, n: (map.value.counts[s] ?? 0) + (s === 'n' ? (map.value.counts.b ?? 0) : 0) })))
const usedN = computed(() => (map.value ? ['u', 'd', 'r', 'g', 'i'].reduce((a, s) => a + (map.value.counts[s] ?? 0), 0) : 0))
const pct = computed(() => (size.value ? Math.round((usedN.value / size.value) * 100) : 0))
const summary = computed(() => (map.value ? t('grid.summary', { cidr: map.value.cidr, n: size.value, used: ['u', 'd', 'r', 'g', 'i'].reduce((a, s) => a + (map.value.counts[s] ?? 0), 0) }) : ''))
</script>

<template>
  <UCard :ui="{ header: open ? undefined : 'py-2 sm:py-2', body: open ? 'p-3 sm:p-3' : 'hidden' }">
    <template #header>
      <div class="flex items-center gap-2">
        <UIcon name="i-lucide-grid-3x3" class="size-4 text-muted" />
        <span class="font-medium text-sm">{{ t('grid.title') }}</span>
        <span v-if="map" class="font-mono text-xs text-muted">{{ map.cidr }}</span>
        <template v-if="map && !open">
          <span class="text-xs text-muted">· {{ t('grid.compact', { used: usedN, n: size, pct }) }}</span>
          <span class="hidden sm:block h-1.5 w-24 rounded-full bg-elevated overflow-hidden" aria-hidden="true"><span class="block h-full bg-primary" :style="{ width: pct + '%' }" /></span>
        </template>
        <UIcon v-if="loading" name="i-lucide-loader-circle" class="size-4 animate-spin text-muted" :aria-label="t('common.loading')" />
        <UButton class="ms-auto" size="xs" color="neutral" variant="ghost" :icon="open ? 'i-lucide-chevron-up' : 'i-lucide-chevron-down'" :label="open ? t('grid.hide') : t('grid.show')" :aria-expanded="open" data-test="grid-toggle" @click="toggle" />
      </div>
    </template>
    <UAlert v-if="err" color="neutral" variant="subtle" icon="i-lucide-info" :title="err" />
    <div v-else-if="map && open" class="flex flex-col gap-2">
      <div class="overflow-auto max-h-[28rem]">
        <canvas ref="canvas" role="application" :aria-label="summary" class="cursor-pointer" @mousemove="hover = offsetOf($event)" @mouseleave="hover = -1" @click="click" />
      </div>
      <div class="min-h-5 text-xs font-mono" aria-live="polite">
        <template v-if="info">{{ info.ip }} — {{ t(`grid.state.${info.state}`) }}<template v-if="info.hostname"> · {{ info.hostname }}</template><template v-if="info.mac"> · {{ info.mac }}</template></template>
        <span v-else class="text-muted font-sans">{{ t('grid.hint') }}</span>
      </div>
      <ul class="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        <li v-for="l in legend" :key="l.s" class="flex items-center gap-1.5">
          <span class="inline-block size-3 rounded-sm border border-default" :style="{ background: COLORS[l.s] }" aria-hidden="true" />{{ t(`grid.state.${l.s}`) }} <span class="text-muted font-mono">{{ l.n }}</span>
        </li>
      </ul>
    </div>
  </UCard>
</template>
