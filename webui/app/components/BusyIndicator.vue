<script setup lang="ts">
// Indicateur d'attente global : toute action un peu longue (écriture, déploiement, import, mise à jour…) affiche un spinner.
// Il n'apparaît qu'après 400 ms pour ne pas clignoter sur les actions instantanées, et reste visible au moins 500 ms une fois affiché.
const { t } = useT()
const busy = useState<number>('busy', () => 0)
const shown = ref(false)
let showTimer: ReturnType<typeof setTimeout> | undefined, hideTimer: ReturnType<typeof setTimeout> | undefined, since = 0
watch(busy, (n) => {
  if (n > 0) {
    clearTimeout(hideTimer)
    if (!shown.value && !showTimer) showTimer = setTimeout(() => { showTimer = undefined; if (busy.value > 0) { shown.value = true; since = Date.now() } }, 400)
  } else {
    clearTimeout(showTimer); showTimer = undefined
    if (shown.value) hideTimer = setTimeout(() => { shown.value = false }, Math.max(0, 500 - (Date.now() - since)))
  }
})
onBeforeUnmount(() => { clearTimeout(showTimer); clearTimeout(hideTimer) })
</script>

<template>
  <Teleport to="body">
    <div v-if="shown" role="status" aria-live="polite" class="fixed inset-x-0 top-0 z-[100] pointer-events-none">
      <div class="h-0.5 w-full overflow-hidden bg-primary/20"><div class="busy-bar h-full w-1/3 bg-primary" /></div>
      <div class="mx-auto mt-3 flex w-fit items-center gap-2 rounded-full border border-default bg-default px-4 py-1.5 text-sm shadow-lg">
        <UIcon name="i-lucide-loader-circle" class="size-4 animate-spin text-primary" />
        <span>{{ t('common.working') }}</span>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.busy-bar { animation: busy-slide 1.1s ease-in-out infinite; }
@keyframes busy-slide { 0% { transform: translateX(-100%); } 100% { transform: translateX(300%); } }
@media (prefers-reduced-motion: reduce) { .busy-bar { animation: none; width: 100%; } }
</style>
