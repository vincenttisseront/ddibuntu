<script setup lang="ts">
// Bouton « Expliquer » de l'assistant IA (0.23.0) : n'apparaît que si l'assistant et cet usage sont activés, pour un opérateur ou un administrateur.
// Le texte rendu par le modèle est affiché en texte brut (jamais interprété en HTML) et toujours signalé comme à vérifier.
const props = defineProps<{ use: string; payload: Record<string, unknown>; label?: string }>()
const { t, lang } = useT(); const api = useApi(); const { can, load } = useAi(); const { canWrite } = useRole()
void load()   // sans attente : le composant peut apparaître après coup (panneau, ligne dépliée)
const shown = computed(() => canWrite.value && can(props.use))
const busy = ref(false), err = ref(''), res = ref<{ text: string; model: string; cached: boolean; pseudonymized: boolean; ms: number } | null>(null)
// une autre ligne ou un autre événement : l'ancienne explication ne s'applique plus
watch(() => JSON.stringify(props.payload), () => { res.value = null; err.value = '' })
async function run(refresh = false) {
  busy.value = true; err.value = ''
  try { res.value = await api.call('POST', '/ai/explain', { use: props.use, ...props.payload, lang: lang.value, refresh }, { silent: true }) }
  catch (e: any) { err.value = e.info?.upstream?.detail ? `${e.info.message} (${e.info.upstream.detail})` : e.info?.message ?? t('err.internal') } finally { busy.value = false }
}
</script>

<template>
  <div v-if="shown" class="flex flex-col gap-2" data-test="ai-explain">
    <div><UButton size="xs" variant="soft" icon="i-lucide-sparkles" :label="label ?? t('ai.explain')" :loading="busy" :disabled="busy" data-test="ai-explain-btn" @click.stop="run(false)" /></div>
    <p v-if="busy" class="text-xs text-muted" role="status">{{ t('ai.thinking') }}</p>
    <p v-if="err" class="text-sm text-error" role="alert" data-test="ai-explain-error">{{ err }}</p>
    <div v-if="res" class="rounded-md border border-default bg-elevated/40 p-3 text-sm" data-test="ai-explain-result" @click.stop>
      <div class="flex flex-wrap items-center gap-2 mb-2">
        <UBadge size="sm" color="warning" variant="subtle" icon="i-lucide-sparkles" :label="t('ai.generated')" />
        <span class="text-xs text-dimmed font-mono truncate max-w-56" :title="res.model">{{ res.model }}</span>
        <span v-if="res.cached" class="text-xs text-dimmed">· {{ t('ai.cached') }}</span>
        <span v-else-if="res.ms" class="text-xs text-dimmed num">· {{ (res.ms / 1000).toFixed(1) }} s</span>
        <span v-if="res.pseudonymized" class="text-xs text-dimmed">· {{ t('ai.pseudo_on') }}</span>
        <UButton class="ms-auto" size="xs" color="neutral" variant="ghost" icon="i-lucide-refresh-cw" :aria-label="t('ai.regenerate')" :title="t('ai.regenerate')" :disabled="busy" @click.stop="run(true)" />
      </div>
      <AiText :text="res.text" />
    </div>
  </div>
</template>
