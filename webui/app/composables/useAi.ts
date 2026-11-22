// État de l'assistant IA (activé ? quels usages ?) : lu une fois par session, relu après un changement de réglages.
export function useAi() {
  const st = useState<{ enabled: boolean; model: string | null; uses: Record<string, boolean> } | null>('ai-status', () => null)
  async function load(force = false) {
    if (st.value && !force) return
    try { st.value = await $fetch<any>('/api/ai/status') } catch { st.value = { enabled: false, model: null, uses: {} } }
  }
  const can = (use: string) => !!st.value?.enabled && !!st.value.uses?.[use]
  return { status: st, load, can }
}
