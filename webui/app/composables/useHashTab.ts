// Onglet interne adressable par l'URL : /page#onglet (lien direct, retour arrière, favoris).
export function useHashTab(def: string, allowed: string[]) {
  const route = useRoute()
  const router = useRouter()
  const tab = ref(def)
  const apply = (h: string) => { const v = h.replace(/^#/, ''); if (allowed.includes(v)) tab.value = v }
  onMounted(() => apply(route.hash))
  watch(() => route.hash, (h) => apply(h))
  watch(tab, (v) => { if (route.hash !== '#' + v) router.replace({ hash: '#' + v }) })
  return tab
}
