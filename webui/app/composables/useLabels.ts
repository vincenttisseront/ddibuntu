// Catalogue des labels IPAM (couleurs, descriptions) partagé par tous les composants qui affichent ou saisissent des labels.
const PALETTE = ['#2563eb', '#0d9488', '#7c3aed', '#c2410c', '#be185d', '#4d7c0f', '#0369a1', '#a16207', '#9333ea', '#b91c1c']
/** Couleur de repli stable : la même pour un même nom (aucune configuration nécessaire). */
export function labelHashColor(name: string): string {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0
  return PALETTE[h % PALETTE.length]!
}
export function useLabels() {
  const { data, refresh } = useFetch<any>('/api/ipam/labels', { key: 'ipam-labels', default: () => ({ items: [] }), lazy: true })
  const items = computed<any[]>(() => data.value?.items ?? [])
  const colors = computed(() => new Map(items.value.map((l: any) => [l.name as string, l.color as string | null])))
  const colorOf = (name: string) => colors.value.get(name) || labelHashColor(name)
  return { items, colorOf, refresh }
}
