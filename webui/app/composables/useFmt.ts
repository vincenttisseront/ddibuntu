// Dates et heures : le serveur (fuseau horaire, langue) et le navigateur diffèrent. Pour éviter tout écart d'hydratation, rien n'est affiché
// côté serveur ; le texte apparaît dès que la page est montée dans le navigateur (avec SON fuseau et SA langue).
export function useFmt() {
  const ready = useState<boolean>('fmt_ready', () => false)
  onMounted(() => { ready.value = true })
  const dateTime = (v: string | number | Date | null | undefined): string => (!ready.value || v === null || v === undefined || v === '' ? '' : new Date(v).toLocaleString())
  const time = (v: string | number | Date | null | undefined): string => (!ready.value || v === null || v === undefined || v === '' ? '' : new Date(v).toLocaleTimeString())
  return { ready, dateTime, time }
}
