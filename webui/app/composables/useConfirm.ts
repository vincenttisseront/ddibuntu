export function useConfirm() {
  const state = useState('confirm', () => ({ open: false, title: '', message: '', danger: true, resolve: null as null | ((v: boolean) => void) }))
  const ask = (title: string, message: string, danger = true) =>
    new Promise<boolean>((resolve) => { state.value = { open: true, title, message, danger, resolve } })
  return { state, ask }
}
