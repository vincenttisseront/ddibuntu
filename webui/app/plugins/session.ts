// Charge l'utilisateur courant (rendu serveur compris : le cookie est transmis par useRequestFetch).
export default defineNuxtPlugin(async () => {
  const user = useState<any>('user', () => null)
  const csrf = useState<string>('csrf', () => '')
  const f = useRequestFetch()
  try {
    const r: any = await f('/api/auth/me')
    user.value = r.user ? { ...r.user, mfaEnrol: !!r.mfaEnrol } : null
    csrf.value = r.csrf ?? ''
  } catch {
    user.value = null
  }
})
