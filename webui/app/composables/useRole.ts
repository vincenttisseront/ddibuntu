export function useRole() {
  const user = useState<any>('user')
  const isAdmin = computed(() => user.value?.role === 'admin')
  const canWrite = computed(() => ['admin', 'operator'].includes(user.value?.role))
  return { user, isAdmin, canWrite }
}
export const prune = (o: any): any => {
  if (Array.isArray(o)) return o.length ? o : undefined
  if (o && typeof o === 'object') { const r: any = {}; for (const [k, v] of Object.entries(o)) { const p = prune(v); if (p !== undefined && p !== null && p !== '') r[k] = p } return Object.keys(r).length ? r : undefined }
  return o
}
