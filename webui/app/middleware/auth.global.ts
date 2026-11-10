export default defineNuxtRouteMiddleware((to) => {
  const user = useState<any>('user')
  const open = ['/login', '/setup']
  if (!user.value && !open.includes(to.path)) return navigateTo('/login')
  if (user.value && open.includes(to.path)) return navigateTo('/')
})
