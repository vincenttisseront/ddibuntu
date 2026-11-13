<script setup lang="ts">
const { t, lang, setLang } = useT()
const user = useState<any>('user')
const api = useApi()
const enrolOpen = ref(false)                                   // MFA imposée à ce rôle : fenêtre d'inscription non fermable
watch(() => user.value?.mfaEnrol, (v) => { enrolOpen.value = !!v }, { immediate: true })
const enrolDone = () => { if (user.value) user.value = { ...user.value, mfaEnrol: false }; enrolOpen.value = false }
const route = useRoute()
const { data: about, refresh: refreshAbout } = useFetch<any>('/api/about', { server: false, lazy: true, default: () => null })
const { data: clusterInfo, refresh: refreshCluster } = useFetch<any>('/api/cluster/status', { server: false, lazy: true, default: () => null })
const clusterOn = computed(() => !!clusterInfo.value?.clustered)
const replicaNode = computed(() => !!clusterInfo.value?.replica)
const clusterSt = computed(() => clusterInfo.value?.state ?? null)
const target = computed(() => primaryTarget(clusterSt.value))
// état du cluster rafraîchi toutes les 15 s tant qu'on est en mode cluster (rôles du sélecteur et bandeau toujours justes, y compris après une bascule)
let clusterTimer: ReturnType<typeof setInterval> | undefined
let aboutTimer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  clusterTimer = setInterval(() => { if (clusterOn.value && !document.hidden) refreshCluster() }, 15000)
  // version affichée : relue chaque minute (après une mise à jour la console redémarre, l'onglet resterait sinon sur l'ancienne version)
  aboutTimer = setInterval(() => { if (!document.hidden) refreshAbout() }, 60000)
})
onBeforeUnmount(() => { if (clusterTimer) clearInterval(clusterTimer); if (aboutTimer) clearInterval(aboutTimer) })
// la page chargée est celle de l'ancienne version : on propose de la recharger (interface et serveur doivent concorder)
const toast = useToast()
let seenVersion = ''
watch(() => about.value?.version, (v) => {
  if (!v) return
  if (seenVersion && v !== seenVersion) toast.add({ title: t('upd.reload_title', { v }), description: t('upd.reload_desc'), color: 'info', icon: 'i-lucide-refresh-cw', duration: 0, actions: [{ label: t('upd.reload'), onClick: () => { window.location.reload() } }] })
  seenVersion = v
})
const updateAvailable = computed(() => !!about.value?.update?.available)
const role = computed(() => user.value?.role)
const initials = computed(() => { const n = (user.value?.displayName || user.value?.username || '?').trim(); const w = n.split(/[\s._@-]+/).filter(Boolean); return ((w[0]?.[0] ?? '?') + (w.length > 1 ? (w[w.length - 1]![0] ?? '') : '')).toUpperCase() })
// Navigation par module : données (IPAM, DNS, DHCP), sécurité, puis exploitation. Les groupes vides n'apparaissent pas.
const navGroups = computed(() => {
  const g: Array<{ label?: string; items: any[] }> = [
    { items: [{ label: t('nav.dashboard'), icon: 'i-lucide-layout-dashboard', to: '/' }] },
    { label: t('nav.grp_ddi'), items: [
      { label: t('nav.ipam'), icon: 'i-lucide-network', to: '/ipam' },
      { label: t('nav.dns'), icon: 'i-lucide-globe', to: '/dns' },
      { label: t('nav.dhcp'), icon: 'i-lucide-server', to: '/dhcp' },
      { label: t('nav.trace'), icon: 'i-lucide-history', to: '/trace' },
    ] },
    { label: t('nav.grp_security'), items: [{ label: t('nav.filtering'), icon: 'i-lucide-shield-ban', to: '/filtering' }] },
    { label: t('nav.grp_ops'), items: [
      { label: t('nav.import'), icon: 'i-lucide-file-input', to: '/import' },
      ...(['admin', 'operator'].includes(role.value) ? [{ label: t('nav.ad'), icon: 'i-lucide-building-2', to: '/ad' }] : []),
      // un administrateur voit toujours l'entrée : c'est par elle qu'on crée un cluster ou qu'on en rejoint un depuis un serveur encore seul
      ...(clusterOn.value || role.value === 'admin' ? [{ label: t('nav.cluster'), icon: 'i-lucide-server-cog', to: '/cluster' }] : []),
      ...(role.value === 'admin' ? [{ label: t('nav.system'), icon: 'i-lucide-settings', to: '/system', ...(updateAvailable.value ? { badge: t('update.badge'), to: '/system#updates' } : {}) }] : []),
    ] },
  ]
  return g.filter((x) => x.items.length)
})
const navMenu = computed(() => navGroups.value.map((g) => [...(g.label ? [{ label: g.label, type: 'label' as const }] : []), ...g.items]))
const nav = computed(() => navGroups.value.flatMap((g) => g.items))
const searchOpen = ref(false)
defineShortcuts({ meta_k: { handler: () => { searchOpen.value = true }, usingInput: true }, '/': () => { searchOpen.value = true } })
const title = computed(() => route.path === '/profile' ? t('profile.title') : nav.value.find((n) => (n.to === '/' ? route.path === '/' : route.path.startsWith(n.to)))?.label ?? '')
async function logout() {
  try { await api.call('POST', '/auth/logout', {}, { silent: true }) } catch { /* session déjà fermée */ }
  useState<any>('user').value = null
  await navigateTo('/login')
}
</script>

<template>
  <UDashboardGroup>
    <UDashboardSidebar collapsible resizable :min-size="14" :default-size="16">
      <template #header="{ collapsed }">
        <div class="flex items-center gap-2 px-1">
          <UIcon name="i-lucide-network" class="size-6 text-primary shrink-0" />
          <div v-if="!collapsed" class="flex flex-col leading-tight min-w-0">
            <span class="font-semibold tracking-tight font-mono">DDI-Buntu</span>
            <span v-if="about?.version" class="text-xs text-muted font-mono truncate" :title="about?.hostname">v{{ about.version }}<template v-if="about?.hostname"> · {{ about.hostname }}</template></span>
          </div>
        </div>
      </template>
      <template #default="{ collapsed }">
        <UButton :icon="'i-lucide-search'" color="neutral" variant="outline" size="sm" :block="!collapsed" :square="collapsed" :label="collapsed ? undefined : t('search.open')" :aria-label="t('search.open')" class="mb-2" @click="searchOpen = true">
          <template v-if="!collapsed" #trailing><UKbd value="meta" /><UKbd value="K" /></template>
        </UButton>
        <UNavigationMenu :items="navMenu" orientation="vertical" :collapsed="collapsed" :aria-label="t('nav.label')" />
      </template>
      <template #footer="{ collapsed }">
        <div class="flex items-center gap-1 w-full" :class="collapsed ? 'flex-col' : ''">
          <NuxtLink to="/profile" class="flex items-center gap-2 min-w-0 flex-1 rounded-md p-1 hover:bg-elevated focus-visible:outline-2 focus-visible:outline-primary" :class="collapsed ? 'justify-center' : ''" :title="t('profile.open')" :aria-label="t('profile.open')">
            <UAvatar :text="initials" size="sm" class="shrink-0" />
            <span v-if="!collapsed" class="flex flex-col min-w-0 leading-tight">
              <span class="text-sm font-medium truncate">{{ user?.displayName || user?.username }}</span>
              <span class="text-xs text-muted truncate">{{ t(`system.role.${user?.role}`) }} · {{ t(`profile.src.${user?.source}`) }}</span>
            </span>
            <span v-else-if="about?.version" class="sr-only">v{{ about.version }}</span>
          </NuxtLink>
          <UButton icon="i-lucide-log-out" color="neutral" variant="ghost" size="sm" :aria-label="t('nav.logout')" :title="t('nav.logout')" @click="logout" />
        </div>
      </template>
    </UDashboardSidebar>

    <UDashboardPanel>
      <template #header>
        <UDashboardNavbar :title="title">
          <template #right>
            <ClusterNodeSwitcher v-if="clusterOn" :st="clusterSt" />
            <UButton color="neutral" variant="ghost" size="sm" :label="lang === 'fr' ? 'EN' : 'FR'" :aria-label="t('nav.language')" @click="setLang(lang === 'fr' ? 'en' : 'fr')" />
            <UColorModeButton :aria-label="t('nav.theme')" />
          </template>
        </UDashboardNavbar>
      </template>
      <template #body>
        <UAlert v-if="replicaNode" class="mb-3" color="info" variant="subtle" icon="i-lucide-copy" :title="t('cluster.replica_title')"
          :description="[t('cluster.replica_desc'), clusterSt?.leader ? t('cluster.replica_where', { n: clusterSt.leader }) : ''].filter(Boolean).join(' ')"
          :actions="target ? [{ label: target.viaVip ? t('cluster.replica_go_vip') : t('cluster.replica_go'), icon: 'i-lucide-external-link', color: 'neutral', variant: 'outline', onClick: () => openConsole(target!.host) }] : []" />
        <slot />
      </template>
    </UDashboardPanel>
    <GlobalSearch v-model:open="searchOpen" />
    <AccountSecurity v-if="user?.mfaEnrol" v-model:open="enrolOpen" forced @enabled="enrolDone" />
  </UDashboardGroup>
</template>
