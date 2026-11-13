<script setup lang="ts">
// Profil de l'utilisateur connecté : identité, origine de connexion, périmètre, mot de passe, double authentification, sessions actives.
const { t } = useT(); const api = useApi(); const toast = useToast(); const { ask } = useConfirm(); const fmt = useFmt()
const me = useState<any>('user')
const prof = ref<any>(null), sess = ref<any>(null), pwOpen = ref(false), secOpen = ref(false), busy = ref('')
async function load() {
  prof.value = await api.call('GET', '/auth/profile', undefined, { silent: true }).catch(() => null)
  sess.value = await api.call('GET', '/auth/sessions', undefined, { silent: true }).catch(() => null)
}
onMounted(load)
watch(secOpen, (o) => { if (!o) load() })
const src = computed(() => prof.value?.source ?? me.value?.source ?? 'local')
const local = computed(() => src.value === 'local')
const when = (v: any) => (v ? fmt.dateTime(v) : '—')
const initials = computed(() => { const n = (prof.value?.displayName || prof.value?.username || '?').trim(); const w = n.split(/[\s._@-]+/).filter(Boolean); return ((w[0]?.[0] ?? '?') + (w.length > 1 ? (w[w.length - 1]![0] ?? '') : '')).toUpperCase() })
const roleColor = computed(() => (prof.value?.role === 'admin' ? 'error' : prof.value?.role === 'operator' ? 'primary' : 'neutral'))
// Navigateur lisible depuis l'agent utilisateur (sans dépendance)
function agent(ua: string | null) {
  if (!ua) return t('profile.unknown_device')
  const b = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl|python|node|axios/i.test(ua) ? t('profile.script') : t('profile.unknown_device')
  const o = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : ''
  return o ? `${b} · ${o}` : b
}
async function revoke(s: any) {
  if (!(await ask(t('profile.revoke_title'), t('profile.revoke_body', { d: agent(s.user_agent) }), true))) return
  busy.value = String(s.id)
  try { await api.call('DELETE', `/auth/sessions/${s.id}`, undefined, { busy: true }); toast.add({ title: t('profile.revoked'), color: 'success', icon: 'i-lucide-check' }); await load() } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { busy.value = '' }
}
async function revokeOthers() {
  if (!(await ask(t('profile.revoke_all_title'), t('profile.revoke_all_body'), true))) return
  busy.value = 'all'
  try { const r: any = await api.call('POST', '/auth/sessions/revoke-others', {}, { busy: true }); toast.add({ title: t('profile.revoked_n', { n: r.count }), color: 'success', icon: 'i-lucide-check' }); await load() } catch (e: any) { toast.add({ title: e.info?.message ?? t('err.internal'), color: 'error' }) } finally { busy.value = '' }
}
const others = computed(() => (sess.value?.items ?? []).filter((s: any) => !s.current))
</script>

<template>
  <div class="flex flex-col gap-4 max-w-4xl">
    <UCard>
      <div class="flex flex-wrap items-center gap-4">
        <UAvatar :text="initials" size="3xl" />
        <div class="flex flex-col gap-1 min-w-0">
          <h2 class="text-lg font-semibold truncate">{{ prof?.displayName || prof?.username }}</h2>
          <span class="text-sm text-muted font-mono truncate">{{ prof?.username }}</span>
          <div class="flex flex-wrap gap-2 mt-1">
            <UBadge :color="roleColor" variant="subtle" :label="t(`system.role.${prof?.role ?? 'viewer'}`)" />
            <UBadge color="neutral" variant="outline" :icon="`i-lucide-${src === 'local' ? 'user' : src === 'oidc' ? 'log-in' : 'book-user'}`" :label="t(`profile.src.${src}`)" />
          </div>
        </div>
        <dl class="ml-auto grid grid-cols-[auto_auto] gap-x-4 gap-y-1 text-sm">
          <dt class="text-muted">{{ t('profile.created') }}</dt><dd>{{ when(prof?.createdAt) }}</dd>
          <dt class="text-muted">{{ t('profile.last_login') }}</dt><dd>{{ when(prof?.lastLogin) }}</dd>
          <dt class="text-muted">{{ t('profile.scope') }}</dt>
          <dd><span v-if="!prof?.spaces">{{ t('profile.scope_all') }}</span><span v-else-if="!prof.spaces.length">{{ t('profile.scope_none') }}</span><span v-else>{{ prof.spaces.map((x: any) => x.name).join(', ') }}</span></dd>
        </dl>
      </div>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-shield-check" class="size-5 text-primary" /><h3 class="font-semibold">{{ t('profile.security') }}</h3></div></template>
      <UAlert v-if="!local" color="neutral" variant="subtle" icon="i-lucide-info" :title="t(`profile.managed.${src}`)" :description="t('profile.managed_desc')" />
      <div v-else class="flex flex-col divide-y divide-default">
        <div class="flex flex-wrap items-center gap-3 py-3">
          <UIcon name="i-lucide-key-round" class="size-5 text-muted" />
          <div class="flex-1 min-w-48"><div class="font-medium text-sm">{{ t('profile.password') }}</div><div class="text-xs text-muted">{{ t('profile.password_desc') }}</div></div>
          <UButton color="neutral" variant="outline" icon="i-lucide-pencil" :label="t('login.change_password')" @click="pwOpen = true" />
        </div>
        <div class="flex flex-wrap items-center gap-3 py-3">
          <UIcon name="i-lucide-smartphone" class="size-5 text-muted" />
          <div class="flex-1 min-w-48"><div class="font-medium text-sm flex items-center gap-2">{{ t('profile.mfa') }}<UBadge :color="prof?.mfa ? 'success' : 'warning'" variant="subtle" :label="prof?.mfa ? t('mfa.on') : t('mfa.off')" /></div><div class="text-xs text-muted">{{ t('profile.mfa_desc') }}</div></div>
          <UButton color="neutral" variant="outline" icon="i-lucide-shield-check" :label="prof?.mfa ? t('profile.mfa_manage') : t('mfa.enable')" @click="secOpen = true" />
        </div>
      </div>
    </UCard>

    <UCard>
      <template #header><div class="flex items-center gap-2"><UIcon name="i-lucide-monitor-smartphone" class="size-5 text-primary" /><h3 class="font-semibold">{{ t('profile.sessions') }}</h3>
        <UButton v-if="others.length" class="ml-auto" size="xs" color="neutral" variant="outline" icon="i-lucide-log-out" :loading="busy === 'all'" :label="t('profile.revoke_all')" @click="revokeOthers" /></div></template>
      <p v-if="sess?.unavailable" class="text-sm text-muted">{{ t('profile.sessions_replica') }}</p>
      <p v-else-if="!sess" class="text-sm text-muted">{{ t('common.loading') }}</p>
      <ul v-else class="divide-y divide-default">
        <li v-for="s in sess.items" :key="s.id" class="py-2 flex flex-wrap items-center gap-3">
          <UIcon name="i-lucide-laptop" class="size-5 text-muted" />
          <div class="flex-1 min-w-48 text-sm"><div class="font-medium flex items-center gap-2">{{ agent(s.user_agent) }}<UBadge v-if="s.current" color="success" variant="subtle" :label="t('profile.this_session')" /></div>
            <div class="text-xs text-muted">{{ s.ip || '—' }} · {{ t('profile.started') }} {{ when(s.created_at) }} · {{ t('profile.active') }} {{ when(s.last_seen) }}</div></div>
          <UButton v-if="!s.current" size="xs" color="neutral" variant="outline" icon="i-lucide-x" :loading="busy === String(s.id)" :label="t('profile.revoke')" @click="revoke(s)" />
        </li>
      </ul>
    </UCard>
    <PasswordDialog v-model:open="pwOpen" />
    <AccountSecurity v-model:open="secOpen" />
  </div>
</template>
