<script setup lang="ts">
const { t } = useT()
const fmt = useFmt()
const { isAdmin } = useRole()
if (!isAdmin.value) await navigateTo('/')
const tab = useHashTab('users', ['users', 'audit', 'alerts', 'backup', 'restore', 'updates', 'about'])
const baseTabs = computed(() => [{ label: t('system.users'), value: 'users', icon: 'i-lucide-users' }, { label: t('system.audit'), value: 'audit', icon: 'i-lucide-scroll-text' }, { label: t('system.about'), value: 'about', icon: 'i-lucide-info' }])
const tabs = computed(() => { const b = baseTabs.value; return [...b.slice(0, 2), { label: t('alerts.tab'), value: 'alerts', icon: 'i-lucide-bell-ring' }, { label: t('backup.tab'), value: 'backup', icon: 'i-lucide-database-backup' }, { label: t('restore.tab'), value: 'restore', icon: 'i-lucide-history' }, { label: t('update.tab'), value: 'updates', icon: 'i-lucide-download' }, ...b.slice(2)] })
const roleOptions = computed(() => ['admin', 'operator', 'viewer'].map((v) => ({ label: t(`system.role.${v}`), value: v })))
const userCols = computed(() => [{ key: 'username', label: t('system.user'), kind: 'mono' }, { key: 'display_name', label: t('common.name') }, { key: 'role', label: t('system.role_label'), kind: 'badge', trans: 'system.role' }, { key: 'source', label: t('system.source'), kind: 'badge', trans: 'system.src' }, { key: 'disabled', label: t('common.disabled'), kind: 'bool' }, { key: 'last_login', label: t('system.last_login'), kind: 'date' }])
const userFields = computed(() => [
  { key: 'username', label: t('system.user'), type: 'text', required: true, createOnly: true, mono: true }, { key: 'display_name', label: t('common.name'), type: 'text' },
  { key: 'role', label: t('system.role_label'), type: 'select', required: true, default: 'viewer', options: roleOptions.value }, { key: 'password', label: t('login.password'), type: 'password', hint: t('login.policy') },
  { key: 'disabled', label: t('common.disabled'), type: 'switch', editHidden: false },
] as any[])
const userBody = (b: any, editing: boolean) => { const o = { ...b }; if (!editing) delete o.disabled; return o }
const auditCols = computed(() => [{ key: 'at', label: t('common.date'), kind: 'date' }, { key: 'username', label: t('system.user') }, { key: 'action', label: t('system.action'), kind: 'mono' }, { key: 'entity', label: t('system.entity') }, { key: 'entity_id', label: 'ID', kind: 'mono' }, { key: 'ip', label: 'IP', kind: 'mono' }])
const { data: info } = await useFetch<any>('/api/system/info')
const { data: deps } = await useFetch<any>('/api/system/deployments')
</script>

<template>
  <div class="flex flex-col gap-3">
    <UTabs v-model="tab" :items="tabs" :content="false" :aria-label="t('nav.system')" />
    <div v-if="tab === 'users'" class="flex flex-col gap-3"><SessionSettings />
          <ResourceTable endpoint="/users" :columns="userCols" :fields="userFields" can-write create-url="/users" :update-url="(r: any) => `/users/${r.id}`" :delete-url="(r: any) => `/users/${r.id}`" :delete-name="(r: any) => r.username" :create-label="t('system.add_user')" :transform="userBody" /></div>
    <ResourceTable v-else-if="tab === 'audit'" endpoint="/audit" :columns="auditCols" searchable />
    <AlertsPanel v-else-if="tab === 'alerts'" />
    <BackupPanel v-else-if="tab === 'backup'" />
    <RestorePanel v-else-if="tab === 'restore'" />
    <UpdatePanel v-else-if="tab === 'updates'" />
    <div v-else class="grid gap-4 lg:grid-cols-2">
      <UCard><template #header><span class="font-medium">DDI-Buntu</span></template>
        <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm"><dt class="text-muted">{{ t('system.version') }}</dt><dd class="font-mono">{{ info?.version }}</dd><dt class="text-muted">{{ t('system.db') }}</dt><dd class="font-mono">{{ info?.db }} · schéma {{ info?.schema }}</dd>
          <dt class="text-muted">{{ t('system.generated_dir') }}</dt><dd class="font-mono text-xs">{{ info?.generatedDir }}</dd>
          <template v-for="b in info?.binaries ?? []" :key="b.name"><dt class="text-muted font-mono text-xs">{{ b.name }}</dt><dd><UBadge :color="b.ok ? 'success' : 'error'" variant="subtle" :label="b.ok ? t('system.available') : t('system.missing')" /></dd></template></dl></UCard>
      <UCard><template #header><span class="font-medium">{{ t('system.deployments') }}</span></template>
        <ul class="text-sm flex flex-col gap-1 max-h-72 overflow-auto"><li v-for="d in deps?.items ?? []" :key="d.id" class="flex gap-2 items-center"><UIcon :name="d.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'" :class="d.ok ? 'text-success' : 'text-error'" /><span class="num text-xs">{{ fmt.dateTime(d.at) }}</span><span class="text-muted text-xs">{{ d.username }}</span></li></ul>
        <p v-if="!(deps?.items ?? []).length" class="text-sm text-muted">{{ t('common.empty') }}</p></UCard>
    </div>
  </div>
</template>
