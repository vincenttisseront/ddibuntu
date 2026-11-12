<script setup lang="ts">
// Sélecteur de nœuds (en-tête, mode cluster) : rôle de chacun d'un coup d'œil, passage direct à la console d'un autre nœud.
const props = defineProps<{ st: any }>()
const { t } = useT()
const nodes = computed<any[]>(() => props.st?.nodes ?? [])
const me = computed(() => nodes.value.find((n) => n.name === props.st?.node))
const kindOf = (n: any) => (n.role === 'witness' ? 'witness' : n.name === props.st?.leader ? 'leader' : n.patroniRole === 'replica' ? 'replica' : 'unknown')
const color = (k: string) => (k === 'leader' ? 'success' : k === 'replica' ? 'info' : 'neutral') as any
const label = (k: string) => (k === 'witness' ? t('cluster.witness') : t(`cluster.pg.${k}`))
const myKind = computed(() => (me.value ? kindOf(me.value) : 'unknown'))
const vipHolder = computed(() => (props.st?.vip ? props.st.leader : null))
const items = computed(() => {
  const rows: any[] = nodes.value.map((n) => {
    const k = kindOf(n), here = n.name === props.st?.node, canOpen = n.role === 'data' && !here
    const sfx = [n.name === props.st?.preferred?.node ? '★' : '', n.name === vipHolder.value ? 'VIP' : ''].filter(Boolean).join(' ')
    return {
      label: `${n.name}${sfx ? ' ' + sfx : ''}`,
      description: `${label(k)} · ${n.ip}${here ? ' · ' + t('cluster.switcher.here') : n.role === 'witness' ? ' · ' + t('cluster.switcher.witness') : ''}`,
      icon: n.role === 'witness' ? 'i-lucide-scale' : k === 'leader' ? 'i-lucide-crown' : 'i-lucide-server',
      disabled: !canOpen,
      onSelect: () => openConsole(n.ip),
    }
  })
  return [rows, [{ label: t('cluster.switcher.view'), icon: 'i-lucide-server-cog', to: '/cluster' }]]
})
</script>

<template>
  <UDropdownMenu v-if="st && nodes.length" :items="items" :content="{ align: 'start' }" :ui="{ content: 'min-w-72' }">
    <UButton color="neutral" variant="subtle" size="sm" icon="i-lucide-server-cog" trailing-icon="i-lucide-chevron-down" :aria-label="t('cluster.switcher.label')" :title="t('cluster.switcher.label')">
      <span class="font-mono">{{ st.node }}</span>
      <UBadge :color="color(myKind)" variant="subtle" size="sm" :label="label(myKind)" />
      <UIcon v-if="st.stale" name="i-lucide-clock-alert" class="text-warning" :title="t('cluster.switcher.stale')" />
    </UButton>
  </UDropdownMenu>
</template>
