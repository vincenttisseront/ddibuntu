<script setup lang="ts">
// Saisie de labels : on tape puis Entrée (ou virgule) ; les labels existants du catalogue sont proposés d'un clic.
const model = defineModel<string[]>({ default: () => [] })
defineProps<{ placeholder?: string; ariaLabel?: string }>()
const { t } = useT()
const { items, colorOf } = useLabels()
const norm = (s: string) => s.normalize('NFC').trim().replace(/\s+/g, ' ').toLowerCase()
const value = computed({
  get: () => model.value ?? [],
  set: (v: string[]) => { model.value = [...new Set(v.map(norm).filter(Boolean))] },
})
const suggestions = computed(() => items.value.map((l: any) => l.name as string).filter((n) => !value.value.includes(n)).slice(0, 12))
const allNames = computed(() => items.value.map((l: any) => l.name as string))
const q = ref('')
const shown = computed(() => allNames.value.filter((n) => !q.value.trim() || n.includes(q.value.trim().toLowerCase())))
const toggle = (n: string) => { value.value = value.value.includes(n) ? value.value.filter((x) => x !== n) : [...value.value, n] }
const add = (n: string) => { value.value = [...value.value, n] }
</script>

<template>
  <div class="flex flex-col gap-1.5">
    <div class="flex items-start gap-1.5">
      <UInputTags v-model="value" class="min-w-0 flex-1" :placeholder="placeholder ?? t('label.input_ph')" :aria-label="ariaLabel ?? t('label.title')" add-on-paste :max="20" />
      <UPopover v-if="allNames.length" :content="{ align: 'end' }">
        <UButton color="neutral" variant="outline" icon="i-lucide-chevrons-up-down" trailing-icon="i-lucide-chevron-down" :label="value.length ? t('label.picked', { n: value.length }) : t('label.pick')" :aria-label="t('label.pick')" />
        <template #content>
          <div class="flex w-64 flex-col gap-1 p-2" data-testid="label-picker">
            <UInput v-model="q" size="xs" icon="i-lucide-search" :placeholder="t('label.search')" :aria-label="t('label.search')" autocomplete="off" />
            <ul class="max-h-60 overflow-auto" role="listbox" aria-multiselectable="true">
              <li v-for="n in shown" :key="n" role="option" :aria-selected="value.includes(n)">
                <button type="button" class="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-sm hover:bg-elevated" @click="toggle(n)">
                  <UIcon :name="value.includes(n) ? 'i-lucide-square-check-big' : 'i-lucide-square'" class="size-4 shrink-0" :class="value.includes(n) ? 'text-primary' : 'text-muted'" />
                  <span class="truncate" :style="{ color: colorOf(n) }">{{ n }}</span>
                </button>
              </li>
              <li v-if="!shown.length" class="px-1.5 py-1 text-xs text-muted">{{ t('common.empty') }}</li>
            </ul>
          </div>
        </template>
      </UPopover>
    </div>
    <div v-if="suggestions.length" class="flex flex-wrap items-center gap-1">
      <span class="text-xs text-muted">{{ t('label.suggest') }}</span>
      <button v-for="n in suggestions" :key="n" type="button" class="rounded-full border border-default px-1.5 py-px text-xs hover:bg-elevated" :style="{ color: colorOf(n) }" @click="add(n)">+ {{ n }}</button>
    </div>
  </div>
</template>
