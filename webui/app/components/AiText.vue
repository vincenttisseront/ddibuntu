<script setup lang="ts">
// Réponse de l'assistant IA mise en forme (titres, gras, code, listes) sans jamais interpréter de HTML.
const props = defineProps<{ text: string }>()
const blocks = computed(() => aiBlocks(props.text))
</script>

<template>
  <div class="flex flex-col gap-2 text-sm leading-relaxed" data-test="ai-text">
    <template v-for="(b, i) in blocks" :key="i">
      <p v-if="b.k === 'h'" class="font-semibold text-highlighted" :class="i > 0 ? 'mt-1' : ''" role="heading" aria-level="4">
        <template v-for="(s, j) in b.parts" :key="j">{{ s.v }}</template>
      </p>
      <p v-else-if="b.k === 'p'" class="break-words">
        <template v-for="(s, j) in b.parts" :key="j"><strong v-if="s.t === 'strong'" class="font-semibold">{{ s.v }}</strong><code v-else-if="s.t === 'code'" class="font-mono text-xs px-1 rounded bg-elevated">{{ s.v }}</code><template v-else>{{ s.v }}</template></template>
      </p>
      <component :is="b.k" v-else class="flex flex-col gap-1 ps-5 break-words" :class="b.k === 'ol' ? 'list-decimal' : 'list-disc'">
        <li v-for="(it, j) in b.items" :key="j">
          <template v-for="(s, n) in it" :key="n"><strong v-if="s.t === 'strong'" class="font-semibold">{{ s.v }}</strong><code v-else-if="s.t === 'code'" class="font-mono text-xs px-1 rounded bg-elevated">{{ s.v }}</code><template v-else>{{ s.v }}</template></template>
        </li>
      </component>
    </template>
  </div>
</template>
