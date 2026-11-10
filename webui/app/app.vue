<script setup lang="ts">
const { t, lang } = useT()
useHead({ htmlAttrs: { lang: () => lang.value }, title: () => t('app.title') })
</script>

<template>
  <UApp>
    <NuxtLayout>
      <NuxtPage />
    </NuxtLayout>
    <ConfirmDialog />
  </UApp>
</template>
