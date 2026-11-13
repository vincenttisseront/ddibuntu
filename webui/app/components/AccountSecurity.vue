<script setup lang="ts">
// Sécurité du compte : double authentification (TOTP) — activation avec QR code, codes de secours, désactivation.
import QRCode from 'qrcode'
const open = defineModel<boolean>('open', { default: false })
const { t } = useT(); const api = useApi(); const toast = useToast()
const st = ref<{ available: boolean; enabled: boolean; recoveryLeft: number } | null>(null)
const step = ref<'home' | 'password' | 'scan' | 'codes' | 'disable' | 'regen'>('home')
const password = ref(''), code = ref(''), error = ref(''), busy = ref(false)
const secret = ref(''), qr = ref(''), codes = ref<string[]>([])
async function load() { try { st.value = await api.call('GET', '/auth/mfa') } catch { st.value = null } }
watch(open, (o) => { if (o) { step.value = 'home'; password.value = code.value = error.value = ''; codes.value = []; void load() } })
async function run(fn: () => Promise<void>) { busy.value = true; error.value = ''; try { await fn() } catch (e: any) { error.value = e.info?.message ?? t('err.internal') } finally { busy.value = false } }
const start = () => run(async () => {
  const r: any = await api.call('POST', '/auth/mfa/setup', { password: password.value }, { silent: true })
  secret.value = r.secret; qr.value = await QRCode.toDataURL(r.uri, { margin: 1, width: 192, color: { dark: '#0f172a', light: '#ffffff' } }); password.value = ''; code.value = ''; step.value = 'scan'
})
const enable = () => run(async () => { codes.value = ((await api.call('POST', '/auth/mfa/enable', { code: code.value }, { silent: true })) as any).codes; code.value = ''; step.value = 'codes'; await load() })
const disable = () => run(async () => { await api.call('POST', '/auth/mfa/disable', { password: password.value, code: code.value }, { silent: true }); toast.add({ title: t('mfa.disabled'), color: 'success', icon: 'i-lucide-check' }); await load(); step.value = 'home'; password.value = code.value = '' })
const regen = () => run(async () => { codes.value = ((await api.call('POST', '/auth/mfa/recovery', { password: password.value }, { silent: true })) as any).codes; password.value = ''; step.value = 'codes'; await load() })
const grouped = computed(() => secret.value.replace(/(.{4})/g, '$1 ').trim())
const copy = async (txt: string) => { try { await navigator.clipboard.writeText(txt); toast.add({ title: t('common.copied'), color: 'success', icon: 'i-lucide-check' }) } catch { /* presse-papiers indisponible */ } }
</script>

<template>
  <UModal v-model:open="open" :title="t('mfa.title')" :description="t('mfa.desc')">
    <template #body>
      <div v-if="busy && !st" class="flex items-center gap-2 text-sm text-muted"><UIcon name="i-lucide-loader-circle" class="animate-spin" />{{ t('common.loading') }}</div>
      <UAlert v-if="st && !st.available" color="neutral" variant="subtle" icon="i-lucide-info" :title="t('mfa.local_only')" />
      <div v-else-if="st" class="flex flex-col gap-4">
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="error" role="alert" />

        <template v-if="step === 'home'">
          <div class="flex items-center gap-3"><UBadge :color="st.enabled ? 'success' : 'neutral'" variant="subtle" :label="st.enabled ? t('mfa.on') : t('mfa.off')" /><span v-if="st.enabled" class="text-sm text-muted">{{ t('mfa.codes_left', { n: st.recoveryLeft }) }}</span></div>
          <p class="text-sm text-muted">{{ st.enabled ? t('mfa.on_hint') : t('mfa.off_hint') }}</p>
          <div class="flex flex-wrap justify-end gap-2">
            <template v-if="st.enabled"><UButton color="neutral" variant="outline" icon="i-lucide-refresh-cw" :label="t('mfa.regen')" @click="step = 'regen'; password = ''; error = ''" /><UButton color="error" variant="outline" icon="i-lucide-shield-off" :label="t('mfa.disable')" @click="step = 'disable'; password = code = ''; error = ''" /></template>
            <UButton v-else icon="i-lucide-shield-plus" :label="t('mfa.enable')" @click="step = 'password'; password = ''; error = ''" />
          </div>
        </template>

        <form v-else-if="step === 'password'" class="flex flex-col gap-3" @submit.prevent="start">
          <p class="text-sm text-muted">{{ t('mfa.confirm_pw') }}</p>
          <UFormField :label="t('login.password')" required><UInput v-model="password" type="password" autocomplete="current-password" autofocus class="w-full" /></UFormField>
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="step = 'home'" /><UButton type="submit" :loading="busy" :disabled="!password" :label="t('mfa.next')" /></div>
        </form>

        <form v-else-if="step === 'scan'" class="flex flex-col gap-3" @submit.prevent="enable">
          <ol class="list-decimal ps-5 text-sm text-muted flex flex-col gap-1"><li>{{ t('mfa.s1') }}</li><li>{{ t('mfa.s2') }}</li><li>{{ t('mfa.s3') }}</li></ol>
          <div class="flex flex-col items-center gap-2">
            <img :src="qr" width="192" height="192" class="rounded border border-default bg-white" :alt="t('mfa.qr_alt')">
            <button type="button" class="font-mono text-xs tracking-wider text-muted hover:text-default" :title="t('common.copy')" @click="copy(secret)">{{ grouped }}</button>
          </div>
          <UFormField :label="t('mfa.code6')" required><UInput v-model="code" inputmode="numeric" maxlength="7" autocomplete="one-time-code" autofocus class="w-full font-mono" placeholder="123456" /></UFormField>
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="step = 'home'" /><UButton type="submit" :loading="busy" :disabled="code.replace(/\s/g, '').length !== 6" :label="t('mfa.activate')" /></div>
        </form>

        <template v-else-if="step === 'codes'">
          <UAlert color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="t('mfa.codes_title')" :description="t('mfa.codes_hint')" />
          <ul class="grid grid-cols-2 gap-x-6 gap-y-1 font-mono text-sm rounded border border-default p-3 bg-elevated/40"><li v-for="c in codes" :key="c">{{ c }}</li></ul>
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" icon="i-lucide-copy" :label="t('common.copy')" @click="copy(codes.join('\n'))" /><UButton :label="t('mfa.saved')" @click="step = 'home'" /></div>
        </template>

        <form v-else-if="step === 'disable'" class="flex flex-col gap-3" @submit.prevent="disable">
          <p class="text-sm text-muted">{{ t('mfa.disable_hint') }}</p>
          <UFormField :label="t('login.password')" required><UInput v-model="password" type="password" autocomplete="current-password" autofocus class="w-full" /></UFormField>
          <UFormField :label="t('mfa.code_or_recovery')" required><UInput v-model="code" autocomplete="one-time-code" class="w-full font-mono" /></UFormField>
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="step = 'home'" /><UButton type="submit" color="error" :loading="busy" :disabled="!password || !code" :label="t('mfa.disable')" /></div>
        </form>

        <form v-else-if="step === 'regen'" class="flex flex-col gap-3" @submit.prevent="regen">
          <p class="text-sm text-muted">{{ t('mfa.regen_hint') }}</p>
          <UFormField :label="t('login.password')" required><UInput v-model="password" type="password" autocomplete="current-password" autofocus class="w-full" /></UFormField>
          <div class="flex justify-end gap-2"><UButton color="neutral" variant="outline" :label="t('common.cancel')" @click="step = 'home'" /><UButton type="submit" :loading="busy" :disabled="!password" :label="t('mfa.regen')" /></div>
        </form>
      </div>
    </template>
  </UModal>
</template>
