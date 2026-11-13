<script setup lang="ts">
// Après la migration (0.12.7) : localisation des contrôleurs de domaine (SRV), gabarit GSS-TSIG, retrait des rôles Windows. Lecture seule / gabarits.
import { PS_RETIRE } from '~/utils/migration-scripts'
const { t } = useT(); const api = useApi(); const { canWrite } = useRole(); const toast = useToast()
const post = ref<any>(null), zones = ref<any[]>([]), zid = ref<number | null>(null), loc = ref<any>(null), err = ref(''), busy = ref('')
const gss = reactive({ zone: '', realm: '', out: '' })
try { post.value = await api.call('GET', '/migration/post', undefined, { silent: true }) } catch { /* lecture seule */ }
try { zones.value = ((await api.call('GET', '/dns/zones', undefined, { silent: true })) as any)?.items?.filter((z: any) => z.type === 'primary' && !z.name.endsWith('.arpa')) ?? [] } catch { /* ignore */ }
const KIND = computed<Record<string, string>>(() => ({ missing: t('mp.k_missing'), target_unresolved: t('mp.k_target'), bad_rdata: t('mp.k_bad') }))
async function check() {
  if (!zid.value) return
  busy.value = 'loc'; err.value = ''; loc.value = null
  try { loc.value = await api.call('GET', `/migration/post/locator?zone_id=${zid.value}`, undefined, { silent: true }) } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
async function tpl() {
  busy.value = 'gss'; err.value = ''; gss.out = ''
  try { gss.out = (await api.call('POST', '/migration/post/gss', { zone: gss.zone.trim(), realm: gss.realm.trim() }, { silent: true }) as any).template } catch (e: any) { err.value = e?.info?.message ?? t('err.internal') } finally { busy.value = '' }
}
const copy = async (s: string) => { try { await navigator.clipboard.writeText(s); toast.add({ title: t('mig.copied'), color: 'success' }) } catch { /* ignore */ } }
</script>

<template>
  <div class="flex flex-col gap-4 rounded-md bg-elevated/50 p-3" data-test="mp-root">
    <UAlert v-if="err" color="error" variant="subtle" icon="i-lucide-triangle-alert" :title="err" role="alert" />
    <div class="flex flex-col gap-2">
      <div class="font-medium text-sm">{{ t('mp.loc_title') }}</div>
      <p class="text-sm text-muted">{{ t('mp.loc_help') }}</p>
      <div class="flex flex-wrap gap-2 items-end">
        <USelect v-model="zid" :items="zones.map((z: any) => ({ label: z.name, value: z.id }))" :placeholder="t('mp.zone')" class="min-w-64" data-test="mp-zone" />
        <UButton icon="i-lucide-radar" :label="t('mp.check')" :loading="busy === 'loc'" :disabled="!zid" data-test="mp-check" @click="check" />
      </div>
      <template v-if="loc">
        <UAlert v-if="!loc.findings.length" color="success" variant="subtle" icon="i-lucide-circle-check" :title="t('mp.loc_ok', { n: loc.expected })" data-test="mp-ok" />
        <ul v-else class="flex flex-col gap-1" data-test="mp-list">
          <li v-for="(f, i) in loc.findings" :key="i" class="text-sm flex flex-wrap gap-2 rounded-md border border-default p-2"><UBadge color="warning" variant="subtle" :label="KIND[f.kind] ?? f.kind" /><span class="font-mono">{{ f.name }}</span><span class="font-mono text-muted">{{ f.detail }}</span></li>
        </ul>
      </template>
    </div>
    <div v-if="canWrite" class="flex flex-col gap-2">
      <div class="font-medium text-sm">{{ t('mp.gss_title') }}</div>
      <p class="text-sm text-muted">{{ t('mp.gss_help') }}</p>
      <div class="grid gap-3 md:grid-cols-2">
        <UFormField :label="t('mp.gss_zone')"><UInput v-model="gss.zone" class="w-full" placeholder="corp.example.com" data-test="mp-gzone" /></UFormField>
        <UFormField :label="t('mp.gss_realm')" :help="t('mp.gss_realm_h')"><UInput v-model="gss.realm" class="w-full" placeholder="CORP.EXAMPLE.COM" data-test="mp-realm" /></UFormField>
      </div>
      <div><UButton icon="i-lucide-file-cog" :label="t('mp.gss_gen')" :loading="busy === 'gss'" :disabled="!gss.zone.trim() || !gss.realm.trim()" data-test="mp-gen" @click="tpl" /></div>
      <template v-if="gss.out"><pre class="text-xs font-mono bg-elevated rounded-md p-3 overflow-x-auto" data-test="mp-tpl">{{ gss.out }}</pre><div><UButton size="xs" icon="i-lucide-copy" :label="t('mig.copy')" @click="copy(gss.out)" /></div></template>
    </div>
    <div class="flex flex-col gap-2">
      <div class="font-medium text-sm">{{ t('mp.ret_title') }}</div>
      <UAlert v-if="post && !post.cutoverFinished" color="warning" variant="subtle" icon="i-lucide-lock" :title="t('mp.ret_locked')" data-test="mp-locked" />
      <template v-else-if="post">
        <p class="text-sm text-muted">{{ t('mp.ret_help') }}</p>
        <pre class="text-xs font-mono bg-elevated rounded-md p-3 overflow-x-auto" data-test="mp-retire">{{ PS_RETIRE }}</pre>
        <div><UButton size="xs" icon="i-lucide-copy" :label="t('mig.copy')" @click="copy(PS_RETIRE)" /></div>
      </template>
    </div>
  </div>
</template>
