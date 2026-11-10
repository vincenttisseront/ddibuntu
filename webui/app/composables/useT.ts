import fr from '~/i18n/fr'
import en from '~/i18n/en'

export function useT() {
  const lang = useCookie<'fr' | 'en'>('ddi_lang', { default: () => 'fr', sameSite: 'lax', maxAge: 60 * 60 * 24 * 365 })
  const dict = computed<Record<string, string>>(() => (lang.value === 'en' ? en : fr))
  const t = (key: string, params?: Record<string, string | number>): string => {
    let s = dict.value[key] ?? (fr as Record<string, string>)[key] ?? key
    if (params) for (const [k, v] of Object.entries(params)) s = s.split(`{${k}}`).join(String(v))
    return s
  }
  const setLang = (l: 'fr' | 'en') => { lang.value = l }
  return { t, lang, setLang }
}
