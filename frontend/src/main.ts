import { createApp, watch } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import enUs from 'element-plus/es/locale/lang/en'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import './style.css'
import App from './App.vue'
import i18n, { setI18nLanguage } from './i18n'
import router from './router'
import { useAppStore } from './stores/app'

const app = createApp(App)
const pinia = createPinia()
const appStore = useAppStore(pinia)

Object.entries(ElementPlusIconsVue).forEach(([key, component]) => {
	app.component(key, component)
})

watch(
	() => appStore.systemConfig.language,
	(language) => {
		setI18nLanguage(language)
	},
	{ immediate: true },
)

// Drop any stale theme override that earlier builds may have written
// into localStorage. The system theme is now fixed to the values defined
// in style.css; any inline overrides on documentElement are cleared so
// the page falls back to the stylesheet defaults.
localStorage.removeItem('modern-dns-theme-color')
;(['--app-accent', '--app-accent-soft', '--app-accent-muted'] as const).forEach((p) => {
	document.documentElement.style.removeProperty(p)
})

// ─────────────────────────────────────────────────────────────────────
// Global error handlers — mirror Modern-DHCP main.ts so unexpected
// frontend exceptions surface as user-visible toasts instead of dying
// silently in the console. The ResizeObserver noise filter exists
// because Chromium fires a benign "ResizeObserver loop completed with
// undelivered notifications" warning whenever any responsive layout
// flushes mid-frame; treating it as an error spams the toast queue.
// ─────────────────────────────────────────────────────────────────────
const isIgnorableGlobalError = (message?: string): boolean => {
	const text = (message || '').toLowerCase()
	return (
		text.includes('resizeobserver loop completed with undelivered notifications') ||
		text.includes('resizeobserver loop limit exceeded')
	)
}

window.addEventListener('error', (event) => {
	const message = String(event?.message || event?.error?.message || '')
	if (isIgnorableGlobalError(message)) return
	console.error('[GlobalError]', event.error || event.message)
	ElMessage.error('页面出现异常，请刷新重试')
})

window.addEventListener('unhandledrejection', (event) => {
	const reason = event.reason as { message?: string } | string | undefined
	const reasonMessage =
		typeof reason === 'string' ? reason : String(reason?.message || '')
	if (isIgnorableGlobalError(reasonMessage)) return
	console.error('[UnhandledRejection]', event.reason)
	// Many axios rejections are already shown by the response interceptor.
	// We intentionally do NOT toast here to avoid duplicate alerts; we
	// only log. Flip this back on if a class of rejection escapes the
	// interceptor.
})

// Pick the Element Plus locale bundle that matches our app i18n locale
// so DatePicker / Pagination / Form validation messages localise too.
const elLocale = i18n.global.locale.value === 'en-US' ? enUs : zhCn

app.use(ElementPlus, { locale: elLocale })
app.use(pinia)
app.use(i18n)
app.use(router)
app.mount('#app')
