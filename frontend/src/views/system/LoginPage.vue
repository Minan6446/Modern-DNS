<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Lock, User } from '@element-plus/icons-vue'
import { useAppStore } from '../../stores/app'
import { loginByPassword, totpSetup, totpVerify } from '../../api/auth'
import { validateFormAndFocus } from '../../utils/interaction'
import BrandLogo from '../../components/BrandLogo.vue'

const { t } = useI18n()

const REMEMBER_KEY = 'modern-dns-remember-login'

const router = useRouter()
const route = useRoute()
const appStore = useAppStore()

const loading = ref(false)
const errorText = ref('')
const formRef = ref()

const loginForm = reactive({
  username: '',
  password: '',
  remember: false,
})

const loginRules = computed(() => ({
  username: [{ required: true, message: t('login.usernameRequired'), trigger: 'blur' }],
  password: [{ required: true, message: t('login.passwordRequired'), trigger: 'blur' }],
}))

const canSubmit = computed(
  () => Boolean(loginForm.username.trim() && loginForm.password.trim()) && !loading.value,
)

const rememberCurrentLogin = () => {
  if (loginForm.remember) {
    localStorage.setItem(
      REMEMBER_KEY,
      JSON.stringify({ username: loginForm.username, password: loginForm.password, remember: true }),
    )
    return
  }
  localStorage.removeItem(REMEMBER_KEY)
}

const loadRememberedLogin = () => {
  const raw = localStorage.getItem(REMEMBER_KEY)
  if (!raw) {
    return
  }
  try {
    const data = JSON.parse(raw)
    loginForm.username = data.username || ''
    loginForm.password = data.password || ''
    loginForm.remember = Boolean(data.remember)
  } catch (_error) {
    localStorage.removeItem(REMEMBER_KEY)
  }
}

// ── MFA enrolment wizard state ─────────────────────────────────────────
// idle  → username/password form
// verify → MFA block (after backend returned ENROLL_MFA + we ran setup)
type MfaStage = 'idle' | 'verify'
const mfaStage = ref<MfaStage>('idle')
const mfaEnrollToken = ref('')
const mfaSecret = ref('')
const mfaOtpAuth = ref('')
const mfaCode = ref('')
const mfaSubmitting = ref(false)

const resetMfaState = () => {
  mfaStage.value = 'idle'
  mfaEnrollToken.value = ''
  mfaSecret.value = ''
  mfaOtpAuth.value = ''
  mfaCode.value = ''
}

const navigateAfterLogin = async () => {
  const redirectPath = typeof route.query.redirect === 'string' ? route.query.redirect : '/dashboard/overview'
  await router.replace(redirectPath)
}

const handleLogin = async () => {
  errorText.value = ''
  const valid = await validateFormAndFocus(formRef.value)
  if (!valid) {
    return
  }

  loading.value = true
  try {
    const result = await loginByPassword({
      username: loginForm.username.trim(),
      password: loginForm.password,
    })

    if (result.code !== 0) {
      errorText.value = result.message || t('login.loginFailed')
      return
    }

    // Branch 1: backend demands MFA enrolment before issuing real tokens.
    if (result.data && 'action' in result.data && result.data.action === 'ENROLL_MFA') {
      // Re-cast inside the branch — TS doesn't narrow optional discriminants
      // through `'action' in obj` reliably across union members.
      const enroll = result.data as { action: 'ENROLL_MFA'; enrollToken: string }
      mfaEnrollToken.value = enroll.enrollToken
      const setup = await totpSetup(mfaEnrollToken.value)
      if (setup.code !== 0 || !setup.data) {
        errorText.value = setup.message || t('login.mfaSetupFailed')
        resetMfaState()
        return
      }
      mfaSecret.value = setup.data.secret
      mfaOtpAuth.value = setup.data.otpauth
      mfaStage.value = 'verify'
      return
    }

    // Branch 2: normal login.
    if (result.data && 'token' in result.data) {
      appStore.login(result.data)
      rememberCurrentLogin()
      ElMessage.success(t('login.loginSuccess'))
      await navigateAfterLogin()
    }
  } catch (_error) {
    errorText.value = t('login.loginFailed')
  } finally {
    loading.value = false
  }
}

const submitMfaCode = async () => {
  errorText.value = ''
  const code = mfaCode.value.trim()
  if (!/^\d{6}$/.test(code)) {
    errorText.value = t('login.mfaCodeInvalid')
    return
  }
  mfaSubmitting.value = true
  try {
    const r = await totpVerify(mfaEnrollToken.value, code)
    if (r.code !== 0 || !r.data?.token || !r.data?.user) {
      errorText.value = r.message || t('login.mfaVerifyFailed')
      return
    }
    appStore.login({ token: r.data.token, user: r.data.user })
    rememberCurrentLogin()
    ElMessage.success(t('login.mfaEnrolled'))
    resetMfaState()
    await navigateAfterLogin()
  } catch (_error) {
    errorText.value = t('login.mfaVerifyFailed')
  } finally {
    mfaSubmitting.value = false
  }
}

const cancelMfa = () => {
  resetMfaState()
  loginForm.password = ''
}

const copySecret = async () => {
  try {
    await navigator.clipboard.writeText(mfaSecret.value)
    ElMessage.success(t('common.copied'))
  } catch {
    ElMessage.error(t('login.mfaCopyFailed'))
  }
}

onMounted(() => {
  loadRememberedLogin()
})
</script>

<template>
  <!-- Single-card layout aligned with the Modern-DHCP login page:
       a dark navy gradient backdrop with a subtle topology grid +
       radial glows behind a centred white card. The DNS-specific
       MFA enrolment wizard is rendered inline inside the same card
       (it replaces the username/password form) so the visual
       container stays consistent across both stages. -->
  <div class="login-page">
    <div class="bg-topology" aria-hidden="true"></div>
    <div class="bg-orb orb-a" aria-hidden="true"></div>
    <div class="bg-orb orb-b" aria-hidden="true"></div>

    <div class="login-card">
      <div class="brand-section">
        <BrandLogo :size="40" solid class="brand-img" />
        <div class="brand-text">
          <div class="title-row">
            <h1 class="app-title">Modern DNS</h1>
          </div>
          <p class="app-subtitle">{{ $t('login.subtitle') }}</p>
        </div>
      </div>

      <div class="form-title">
        {{ mfaStage === 'verify' ? $t('login.mfaTitle') : $t('login.welcome') }}
      </div>

      <el-alert
        v-if="errorText"
        class="top-error"
        type="error"
        :closable="false"
        show-icon
        :title="errorText"
      />

      <!-- ── MFA enrolment wizard ────────────────────────────────────
           Shown only after the backend returns ENROLL_MFA. Replaces
           the username/password form so the operator focuses on the
           bind. Same card chrome, same input styling. -->
      <div v-if="mfaStage === 'verify'" class="mfa-wizard">
        <p class="mfa-intro">{{ $t('login.mfaIntro') }}</p>

        <div class="mfa-secret-row">
          <span class="mfa-secret-label">{{ $t('login.mfaSecret') }}</span>
          <code class="mfa-secret-value">{{ mfaSecret }}</code>
          <el-button plain type="primary" size="small" @click="copySecret">
            {{ $t('common.copy') }}
          </el-button>
        </div>

        <a class="mfa-otpauth-link" :href="mfaOtpAuth">
          {{ $t('login.mfaOpenLink') }}
        </a>

        <el-input
          v-model="mfaCode"
          :placeholder="$t('login.mfaCodePlaceholder')"
          maxlength="6"
          class="mfa-code-input"
          @keyup.enter="submitMfaCode"
        />

        <el-button
          class="login-btn"
          type="primary"
          :loading="mfaSubmitting"
          :disabled="mfaCode.trim().length !== 6"
          @click="submitMfaCode"
        >
          {{ $t('login.mfaVerify') }}
        </el-button>

        <el-button
          text
          class="mfa-cancel"
          :disabled="mfaSubmitting"
          @click="cancelMfa"
        >
          {{ $t('login.mfaCancel') }}
        </el-button>
      </div>

      <el-form
        v-else
        ref="formRef"
        :model="loginForm"
        :rules="loginRules"
        label-position="top"
        hide-required-asterisk
        class="login-form"
        :disabled="loading"
        @keyup.enter="canSubmit && handleLogin()"
      >
        <el-form-item :label="$t('login.username')" prop="username">
          <el-input
            v-model.trim="loginForm.username"
            autocomplete="username"
            clearable
            :prefix-icon="User"
            :placeholder="$t('login.usernameRequired')"
            tabindex="1"
          />
        </el-form-item>

        <el-form-item :label="$t('login.password')" prop="password">
          <el-input
            v-model="loginForm.password"
            show-password
            autocomplete="current-password"
            :prefix-icon="Lock"
            :placeholder="$t('login.passwordRequired')"
            tabindex="2"
          />
        </el-form-item>

        <div class="form-actions">
          <el-checkbox v-model="loginForm.remember" :disabled="loading" tabindex="3">
            {{ $t('login.rememberMe') }}
          </el-checkbox>
        </div>

        <el-button
          class="login-btn"
          type="primary"
          :loading="loading"
          :disabled="!canSubmit"
          tabindex="4"
          @click="handleLogin"
        >
          {{ loading ? $t('login.loggingIn') : $t('login.login') }}
        </el-button>
      </el-form>

      <div class="footer">
        <div class="support">
          {{ $t('login.techSupport') }}：
          <a href="mailto:minan959@163.com">minan959@163.com</a>
        </div>
        <div class="copyright">{{ $t('login.copyright') }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* ════════════════════════════════════════════════════════════════════
   Login page — visually aligned with Modern-DHCP's auth/Login.vue.
   Structure: dark-navy gradient page → topology grid + glow orbs →
   centred 400px white card holding brand row, form-title, alert,
   form (or MFA wizard), footer.
   Tokens are duplicated locally (instead of pulled from style.css)
   on purpose: the login page is the single screen that runs *before*
   the app theme/tokens cascade is meaningful, so keeping it
   self-contained makes accidental token drift impossible. */
.login-page {
  --card-bg: rgba(255, 255, 255, 0.96);
  --card-border: rgba(255, 255, 255, 0.5);
  --title: #0f172a;
  --subtitle: #64748b;
  --line: #e2e8f0;
  --text: #334155;
  --muted: #94a3b8;
  --input-bg: #ffffff;
  --input-border: #d0d7e2;
  --input-hover: #7aa7ff;
  --input-focus: #165dff;
  --primary: #165dff;
  --primary-hover: #3b82f6;
  --primary-active: #0f4eea;
  min-height: 100vh;
  width: 100%;
  display: grid;
  place-items: center;
  padding: 24px;
  position: relative;
  overflow: hidden;
  background: linear-gradient(145deg, #162d70 0%, #0f172a 100%);
}

/* Subtle 26×26 grid + two radial glows behind the card. The grid sells
   the "network topology" feel without distracting from the form. */
.bg-topology {
  position: absolute;
  inset: 0;
  background-image:
    radial-gradient(circle at 20% 20%, rgba(125, 211, 252, 0.14), transparent 26%),
    radial-gradient(circle at 80% 70%, rgba(59, 130, 246, 0.12), transparent 30%),
    linear-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.04) 1px, transparent 1px);
  background-size: auto, auto, 26px 26px, 26px 26px;
  opacity: 0.45;
  pointer-events: none;
}

.bg-orb {
  position: absolute;
  border-radius: 999px;
  filter: blur(60px);
  opacity: 0.22;
  pointer-events: none;
}

.orb-a { width: 280px; height: 280px; background: #7dd3fc; top: 8%;     left: 10%; }
.orb-b { width: 220px; height: 220px; background: #93c5fd; bottom: 10%; right: 10%; }

/* ── Card ── */
.login-card {
  width: 400px;
  max-width: calc(100vw - 32px);
  border-radius: 8px;
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  box-shadow: 0 10px 30px rgba(7, 18, 44, 0.32);
  padding: 32px 24px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  position: relative;
  z-index: 1;
}

.brand-section {
  display: flex;
  align-items: center;
  gap: 12px;
}

/* BrandLogo paints its own dark rounded backdrop via :solid, so we
   don't add extra shadows/borders here — keeps the mark crisp. */
.brand-img {
  flex-shrink: 0;
}

.brand-text {
  flex: 1;
  min-width: 0;
}

.title-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.app-title {
  margin: 0;
  font-size: 22px;
  line-height: 30px;
  color: var(--title);
  font-weight: 700;
}

.app-subtitle {
  margin: 0;
  font-size: 14px;
  line-height: 20px;
  color: var(--subtitle);
}

.form-title {
  font-size: 16px;
  line-height: 24px;
  font-weight: 600;
  color: var(--title);
}

.top-error {
  margin-bottom: 4px;
}

/* ── Form ── */
.login-form {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.login-form :deep(.el-form-item) {
  margin-bottom: 8px;
}

.login-form :deep(.el-form-item__label) {
  color: var(--text);
  line-height: 20px;
  margin-bottom: 4px;
}

.login-form :deep(.el-input__wrapper),
.mfa-code-input :deep(.el-input__wrapper) {
  border-radius: 4px;
  min-height: 36px;
  background: var(--input-bg);
  box-shadow: 0 0 0 1px var(--input-border) inset;
  transition: box-shadow 0.2s ease, background 0.2s ease;
}

.login-form :deep(.el-input__wrapper:hover),
.mfa-code-input :deep(.el-input__wrapper:hover) {
  box-shadow: 0 0 0 1px var(--input-hover) inset;
}

.login-form :deep(.el-input__wrapper.is-focus),
.mfa-code-input :deep(.el-input__wrapper.is-focus) {
  box-shadow: 0 0 0 2px color-mix(in oklab, var(--input-focus) 30%, transparent) inset;
}

.login-form :deep(.el-input.is-disabled .el-input__wrapper) {
  opacity: 0.7;
  cursor: not-allowed;
}

.login-form :deep(.el-form-item.is-error .el-input__wrapper) {
  box-shadow: 0 0 0 2px #f53f3f inset;
}

.form-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 4px;
}

/* ── Login button ── */
.login-btn {
  width: 100%;
  height: 36px;
  border-radius: 4px;
  border-color: var(--primary);
  background: var(--primary);
  color: #fff;
  font-weight: 600;
  margin-top: 4px;
}

.login-btn:not(:disabled):hover {
  border-color: var(--primary-hover);
  background: var(--primary-hover);
}

.login-btn:not(:disabled):active {
  border-color: var(--primary-active);
  background: var(--primary-active);
}

.login-btn.is-disabled,
.login-btn:disabled {
  opacity: 0.55;
}

/* ── Footer ── */
.footer {
  margin-top: 8px;
  padding-top: 16px;
  border-top: 1px solid var(--line);
  display: flex;
  flex-direction: column;
  gap: 4px;
  text-align: center;
}

.support {
  font-size: 12px;
  color: var(--text);
}

.support a {
  color: var(--primary);
  text-decoration: none;
}

.support a:hover {
  text-decoration: underline;
}

.copyright {
  font-size: 12px;
  color: var(--muted);
}

/* ── MFA enrolment wizard ── */
.mfa-wizard {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.mfa-intro {
  margin: 0;
  font-size: 13px;
  color: var(--text);
  line-height: 1.55;
}

.mfa-secret-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  background: #f1f5f9;
  border: 1px solid var(--line);
  border-radius: 6px;
}

.mfa-secret-label {
  font-size: 12px;
  color: var(--subtitle);
  flex-shrink: 0;
}

.mfa-secret-value {
  flex: 1;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 13px;
  font-weight: 600;
  color: var(--title);
  word-break: break-all;
  letter-spacing: 0.5px;
}

.mfa-otpauth-link {
  display: inline-block;
  font-size: 12px;
  color: var(--primary);
  text-decoration: none;
  word-break: break-all;
  padding: 8px 12px;
  background: rgba(22, 93, 255, 0.06);
  border: 1px dashed rgba(22, 93, 255, 0.3);
  border-radius: 6px;
}

.mfa-otpauth-link:hover {
  background: rgba(22, 93, 255, 0.1);
}

.mfa-code-input :deep(.el-input__inner) {
  letter-spacing: 8px;
  text-align: center;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  font-size: 18px;
  font-weight: 600;
}

.mfa-cancel {
  align-self: center;
  font-size: 13px;
  color: var(--subtitle);
  margin-top: -4px;
}

/* ── Responsive ── */
@media (max-width: 520px) {
  .login-page {
    padding: 12px;
  }

  .login-card {
    width: 100%;
    padding: 24px 18px;
  }

  .form-actions {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
}
</style>

