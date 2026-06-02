<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import EmailTab from '../../components/notification/EmailTab.vue'
import SmsTab from '../../components/notification/SmsTab.vue'
import WebhookTab from '../../components/notification/WebhookTab.vue'
import ChatBotTab from '../../components/notification/ChatBotTab.vue'
import VoiceTab from '../../components/notification/VoiceTab.vue'
import NoticeTemplateDrawer from '../../components/notification/NoticeTemplateDrawer.vue'
import {
  getNotificationConfigApi,
  testNotificationChannelApi,
  updateNotificationChannelApi,
} from '../../api/notification'
import type { NotificationChannel, NotificationConfig, NotificationTabExpose } from '../../types/notification'
import { NOTIFICATION_CHANNELS, createDefaultNotificationConfig } from '../../types/notification'

const { t } = useI18n()
const activeChannel = ref<NotificationChannel>('email')
const pageLoading = ref(false)
const savingChannel = ref<NotificationChannel | null>(null)
const testingChannel = ref<NotificationChannel | null>(null)
const notificationForm = reactive<NotificationConfig>(createDefaultNotificationConfig())

const emailTabRef = ref<NotificationTabExpose>()
const webhookTabRef = ref<NotificationTabExpose>()
const smsTabRef = ref<NotificationTabExpose>()
const dingtalkTabRef = ref<NotificationTabExpose>()
const feishuTabRef = ref<NotificationTabExpose>()
const wecomTabRef = ref<NotificationTabExpose>()
const slackTabRef = ref<NotificationTabExpose>()
const voiceTabRef = ref<NotificationTabExpose>()

const channelTitleMap = computed<Record<NotificationChannel, string>>(() => ({
  email: t('notice.channelEmail'),
  webhook: t('notice.webhook'),
  sms: t('notice.channelSms'),
  dingtalk: t('notice.dingtalk.tabLabel'),
  feishu: t('notice.feishu.tabLabel'),
  wecom: t('notice.wecom.tabLabel'),
  slack: t('notice.slack.tabLabel'),
  voice: t('notice.voice.tabLabel'),
}))

const channelRefMap: Record<NotificationChannel, typeof emailTabRef> = {
  email: emailTabRef,
  webhook: webhookTabRef,
  sms: smsTabRef,
  dingtalk: dingtalkTabRef,
  feishu: feishuTabRef,
  wecom: wecomTabRef,
  slack: slackTabRef,
  voice: voiceTabRef,
}

// assignConfig copies the server-side payload back into the reactive
// form. Iterating the channel list rather than naming fields means a
// future channel only needs an entry in NOTIFICATION_CHANNELS plus the
// matching tab — no risk of forgetting the assign step.
const assignConfig = (payload: NotificationConfig): void => {
  for (const ch of NOTIFICATION_CHANNELS) {
    Object.assign(notificationForm[ch] as object, payload[ch] as object)
  }
}

const getChannelDisabled = (channel: NotificationChannel): boolean => !notificationForm[channel].enabled

const validateChannel = async (channel: NotificationChannel): Promise<boolean> => {
  if (getChannelDisabled(channel)) {
    return true
  }
  return channelRefMap[channel].value?.validate() ?? false
}

const loadNotificationConfig = async (): Promise<void> => {
  pageLoading.value = true
  try {
    const { data } = await getNotificationConfigApi()
    assignConfig(data)
    // Test recipients are transient input for "send test" only.
    // Never hydrate historical values from persisted config.
    notificationForm.email.receivers = ''
  } catch (_error) {
    ElMessage.error(t('notice.configLoadFailed'))
  } finally {
    pageLoading.value = false
  }
}

const saveChannel = async (channel: NotificationChannel): Promise<void> => {
  if (savingChannel.value || testingChannel.value) {
    return
  }
  const valid = await validateChannel(channel)
  if (!valid) {
    return
  }
  savingChannel.value = channel
  try {
    const payload = channel === 'email'
      ? { ...notificationForm.email, receivers: '' }
      : notificationForm[channel]
    const { data } = await updateNotificationChannelApi(channel, payload as any)
    assignConfig(data)
    if (channel === 'email') {
      notificationForm.email.receivers = ''
    }
    ElMessage.success(t('notice.configUpdated', { channel: channelTitleMap.value[channel] }))
  } catch (_error) {
    ElMessage.error(t('notice.configUpdateFailed', { channel: channelTitleMap.value[channel] }))
  } finally {
    savingChannel.value = null
  }
}

const testChannel = async (channel: NotificationChannel): Promise<void> => {
  if (testingChannel.value || savingChannel.value || getChannelDisabled(channel)) {
    return
  }
  const valid = await validateChannel(channel)
  if (!valid) {
    return
  }
  testingChannel.value = channel
  try {
    const { data } = await testNotificationChannelApi(channel, notificationForm[channel])
    ElMessage.success(data.message)
  } catch (_error) {
    ElMessage.error(t('notice.testFailed', { channel: channelTitleMap.value[channel] }))
  } finally {
    if (channel === 'email') {
      notificationForm.email.receivers = ''
      emailTabRef.value?.clearValidate()
    }
    testingChannel.value = null
  }
}

// enabledCount tallies every channel that has its `enabled` switch on.
// Iterating NOTIFICATION_CHANNELS (the canonical list) keeps the count
// honest as channels are added — earlier this was a hard-coded
// ['email','webhook','sms'] which would have under-reported once the
// chat-platform tabs landed.
const enabledCount = computed(() =>
  NOTIFICATION_CHANNELS.filter((ch) => notificationForm[ch].enabled).length,
)
const totalChannels = NOTIFICATION_CHANNELS.length

// Per-channel metadata for the stats strip above the tabs. Listed in
// display order so the cards mirror the tabs below 1:1 — the previous
// hard-coded 3-card strip (email / webhook / sms) plus a single
// 1-of-N summary diverged once chat-platform tabs (dingtalk / feishu /
// wecom / slack / voice) landed: 3 cards on top, 8 tabs below.
// SVG paths use a shared 24x24 viewBox so the template can stay simple.
interface ChannelStatMeta {
  code: NotificationChannel
  labelKey: string
  accent: NotificationChannel
  iconPath: string
}
const CHANNEL_STATS_META: ReadonlyArray<ChannelStatMeta> = [
  {
    code: 'email',
    labelKey: 'notice.emailAlert',
    accent: 'email',
    iconPath:
      'M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z',
  },
  {
    code: 'webhook',
    labelKey: 'notice.webhook',
    accent: 'webhook',
    iconPath:
      'M13.5 2c-5.62 0-10.19 4.27-10.48 9.82L1 9.8v4.49l5.26-3.6-5.26-3.64v2.52C1.26 6.88 6.89 2.75 13.5 2.75c5.52 0 10.16 3.57 11.89 8.6l.85-.61A12.73 12.73 0 0 0 13.5 2zM22 9.71l-5.26 3.6 5.26 3.64v-2.52C21.74 17.12 16.11 21.25 9.5 21.25c-5.52 0-10.16-3.57-11.89-8.6l-.85.61A12.73 12.73 0 0 0 9.5 22c5.62 0 10.19-4.27 10.48-9.82L22 14.2V9.71z',
  },
  {
    code: 'sms',
    labelKey: 'notice.smsAlert',
    accent: 'sms',
    iconPath:
      'M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z',
  },
  {
    code: 'dingtalk',
    labelKey: 'notice.dingtalk.tabLabel',
    accent: 'dingtalk',
    iconPath:
      'M12 2A10 10 0 1 0 22 12 10 10 0 0 0 12 2zm4.41 9.62-1.06 4.55c-.13.55-.66.91-1.22.78l-.93-.21.74-1.32-2.27.36 2.27-3.83-3.59.61c.99-1.65 2.85-2.69 4.86-2.69h.05c.81 0 1.43.74 1.15 1.75z',
  },
  {
    code: 'feishu',
    labelKey: 'notice.feishu.tabLabel',
    accent: 'feishu',
    iconPath:
      'M2.01 21 23 12 2.01 3 2 10l15 2-15 2z',
  },
  {
    code: 'wecom',
    labelKey: 'notice.wecom.tabLabel',
    accent: 'wecom',
    iconPath:
      'M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z',
  },
  {
    code: 'slack',
    labelKey: 'notice.slack.tabLabel',
    accent: 'slack',
    iconPath:
      'M6 15a2 2 0 1 1-2-2h2v2zm1 0a2 2 0 1 1 4 0v5a2 2 0 1 1-4 0v-5zm2-10a2 2 0 1 1 2-2v2H9zm0 1a2 2 0 1 1 0 4H4a2 2 0 1 1 0-4h5zm10 4a2 2 0 1 1 2 2h-2V8zm-1 0a2 2 0 1 1-4 0V3a2 2 0 1 1 4 0v5zm-2 11a2 2 0 1 1-2 2v-2h2zm0-1a2 2 0 1 1 0-4h5a2 2 0 1 1 0 4h-5z',
  },
  {
    code: 'voice',
    labelKey: 'notice.voice.tabLabel',
    accent: 'voice',
    iconPath:
      'M20.01 15.38c-1.23 0-2.42-.2-3.53-.56a.977.977 0 0 0-1.01.24l-1.57 1.97c-2.83-1.35-5.48-3.9-6.89-6.83l1.95-1.66c.27-.28.35-.67.24-1.02-.37-1.11-.56-2.3-.56-3.53 0-.54-.45-.99-.99-.99H4.19C3.65 3 3 3.24 3 3.99 3 13.28 10.73 21 20.01 21c.71 0 .99-.63.99-1.18v-3.45c0-.54-.45-.99-.99-.99z',
  },
]

// Template editor drawer. Lives next to the channel-config tabs but
// has its own opening trigger in the page header so operators don't
// confuse "edit channel credentials" with "edit message template".
const templateDrawerOpen = ref(false)
const openTemplateDrawer = () => {
  templateDrawerOpen.value = true
}

onMounted(() => {
  loadNotificationConfig()
})
</script>

<template>
  <div class="notification-page page-shell" v-loading="pageLoading">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ $t('notice.title') }}</h1>
        <p class="page-subtitle">
          {{ $t('notice.subtitle') }}
          <span class="page-subtitle-divider">·</span>
          <span class="page-subtitle-count">
            {{ $t('notice.enabledChannels') }}
            <strong>{{ enabledCount }}</strong> / {{ totalChannels }}
          </span>
        </p>
      </div>
      <div class="page-header-actions">
        <el-button type="primary" plain @click="openTemplateDrawer">
          <svg viewBox="0 0 24 24" fill="currentColor" width="14" height="14" style="margin-right:6px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z" /></svg>
          {{ $t('noticeTemplate.openButton') }}
        </el-button>
      </div>
    </div>

    <!-- ═══ Stats strip ═══
         8 cards, one per channel, mirroring the tab order below.
         Driven by CHANNEL_STATS_META so adding a 9th channel only
         requires a new entry there + a matching tab pane. -->
    <div class="nt-stats">
      <div
        v-for="meta in CHANNEL_STATS_META"
        :key="meta.code"
        class="nt-stat"
        :class="{ 'nt-stat--off': !notificationForm[meta.code].enabled }"
      >
        <div class="nt-stat-icon" :class="`nt-stat-icon-${meta.accent}`">
          <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
            <path :d="meta.iconPath" />
          </svg>
        </div>
        <div class="nt-stat-body">
          <div class="nt-stat-label">{{ $t(meta.labelKey) }}</div>
          <div class="nt-stat-value">
            <span class="nt-dot" :class="notificationForm[meta.code].enabled ? 'is-on' : 'is-off'" />
            {{ notificationForm[meta.code].enabled ? $t('notice.enabled') : $t('notice.disabled') }}
          </div>
        </div>
      </div>
    </div>

    <!-- ═══ Tabs card ═══ -->
    <el-card class="nt-main-card" shadow="never">
      <el-tabs v-model="activeChannel" class="nt-tabs">

        <el-tab-pane name="email">
          <template #label>
            <span class="nt-tab-label">
              <svg class="nt-tab-icon" viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z" /></svg>
              {{ $t('notice.emailAlert') }}
              <span class="nt-tab-dot" :class="notificationForm.email.enabled ? 'is-on' : 'is-off'" />
            </span>
          </template>
          <EmailTab
            ref="emailTabRef"
            :model="notificationForm.email"
            :loading="savingChannel === 'email' || testingChannel === 'email'"
            :disabled="!notificationForm.email.enabled"
            @test="testChannel('email')"
            @save="saveChannel('email')"
          />
        </el-tab-pane>

        <el-tab-pane name="webhook">
          <template #label>
            <span class="nt-tab-label">
              <svg class="nt-tab-icon" viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M13.5 2c-5.62 0-10.19 4.27-10.48 9.82L1 9.8v4.49l5.26-3.6-5.26-3.64v2.52C1.26 6.88 6.89 2.75 13.5 2.75c5.52 0 10.16 3.57 11.89 8.6l.85-.61A12.73 12.73 0 0 0 13.5 2zM22 9.71l-5.26 3.6 5.26 3.64v-2.52C21.74 17.12 16.11 21.25 9.5 21.25c-5.52 0-10.16-3.57-11.89-8.6l-.85.61A12.73 12.73 0 0 0 9.5 22c5.62 0 10.19-4.27 10.48-9.82L22 14.2V9.71z" /></svg>
              {{ $t('notice.webhook') }}
              <span class="nt-tab-dot" :class="notificationForm.webhook.enabled ? 'is-on' : 'is-off'" />
            </span>
          </template>
          <WebhookTab
            ref="webhookTabRef"
            :model="notificationForm.webhook"
            :loading="savingChannel === 'webhook' || testingChannel === 'webhook'"
            :disabled="!notificationForm.webhook.enabled"
            @test="testChannel('webhook')"
            @save="saveChannel('webhook')"
          />
        </el-tab-pane>

        <el-tab-pane name="sms">
          <template #label>
            <span class="nt-tab-label">
              <svg class="nt-tab-icon" viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z" /></svg>
              {{ $t('notice.smsAlert') }}
              <span class="nt-tab-dot" :class="notificationForm.sms.enabled ? 'is-on' : 'is-off'" />
            </span>
          </template>
          <SmsTab
            ref="smsTabRef"
            :model="notificationForm.sms"
            :loading="savingChannel === 'sms' || testingChannel === 'sms'"
            :disabled="!notificationForm.sms.enabled"
            @test="testChannel('sms')"
            @save="saveChannel('sms')"
          />
        </el-tab-pane>

        <!-- DingTalk / Feishu / WeCom / Slack share ChatBotTab through
             the `platform` prop. Each tab still owns its own ref so
             form-level validation triggers in isolation. -->
        <el-tab-pane name="dingtalk">
          <template #label>
            <span class="nt-tab-label">
              <svg class="nt-tab-icon" viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z" /></svg>
              {{ $t('notice.dingtalk.tabLabel') }}
              <span class="nt-tab-dot" :class="notificationForm.dingtalk.enabled ? 'is-on' : 'is-off'" />
            </span>
          </template>
          <ChatBotTab
            ref="dingtalkTabRef"
            platform="dingtalk"
            :model="notificationForm.dingtalk"
            :loading="savingChannel === 'dingtalk' || testingChannel === 'dingtalk'"
            :disabled="!notificationForm.dingtalk.enabled"
            @test="testChannel('dingtalk')"
            @save="saveChannel('dingtalk')"
          />
        </el-tab-pane>

        <el-tab-pane name="feishu">
          <template #label>
            <span class="nt-tab-label">
              <svg class="nt-tab-icon" viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z" /></svg>
              {{ $t('notice.feishu.tabLabel') }}
              <span class="nt-tab-dot" :class="notificationForm.feishu.enabled ? 'is-on' : 'is-off'" />
            </span>
          </template>
          <ChatBotTab
            ref="feishuTabRef"
            platform="feishu"
            :model="notificationForm.feishu"
            :loading="savingChannel === 'feishu' || testingChannel === 'feishu'"
            :disabled="!notificationForm.feishu.enabled"
            @test="testChannel('feishu')"
            @save="saveChannel('feishu')"
          />
        </el-tab-pane>

        <el-tab-pane name="wecom">
          <template #label>
            <span class="nt-tab-label">
              <svg class="nt-tab-icon" viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z" /></svg>
              {{ $t('notice.wecom.tabLabel') }}
              <span class="nt-tab-dot" :class="notificationForm.wecom.enabled ? 'is-on' : 'is-off'" />
            </span>
          </template>
          <ChatBotTab
            ref="wecomTabRef"
            platform="wecom"
            :model="notificationForm.wecom"
            :loading="savingChannel === 'wecom' || testingChannel === 'wecom'"
            :disabled="!notificationForm.wecom.enabled"
            @test="testChannel('wecom')"
            @save="saveChannel('wecom')"
          />
        </el-tab-pane>

        <el-tab-pane name="slack">
          <template #label>
            <span class="nt-tab-label">
              <svg class="nt-tab-icon" viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z" /></svg>
              {{ $t('notice.slack.tabLabel') }}
              <span class="nt-tab-dot" :class="notificationForm.slack.enabled ? 'is-on' : 'is-off'" />
            </span>
          </template>
          <ChatBotTab
            ref="slackTabRef"
            platform="slack"
            :model="notificationForm.slack"
            :loading="savingChannel === 'slack' || testingChannel === 'slack'"
            :disabled="!notificationForm.slack.enabled"
            @test="testChannel('slack')"
            @save="saveChannel('slack')"
          />
        </el-tab-pane>

        <el-tab-pane name="voice">
          <template #label>
            <span class="nt-tab-label">
              <svg class="nt-tab-icon" viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M6.62 10.79a15.05 15.05 0 0 0 6.59 6.59l2.2-2.2a1 1 0 0 1 1.05-.24c1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20a1 1 0 0 1-1 1A17 17 0 0 1 3 4a1 1 0 0 1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z"/></svg>
              {{ $t('notice.voice.tabLabel') }}
              <span class="nt-tab-dot" :class="notificationForm.voice.enabled ? 'is-on' : 'is-off'" />
            </span>
          </template>
          <VoiceTab
            ref="voiceTabRef"
            :model="notificationForm.voice"
            :loading="savingChannel === 'voice' || testingChannel === 'voice'"
            :disabled="!notificationForm.voice.enabled"
            @test="testChannel('voice')"
            @save="saveChannel('voice')"
          />
        </el-tab-pane>

      </el-tabs>
    </el-card>

    <NoticeTemplateDrawer v-model="templateDrawerOpen" />
  </div>
</template>

<style scoped>
/* ═══════════════ Page ═══════════════ */
.notification-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.notification-page :deep(.el-card__body) {
  padding: 0;
}

/* ═══════════════ Stats strip ═══════════════ */
.nt-stats {
  display: grid;
  /* 4 columns × 2 rows on desktop → 8 cards mirroring the 8 tabs.
     Auto-flow keeps the layout intact even if a channel is added
     or temporarily hidden. */
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

/* Disabled-channel cards desaturate slightly to make the enabled
   ones "pop" — the bottom tabs already show enabled-state via the
   coloured dot, so we mirror that visual hierarchy here. */
.nt-stat--off {
  background: var(--app-bg-secondary);
}
.nt-stat--off .nt-stat-icon {
  filter: grayscale(0.35);
  opacity: 0.85;
}
.nt-stat--off .nt-stat-label {
  color: var(--app-text-secondary);
}

.nt-stat {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 16px 20px;
  background: var(--app-bg-secondary);
  border: 1px solid var(--app-border);
  border-radius: 10px;
  box-shadow: var(--app-shadow-soft);
  transition: box-shadow 0.2s, transform 0.2s;
}

.nt-stat:hover {
  box-shadow: 0 6px 18px rgba(22, 93, 255, 0.12);
  transform: translateY(-1px);
}

.nt-stat-icon {
  width: 44px;
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 10px;
  flex-shrink: 0;
}

/* Per-channel icon tints — each card gets a brand-flavoured
   12% background + the brand colour for the glyph. The chat
   platforms reuse their public brand colours so users orient by
   colour not just label. */
.nt-stat-icon-email    { background: var(--app-accent-soft);          color: var(--app-accent); }
.nt-stat-icon-webhook  { background: rgba(114, 46, 209, 0.10);        color: #722ED1; }
.nt-stat-icon-sms      { background: rgba(255, 125, 0, 0.10);         color: var(--app-warning); }
.nt-stat-icon-dingtalk { background: rgba(18, 150, 219, 0.12);        color: #1296DB; }
.nt-stat-icon-feishu   { background: rgba(0, 214, 185, 0.14);         color: #00B5A0; }
.nt-stat-icon-wecom    { background: rgba(7, 193, 96, 0.12);          color: #07C160; }
.nt-stat-icon-slack    { background: rgba(74, 21, 75, 0.10);          color: #4A154B; }
.nt-stat-icon-voice    { background: rgba(245, 63, 63, 0.10);         color: var(--app-danger); }

.nt-stat-body {
  flex: 1;
  min-width: 0;
}

.nt-stat-label {
  font-size: 12px;
  color: var(--app-text-regular);
  margin-bottom: 4px;
}

.nt-stat-value {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 600;
  color: var(--app-title);
}

.nt-stat-value-num {
  font-size: 22px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}

.nt-stat-value-unit {
  font-size: 13px;
  font-weight: 400;
  color: var(--app-text-regular);
}

.nt-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}

.nt-dot.is-on {
  background: var(--app-success);
  box-shadow: 0 0 0 3px rgba(0, 180, 42, 0.18);
}

.nt-dot.is-off {
  background: var(--app-disabled);
}

/* ═══════════════ Main card & tabs ═══════════════ */
.nt-main-card {
  overflow: hidden;
}

.nt-tabs :deep(.el-tabs__header) {
  margin: 0;
  padding: 0 20px;
  background: var(--app-bg-secondary);
  border-bottom: 1px solid var(--app-border);
}

.nt-tabs :deep(.el-tabs__nav-wrap::after) {
  display: none;
}

.nt-tabs :deep(.el-tabs__item) {
  font-size: 14px;
  height: 48px;
  line-height: 48px;
  padding: 0 20px !important;
}

.nt-tabs :deep(.el-tabs__content) {
  padding: 24px;
}

.nt-tab-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  font-weight: 500;
}

.nt-tab-icon {
  flex-shrink: 0;
}

.nt-tab-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}

.nt-tab-dot.is-on {
  background: var(--app-success);
  box-shadow: 0 0 0 2px rgba(0, 180, 42, 0.2);
}

.nt-tab-dot.is-off {
  background: var(--app-disabled);
}

/* ═══════════════ Responsive ═══════════════ */
@media (max-width: 1280px) {
  .nt-stats {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 960px) {
  .nt-stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 640px) {
  .nt-stats {
    grid-template-columns: 1fr;
  }

  .nt-tabs :deep(.el-tabs__item) {
    padding: 0 14px !important;
  }

  .nt-tabs :deep(.el-tabs__content) {
    padding: 16px;
  }
}
</style>