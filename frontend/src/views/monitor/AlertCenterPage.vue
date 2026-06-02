<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import AlertNoticePage from './AlertNoticePage.vue'
import AlertSubscribePage from './AlertSubscribePage.vue'

type AlertTab = 'events' | 'push'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()

const normalizeTab = (value: unknown): AlertTab => {
  const v = String(value || '').trim().toLowerCase()
  if (v === 'push') return 'push'
  if (v === 'rules') return 'push'
  return 'events'
}

const activeTab = ref<AlertTab>(normalizeTab(route.query.tab))

watch(
  () => route.query.tab,
  (value) => {
    const next = normalizeTab(value)
    if (next !== activeTab.value) {
      activeTab.value = next
    }
  },
)

watch(activeTab, (tab) => {
  if (normalizeTab(route.query.tab) !== tab) {
    router.replace({ query: { ...route.query, tab } })
  }
})

const activeComponent = computed(() => {
  if (activeTab.value === 'push') return AlertSubscribePage
  return AlertNoticePage
})

</script>

<template>
  <div class="page-shell">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ $t('menu.monitor-alert-center') }}</h1>
        <p class="page-subtitle">{{ t('monitor.alertSubtitle') }}</p>
      </div>
    </div>

    <el-card class="alert-center-card">
      <el-tabs v-model="activeTab" class="alert-center-tabs">
        <el-tab-pane :label="$t('menu.monitor-alert-notice')" name="events" />
        <el-tab-pane :label="$t('menu.monitor-alert-subscribe')" name="push" />
      </el-tabs>

      <div class="alert-center-content">
        <keep-alive>
          <component :is="activeComponent" />
        </keep-alive>
      </div>
    </el-card>
  </div>
</template>

<style scoped>
.alert-center-card {
  padding: 0;
}

.alert-center-tabs {
  margin-bottom: 8px;
}

.alert-center-content {
  min-height: 420px;
}

:deep(.alert-center-content .page-shell) {
  padding: 0;
  background: transparent;
}

:deep(.alert-center-content .page-header) {
  display: none;
}

:deep(.alert-center-content .mn-card),
:deep(.alert-center-content .monitor-card),
:deep(.alert-center-content .stack-card) {
  margin-top: 0;
}
</style>