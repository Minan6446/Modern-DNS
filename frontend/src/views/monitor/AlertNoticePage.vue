<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAlertStore, type AlertNotice } from '../../stores/alert'
import { formatDateTime } from '../../utils/datetime'

const alertStore = useAlertStore()
const { t } = useI18n()

type Level = 'critical' | 'warning' | 'info' | string

const filters = reactive({ level: '', status: '', keyword: '' })
const detailVisible = ref(false)
const detailItem = ref<AlertNotice | null>(null)
const selectedRows = ref<AlertNotice[]>([])

const statusOf = (n: AlertNotice) => {
  if (n.status === '已处理') return 'handled'
  if (n.status === '已抑制') return 'suppressed'
  return n.read ? 'read' : 'unread'
}

const filtered = computed(() => alertStore.notices.filter(n => {
  const s = statusOf(n)
  const matchK = !filters.keyword || n.content.includes(filters.keyword) || n.type.includes(filters.keyword)
  const levelAliases: Record<string, string[]> = { critical: ['critical', '紧急'], warning: ['warning', '警告'], info: ['info', '提示'] }
  const matchL = !filters.level || (levelAliases[filters.level] || [filters.level]).includes(n.level)
  const matchS = !filters.status || s === filters.status
  return matchK && matchL && matchS
}))

// Total comes from the server-side row count (alert_events COUNT(*))
// — `notices.length` is only the windowed slice we render, which is
// capped by the backend's `limit` param (default 500). The other KPIs
// stay derived from the in-memory list because they need per-row
// status / level filtering, which the server doesn't pre-aggregate.
const kpiTotal    = computed(() => alertStore.total || alertStore.notices.length)
const kpiUnread   = computed(() => alertStore.notices.filter(n => !n.read && n.status !== '已处理').length)
const kpiCritical = computed(() => alertStore.notices.filter(n => n.level === 'critical' || n.level === '紧急').length)
const kpiHandled  = computed(() => alertStore.notices.filter(n => n.status === '已处理').length)

const levelLabelMap = computed<Record<string, string>>(() => ({ critical: t('monitor.severe'), warning: t('monitor.warningLevel'), info: t('monitor.infoLevel'), '紧急': t('monitor.severe'), '警告': t('monitor.warningLevel'), '提示': t('monitor.infoLevel') }))
const levelClassMap: Record<string, string> = { critical: 'level-critical', warning: 'level-warning', info: 'level-info', '紧急': 'level-critical', '警告': 'level-warning', '提示': 'level-info' }
const levelLabel = (l: string) => levelLabelMap.value[l] || l
const levelClass = (l: string) => levelClassMap[l] || 'level-info'
const metricSourceLabel = (value: string) => {
  const token = String(value || '').trim().toLowerCase()
  if (!token) return ''
  const map: Record<string, string> = {
    latency: t('monitor.metricResponseTime'),
    p99_latency: t('monitor.metricP99Latency'),
    error_rate: t('monitor.metricErrorRate'),
    success_rate: t('monitor.metricSuccessRate'),
    nxdomain_rate: t('monitor.metricNxdomainRate'),
    servfail_rate: t('monitor.metricServfailRate'),
    refused_rate: t('monitor.metricRefusedRate'),
    formerr_rate: t('monitor.metricFormerrRate'),
    cache_hit_rate: t('monitor.metricCacheHitRate'),
    cache_hit_drop_pct: t('monitor.metricCacheHitDropPct'),
    domain_qps_spike_ratio: t('monitor.metricDomainQpsSpikeRatio'),
    dnssec_failure_rate: t('monitor.metricDnssecFailureRate'),
    cert_expiring_30d_count: t('monitor.metricCertExpiring30dCount'),
    cluster_sync_failed_count: t('monitor.metricClusterSyncFailedCount'),
    notify_deadletter_15m_count: t('monitor.metricNotifyDeadletterCount'),
  }
  if (token === 'qps') return 'QPS'
  return map[token] || ''
}
const sourceLabel = (value: string) => {
  const text = String(value || '').trim()
  if (!text) return '--'
  const keyMap: Record<string, string> = {
    qps_spike: 'monitor.alertSourceQpsSpike',
    cache_low: 'monitor.alertSourceCacheLow',
  }
  const key = keyMap[text]
  if (key) return t(key)
  if (/^subscribe_/i.test(text)) {
    const metric = text.replace(/^subscribe_/i, '')
    const label = metricSourceLabel(metric)
    return label ? t('monitor.alertSourceSubscribeMetric', { metric: label }) : t('monitor.alertSourceSubscribeRule')
  }
  const metricLabel = metricSourceLabel(text)
  return metricLabel || text
}
const suppressTagLabel = (n: AlertNotice) => {
  if (n.suppressType === 'silence') return t('monitor.silenceHit')
  if (n.suppressType === 'inhibit') return t('monitor.inhibitHit')
  return ''
}
const statusLabelMap = computed<Record<string, string>>(() => ({
  unread: t('monitor.unreadStatus'),
  read: t('monitor.readStatus'),
  handled: t('monitor.handledStatus'),
  suppressed: t('monitor.suppressedStatus'),
}))
const statusClassMap: Record<string, string> = {
  unread: 'mn-badge--danger',
  read: 'mn-badge--neutral',
  handled: 'mn-badge--success',
  suppressed: 'mn-badge--warning',
}

const canHandle = (n: AlertNotice) => n.status !== '已处理' && n.status !== '已抑制'
const handleableSelected = computed(() => selectedRows.value.filter((row) => canHandle(row)))

const onSelectionChange = (rows: AlertNotice[]) => {
  selectedRows.value = rows
}

const openDetail = (row: AlertNotice) => {
  if (!row.read) alertStore.markRead(row.id)
  detailItem.value = row
  detailVisible.value = true
}

const markHandled = async (row: AlertNotice) => {
  try {
    await alertStore.handleAlert(row.id)
    ElMessage.success(t('monitor.markedHandled'))
    detailVisible.value = false
  } catch {
    ElMessage.error(t('monitor.operationFailed'))
  }
}

const batchHandleSelected = async () => {
  const rows = handleableSelected.value
  if (!rows.length) {
    ElMessage.warning(t('monitor.selectAtLeastOneHandleableAlert'))
    return
  }
  try {
    await Promise.all(rows.map((row) => alertStore.handleAlert(row.id)))
    ElMessage.success(t('monitor.batchHandledDone', { n: rows.length }))
  } catch {
    ElMessage.error(t('monitor.operationFailed'))
  }
}

// Batch delete: hard-removes the selected alert_events rows server-side.
// We pair this with the existing 批量处理 (which only flips status) so
// operators can either *triage* (status → 已处理, row stays) or *purge*
// (row gone) the same selection without two trips to the row menu.
const batchDeleteLoading = ref(false)
const batchDeleteSelected = async () => {
  const rows = selectedRows.value
  if (!rows.length) {
    ElMessage.warning(t('monitor.selectAtLeastOneAlert'))
    return
  }
  try {
    await ElMessageBox.confirm(
      t('monitor.batchDeleteConfirm', { n: rows.length }),
      t('monitor.batchDeleteTitle'),
      { type: 'warning', confirmButtonText: t('common.confirm'), cancelButtonText: t('common.cancel') },
    )
  } catch {
    return
  }
  batchDeleteLoading.value = true
  try {
    const deleted = await alertStore.batchDelete(rows.map((r) => r.id))
    selectedRows.value = []
    ElMessage.success(t('monitor.batchDeletedDone', { n: deleted }))
  } catch {
    ElMessage.error(t('monitor.operationFailed'))
  } finally {
    batchDeleteLoading.value = false
  }
}

const markAllRead = async () => {
  try {
    await alertStore.markAllRead()
    ElMessage.success(t('monitor.allMarkedRead'))
  } catch {
    ElMessage.error(t('monitor.operationFailed'))
  }
}

const clearHandled = async () => {
  await ElMessageBox.confirm(t('monitor.clearHandledConfirm'), t('monitor.clearHandledTitle'), { type: 'warning' })
  alertStore.clearHandled()
  ElMessage.success(t('monitor.clearedHandled'))
}

onMounted(() => {
  alertStore.fetchAlerts()
})
</script>

<template>
  <div class="page-shell">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ $t('monitor.alertNotice') }}</h1>
        <p class="page-subtitle">{{ $t('monitor.alertSubtitle') }}</p>
      </div>
      <div class="header-actions">
        <el-button size="small" @click="markAllRead" :disabled="kpiUnread === 0">{{ $t('monitor.allRead') }}</el-button>
        <el-button size="small" type="danger" plain @click="clearHandled">{{ $t('monitor.clearHandled') }}</el-button>
      </div>
    </div>

    <!-- KPI -->
    <div class="mn-stats-strip">
      <div class="mn-stat-tile"><span class="mn-stat-value">{{ kpiTotal }}</span><span class="mn-stat-label">{{ $t('monitor.totalAlerts') }}</span></div>
      <div class="mn-stat-tile mn-stat-tile--danger"><span class="mn-stat-value">{{ kpiUnread }}</span><span class="mn-stat-label">{{ $t('monitor.unread') }}</span></div>
      <div class="mn-stat-tile mn-stat-tile--danger"><span class="mn-stat-value">{{ kpiCritical }}</span><span class="mn-stat-label">{{ $t('monitor.severe') }}</span></div>
      <div class="mn-stat-tile mn-stat-tile--success"><span class="mn-stat-value">{{ kpiHandled }}</span><span class="mn-stat-label">{{ $t('monitor.handled') }}</span></div>
    </div>

    <!-- Table card -->
    <el-card class="mn-card">
      <div class="mn-toolbar">
        <div class="mn-toolbar-filters">
          <el-input v-model="filters.keyword" clearable :placeholder="$t('monitor.searchAlert')" style="width:240px">
            <template #prefix>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            </template>
          </el-input>
          <el-select v-model="filters.level" clearable :placeholder="$t('monitor.levelLabel')" style="width:120px">
            <el-option :label="$t('monitor.criticalUrgent')" value="critical" />
            <el-option :label="$t('monitor.warningLevel')" value="warning" />
            <el-option :label="$t('monitor.infoLevel')" value="info" />
          </el-select>
          <el-select v-model="filters.status" clearable :placeholder="$t('common.status')" style="width:120px">
            <el-option :label="$t('monitor.unreadStatus')" value="unread" />
            <el-option :label="$t('monitor.readStatus')" value="read" />
            <el-option :label="$t('monitor.handledStatus')" value="handled" />
          </el-select>
        </div>
        <div class="mn-toolbar-actions">
          <el-button type="primary" plain :disabled="handleableSelected.length === 0" @click="batchHandleSelected">
            {{ $t('monitor.batchHandle') }}
            <span v-if="handleableSelected.length > 0">({{ handleableSelected.length }})</span>
          </el-button>
          <el-button
            type="danger"
            plain
            :disabled="selectedRows.length === 0"
            :loading="batchDeleteLoading"
            @click="batchDeleteSelected"
          >
            {{ $t('monitor.batchDelete') }}
            <span v-if="selectedRows.length > 0">({{ selectedRows.length }})</span>
          </el-button>
        </div>
      </div>

      <el-table
        :data="filtered"
        stripe
        class="mn-table"
        v-loading="alertStore.loading"
        table-layout="auto"
        row-key="id"
        :row-class-name="({ row }) => !row.read && row.status !== '已处理' ? 'row-unread' : ''"
        @selection-change="onSelectionChange"
      >
        <el-table-column type="selection" width="48" reserve-selection />
        <el-table-column :label="$t('monitor.levelLabel')" width="90" align="center">
          <template #default="{ row }">
            <span :class="['level-badge', levelClass(row.level)]">{{ levelLabel(row.level) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="content" :label="$t('monitor.alertContentLabel')" min-width="260" show-overflow-tooltip>
          <template #default="{ row }">
            <div class="notice-main">
              <span :class="['notice-title', { 'is-unread': !row.read && row.status !== '已处理' }]">{{ row.content }}</span>
              <span v-if="row.suppressType" class="suppress-tag">{{ suppressTagLabel(row) }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="type" :label="$t('monitor.source')" width="120" align="center">
          <template #default="{ row }">
            <span class="mn-badge mn-badge--neutral">{{ sourceLabel(row.type) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="triggeredAt" :label="$t('monitor.time')" width="170">
          <template #default="{ row }"><span class="mn-time">{{ formatDateTime(row.triggeredAt) }}</span></template>
        </el-table-column>
        <el-table-column :label="$t('common.status')" width="100" align="center">
          <template #default="{ row }">
            <span :class="['mn-badge', statusClassMap[statusOf(row)]]">{{ statusLabelMap[statusOf(row)] }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('common.operation')" width="140">
          <template #default="{ row }">
            <div class="mn-row-ops">
              <el-button plain type="primary" @click="openDetail(row)">{{ $t('common.detail') }}</el-button>
              <el-button plain type="success" :disabled="!canHandle(row)" @click="markHandled(row)">{{ $t('monitor.handle') }}</el-button>
            </div>
          </template>
        </el-table-column>
        <template #empty><el-empty :description="$t('monitor.noAlertNotice')" /></template>
      </el-table>
    </el-card>

    <!-- Detail drawer -->
    <el-dialog v-model="detailVisible" :title="$t('monitor.alertDetail')" width="480px" append-to-body>
      <template v-if="detailItem">
        <div class="detail-header">
          <span :class="['level-badge', 'level-badge--lg', levelClass(detailItem.level)]">{{ levelLabel(detailItem.level) }}</span>
          <span class="detail-title">{{ detailItem.content }}</span>
        </div>
        <el-descriptions :column="2" border class="detail-meta">
          <el-descriptions-item :label="$t('monitor.source')">{{ sourceLabel(detailItem.type) }}</el-descriptions-item>
          <el-descriptions-item :label="$t('monitor.time')">{{ formatDateTime(detailItem.triggeredAt) }}</el-descriptions-item>
          <el-descriptions-item :label="$t('common.domain')">{{ detailItem.domain || '--' }}</el-descriptions-item>
          <el-descriptions-item :label="$t('common.status')">
            <span :class="['mn-badge', statusClassMap[statusOf(detailItem)]]">{{ statusLabelMap[statusOf(detailItem)] }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="detailItem.suppressType" :label="$t('monitor.suppressReason')">
            <span class="suppress-reason">{{ detailItem.suppressReason || suppressTagLabel(detailItem) }}</span>
          </el-descriptions-item>
        </el-descriptions>
      </template>
      <template #footer>
        <el-button @click="detailVisible = false">{{ $t('common.close') }}</el-button>
        <el-button type="primary" :disabled="!detailItem || !canHandle(detailItem)" @click="detailItem && markHandled(detailItem)">{{ $t('monitor.markHandled') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.page-header { display:flex; align-items:flex-start; justify-content:space-between; }
.header-actions { display:flex; gap:8px; flex-shrink:0; margin-top:4px; }

.mn-stats-strip { display:flex; gap:14px; flex-wrap:wrap; }
.mn-stat-tile { display:flex; flex-direction:row; align-items:center; gap:14px; padding:14px 24px; border-radius:10px; border:1px solid var(--app-border); background:var(--app-bg); min-width:100px; flex:1; box-shadow:var(--app-shadow-soft); }
.mn-stat-value { font-size:28px; font-weight:700; font-variant-numeric:tabular-nums; letter-spacing:-0.03em; line-height:1; }
.mn-stat-label { font-size:12px; font-weight:500; color:var(--app-text-regular); line-height:1.4; }
.mn-stat-tile--success .mn-stat-value { color:var(--app-success); }
.mn-stat-tile--danger .mn-stat-value  { color:var(--app-danger); }
.mn-stat-tile--warning .mn-stat-value { color:var(--app-warning); }
.mn-stat-tile--accent .mn-stat-value  { color:var(--app-accent); }
.mn-stat-tile--neutral .mn-stat-value { color:var(--app-text-secondary); }

.level-badge {
  display: inline-flex; align-items: center; justify-content: center;
  padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 700; color: #fff;
}
.level-badge--lg { font-size: 13px; padding: 3px 12px; }
.level-critical { background: #ef4444; }
.level-warning  { background: #f59e0b; }
.level-info     { background: #3b82f6; }

.notice-title { font-size: 13px; color: var(--app-text-primary,#1d2129); }
.notice-title.is-unread { font-weight: 700; }
.notice-main { display: flex; align-items: center; gap: 8px; }
.suppress-tag {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  border-radius: 10px;
  font-size: 11px;
  color: #7a4f01;
  background: #fff3d6;
  border: 1px solid #f7d79c;
}
.suppress-reason {
  color: #7a4f01;
  font-weight: 600;
}

:deep(.row-unread td) { background: #fffbf0 !important; }

.detail-header { display:flex; align-items:center; gap:10px; margin-bottom:16px; }
.detail-title { font-size:15px; font-weight:700; color:var(--app-text-primary,#1d2129); line-height:1.4; }
.detail-meta { margin-top:0; }
</style>
