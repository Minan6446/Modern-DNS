<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  getAlertSubscribeRules,
  createAlertSubscribeRule,
  updateAlertSubscribeRule,
  batchUpdateAlertSubscribeRules,
  deleteAlertSubscribeRule,
  toggleAlertSubscribeRule,
  getAlertContactGroups,
  createAlertContactGroup,
  updateAlertContactGroup,
  deleteAlertContactGroup,
  getAlertContactUsers,
  getAlertSilenceRules,
  createAlertSilenceRule,
  updateAlertSilenceRule,
  deleteAlertSilenceRule,
  getAlertInhibitRules,
  createAlertInhibitRule,
  updateAlertInhibitRule,
  deleteAlertInhibitRule,
  type AlertContactGroup,
  type AlertContactUser,
  type AlertSilenceRule,
  type AlertInhibitRule,
} from '../../api/monitor'
import { formatDateTime } from '../../utils/datetime'

interface AlertRule {
  id: number
  name: string
  metric: string
  operator: '>' | '<' | '>=' | '<='
  threshold: number
  unit: string
  duration: number
  channels: string[]
  contactGroupId: number
  silenceMinutes: number
  status: '启用' | '禁用'
  triggerCount: number
  lastTriggered: string
}

type RuleForm = Omit<AlertRule, 'id' | 'triggerCount' | 'lastTriggered'>
type BatchRuleForm = {
  applyStatus: boolean
  status: '启用' | '禁用'
  applyDuration: boolean
  duration: number
  applySilenceMinutes: boolean
  silenceMinutes: number
  applyContactGroup: boolean
  contactGroupId: number
  applyChannels: boolean
  channels: string[]
}

type ContactGroupForm = {
  id?: number
  name: string
  memberUserIds: number[]
  remark: string
  status: '启用' | '禁用'
}

type SilenceForm = {
  name: string
  alertTypePattern: string
  domainPattern: string
  levels: string
  startAt: Date | null
  endAt: Date | null
  status: '启用' | '禁用'
}

type InhibitForm = {
  name: string
  sourceAlertType: string
  sourceLevel: string
  targetAlertType: string
  targetLevel: string
  domainScoped: boolean
  status: '启用' | '禁用'
}

const { t } = useI18n()
const pageTab = ref<'rules' | 'groups' | 'silence' | 'inhibit'>('rules')
const loading = ref(false)
const submitting = ref(false)
const batchSubmitting = ref(false)

const rules = ref<AlertRule[]>([])
const groups = ref<AlertContactGroup[]>([])
const users = ref<AlertContactUser[]>([])
const silenceRules = ref<AlertSilenceRule[]>([])
const inhibitRules = ref<AlertInhibitRule[]>([])

const ruleDialogVisible = ref(false)
const batchRuleDialogVisible = ref(false)
const groupDialogVisible = ref(false)
const silenceDialogVisible = ref(false)
const inhibitDialogVisible = ref(false)

const isEditRule = ref(false)
const isEditGroup = ref(false)
const isEditSilence = ref(false)
const isEditInhibit = ref(false)

const editingRuleId = ref<number | null>(null)
const editingGroupId = ref<number | null>(null)
const editingSilenceId = ref<number | null>(null)
const editingInhibitId = ref<number | null>(null)
const selectedRules = ref<AlertRule[]>([])
const ruleTableRef = ref<any>(null)

const metricOptions = computed(() => [
  { value: 'qps', label: 'QPS' },
  { value: 'latency', label: t('monitor.metricResponseTime') },
  { value: 'p99_latency', label: t('monitor.metricP99Latency') },
  { value: 'error_rate', label: t('monitor.metricErrorRate') },
  { value: 'success_rate', label: t('monitor.metricSuccessRate') },
  { value: 'nxdomain_rate', label: t('monitor.metricNxdomainRate') },
  { value: 'servfail_rate', label: t('monitor.metricServfailRate') },
  { value: 'refused_rate', label: t('monitor.metricRefusedRate') },
  { value: 'formerr_rate', label: t('monitor.metricFormerrRate') },
  { value: 'cache_hit_rate', label: t('monitor.metricCacheHitRate') },
  { value: 'cache_hit_drop_pct', label: t('monitor.metricCacheHitDropPct') },
  { value: 'domain_qps_spike_ratio', label: t('monitor.metricDomainQpsSpikeRatio') },
  { value: 'dnssec_failure_rate', label: t('monitor.metricDnssecFailureRate') },
  { value: 'cert_expiring_30d_count', label: t('monitor.metricCertExpiring30dCount') },
  { value: 'cluster_sync_failed_count', label: t('monitor.metricClusterSyncFailedCount') },
  { value: 'notify_deadletter_15m_count', label: t('monitor.metricNotifyDeadletterCount') },
])

const channelOptions = computed(() => [
  { value: '邮件', label: t('monitor.channelEmail') },
  { value: 'WebHook', label: t('monitor.channelWebhook') },
  { value: '钉钉', label: t('monitor.channelDingTalk') },
  { value: '企业微信', label: t('monitor.channelWechatWork') },
])

const levelOptions = computed(() => [
  { value: 'critical', label: t('monitor.critical') },
  { value: 'warning', label: t('monitor.warningLevel') },
  { value: 'info', label: t('monitor.infoLevel') },
])

const emptyRuleForm = (): RuleForm => ({
  name: '',
  metric: 'qps',
  operator: '>',
  threshold: 1000,
  unit: 'QPS',
  duration: 5,
  channels: [],
  contactGroupId: 0,
  silenceMinutes: 0,
  status: '启用',
})

const emptyGroupForm = (): ContactGroupForm => ({
  name: '',
  memberUserIds: [],
  remark: '',
  status: '启用',
})

const emptyBatchRuleForm = (): BatchRuleForm => ({
  applyStatus: false,
  status: '启用',
  applyDuration: false,
  duration: 5,
  applySilenceMinutes: false,
  silenceMinutes: 0,
  applyContactGroup: false,
  contactGroupId: 0,
  applyChannels: false,
  channels: [],
})

const emptySilenceForm = (): SilenceForm => ({
  name: '',
  alertTypePattern: '*',
  domainPattern: '*',
  levels: '*',
  startAt: new Date(),
  endAt: new Date(Date.now() + 60 * 60 * 1000),
  status: '启用',
})

const emptyInhibitForm = (): InhibitForm => ({
  name: '',
  sourceAlertType: '',
  sourceLevel: '',
  targetAlertType: '',
  targetLevel: '',
  domainScoped: false,
  status: '启用',
})

const ruleForm = reactive<RuleForm>(emptyRuleForm())
const batchRuleForm = reactive<BatchRuleForm>(emptyBatchRuleForm())
const groupForm = reactive<ContactGroupForm>(emptyGroupForm())
const silenceForm = reactive<SilenceForm>(emptySilenceForm())
const inhibitForm = reactive<InhibitForm>(emptyInhibitForm())

const metricUnits: Record<string, string> = {
  qps: 'QPS',
  latency: 'ms',
  p99_latency: 'ms',
  error_rate: '%',
  success_rate: '%',
  nxdomain_rate: '%',
  servfail_rate: '%',
  refused_rate: '%',
  formerr_rate: '%',
  cache_hit_rate: '%',
  cache_hit_drop_pct: '%',
  domain_qps_spike_ratio: '%',
  dnssec_failure_rate: '%',
  cert_expiring_30d_count: '个',
  cluster_sync_failed_count: '个',
  notify_deadletter_15m_count: '个',
}

const channelTypeColor: Record<string, string> = {
  邮件: '#3b82f6',
  WebHook: '#8b5cf6',
  钉钉: '#10b981',
  企业微信: '#f59e0b',
}

const parseIdList = (value: string): number[] =>
  String(value || '')
    .split(',')
    .map((part) => Number(part.trim()))
    .filter((id) => Number.isInteger(id) && id > 0)

const toIdListString = (ids: number[]): string =>
  ids
    .filter((id, idx, arr) => Number.isInteger(id) && id > 0 && arr.indexOf(id) === idx)
    .join(',')

const userNameMap = computed<Record<number, string>>(() => {
  const map: Record<number, string> = {}
  users.value.forEach((u) => {
    map[u.id] = u.realName || u.username || `#${u.id}`
  })
  return map
})

const groupNameMap = computed<Record<number, string>>(() => {
  const map: Record<number, string> = {}
  groups.value.forEach((g) => {
    map[g.id] = g.name
  })
  return map
})

const contactGroupOptions = computed(() =>
  groups.value
    .filter((g) => g.status === '启用')
    .map((g) => ({ value: g.id, label: g.name })),
)

const kpiEnabled = computed(() => rules.value.filter((r) => r.status === '启用').length)
const kpiTriggered = computed(() => rules.value.reduce((sum, r) => sum + Number(r.triggerCount || 0), 0))
const kpiSilence = computed(() => silenceRules.value.filter((r) => r.status === '启用').length)
const kpiInhibit = computed(() => inhibitRules.value.filter((r) => r.status === '启用').length)
const selectedRuleCount = computed(() => selectedRules.value.length)

const metricLabel = (value: string): string => {
  const map: Record<string, string> = {
    qps: 'QPS',
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
  return map[value] || value
}

const channelLabel = (value: string): string => {
  const map: Record<string, string> = {
    邮件: t('monitor.channelEmail'),
    WebHook: t('monitor.channelWebhook'),
    钉钉: t('monitor.channelDingTalk'),
    企业微信: t('monitor.channelWechatWork'),
  }
  return map[value] || value
}

const groupMembersLabel = (row: AlertContactGroup): string => {
  const names = parseIdList(row.memberUserIds).map((id) => userNameMap.value[id] || `#${id}`)
  return names.join('、')
}

const updateUnit = () => {
  ruleForm.unit = metricUnits[ruleForm.metric] || ''
}

const statusLabel = (status: string): string => (status === '启用' ? t('common.enable') : t('common.disable'))
const statusClass = (status: string): string => (status === '启用' ? 'mn-badge--success' : 'mn-badge--neutral')

const normalizeLevels = (raw: string): string => {
  const txt = String(raw || '').trim()
  return txt ? txt : '*'
}

const parseLevelInput = (raw: string): string[] => {
  const txt = normalizeLevels(raw)
  if (txt === '*') return [t('monitor.allLevels')]
  return txt.split(',').map((s) => s.trim()).filter(Boolean)
}

const levelText = (level: string): string => {
  const map: Record<string, string> = {
    critical: t('monitor.critical'),
    warning: t('monitor.warningLevel'),
    info: t('monitor.infoLevel'),
    '*': t('monitor.allLevels'),
  }
  return map[level] || level
}

const levelsLabel = (raw: string): string => parseLevelInput(raw).map((s) => levelText(s)).join('、')

const formatRuleTypePattern = (value: string): string => String(value || '').trim() || '*'

const fetchRules = async () => {
  const { data } = await getAlertSubscribeRules()
  rules.value = (data || []).map((r: any) => ({
    ...r,
    channels: r.channels
      ? (typeof r.channels === 'string' ? r.channels.split(',').map((s: string) => s.trim()).filter(Boolean) : r.channels)
      : [],
    contactGroupId: Number(r.contactGroupId || 0),
    silenceMinutes: Math.max(0, Number(r.silenceMinutes || 0)),
  }))
}

const fetchGroups = async () => {
  const { data } = await getAlertContactGroups()
  groups.value = data || []
}

const fetchUsers = async () => {
  const { data } = await getAlertContactUsers()
  users.value = data || []
}

const fetchSilenceRules = async () => {
  const { data } = await getAlertSilenceRules()
  silenceRules.value = data || []
}

const fetchInhibitRules = async () => {
  const { data } = await getAlertInhibitRules()
  inhibitRules.value = data || []
}

const fetchAll = async () => {
  loading.value = true
  try {
    await Promise.all([fetchRules(), fetchGroups(), fetchUsers(), fetchSilenceRules(), fetchInhibitRules()])
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void fetchAll()
})

const openCreateRule = () => {
  isEditRule.value = false
  editingRuleId.value = null
  Object.assign(ruleForm, emptyRuleForm())
  ruleDialogVisible.value = true
}

const onRuleSelectionChange = (rows: AlertRule[]) => {
  selectedRules.value = rows
}

const clearRuleSelection = () => {
  selectedRules.value = []
  ruleTableRef.value?.clearSelection?.()
}

const openBatchEditRule = () => {
  if (!selectedRules.value.length) {
    ElMessage.warning(t('monitor.selectAtLeastOneRule'))
    return
  }
  Object.assign(batchRuleForm, emptyBatchRuleForm())
  batchRuleDialogVisible.value = true
}

const openEditRule = (row: AlertRule) => {
  isEditRule.value = true
  editingRuleId.value = row.id
  Object.assign(ruleForm, {
    name: row.name,
    metric: row.metric,
    operator: row.operator,
    threshold: row.threshold,
    unit: row.unit,
    duration: row.duration,
    channels: [...row.channels],
    contactGroupId: Number(row.contactGroupId || 0),
    silenceMinutes: Math.max(0, Number(row.silenceMinutes || 0)),
    status: row.status,
  })
  ruleDialogVisible.value = true
}

const submitRule = async () => {
  if (!ruleForm.name.trim()) {
    ElMessage.warning(t('monitor.fillRuleName'))
    return
  }
  submitting.value = true
  try {
    const payload = {
      ...ruleForm,
      channels: ruleForm.channels.join(','),
      contactGroupId: Number(ruleForm.contactGroupId || 0),
      silenceMinutes: Math.max(0, Number(ruleForm.silenceMinutes || 0)),
    }
    if (isEditRule.value && editingRuleId.value) {
      await updateAlertSubscribeRule(editingRuleId.value, payload)
      ElMessage.success(t('monitor.ruleUpdated'))
    } else {
      await createAlertSubscribeRule(payload)
      ElMessage.success(t('monitor.ruleCreated'))
    }
    ruleDialogVisible.value = false
    await fetchRules()
  } finally {
    submitting.value = false
  }
}

const submitBatchRule = async () => {
  if (!selectedRules.value.length) {
    ElMessage.warning(t('monitor.selectAtLeastOneRule'))
    return
  }

  const hasAnyField = [
    batchRuleForm.applyStatus,
    batchRuleForm.applyDuration,
    batchRuleForm.applySilenceMinutes,
    batchRuleForm.applyContactGroup,
    batchRuleForm.applyChannels,
  ].some(Boolean)
  if (!hasAnyField) {
    ElMessage.warning(t('monitor.selectAtLeastOneBatchField'))
    return
  }

  batchSubmitting.value = true
  try {
    const payload: {
      ids: number[]
      status?: '启用' | '禁用'
      duration?: number
      silenceMinutes?: number
      contactGroupId?: number
      channels?: string
    } = {
      ids: selectedRules.value.map((row) => row.id),
    }
    if (batchRuleForm.applyStatus) {
      payload.status = batchRuleForm.status
    }
    if (batchRuleForm.applyDuration) {
      payload.duration = Number(batchRuleForm.duration)
    }
    if (batchRuleForm.applySilenceMinutes) {
      payload.silenceMinutes = Math.max(0, Number(batchRuleForm.silenceMinutes))
    }
    if (batchRuleForm.applyContactGroup) {
      payload.contactGroupId = Number(batchRuleForm.contactGroupId || 0)
    }
    if (batchRuleForm.applyChannels) {
      payload.channels = batchRuleForm.channels.join(',')
    }

    await batchUpdateAlertSubscribeRules(payload)
    ElMessage.success(t('monitor.batchEditSuccess', { n: selectedRules.value.length }))
    batchRuleDialogVisible.value = false
    await fetchRules()
    clearRuleSelection()
  } finally {
    batchSubmitting.value = false
  }
}

const removeRule = async (row: AlertRule) => {
  await ElMessageBox.confirm(t('monitor.deleteRuleConfirm', { name: row.name }), t('monitor.deleteRuleTitle'), { type: 'warning' })
  await deleteAlertSubscribeRule(row.id)
  ElMessage.success(t('monitor.deleted'))
  await fetchRules()
}

const toggleRuleStatus = async (row: AlertRule) => {
  const next = row.status === '启用' ? '禁用' : '启用'
  await toggleAlertSubscribeRule(row.id, next)
  row.status = next
}

const openCreateGroup = () => {
  isEditGroup.value = false
  editingGroupId.value = null
  Object.assign(groupForm, emptyGroupForm())
  groupDialogVisible.value = true
}

const openEditGroup = (row: AlertContactGroup) => {
  isEditGroup.value = true
  editingGroupId.value = row.id
  Object.assign(groupForm, {
    id: row.id,
    name: row.name,
    memberUserIds: parseIdList(row.memberUserIds),
    remark: row.remark || '',
    status: row.status || '启用',
  })
  groupDialogVisible.value = true
}

const submitGroup = async () => {
  if (!groupForm.name.trim()) {
    ElMessage.warning(t('monitor.fillGroupName'))
    return
  }
  if (!groupForm.memberUserIds.length) {
    ElMessage.warning(t('monitor.fillGroupMembers'))
    return
  }
  submitting.value = true
  try {
    const payload = {
      name: groupForm.name.trim(),
      memberUserIds: toIdListString(groupForm.memberUserIds),
      remark: groupForm.remark,
      status: groupForm.status,
    }
    if (isEditGroup.value && editingGroupId.value) {
      await updateAlertContactGroup(editingGroupId.value, payload)
      ElMessage.success(t('monitor.groupUpdated'))
    } else {
      await createAlertContactGroup(payload)
      ElMessage.success(t('monitor.groupCreated'))
    }
    groupDialogVisible.value = false
    await fetchGroups()
  } finally {
    submitting.value = false
  }
}

const removeGroup = async (row: AlertContactGroup) => {
  await ElMessageBox.confirm(t('monitor.deleteRuleConfirm', { name: row.name }), t('monitor.deleteRuleTitle'), { type: 'warning' })
  await deleteAlertContactGroup(row.id)
  ElMessage.success(t('monitor.deleted'))
  await Promise.all([fetchGroups(), fetchRules()])
}

const openCreateSilence = () => {
  isEditSilence.value = false
  editingSilenceId.value = null
  Object.assign(silenceForm, emptySilenceForm())
  silenceDialogVisible.value = true
}

const openEditSilence = (row: AlertSilenceRule) => {
  isEditSilence.value = true
  editingSilenceId.value = row.id
  Object.assign(silenceForm, {
    name: row.name,
    alertTypePattern: row.alertTypePattern,
    domainPattern: row.domainPattern,
    levels: normalizeLevels(row.levels),
    startAt: row.startAt ? new Date(row.startAt) : new Date(),
    endAt: row.endAt ? new Date(row.endAt) : new Date(Date.now() + 60 * 60 * 1000),
    status: row.status,
  })
  silenceDialogVisible.value = true
}

const submitSilence = async () => {
  if (!silenceForm.name.trim()) {
    ElMessage.warning(t('monitor.fillSilenceName'))
    return
  }
  if (!silenceForm.startAt || !silenceForm.endAt || silenceForm.endAt <= silenceForm.startAt) {
    ElMessage.warning(t('monitor.invalidSilenceWindow'))
    return
  }
  submitting.value = true
  try {
    const payload = {
      name: silenceForm.name.trim(),
      alertTypePattern: formatRuleTypePattern(silenceForm.alertTypePattern),
      domainPattern: formatRuleTypePattern(silenceForm.domainPattern),
      levels: normalizeLevels(silenceForm.levels),
      startAt: silenceForm.startAt.toISOString(),
      endAt: silenceForm.endAt.toISOString(),
      status: silenceForm.status,
    }
    if (isEditSilence.value && editingSilenceId.value) {
      await updateAlertSilenceRule(editingSilenceId.value, payload)
      ElMessage.success(t('monitor.silenceRuleUpdated'))
    } else {
      await createAlertSilenceRule(payload)
      ElMessage.success(t('monitor.silenceRuleCreated'))
    }
    silenceDialogVisible.value = false
    await fetchSilenceRules()
  } finally {
    submitting.value = false
  }
}

const removeSilence = async (row: AlertSilenceRule) => {
  await ElMessageBox.confirm(t('monitor.deleteRuleConfirm', { name: row.name }), t('monitor.deleteRuleTitle'), { type: 'warning' })
  await deleteAlertSilenceRule(row.id)
  ElMessage.success(t('monitor.deleted'))
  await fetchSilenceRules()
}

const openCreateInhibit = () => {
  isEditInhibit.value = false
  editingInhibitId.value = null
  Object.assign(inhibitForm, emptyInhibitForm())
  inhibitDialogVisible.value = true
}

const openEditInhibit = (row: AlertInhibitRule) => {
  isEditInhibit.value = true
  editingInhibitId.value = row.id
  Object.assign(inhibitForm, {
    name: row.name,
    sourceAlertType: row.sourceAlertType,
    sourceLevel: row.sourceLevel || '',
    targetAlertType: row.targetAlertType,
    targetLevel: row.targetLevel || '',
    domainScoped: !!row.domainScoped,
    status: row.status,
  })
  inhibitDialogVisible.value = true
}

const submitInhibit = async () => {
  if (!inhibitForm.name.trim()) {
    ElMessage.warning(t('monitor.fillInhibitName'))
    return
  }
  if (!inhibitForm.sourceAlertType.trim() || !inhibitForm.targetAlertType.trim()) {
    ElMessage.warning(t('monitor.fillInhibitTypes'))
    return
  }
  submitting.value = true
  try {
    const payload = {
      name: inhibitForm.name.trim(),
      sourceAlertType: inhibitForm.sourceAlertType.trim(),
      sourceLevel: inhibitForm.sourceLevel.trim(),
      targetAlertType: inhibitForm.targetAlertType.trim(),
      targetLevel: inhibitForm.targetLevel.trim(),
      domainScoped: inhibitForm.domainScoped,
      status: inhibitForm.status,
    }
    if (isEditInhibit.value && editingInhibitId.value) {
      await updateAlertInhibitRule(editingInhibitId.value, payload)
      ElMessage.success(t('monitor.inhibitRuleUpdated'))
    } else {
      await createAlertInhibitRule(payload)
      ElMessage.success(t('monitor.inhibitRuleCreated'))
    }
    inhibitDialogVisible.value = false
    await fetchInhibitRules()
  } finally {
    submitting.value = false
  }
}

const removeInhibit = async (row: AlertInhibitRule) => {
  await ElMessageBox.confirm(t('monitor.deleteRuleConfirm', { name: row.name }), t('monitor.deleteRuleTitle'), { type: 'warning' })
  await deleteAlertInhibitRule(row.id)
  ElMessage.success(t('monitor.deleted'))
  await fetchInhibitRules()
}
</script>

<template>
  <div class="page-shell">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ $t('monitor.subscribe') }}</h1>
        <p class="page-subtitle">{{ $t('monitor.subscribeSubtitle') }}</p>
      </div>
    </div>

    <div class="mn-stats-strip">
      <div class="mn-stat-tile mn-stat-tile--success"><span class="mn-stat-value">{{ kpiEnabled }}</span><span class="mn-stat-label">{{ $t('monitor.enabledRules') }}</span></div>
      <div class="mn-stat-tile mn-stat-tile--warning"><span class="mn-stat-value">{{ kpiTriggered }}</span><span class="mn-stat-label">{{ $t('monitor.totalTriggers') }}</span></div>
      <div class="mn-stat-tile"><span class="mn-stat-value">{{ kpiSilence }}</span><span class="mn-stat-label">{{ $t('monitor.silenceRuleTab') }}</span></div>
      <div class="mn-stat-tile"><span class="mn-stat-value">{{ kpiInhibit }}</span><span class="mn-stat-label">{{ $t('monitor.inhibitRuleTab') }}</span></div>
    </div>

    <el-card class="mn-card">
      <el-tabs v-model="pageTab" class="inner-tabs">
        <el-tab-pane :label="$t('monitor.pushRuleConfigTab')" name="rules" />
        <el-tab-pane :label="$t('monitor.contactGroupConfigTab')" name="groups" />
        <el-tab-pane :label="$t('monitor.silenceRuleTab')" name="silence" />
        <el-tab-pane :label="$t('monitor.inhibitRuleTab')" name="inhibit" />
      </el-tabs>

      <template v-if="pageTab === 'rules'">
        <div class="mn-toolbar">
          <div class="mn-toolbar-filters"></div>
          <div class="mn-toolbar-actions">
            <el-button :disabled="selectedRuleCount === 0" @click="openBatchEditRule">
              {{ $t('monitor.batchEditRules') }}
              <span v-if="selectedRuleCount > 0">({{ selectedRuleCount }})</span>
            </el-button>
            <el-button type="primary" @click="openCreateRule">{{ $t('monitor.createRule') }}</el-button>
          </div>
        </div>

        <el-table
          ref="ruleTableRef"
          :data="rules"
          v-loading="loading"
          stripe
          class="mn-table rule-table"
          table-layout="auto"
          row-key="id"
          @selection-change="onRuleSelectionChange"
        >
          <el-table-column type="selection" width="48" reserve-selection />
          <el-table-column prop="name" :label="$t('monitor.ruleName')" min-width="150" />
          <el-table-column :label="$t('monitor.triggerCondition')" min-width="220">
            <template #default="{ row }">
              <span class="condition-text">{{ metricLabel(row.metric) }} {{ row.operator }} <strong>{{ row.threshold }}{{ row.unit }}</strong> {{ $t('monitor.durationMinutes', { n: row.duration }) }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="channels" :label="$t('monitor.notifyChannel')" min-width="170">
            <template #default="{ row }">
              <div class="tag-list">
                <span v-for="c in row.channels" :key="c" class="type-badge" :style="{ background: channelTypeColor[c] ?? '#6b7280' }">{{ channelLabel(c) }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="$t('monitor.contactGroup')" min-width="140">
            <template #default="{ row }">{{ groupNameMap[row.contactGroupId] || $t('monitor.noContactGroup') }}</template>
          </el-table-column>
          <el-table-column prop="silenceMinutes" :label="$t('monitor.channelSilence')" width="130" align="right" />
          <el-table-column prop="triggerCount" :label="$t('monitor.triggerCount')" width="110" align="right" sortable>
            <template #default="{ row }"><span class="mn-mono trigger-count">{{ row.triggerCount }}</span></template>
          </el-table-column>
          <el-table-column prop="lastTriggered" :label="$t('monitor.lastTriggered')" min-width="150">
            <template #default="{ row }"><span class="mn-time">{{ formatDateTime(row.lastTriggered, '—') }}</span></template>
          </el-table-column>
          <el-table-column prop="status" :label="$t('common.status')" width="90" align="center">
            <template #default="{ row }">
              <el-switch :model-value="row.status === '启用'" size="small" @change="() => toggleRuleStatus(row)" />
            </template>
          </el-table-column>
          <el-table-column :label="$t('common.operation')" width="120" fixed="right">
            <template #default="{ row }">
              <div class="mn-row-ops">
                <el-button plain type="primary" @click="openEditRule(row)">{{ $t('common.edit') }}</el-button>
                <el-button plain type="danger" @click="removeRule(row)">{{ $t('common.delete') }}</el-button>
              </div>
            </template>
          </el-table-column>
          <template #empty><el-empty :description="$t('monitor.noAlertRules')" /></template>
        </el-table>
      </template>

      <template v-else-if="pageTab === 'groups'">
        <div class="mn-toolbar">
          <div class="mn-toolbar-filters"></div>
          <div class="mn-toolbar-actions">
            <el-button type="primary" @click="openCreateGroup">{{ $t('monitor.createContactGroup') }}</el-button>
          </div>
        </div>

        <el-table :data="groups" v-loading="loading" stripe class="mn-table group-table" table-layout="auto">
          <el-table-column prop="name" :label="$t('monitor.groupName')" min-width="180" />
          <el-table-column :label="$t('monitor.groupMembers')" min-width="300" show-overflow-tooltip>
            <template #default="{ row }">{{ groupMembersLabel(row) || '--' }}</template>
          </el-table-column>
          <el-table-column prop="remark" :label="$t('common.remark')" min-width="180" show-overflow-tooltip />
          <el-table-column :label="$t('common.status')" width="90" align="center">
            <template #default="{ row }">
              <span :class="['mn-badge', statusClass(row.status)]">{{ statusLabel(row.status) }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="$t('common.operation')" width="120" fixed="right">
            <template #default="{ row }">
              <div class="mn-row-ops">
                <el-button plain type="primary" @click="openEditGroup(row)">{{ $t('common.edit') }}</el-button>
                <el-button plain type="danger" @click="removeGroup(row)">{{ $t('common.delete') }}</el-button>
              </div>
            </template>
          </el-table-column>
          <template #empty><el-empty :description="$t('monitor.noContactGroups')" /></template>
        </el-table>
      </template>

      <template v-else-if="pageTab === 'silence'">
        <div class="mn-toolbar">
          <div class="mn-toolbar-filters"></div>
          <div class="mn-toolbar-actions">
            <el-button type="primary" @click="openCreateSilence">{{ $t('monitor.createSilenceRule') }}</el-button>
          </div>
        </div>

        <el-table :data="silenceRules" v-loading="loading" stripe class="mn-table" table-layout="auto">
          <el-table-column prop="name" :label="$t('monitor.ruleName')" min-width="180" />
          <el-table-column prop="alertTypePattern" :label="$t('monitor.alertTypePattern')" min-width="180">
            <template #default="{ row }">{{ formatRuleTypePattern(row.alertTypePattern) }}</template>
          </el-table-column>
          <el-table-column prop="domainPattern" :label="$t('monitor.domainPattern')" min-width="180">
            <template #default="{ row }">{{ formatRuleTypePattern(row.domainPattern) }}</template>
          </el-table-column>
          <el-table-column prop="levels" :label="$t('monitor.levelScope')" min-width="150">
            <template #default="{ row }">{{ levelsLabel(row.levels) }}</template>
          </el-table-column>
          <el-table-column :label="$t('monitor.silenceWindow')" min-width="260">
            <template #default="{ row }">{{ formatDateTime(row.startAt) }} ~ {{ formatDateTime(row.endAt) }}</template>
          </el-table-column>
          <el-table-column :label="$t('common.status')" width="90" align="center">
            <template #default="{ row }"><span :class="['mn-badge', statusClass(row.status)]">{{ statusLabel(row.status) }}</span></template>
          </el-table-column>
          <el-table-column :label="$t('common.operation')" width="120" fixed="right">
            <template #default="{ row }">
              <div class="mn-row-ops">
                <el-button plain type="primary" @click="openEditSilence(row)">{{ $t('common.edit') }}</el-button>
                <el-button plain type="danger" @click="removeSilence(row)">{{ $t('common.delete') }}</el-button>
              </div>
            </template>
          </el-table-column>
          <template #empty><el-empty :description="$t('monitor.noSilenceRules')" /></template>
        </el-table>
      </template>

      <template v-else>
        <div class="mn-toolbar">
          <div class="mn-toolbar-filters"></div>
          <div class="mn-toolbar-actions">
            <el-button type="primary" @click="openCreateInhibit">{{ $t('monitor.createInhibitRule') }}</el-button>
          </div>
        </div>

        <el-table :data="inhibitRules" v-loading="loading" stripe class="mn-table" table-layout="auto">
          <el-table-column prop="name" :label="$t('monitor.ruleName')" min-width="180" />
          <el-table-column :label="$t('monitor.sourceCondition')" min-width="240">
            <template #default="{ row }">{{ row.sourceAlertType }} / {{ levelText(row.sourceLevel || '*') }}</template>
          </el-table-column>
          <el-table-column :label="$t('monitor.targetCondition')" min-width="240">
            <template #default="{ row }">{{ row.targetAlertType }} / {{ levelText(row.targetLevel || '*') }}</template>
          </el-table-column>
          <el-table-column prop="domainScoped" :label="$t('monitor.domainScoped')" width="130" align="center">
            <template #default="{ row }">{{ row.domainScoped ? $t('common.yes') : $t('common.no') }}</template>
          </el-table-column>
          <el-table-column :label="$t('common.status')" width="90" align="center">
            <template #default="{ row }"><span :class="['mn-badge', statusClass(row.status)]">{{ statusLabel(row.status) }}</span></template>
          </el-table-column>
          <el-table-column :label="$t('common.operation')" width="120" fixed="right">
            <template #default="{ row }">
              <div class="mn-row-ops">
                <el-button plain type="primary" @click="openEditInhibit(row)">{{ $t('common.edit') }}</el-button>
                <el-button plain type="danger" @click="removeInhibit(row)">{{ $t('common.delete') }}</el-button>
              </div>
            </template>
          </el-table-column>
          <template #empty><el-empty :description="$t('monitor.noInhibitRules')" /></template>
        </el-table>
      </template>
    </el-card>

    <el-dialog v-model="ruleDialogVisible" :title="isEditRule ? $t('monitor.editAlertRule') : $t('monitor.createAlertRule')" width="560px" append-to-body>
      <el-form :model="ruleForm" label-position="top">
        <el-form-item :label="$t('monitor.ruleName')">
          <el-input v-model="ruleForm.name" :placeholder="$t('monitor.ruleNamePlaceholder')" />
        </el-form-item>
        <div class="form-grid-3">
          <el-form-item :label="$t('monitor.monitorMetric')">
            <el-select v-model="ruleForm.metric" style="width:100%" @change="updateUnit">
              <el-option v-for="m in metricOptions" :key="m.value" :label="m.label" :value="m.value" />
            </el-select>
          </el-form-item>
          <el-form-item :label="$t('monitor.triggerCondition')">
            <el-select v-model="ruleForm.operator" style="width:100%">
              <el-option v-for="op in ['>','<','>=','<=']" :key="op" :label="op" :value="op" />
            </el-select>
          </el-form-item>
          <el-form-item :label="$t('monitor.thresholdLabel') + ' (' + ruleForm.unit + ')'">
            <el-input-number v-model="ruleForm.threshold" :min="0" controls-position="right" style="width:100%" />
          </el-form-item>
        </div>
        <div class="form-grid-2">
          <el-form-item :label="$t('monitor.durationLabel')">
            <el-input-number v-model="ruleForm.duration" :min="1" :max="60" controls-position="right" style="width:100%" />
          </el-form-item>
          <el-form-item :label="$t('monitor.channelSilenceMinutes')">
            <el-input-number v-model="ruleForm.silenceMinutes" :min="0" :max="1440" controls-position="right" style="width:100%" />
          </el-form-item>
        </div>
        <el-form-item :label="$t('monitor.contactGroup')">
          <el-select v-model="ruleForm.contactGroupId" style="width:100%" clearable>
            <el-option :label="$t('monitor.noContactGroup')" :value="0" />
            <el-option v-for="g in contactGroupOptions" :key="g.value" :label="g.label" :value="g.value" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('monitor.notifyChannel')">
          <el-checkbox-group v-model="ruleForm.channels">
            <el-checkbox-button v-for="c in channelOptions" :key="c.value" :label="c.value" :value="c.value">{{ c.label }}</el-checkbox-button>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item :label="$t('common.status')">
          <el-radio-group v-model="ruleForm.status">
            <el-radio-button :label="$t('common.enable')" value="启用" />
            <el-radio-button :label="$t('common.disable')" value="禁用" />
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="ruleDialogVisible = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitting" @click="submitRule">{{ isEditRule ? $t('common.save') : $t('common.create') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="batchRuleDialogVisible" :title="$t('monitor.batchEditRules')" width="620px" append-to-body>
      <div class="batch-edit-summary">{{ $t('monitor.batchSelectedCount', { n: selectedRuleCount }) }}</div>
      <el-form :model="batchRuleForm" label-position="top">
        <div class="batch-edit-item">
          <el-checkbox v-model="batchRuleForm.applyStatus">{{ $t('monitor.batchApplyStatus') }}</el-checkbox>
          <el-radio-group v-model="batchRuleForm.status" :disabled="!batchRuleForm.applyStatus">
            <el-radio-button :label="$t('common.enable')" value="启用" />
            <el-radio-button :label="$t('common.disable')" value="禁用" />
          </el-radio-group>
        </div>

        <div class="batch-edit-item">
          <el-checkbox v-model="batchRuleForm.applyDuration">{{ $t('monitor.batchApplyDuration') }}</el-checkbox>
          <el-input-number
            v-model="batchRuleForm.duration"
            :disabled="!batchRuleForm.applyDuration"
            :min="1"
            :max="60"
            controls-position="right"
            style="width:200px"
          />
        </div>

        <div class="batch-edit-item">
          <el-checkbox v-model="batchRuleForm.applySilenceMinutes">{{ $t('monitor.batchApplySilenceMinutes') }}</el-checkbox>
          <el-input-number
            v-model="batchRuleForm.silenceMinutes"
            :disabled="!batchRuleForm.applySilenceMinutes"
            :min="0"
            :max="1440"
            controls-position="right"
            style="width:200px"
          />
        </div>

        <div class="batch-edit-item">
          <el-checkbox v-model="batchRuleForm.applyContactGroup">{{ $t('monitor.batchApplyContactGroup') }}</el-checkbox>
          <el-select v-model="batchRuleForm.contactGroupId" :disabled="!batchRuleForm.applyContactGroup" style="width:260px" clearable>
            <el-option :label="$t('monitor.noContactGroup')" :value="0" />
            <el-option v-for="g in contactGroupOptions" :key="g.value" :label="g.label" :value="g.value" />
          </el-select>
        </div>

        <div class="batch-edit-item batch-edit-item--block">
          <el-checkbox v-model="batchRuleForm.applyChannels">{{ $t('monitor.batchApplyChannels') }}</el-checkbox>
          <el-checkbox-group v-model="batchRuleForm.channels" :disabled="!batchRuleForm.applyChannels">
            <el-checkbox-button v-for="c in channelOptions" :key="c.value" :label="c.value" :value="c.value">{{ c.label }}</el-checkbox-button>
          </el-checkbox-group>
        </div>
      </el-form>
      <template #footer>
        <el-button @click="batchRuleDialogVisible = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="batchSubmitting" @click="submitBatchRule">{{ $t('common.save') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="groupDialogVisible" :title="isEditGroup ? $t('monitor.editContactGroup') : $t('monitor.createContactGroup')" width="560px" append-to-body>
      <el-form :model="groupForm" label-position="top">
        <el-form-item :label="$t('monitor.groupName')">
          <el-input v-model="groupForm.name" :placeholder="$t('monitor.groupNamePlaceholder')" />
        </el-form-item>
        <el-form-item :label="$t('monitor.groupMembers')">
          <el-select v-model="groupForm.memberUserIds" multiple filterable collapse-tags collapse-tags-tooltip style="width:100%" :placeholder="$t('monitor.selectGroupMembers')">
            <el-option v-for="u in users" :key="u.id" :label="(u.realName || u.username) + ' (' + u.username + ')'" :value="u.id" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('common.remark')">
          <el-input v-model="groupForm.remark" type="textarea" :rows="3" />
        </el-form-item>
        <el-form-item :label="$t('common.status')">
          <el-radio-group v-model="groupForm.status">
            <el-radio-button :label="$t('common.enable')" value="启用" />
            <el-radio-button :label="$t('common.disable')" value="禁用" />
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="groupDialogVisible = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitting" @click="submitGroup">{{ isEditGroup ? $t('common.save') : $t('common.create') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="silenceDialogVisible" :title="isEditSilence ? $t('monitor.editSilenceRule') : $t('monitor.createSilenceRule')" width="620px" append-to-body>
      <el-form :model="silenceForm" label-position="top">
        <el-form-item :label="$t('monitor.ruleName')">
          <el-input v-model="silenceForm.name" :placeholder="$t('monitor.silenceRuleNamePlaceholder')" />
        </el-form-item>
        <div class="form-grid-2">
          <el-form-item :label="$t('monitor.alertTypePattern')">
            <el-input v-model="silenceForm.alertTypePattern" :placeholder="$t('monitor.patternPlaceholderSimple')" />
          </el-form-item>
          <el-form-item :label="$t('monitor.domainPattern')">
            <el-input v-model="silenceForm.domainPattern" :placeholder="$t('monitor.patternPlaceholderSimple')" />
          </el-form-item>
        </div>
        <el-form-item :label="$t('monitor.levelScope')">
          <el-input v-model="silenceForm.levels" :placeholder="$t('monitor.levelScopePlaceholder')" />
          <p class="form-help">{{ $t('monitor.levelScopeHint') }}</p>
        </el-form-item>
        <div class="form-grid-2">
          <el-form-item :label="$t('monitor.startAt')">
            <el-date-picker v-model="silenceForm.startAt" type="datetime" style="width:100%" />
          </el-form-item>
          <el-form-item :label="$t('monitor.endAt')">
            <el-date-picker v-model="silenceForm.endAt" type="datetime" style="width:100%" />
          </el-form-item>
        </div>
        <el-form-item :label="$t('common.status')">
          <el-radio-group v-model="silenceForm.status">
            <el-radio-button :label="$t('common.enable')" value="启用" />
            <el-radio-button :label="$t('common.disable')" value="禁用" />
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="silenceDialogVisible = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitting" @click="submitSilence">{{ isEditSilence ? $t('common.save') : $t('common.create') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="inhibitDialogVisible" :title="isEditInhibit ? $t('monitor.editInhibitRule') : $t('monitor.createInhibitRule')" width="620px" append-to-body>
      <el-form :model="inhibitForm" label-position="top">
        <el-form-item :label="$t('monitor.ruleName')">
          <el-input v-model="inhibitForm.name" :placeholder="$t('monitor.inhibitRuleNamePlaceholder')" />
        </el-form-item>
        <div class="form-grid-2">
          <el-form-item :label="$t('monitor.sourceAlertType')">
            <el-input v-model="inhibitForm.sourceAlertType" :placeholder="$t('monitor.alertTypePlaceholder')" />
          </el-form-item>
          <el-form-item :label="$t('monitor.sourceLevel')">
            <el-select v-model="inhibitForm.sourceLevel" clearable style="width:100%" :placeholder="$t('monitor.anyLevel')">
              <el-option v-for="lv in levelOptions" :key="lv.value" :label="lv.label" :value="lv.value" />
            </el-select>
          </el-form-item>
        </div>
        <div class="form-grid-2">
          <el-form-item :label="$t('monitor.targetAlertType')">
            <el-input v-model="inhibitForm.targetAlertType" :placeholder="$t('monitor.alertTypePlaceholder')" />
          </el-form-item>
          <el-form-item :label="$t('monitor.targetLevel')">
            <el-select v-model="inhibitForm.targetLevel" clearable style="width:100%" :placeholder="$t('monitor.anyLevel')">
              <el-option v-for="lv in levelOptions" :key="lv.value" :label="lv.label" :value="lv.value" />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item :label="$t('monitor.domainScoped')">
          <el-switch v-model="inhibitForm.domainScoped" />
          <p class="form-help">{{ $t('monitor.domainScopedHint') }}</p>
        </el-form-item>
        <el-form-item :label="$t('common.status')">
          <el-radio-group v-model="inhibitForm.status">
            <el-radio-button :label="$t('common.enable')" value="启用" />
            <el-radio-button :label="$t('common.disable')" value="禁用" />
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="inhibitDialogVisible = false">{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="submitting" @click="submitInhibit">{{ isEditInhibit ? $t('common.save') : $t('common.create') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.mn-stats-strip {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
}

.mn-stat-tile {
  display: flex;
  flex-direction: row;
  align-items: center;
  gap: 14px;
  padding: 14px 24px;
  border-radius: 10px;
  border: 1px solid var(--app-border);
  background: var(--app-bg);
  min-width: 100px;
  flex: 1;
  box-shadow: var(--app-shadow-soft);
}

.mn-stat-value {
  font-size: 28px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.03em;
  line-height: 1;
}

.mn-stat-label {
  font-size: 12px;
  font-weight: 500;
  color: var(--app-text-regular);
  line-height: 1.4;
}

.mn-stat-tile--success .mn-stat-value {
  color: var(--app-success);
}

.mn-stat-tile--warning .mn-stat-value {
  color: var(--app-warning);
}

.inner-tabs {
  margin-bottom: 8px;
}

.form-grid-3 {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 0 12px;
}

.form-grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 12px;
}

.type-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  color: #fff;
}

.tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.condition-text {
  font-size: 13px;
  color: var(--app-text-primary, #1d2129);
}

.trigger-count {
  color: var(--app-warning);
  font-weight: 600;
}

.form-help {
  margin: 6px 0 0;
  color: var(--app-text-secondary);
  font-size: 12px;
}

.batch-edit-summary {
  margin: 0 0 12px;
  color: var(--app-text-secondary);
  font-size: 13px;
}

.batch-edit-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  padding: 10px 12px;
  margin-bottom: 12px;
}

.batch-edit-item--block {
  align-items: flex-start;
  flex-direction: column;
}

:deep(.rule-table .el-table__header-wrapper th .cell),
:deep(.group-table .el-table__header-wrapper th .cell) {
  white-space: nowrap;
  word-break: keep-all;
}

@media (max-width: 900px) {
  .form-grid-3,
  .form-grid-2 {
    grid-template-columns: 1fr;
  }
}
</style>
