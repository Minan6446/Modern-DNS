<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import BaseChart from '../../components/BaseChart.vue'
import { useReport } from '../../composables/monitor/useReport'

const { t } = useI18n()
const route = useRoute()

const {
  filterForm,
  reportTypeOptions,
  aggregateOptions,
  querying,
  exporting,
  fullscreenVisible,
  chartType,
  loading,
  lastUpdated,
  reportData,
  tableData,
  visibleCharts,
  reportIsEmpty,
  extended,
  fetchReportData,
  handleSearch,
  handleReset,
  exportReport,
  openChartFullscreen,
  closeFullscreenDialog,
  onFullscreenOpened,
} = useReport()

const formatCompactNumber = (value: number): string => {
  const abs = Math.abs(value)
  if (abs >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(1)}M`
  }
  if (abs >= 1_000) {
    return `${(value / 1_000).toFixed(1)}K`
  }
  return `${value}`
}

const normalizeStatusCode = (value: string): string => {
  const text = String(value || '').trim()
  const upper = text.toUpperCase()
  if (!upper) {
    return ''
  }
  if (upper === 'SUCCESS' || text === '成功') {
    return 'NOERROR'
  }
  if (upper === 'FAIL' || text === '失败') {
    return 'SERVFAIL'
  }
  return upper
}

const topDomainOption = computed(() => ({
  grid: { left: 12, right: 12, top: 22, bottom: 12, containLabel: true },
  tooltip: { trigger: 'axis', confine: true, axisPointer: { type: 'shadow' } },
  xAxis: { type: 'value', splitLine: { show: false }, axisLabel: { formatter: (v: number) => formatCompactNumber(v) } },
  yAxis: { type: 'category', data: reportData.value.topDomain.map((item) => item.name), inverse: true, splitLine: { show: false } },
  series: [
    {
      name: t('monitor.queryCountLabel'),
      type: 'bar',
      barMaxWidth: 22,
      data: reportData.value.topDomain.map((item) => item.value),
      itemStyle: {
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 1,
          y2: 0,
          colorStops: [
            { offset: 0, color: '#1677FF' },
            { offset: 1, color: '#69B1FF' },
          ],
        },
      },
    },
  ],
}))

const topIpOption = computed(() => ({
  grid: { left: 12, right: 12, top: 22, bottom: 12, containLabel: true },
  tooltip: { trigger: 'axis', confine: true, axisPointer: { type: 'shadow' } },
  xAxis: { type: 'value', splitLine: { show: false }, axisLabel: { formatter: (v: number) => formatCompactNumber(v) } },
  yAxis: { type: 'category', data: reportData.value.topIp.map((item) => item.name), inverse: true, splitLine: { show: false } },
  series: [
    {
      name: t('monitor.visitCountLabel'),
      type: 'bar',
      barMaxWidth: 22,
      data: reportData.value.topIp.map((item) => item.value),
      itemStyle: {
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 1,
          y2: 0,
          colorStops: [
            { offset: 0, color: '#1677FF' },
            { offset: 1, color: '#95DE64' },
          ],
        },
      },
    },
  ],
}))

const heatmapOption = computed(() => ({
  grid: { left: 12, right: 12, top: 22, bottom: 38, containLabel: true },
  tooltip: { position: 'top', confine: true },
  xAxis: { type: 'category', data: reportData.value.heatmap.periods || [], splitLine: { show: false } },
  yAxis: { type: 'category', data: reportData.value.heatmap.regions || [], splitLine: { show: false } },
  visualMap: {
    min: 0,
    max: Math.max(1, ...((reportData.value.heatmap.values || []).map((item) => Number(item[2] || 0)))),
    calculable: true,
    orient: 'horizontal',
    left: 'center',
    bottom: 0,
    inRange: { color: ['#E6F4FF', '#91CAFF', '#1677FF'] },
  },
  series: [{ type: 'heatmap', data: reportData.value.heatmap.values || [], label: { show: true, formatter: (item: { value: number[] }) => formatCompactNumber(item.value[2]) } }],
}))

const statusPieOption = computed(() => ({
  tooltip: {
    trigger: 'item',
    confine: true,
    formatter: (params: { name?: string; value?: number }) => {
      const value = Number(params?.value || 0)
      const total = reportData.value.statusDistribution.reduce((sum, item) => sum + Number(item.value || 0), 0)
      const percent = total ? ((value / total) * 100).toFixed(2) : '0.00'
      return `${params?.name}<br/>${t('monitor.quantityLabel')}: ${formatCompactNumber(value)}<br/>${t('monitor.percentLabel')}: ${percent}%`
    },
  },
  legend: { bottom: 0, left: 'center' },
  series: [
    {
      name: t('monitor.resolveStatusLabel'),
      type: 'pie',
      radius: ['46%', '70%'],
      avoidLabelOverlap: false,
      label: { show: true, formatter: '{b} {d}%' },
      data: reportData.value.statusDistribution,
      color: reportData.value.statusDistribution.map((item) => ({
        NOERROR: '#00B42A',
        CACHED: '#86909C',
        NXDOMAIN: '#FF7D00',
        SERVFAIL: '#F53F3F',
        REFUSED: '#4E5969',
      }[normalizeStatusCode((item as { statusCode?: string; rawName?: string; name?: string }).statusCode || (item as { rawName?: string; name?: string }).rawName || item.name)] || '#86909C')),
    },
  ],
}))

// ── Extended (A-tier) chart options ────────────────────────────────────
// Each follows the same conventions as the four legacy charts so the
// off-screen export renderer can treat them uniformly. We intentionally
// duplicate the colour palette references (rather than reading from
// echarts theme) because the export render path doesn't get the
// runtime theme applied — colours have to be baked into the option.

const recordTypeOption = computed(() => ({
  tooltip: { trigger: 'item', confine: true, formatter: '{b}: {c} ({d}%)' },
  legend: { bottom: 0, left: 'center' },
  series: [
    {
      name: t('monitor.recordTypeDist'),
      type: 'pie',
      radius: ['45%', '70%'],
      avoidLabelOverlap: true,
      label: { show: true, formatter: '{b} {d}%' },
      data: extended.value.recordTypes,
    },
  ],
}))

const latencyHistogramOption = computed(() => ({
  grid: { left: 12, right: 12, top: 22, bottom: 24, containLabel: true },
  tooltip: { trigger: 'axis', confine: true, axisPointer: { type: 'shadow' } },
  xAxis: {
    type: 'category',
    data: extended.value.latencyBuckets.map((item) => item.name),
    axisLabel: { interval: 0, fontSize: 11 },
  },
  yAxis: { type: 'value', splitLine: { show: false }, axisLabel: { formatter: (v: number) => formatCompactNumber(v) } },
  series: [
    {
      name: t('monitor.quantityLabel'),
      type: 'bar',
      barMaxWidth: 36,
      data: extended.value.latencyBuckets.map((item) => item.value),
      itemStyle: {
        color: {
          type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
          colorStops: [
            { offset: 0, color: '#52C41A' },
            { offset: 1, color: '#F5222D' },
          ],
        },
      },
    },
  ],
}))

const qpsTrendOption = computed(() => ({
  grid: { left: 12, right: 12, top: 22, bottom: 24, containLabel: true },
  tooltip: { trigger: 'axis', confine: true },
  xAxis: {
    type: 'category',
    boundaryGap: false,
    data: extended.value.qpsTrend.periods,
    axisLabel: { hideOverlap: true, fontSize: 11 },
  },
  yAxis: { type: 'value', splitLine: { show: false }, axisLabel: { formatter: (v: number) => formatCompactNumber(v) } },
  series: [
    {
      name: t('monitor.queryCountLabel'),
      type: 'line',
      smooth: true,
      showSymbol: false,
      areaStyle: { opacity: 0.18 },
      data: extended.value.qpsTrend.values,
      itemStyle: { color: '#1677FF' },
      lineStyle: { color: '#1677FF', width: 2 },
    },
  ],
}))

const rcodeTrendOption = computed(() => {
  // Pre-compute palette keyed by rcode so legend colours don't shuffle
  // when ECharts re-orders series. Specific rcodes get a fixed colour
  // (NOERROR green, SERVFAIL red, etc.) for instant operator
  // recognition; everything else cycles through a soft palette.
  const palette: Record<string, string> = {
    NOERROR: '#52C41A',
    NXDOMAIN: '#FAAD14',
    SERVFAIL: '#F5222D',
    REFUSED: '#722ED1',
    FORMERR: '#13C2C2',
  }
  const fallback = ['#1677FF', '#FF7A45', '#A0D911', '#9254DE', '#36CFC9']
  const series = extended.value.rcodeTrend.series.map((s, idx) => ({
    name: s.name,
    type: 'line',
    stack: 'rcode',
    smooth: true,
    showSymbol: false,
    areaStyle: { opacity: 0.6 },
    data: s.data,
    itemStyle: { color: palette[s.name] || fallback[idx % fallback.length] },
  }))
  return {
    grid: { left: 12, right: 12, top: 38, bottom: 24, containLabel: true },
    tooltip: { trigger: 'axis', confine: true },
    legend: { top: 4, left: 'center' },
    xAxis: { type: 'category', boundaryGap: false, data: extended.value.rcodeTrend.periods, axisLabel: { hideOverlap: true, fontSize: 11 } },
    yAxis: { type: 'value', splitLine: { show: false }, axisLabel: { formatter: (v: number) => formatCompactNumber(v) } },
    series,
  }
})

const slowDomainOption = computed(() => ({
  grid: { left: 12, right: 12, top: 22, bottom: 12, containLabel: true },
  tooltip: {
    trigger: 'axis',
    confine: true,
    axisPointer: { type: 'shadow' },
    formatter: (params: Array<{ name: string; value: number; dataIndex: number }>) => {
      const row = extended.value.slowDomains[params[0]?.dataIndex] || ({} as any)
      return `${row.name || ''}<br/>${t('monitor.avgLatency')}: ${Math.round(row.avgLatencyMs || 0)}ms<br/>${t('monitor.maxLatency')}: ${row.maxLatencyMs || 0}ms<br/>${t('monitor.sampleCount')}: ${row.sampleCount || 0}`
    },
  },
  xAxis: { type: 'value', splitLine: { show: false }, axisLabel: { formatter: '{value} ms' } },
  yAxis: { type: 'category', inverse: true, data: extended.value.slowDomains.map((item) => item.name), splitLine: { show: false } },
  series: [
    {
      name: t('monitor.avgLatency'),
      type: 'bar',
      barMaxWidth: 22,
      data: extended.value.slowDomains.map((item) => Math.round(item.avgLatencyMs)),
      itemStyle: {
        color: {
          type: 'linear', x: 0, y: 0, x2: 1, y2: 0,
          colorStops: [
            { offset: 0, color: '#FA8C16' },
            { offset: 1, color: '#F5222D' },
          ],
        },
      },
    },
  ],
}))

const fullscreenOption = computed(() => {
  switch (chartType.value) {
    case 'domain': return topDomainOption.value
    case 'ip': return topIpOption.value
    case 'heatmap': return heatmapOption.value
    case 'recordType': return recordTypeOption.value
    case 'latency': return latencyHistogramOption.value
    case 'qpsTrend': return qpsTrendOption.value
    case 'rcodeTrend': return rcodeTrendOption.value
    case 'slowDomain': return slowDomainOption.value
    case 'status':
    default: return statusPieOption.value
  }
})

// Thin wrapper that hands the current chart option objects into the
// composable's export pipeline. Kept in the page (not the composable)
// because the option computeds reference template-only locals like
// formatCompactNumber and the i18n-localised tooltip formatters.
const handleExportCommand = (command: string): void => {
  void exportReport(command, {
    domain: topDomainOption.value,
    ip: topIpOption.value,
    heatmap: heatmapOption.value,
    status: statusPieOption.value,
    recordType: recordTypeOption.value,
    latency: latencyHistogramOption.value,
    qpsTrend: qpsTrendOption.value,
    rcodeTrend: rcodeTrendOption.value,
    slowDomain: slowDomainOption.value,
  })
}

onMounted(async () => {
  await fetchReportData()
})
</script>

<template>
  <div class="monitor-shell page-shell">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ $t('menu.' + route.meta.titleKey) }}</h1>
        <p class="page-subtitle">{{ $t('monitor.reportSubtitle') }}{{ $t('common.lastRefresh') }}{{ lastUpdated || $t('common.loading') }}</p>
      </div>
    </div>

    <div class="stack-card">
      <!-- ── 查询条 ── -->
      <el-card class="monitor-card">
        <div class="mn-toolbar">
          <div class="mn-toolbar-filters">
            <el-select v-model="filterForm.reportType" style="width: 140px">
              <el-option v-for="item in reportTypeOptions" :key="item.value" :label="item.label" :value="item.value" />
            </el-select>
            <el-select v-model="filterForm.aggregateDimension" style="width: 160px">
              <el-option v-for="item in aggregateOptions" :key="item.value" :label="item.label" :value="item.value" />
            </el-select>
            <el-select v-model="filterForm.timePreset" style="width: 130px">
              <el-option :label="$t('monitor.last1d')" value="1d" />
              <el-option :label="$t('monitor.last7d')" value="7d" />
              <el-option :label="$t('monitor.last30d')" value="30d" />
              <el-option :label="$t('monitor.custom')" value="custom" />
            </el-select>
            <el-date-picker
              v-if="filterForm.timePreset === 'custom'"
              v-model="filterForm.timeRange"
              type="daterange"
              value-format="YYYY-MM-DD"
              :range-separator="$t('monitor.rangeSeparator')"
              :start-placeholder="$t('monitor.startTime')"
              :end-placeholder="$t('monitor.endTime')"
            />
            <el-input v-model="filterForm.domain" clearable :placeholder="$t('monitor.filterByDomain')" style="width: 200px">
              <template #prefix><svg class="mn-input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></template>
            </el-input>
            <el-button type="primary" :loading="querying" @click="handleSearch">{{ $t('monitor.query') }}</el-button>
            <el-button @click="handleReset">{{ $t('common.reset') }}</el-button>
          </div>
          <div class="mn-toolbar-actions">
            <el-dropdown @command="handleExportCommand">
              <el-button :loading="exporting" :disabled="exporting">
                <template #icon><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></template>
                {{ $t('monitor.exportReport') }}
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="excel">{{ $t('monitor.exportExcel') }}</el-dropdown-item>
                  <el-dropdown-item command="pdf">{{ $t('monitor.exportPdf') }}</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </div>
      </el-card>

      <!-- ── 聚合明细表 ── -->
      <el-card class="monitor-card agg-table-card">
        <template #header>
          <div class="mn-chart-header">
            <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
            <span>{{ $t('monitor.aggregateTable') }}</span>
          </div>
        </template>
        <el-table v-if="tableData.length" :data="tableData" stripe class="mn-table">
          <el-table-column prop="rank" :label="$t('monitor.rank')" width="90" />
          <el-table-column prop="category" :label="$t('monitor.dimType')" width="120" />
          <el-table-column prop="label" :label="$t('monitor.dimValue')" min-width="220" show-overflow-tooltip />
          <el-table-column prop="value" :label="$t('monitor.aggValue')" min-width="120" align="right" />
        </el-table>
        <el-empty v-else :description="$t('monitor.noAggData')" />
      </el-card>

      <!-- ── 图表区 ── -->
      <div class="mn-chart-grid">
        <el-card v-if="visibleCharts.includes('domain')" class="monitor-card">
          <template #header>
            <div class="mn-chart-header">
              <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
              <span>{{ $t('monitor.topDomainStats') }}</span>
              <el-button text type="primary" style="margin-left:auto" @click="openChartFullscreen('domain')">{{ $t('monitor.fullscreen') }}</el-button>
            </div>
          </template>
          <el-skeleton v-if="loading || querying" animated :rows="7" />
          <el-empty v-else-if="!reportData.topDomain.length" :description="$t('monitor.noReportData')" />
          <BaseChart v-else :option="topDomainOption" :loading="false" :empty="false" height="320px" />
        </el-card>

        <el-card v-if="visibleCharts.includes('ip')" class="monitor-card">
          <template #header>
            <div class="mn-chart-header">
              <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
              <span>{{ $t('monitor.topIpStats') }}</span>
              <el-button text type="primary" style="margin-left:auto" @click="openChartFullscreen('ip')">{{ $t('monitor.fullscreen') }}</el-button>
            </div>
          </template>
          <el-skeleton v-if="loading || querying" animated :rows="7" />
          <el-empty v-else-if="!reportData.topIp.length" :description="$t('monitor.noReportData')" />
          <BaseChart v-else :option="topIpOption" :loading="false" :empty="false" height="320px" />
        </el-card>

        <el-card v-if="visibleCharts.includes('heatmap')" class="monitor-card">
          <template #header>
            <div class="mn-chart-header">
              <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
              <span>{{ $t('monitor.geoHeatmap') }}</span>
              <el-button text type="primary" style="margin-left:auto" @click="openChartFullscreen('heatmap')">{{ $t('monitor.fullscreen') }}</el-button>
            </div>
          </template>
          <el-skeleton v-if="loading || querying" animated :rows="7" />
          <el-empty v-else-if="!reportData.heatmap.values.length" :description="$t('monitor.noReportData')" />
          <BaseChart v-else :option="heatmapOption" :loading="false" :empty="false" height="320px" />
        </el-card>

        <el-card v-if="visibleCharts.includes('status')" class="monitor-card">
          <template #header>
            <div class="mn-chart-header">
              <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.21 15.89A10 10 0 1 1 8 2.83"/><path d="M22 12A10 10 0 0 0 12 2v10z"/></svg>
              <span>{{ $t('monitor.statusDist') }}</span>
              <el-button text type="primary" style="margin-left:auto" @click="openChartFullscreen('status')">{{ $t('monitor.fullscreen') }}</el-button>
            </div>
          </template>
          <el-skeleton v-if="loading || querying" animated :rows="7" />
          <el-empty v-else-if="!reportData.statusDistribution.length" :description="$t('monitor.noReportData')" />
          <BaseChart v-else :option="statusPieOption" :loading="false" :empty="false" height="320px" />
        </el-card>

        <!-- ── 扩展报表 (A-tier) — 5 张新图，由 /monitor/report/extended 提供数据 ── -->
        <el-card v-if="visibleCharts.includes('recordType')" class="monitor-card">
          <template #header>
            <div class="mn-chart-header">
              <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              <span>{{ $t('monitor.recordTypeDist') }}</span>
              <el-button text type="primary" style="margin-left:auto" @click="openChartFullscreen('recordType')">{{ $t('monitor.fullscreen') }}</el-button>
            </div>
          </template>
          <el-empty v-if="!extended.recordTypes.length" :description="$t('monitor.noReportData')" />
          <BaseChart v-else :option="recordTypeOption" :loading="false" :empty="false" height="320px" />
        </el-card>

        <el-card v-if="visibleCharts.includes('latency')" class="monitor-card">
          <template #header>
            <div class="mn-chart-header">
              <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              <span>{{ $t('monitor.latencyHistogram') }}</span>
              <el-button text type="primary" style="margin-left:auto" @click="openChartFullscreen('latency')">{{ $t('monitor.fullscreen') }}</el-button>
            </div>
          </template>
          <el-empty v-if="!extended.latencyBuckets.length" :description="$t('monitor.noReportData')" />
          <BaseChart v-else :option="latencyHistogramOption" :loading="false" :empty="false" height="320px" />
        </el-card>

        <el-card v-if="visibleCharts.includes('qpsTrend')" class="monitor-card">
          <template #header>
            <div class="mn-chart-header">
              <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              <span>{{ $t('monitor.qpsTrend') }}</span>
              <el-button text type="primary" style="margin-left:auto" @click="openChartFullscreen('qpsTrend')">{{ $t('monitor.fullscreen') }}</el-button>
            </div>
          </template>
          <el-empty v-if="!extended.qpsTrend.values.length" :description="$t('monitor.noReportData')" />
          <BaseChart v-else :option="qpsTrendOption" :loading="false" :empty="false" height="320px" />
        </el-card>

        <el-card v-if="visibleCharts.includes('rcodeTrend')" class="monitor-card">
          <template #header>
            <div class="mn-chart-header">
              <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 4 6-6"/></svg>
              <span>{{ $t('monitor.rcodeTrend') }}</span>
              <el-button text type="primary" style="margin-left:auto" @click="openChartFullscreen('rcodeTrend')">{{ $t('monitor.fullscreen') }}</el-button>
            </div>
          </template>
          <el-empty v-if="!extended.rcodeTrend.series.length" :description="$t('monitor.noReportData')" />
          <BaseChart v-else :option="rcodeTrendOption" :loading="false" :empty="false" height="320px" />
        </el-card>

        <el-card v-if="visibleCharts.includes('slowDomain')" class="monitor-card">
          <template #header>
            <div class="mn-chart-header">
              <svg class="mn-chart-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
              <span>{{ $t('monitor.slowDomainTop') }}</span>
              <el-button text type="primary" style="margin-left:auto" @click="openChartFullscreen('slowDomain')">{{ $t('monitor.fullscreen') }}</el-button>
            </div>
          </template>
          <el-empty v-if="!extended.slowDomains.length" :description="$t('monitor.noReportData')" />
          <BaseChart v-else :option="slowDomainOption" :loading="false" :empty="false" height="320px" />
        </el-card>
      </div>

      <el-empty v-if="!loading && !querying && reportIsEmpty" :description="$t('monitor.noReportData')" />
    </div>

    <el-dialog
      v-model="fullscreenVisible"
      :title="$t('monitor.reportFullscreen')"
      width="80%"
      destroy-on-close
      append-to-body
      center
      :show-close="true"
      :close-on-click-modal="true"
      :close-on-press-escape="true"
      modal-class="monitor-fullscreen-overlay"
      @opened="onFullscreenOpened"
      @close="closeFullscreenDialog"
    >
      <BaseChart :option="fullscreenOption" :loading="false" :empty="false" height="70vh" />
    </el-dialog>
  </div>
</template>

<style scoped>
/* ═══════════════ Page ═══════════════ */
.monitor-shell {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

/* ═══════════════ Cards ═══════════════ */
.monitor-card {
  border: 1px solid var(--app-border);
  border-radius: 10px;
  box-shadow: var(--app-shadow-soft);
  overflow: hidden;
}

.monitor-card :deep(.el-card__header) {
  padding: 13px 16px;
  background: var(--app-bg-secondary);
  border-bottom: 1px solid var(--app-border);
}

.monitor-card :deep(.el-card__body) {
  padding: 16px;
}

.agg-table-card :deep(.el-card__body) {
  padding: 0;
}

/* ═══════════════ Toolbar ═══════════════ */
.mn-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
}

.mn-toolbar-filters {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  flex: 1;
}

.mn-toolbar-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}

.mn-input-icon {
  width: 13px;
  height: 13px;
  color: var(--app-text-regular);
}

/* ═══════════════ Chart headers ═══════════════ */
.mn-chart-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  font-weight: 600;
  color: var(--app-title);
}

.mn-chart-icon {
  width: 15px;
  height: 15px;
  color: var(--app-accent);
  flex-shrink: 0;
}

/* ═══════════════ Table ═══════════════ */
.mn-table :deep(.el-table__header th) {
  background: var(--app-bg-secondary);
  color: var(--app-text-secondary);
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.mn-table :deep(.el-table__body tr:hover > td.el-table__cell) {
  background: rgba(22, 93, 255, 0.04) !important;
}

/* ═══════════════ Charts grid ═══════════════ */
.mn-chart-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

/* ═══════════════ Fullscreen dialog overlay ═══════════════ */
:global(.monitor-fullscreen-overlay) {
  background: rgba(29, 33, 41, 0.28) !important;
}

/* ═══════════════ Responsive ═══════════════ */
@media (max-width: 1100px) {
  .mn-chart-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 768px) {
  .mn-toolbar {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>