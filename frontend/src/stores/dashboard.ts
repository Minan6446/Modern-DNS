import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { getOverview, getDomainStatus, getAlerts, getResource } from '../api/dashboard'
import type { DashboardModuleData } from '../types/modules'
import { nowDateTime } from '../utils/datetime'

const FILTER_MAP: Record<string, string> = {
  today: 'today',
  '7d': 'week',
  '30d': 'month',
  custom: 'month',
}

const emptyOverviewSlice = () => ({
  metrics: [],
  qps: { xAxis: [], data: [] },
  response: { xAxis: [], avg: [], max: [], min: [] },
  cache: { total: 0, series: [] },
  total: { xAxis: [], data: [] },
})

export const useDashboardStore = defineStore('dashboard', () => {
  const loading = ref(false)
  const rawData = ref<DashboardModuleData>({
    overview: {
      today: emptyOverviewSlice(),
    },
    domainStatus: [],
    alerts: { rules: [], rows: [], auditLogs: [] },
    resource: { day: { metrics: [], trend: { xAxis: [], queries: [], zones: [], records: [] }, usage: [] } },
  })
  const lastUpdated = ref('')
  const overviewRange = ref('today')
  const overviewCustomRange = ref<string[]>([])
  const resourceDimension = ref('day')
  let pollingTimer: number | null = null

  const fetchData = async () => {
    loading.value = true
    try {
      const range = overviewRange.value
      const dim = resourceDimension.value
      const [start, end] = overviewCustomRange.value
      const [overviewRes, domainRes, alertsRes, resourceRes] = await Promise.allSettled([
        getOverview(range, start, end),
        getDomainStatus(),
        getAlerts(),
        getResource(dim),
      ])

      const overviewData = overviewRes.status === 'fulfilled' ? overviewRes.value.data : null
      const domainData = domainRes.status === 'fulfilled' ? domainRes.value.data : null
      const alertsData = alertsRes.status === 'fulfilled' ? alertsRes.value.data : null
      const resourceData = resourceRes.status === 'fulfilled' ? resourceRes.value.data : null

      // overview response is a single flat slice (metrics/qps/response/
      // cache/total) scoped to the range parameter. The four chart
      // cards on the overview page follow the page-level range
      // selector directly — no per-chart granularity toggle anymore.
      const rangeKey = FILTER_MAP[range] || 'today'
      rawData.value = {
        overview: {
          today: emptyOverviewSlice(),
          week: emptyOverviewSlice(),
          month: emptyOverviewSlice(),
          // Stash the fresh payload under the mapped key so the
          // overviewData computed below always finds it.
          [rangeKey]: overviewData ?? emptyOverviewSlice(),
        },
        domainStatus: (domainData as any) ?? [],
        alerts: {
          rules: [],
          rows: [],
          auditLogs: [],
          ...((alertsData as any) ?? {}),
        },
        resource: {
          day: { metrics: [], trend: { xAxis: [], queries: [], zones: [], records: [] }, usage: [] },
          ...((resourceData as any) ?? {}),
        },
      }
      lastUpdated.value = nowDateTime()
    } finally {
      loading.value = false
    }
  }

  const startPolling = () => {
    if (pollingTimer) {
      window.clearInterval(pollingTimer)
    }
    pollingTimer = window.setInterval(fetchData, 30000)
  }

  const stopPolling = () => {
    if (pollingTimer) {
      window.clearInterval(pollingTimer)
      pollingTimer = null
    }
  }

  const setOverviewRange = (value: string): void => {
    overviewRange.value = value
  }

  const setOverviewCustomRange = (value: string[]): void => {
    overviewCustomRange.value = value
  }

  const setResourceDimension = (value: string): void => {
    resourceDimension.value = value
  }

  const overviewData = computed(() => {
    const mappedKey = FILTER_MAP[overviewRange.value] || 'today'
    return rawData.value.overview[mappedKey] || rawData.value.overview.today
  })

  const resourceData = computed(() => rawData.value.resource[resourceDimension.value] || rawData.value.resource.day)

  return {
    loading,
    rawData,
    lastUpdated,
    overviewRange,
    overviewCustomRange,
    resourceDimension,
    overviewData,
    resourceData,
    fetchData,
    startPolling,
    stopPolling,
    setOverviewRange,
    setOverviewCustomRange,
    setResourceDimension,
  }
})