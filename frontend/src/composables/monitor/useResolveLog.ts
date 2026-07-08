import { computed, onScopeDispose, reactive, ref, watch } from 'vue'
import { ElMessage, ElLoading } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { getResolveLogsApi } from '../../api/monitor'
import type { MonitorResolveLogRow } from '../../types/modules'
import { loadTableState, saveTableState } from '../../utils/tableState'
import { nowDateTime } from '../../utils/datetime'

type SortOrder = 'ascending' | 'descending' | null

type SortState = {
  prop: string
  order: SortOrder
}

type ResolveLogViewState = {
  filters: ResolveLogFilterForm
  pagination: ResolveLogPagination
  sorter: SortState
}

export interface ResolveLogFilterForm {
  keyword: string
  recordType: string
  rcode: string
  timePreset: string
  timeRange: string[]
}

export interface ResolveLogPagination {
  page: number
  size: number
  total: number
}

const RESOLVE_LOG_STATE_KEY = 'modern-dns:resolve-log:view-state'

const DEFAULT_FILTERS: ResolveLogFilterForm = {
  keyword: '',
  recordType: '',
  rcode: '',
  timePreset: '24h',
  timeRange: [],
}

const parseDate = (value: string | number | Date | null | undefined): number => {
  const normalized = String(value || '').trim().replace(' ', 'T')
  const timestamp = Date.parse(normalized)
  return Number.isNaN(timestamp) ? Date.now() : timestamp
}

const isWithinTime = (value: string, preset: string, range: string[]): boolean => {
  const ts = parseDate(value)
  const now = Date.now()
  const presetMap: Record<string, number> = {
    '1h': 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
  }

  if (preset !== 'custom') {
    return now - ts <= (presetMap[preset] || presetMap['24h'])
  }

  if (range.length === 2) {
    const start = parseDate(range[0])
    const end = parseDate(range[1])
    return ts >= start && ts <= end
  }

  return true
}

const copyText = async (text: string, success: string): Promise<void> => {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success(success)
  } catch (_error) {
    const textarea = document.createElement('textarea')
    textarea.value = text
    document.body.appendChild(textarea)
    textarea.select()
    document.execCommand('copy')
    document.body.removeChild(textarea)
    ElMessage.success(success)
  }
}

const exportRows = async (
  rows: Array<Record<string, unknown>>,
  baseName: string,
  format: 'excel' | 'csv' | 'json',
  t: (key: string, params?: Record<string, unknown>) => string,
): Promise<void> => {
  if (!rows.length) {
    ElMessage.warning(t('monitor.noExportData'))
    return
  }
  const loading = ElLoading.service({ text: t('monitor.resolveLogExporting', { format: format.toUpperCase() }), background: 'rgba(0,0,0,0.35)' })
  try {
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json;charset=utf-8' })
      const href = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = href
      anchor.download = `${baseName}.json`
      document.body.appendChild(anchor)
      anchor.click()
      document.body.removeChild(anchor)
      URL.revokeObjectURL(href)
      return
    }

    if (format === 'csv') {
      const columns = Object.keys(rows[0])
      const csv = [
        columns.join(','),
        ...rows.map((row) => columns.map((key) => `"${String(row[key] ?? '').replace(/"/g, '""')}"`).join(',')),
      ].join('\n')
      const blob = new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8' })
      const href = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = href
      anchor.download = `${baseName}.csv`
      document.body.appendChild(anchor)
      anchor.click()
      document.body.removeChild(anchor)
      URL.revokeObjectURL(href)
      return
    }

    const XLSX = await import('xlsx')
    const worksheet = XLSX.utils.json_to_sheet(rows)
    const workbook = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Export')
    XLSX.writeFile(workbook, `${baseName}.xlsx`)
  } finally {
    loading.close()
  }
}

export const useResolveLog = () => {
  const { t } = useI18n()
  const cachedState = loadTableState<ResolveLogViewState>(RESOLVE_LOG_STATE_KEY, {
    filters: DEFAULT_FILTERS,
    pagination: { page: 1, size: 10, total: 0 },
    sorter: { prop: 'time', order: 'descending' },
  })

  const loading = ref(false)
  const resolveLogs = ref<MonitorResolveLogRow[]>([])
  const lastUpdated = ref('')
  const filterForm = reactive<ResolveLogFilterForm>({ ...DEFAULT_FILTERS, ...cachedState.filters, timeRange: [...(cachedState.filters.timeRange || [])] })
  const appliedFilters = reactive<ResolveLogFilterForm>({ ...filterForm, timeRange: [...filterForm.timeRange] })
  const pagination = reactive<ResolveLogPagination>({
    page: cachedState.pagination.page || 1,
    size: cachedState.pagination.size || 10,
    total: 0,
  })
  const sortState = reactive<SortState>({
    prop: cachedState.sorter.prop || 'time',
    order: cachedState.sorter.order || 'descending',
  })
  const querying = ref(false)
  const refreshing = ref(false)
  const exporting = ref(false)
  const detailVisible = ref(false)
  const currentDetail = ref<MonitorResolveLogRow | null>(null)

  const resolveTimeRange = (preset: string, customRange: string[]): { startTime?: string; endTime?: string } => {
    if (preset === 'custom') {
      if (customRange.length === 2) {
        return { startTime: customRange[0], endTime: customRange[1] }
      }
      return {}
    }

    const hoursByPreset: Record<string, number> = {
      '1h': 1,
      '6h': 6,
      '24h': 24,
      '7d': 24 * 7,
    }
    const hours = hoursByPreset[preset] ?? 24
    const end = new Date()
    const start = new Date(end.getTime() - hours * 60 * 60 * 1000)
    const toSqlTime = (date: Date): string => {
      const y = date.getFullYear()
      const m = String(date.getMonth() + 1).padStart(2, '0')
      const d = String(date.getDate()).padStart(2, '0')
      const h = String(date.getHours()).padStart(2, '0')
      const mm = String(date.getMinutes()).padStart(2, '0')
      const s = String(date.getSeconds()).padStart(2, '0')
      return `${y}-${m}-${d} ${h}:${mm}:${s}`
    }
    return {
      startTime: toSqlTime(start),
      endTime: toSqlTime(end),
    }
  }

  watch(
    () => ({
      filters: { ...appliedFilters, timeRange: [...appliedFilters.timeRange] },
      pagination: { page: pagination.page, size: pagination.size, total: pagination.total },
      sorter: { ...sortState },
    }),
    (next) => {
      saveTableState(RESOLVE_LOG_STATE_KEY, next)
    },
    { deep: true },
  )

  const filteredRows = computed<MonitorResolveLogRow[]>(() =>
    resolveLogs.value.filter((item) => {
      const keyword = appliedFilters.keyword.trim().toLowerCase()
      const keywordMatch =
        !keyword ||
        [item.domain, item.queryId, item.transactionId, item.sourceIp]
          .some((field) => String(field || '').toLowerCase().includes(keyword))
      const typeMatch = !appliedFilters.recordType || item.recordType === appliedFilters.recordType
      const codeMatch = !appliedFilters.rcode || item.rcode === appliedFilters.rcode
      const timeMatch = isWithinTime(String(item.time || ''), appliedFilters.timePreset, appliedFilters.timeRange)
      return keywordMatch && typeMatch && codeMatch && timeMatch
    }),
  )

  const sortedRows = computed<MonitorResolveLogRow[]>(() => {
    const rows = [...filteredRows.value]
    if (!sortState.prop || !sortState.order) {
      return rows
    }
    const factor = sortState.order === 'ascending' ? 1 : -1
    return rows.sort((left, right) => String(left[sortState.prop] || '').localeCompare(String(right[sortState.prop] || '')) * factor)
  })

  const resolveRows = computed<MonitorResolveLogRow[]>(() => {
    return sortedRows.value
  })

  const fetchResolveLogs = async (): Promise<void> => {
    try {
      loading.value = true
      const keyword = appliedFilters.keyword.trim()
      const { startTime, endTime } = resolveTimeRange(appliedFilters.timePreset, appliedFilters.timeRange)
      const { data } = await getResolveLogsApi({
        page: pagination.page,
        size: pagination.size,
        keyword: keyword || undefined,
        recordType: appliedFilters.recordType || undefined,
        rcode: appliedFilters.rcode || undefined,
        startTime,
        endTime,
      })
      resolveLogs.value = (data?.rows ?? []).map((item) => {
        const queryId = String((item as any).queryId || (item as any).logId || '')
        return {
          ...item,
          queryId,
          logId: queryId,
        }
      })
      pagination.total = Number(data?.total || 0)
      lastUpdated.value = nowDateTime()
    } catch (_error) {
      ElMessage.error(t('monitor.resolveLogLoadFailed'))
    } finally {
      loading.value = false
    }
  }

  const handleSearch = async (): Promise<void> => {
    querying.value = true
    Object.assign(appliedFilters, {
      ...filterForm,
      timeRange: [...filterForm.timeRange],
    })
    pagination.page = 1
    await fetchResolveLogs()
    querying.value = false
    ElMessage.success(t('monitor.resolveLogSearchApplied'))
  }

  const handleReset = async (): Promise<void> => {
    Object.assign(filterForm, { ...DEFAULT_FILTERS, timeRange: [] })
    Object.assign(appliedFilters, { ...DEFAULT_FILTERS, timeRange: [] })
    pagination.page = 1
    await fetchResolveLogs()
    ElMessage.success(t('monitor.resolveLogResetApplied'))
  }

  const handleRefresh = async (): Promise<void> => {
    if (refreshing.value) {
      return
    }
    try {
      refreshing.value = true
      await fetchResolveLogs()
      ElMessage.success(t('monitor.resolveLogRefreshed'))
    } catch (_error) {
      ElMessage.error(t('monitor.refreshFailedRetry'))
    } finally {
      refreshing.value = false
    }
  }

  const handlePageChange = async (page: number, size = pagination.size): Promise<void> => {
    pagination.page = page
    pagination.size = size
    await fetchResolveLogs()
  }

  const handleSortChange = ({ prop, order }: { prop: string | null; order: SortOrder }): void => {
    sortState.prop = prop || 'time'
    sortState.order = order || 'descending'
  }

  const openDetail = (row: MonitorResolveLogRow): void => {
    currentDetail.value = row
    detailVisible.value = true
  }

  const copyDetailSummary = async (): Promise<void> => {
    if (!currentDetail.value) {
      return
    }
    // Drop the request/response *header* lines — those fields are
    // never populated by the backend (QueryLog only carries the full
    // payload via miekg.Msg.String()) and the dialog itself no longer
    // surfaces them, so keeping them in the copied summary just
    // produces noisy "Request Headers: undefined" lines.
    const lines = [
      `${t('monitor.resolveLogFieldLogId')}: ${currentDetail.value.queryId || currentDetail.value.logId || '-'}`,
      `${t('monitor.resolveLogFieldDomain')}: ${currentDetail.value.domain}`,
      `${t('monitor.resolveLogFieldTransactionId')}: ${currentDetail.value.transactionId}`,
      `${t('monitor.resolveLogFieldRcode')}: ${currentDetail.value.rcode}`,
      `${t('monitor.resolveLogFieldRequestContent')}: ${currentDetail.value.requestPayload || '-'}`,
      `${t('monitor.resolveLogFieldResponseContent')}: ${currentDetail.value.responsePayload || '-'}`,
    ]
    await copyText(lines.join('\n'), t('monitor.resolveLogSummaryCopied'))
  }

  const copyDetailText = async (text: string, success = t('common.copied')): Promise<void> => {
    await copyText(text || '', success)
  }

  const handleExport = async (command: string): Promise<void> => {
    if (exporting.value) {
      return
    }

    try {
      exporting.value = true
      const [scope, format] = command.split('-') as [string, string]

      // Filter payload shared by every page request. `all` ignores the
      // current applied filters; `filtered` honours them so the
      // exported file matches what's on screen.
      const filterPayload =
        scope === 'all'
          ? {}
          : {
              keyword: appliedFilters.keyword.trim() || undefined,
              recordType: appliedFilters.recordType || undefined,
              rcode: appliedFilters.rcode || undefined,
              ...resolveTimeRange(appliedFilters.timePreset, appliedFilters.timeRange),
            }

      // Drain every page, not just the first 5k. Backend caps a single
      // request at 10000 rows (handler/monitor.go), so we loop until
      // we've collected `total` or until a safety cap kicks in to keep
      // a misbehaving server from hanging the browser.
      const PAGE_SIZE = 10000
      const SAFETY_CAP_PAGES = 100 // == 1,000,000 rows max
      const sourceRows: MonitorResolveLogRow[] = []
      let page = 1
      let total = Infinity
      while (sourceRows.length < total && page <= SAFETY_CAP_PAGES) {
        const { data } = await getResolveLogsApi({
          page,
          size: PAGE_SIZE,
          ...filterPayload,
        })
        const batch = (data?.rows ?? []) as MonitorResolveLogRow[]
        if (!batch.length) {
          break
        }
        sourceRows.push(...batch)
        total = Number(data?.total ?? sourceRows.length)
        page += 1
      }

      const rows = sourceRows.map((item) => ({
        [t('monitor.resolveLogFieldLogId')]: item.queryId || item.logId || '',
        [t('monitor.resolveLogFieldTime')]: formatDateTimeMs(String(item.time || '')),
        [t('monitor.resolveLogFieldDomain')]: item.domain,
        [t('monitor.resolveLogFieldRecordType')]: item.recordType,
        [t('monitor.resolveLogFieldTransactionId')]: item.transactionId,
        [t('monitor.resolveLogFieldRcode')]: item.rcode,
        [t('monitor.resolveLogFieldSourceIp')]: item.sourceIp,
        [t('monitor.resolveLogFieldResponseTimeMs')]: item.responseTime,
        // The backing model field is `requestPayload` / `responsePayload`
        // (see model.QueryLog). The previous export wrote `requestHeaders` /
        // `responseHeaders` which never exist on the row, producing two
        // empty columns. Reuse the same i18n keys the detail dialog
        // already uses for "请求内容 / 响应内容" so the column header
        // matches what operators see in the UI.
        [t('monitor.resolveLogFieldRequestContent')]: item.requestPayload,
        [t('monitor.resolveLogFieldResponseContent')]: item.responsePayload,
      }))

      if (format === 'batch') {
        exportRows(rows, 'monitor-resolve-logs', 'excel', t)
        exportRows(rows, 'monitor-resolve-logs', 'csv', t)
        ElMessage.success(t('monitor.resolveLogExportBatch'))
        return
      }

      exportRows(rows, 'monitor-resolve-logs', format as 'excel' | 'csv' | 'json', t)
      ElMessage.success(t('monitor.resolveLogExportSuccess'))
    } catch (_error) {
      ElMessage.error(t('monitor.resolveLogExportFailed'))
    } finally {
      exporting.value = false
    }
  }

  const formatDateTimeMs = (value: string): string => {
    const date = new Date(String(value || '').replace(' ', 'T'))
    if (Number.isNaN(date.getTime())) {
      return String(value || '--')
    }
    const y = date.getFullYear()
    const m = String(date.getMonth() + 1).padStart(2, '0')
    const d = String(date.getDate()).padStart(2, '0')
    const h = String(date.getHours()).padStart(2, '0')
    const mm = String(date.getMinutes()).padStart(2, '0')
    const s = String(date.getSeconds()).padStart(2, '0')
    const ms = String(date.getMilliseconds()).padStart(3, '0')
    return `${y}-${m}-${d} ${h}:${mm}:${s}.${ms}`
  }

  const statusClass = (status: string): string => {
    if (status === 'NOERROR' || status === '成功' || status === '已处理') {
      return 'tag-success'
    }
    if (status === 'NXDOMAIN' || status === '警告' || status === '处理中') {
      return 'tag-warning'
    }
    if (status === 'SERVFAIL' || status === 'REFUSED' || status === '失败' || status === '未处理') {
      return 'tag-danger'
    }
    return 'tag-muted'
  }

  const rowClassName = ({ row }: { row: MonitorResolveLogRow }): string =>
    row.rcode === 'SERVFAIL' || row.rcode === 'REFUSED' ? 'monitor-row-danger' : ''

  onScopeDispose(() => {
    querying.value = false
  })

  return {
    filterForm,
    pagination,
    loading,
    querying,
    refreshing,
    exporting,
    detailVisible,
    currentDetail,
    lastUpdated,
    resolveRows,
    totalRows: computed(() => pagination.total),
    fetchResolveLogs,
    handleSearch,
    handleReset,
    handleRefresh,
    handlePageChange,
    handleSortChange,
    handleExport,
    openDetail,
    copyDetailSummary,
    copyDetailText,
    formatDateTimeMs,
    statusClass,
    rowClassName,
  }
}

export default useResolveLog
