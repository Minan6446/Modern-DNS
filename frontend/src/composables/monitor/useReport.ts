import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { jsPDF } from 'jspdf'
import ExcelJS from 'exceljs'
import { useMonitorStore } from '../../stores/monitor'
import type { MonitorReportData } from '../../types/modules'
import { loadTableState, saveTableState } from '../../utils/tableState'
import { dataUrlToBase64, renderEchartsOptionToPng, renderTextToPng } from '../../utils/chartImage'
import { getMonitorReportExtendedApi, type MonitorReportExtendedData } from '../../api/monitor'

// Original four chart slots + five A-tier extensions. Order is
// significant for the export pipeline: chart pages in the PDF / images
// in the Charts sheet of the Excel are written in this declared order.
export type ReportChartType =
  | 'domain'
  | 'ip'
  | 'heatmap'
  | 'status'
  | 'recordType'
  | 'latency'
  | 'qpsTrend'
  | 'rcodeTrend'
  | 'slowDomain'
export type ReportType = 'overview' | 'traffic' | 'geo' | 'status'
export type AggregateDimension = 'domain' | 'ip' | 'region' | 'status'

// Chart options bag the page component hands to exportReport. Keeping
// the keys identical to ReportChartType lets the export loop iterate
// the same enumeration the page uses for `visibleCharts`.
export type ReportChartOptionsBag = Partial<Record<ReportChartType, Record<string, any>>>

export interface ReportFilterForm {
  reportType: ReportType
  aggregateDimension: AggregateDimension
  timePreset: string
  domain: string
  timeRange: string[]
}

export interface ReportTableRow {
  rank: number
  label: string
  value: number
  category: string
}

interface ReportViewState {
  reportFilters: ReportFilterForm
  chartType: ReportChartType
}

const REPORT_STATE_KEY = 'modern-dns:report:view-state'

const DEFAULT_FILTERS: ReportFilterForm = {
  reportType: 'overview',
  aggregateDimension: 'domain',
  timePreset: '7d',
  domain: '',
  timeRange: [],
}

const parseDate = (value: string | number | Date | null | undefined): number => {
  const normalized = String(value || '').trim().replace(' ', 'T')
  const timestamp = Date.parse(normalized)
  return Number.isNaN(timestamp) ? Date.now() : timestamp
}

const formatDateTime = (value: string): string => {
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
  return `${y}-${m}-${d} ${h}:${mm}:${s}`
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

export const useReport = () => {
  const { t } = useI18n()
  const monitorStore = useMonitorStore()
  const cachedState = loadTableState<ReportViewState>(REPORT_STATE_KEY, {
    reportFilters: DEFAULT_FILTERS,
    chartType: 'status',
  })

  const filterForm = reactive<ReportFilterForm>({
    ...DEFAULT_FILTERS,
    ...cachedState.reportFilters,
    timeRange: [...(cachedState.reportFilters.timeRange || [])],
  })
  const appliedFilters = reactive<ReportFilterForm>({
    ...filterForm,
    timeRange: [...filterForm.timeRange],
  })
  const querying = ref(false)
  const exporting = ref(false)
  const fullscreenVisible = ref(false)
  const chartType = ref<ReportChartType>(cachedState.chartType || 'status')

  // Extended (A-tier) aggregations, loaded from a separate endpoint
  // because the base /monitor/report payload shouldn't grow unbounded
  // and the queries here are non-trivial on a large `query_logs`.
  const extended = ref<MonitorReportExtendedData>({
    recordTypes: [],
    latencyBuckets: [],
    qpsTrend: { periods: [], values: [] },
    rcodeTrend: { periods: [], series: [] },
    slowDomains: [],
  })
  const extendedLoading = ref(false)

  const loading = computed(() => monitorStore.loading)
  const lastUpdated = computed(() => monitorStore.lastUpdated)

  const reportTypeOptions = computed<Array<{ label: string; value: ReportType }>>(() => [
    { label: t('monitor.reportTypeOverview'), value: 'overview' },
    { label: t('monitor.reportTypeTraffic'), value: 'traffic' },
    { label: t('monitor.reportTypeGeo'), value: 'geo' },
    { label: t('monitor.reportTypeStatus'), value: 'status' },
  ])

  const aggregateOptions = computed<Array<{ label: string; value: AggregateDimension }>>(() => [
    { label: t('monitor.aggregateByDomain'), value: 'domain' },
    { label: t('monitor.aggregateByClientIp'), value: 'ip' },
    { label: t('monitor.aggregateByRegion'), value: 'region' },
    { label: t('monitor.aggregateByStatus'), value: 'status' },
  ])

  watch(
    () => ({
      reportFilters: { ...appliedFilters, timeRange: [...appliedFilters.timeRange] },
      chartType: chartType.value,
    }),
    (next) => {
      saveTableState(REPORT_STATE_KEY, next)
    },
    { deep: true },
  )

  const reportScale = computed<number>(() => {
    const preset = appliedFilters.timePreset
    if (preset === '1d') {
      return 0.3
    }
    if (preset === '7d') {
      return 1
    }
    if (preset === '30d') {
      return 4.2
    }
    if (appliedFilters.timeRange.length === 2) {
      const days = Math.max(1, (parseDate(appliedFilters.timeRange[1]) - parseDate(appliedFilters.timeRange[0])) / (24 * 60 * 60 * 1000))
      return Math.max(0.2, Math.min(4.2, days / 7))
    }
    return 1
  })

  const reportData = computed<MonitorReportData>(() => {
    const scale = reportScale.value
    const domainKeyword = appliedFilters.domain.trim()
    const topDomain = monitorStore.report.topDomain
      .filter((item) => !domainKeyword || item.name.includes(domainKeyword))
      .map((item) => ({ ...item, value: Math.round(item.value * scale) }))
    const topIp = monitorStore.report.topIp.map((item) => ({ ...item, value: Math.round(item.value * scale) }))
    const heatmap = {
      ...monitorStore.report.heatmap,
      values: monitorStore.report.heatmap.values.map((item) => [item[0], item[1], Math.round(item[2] * scale)]),
    }
    const statusDistribution = monitorStore.report.statusDistribution.map((item) => {
      const statusCode = normalizeStatusCode(item.name)
      const localizedName = ({
        NOERROR: t('monitor.statusNoerror'),
        CACHED: t('monitor.statusCached'),
        NXDOMAIN: t('monitor.statusNxdomain'),
        SERVFAIL: t('monitor.statusServfail'),
        REFUSED: t('monitor.statusRefused'),
        BLOCKED: t('monitor.statusBlocked'),
      } as Record<string, string>)[statusCode] || item.name
      return {
        ...item,
        name: localizedName,
        statusCode,
        rawName: item.name,
        value: Math.round(item.value * scale),
      }
    })
    return { topDomain, topIp, heatmap, statusDistribution }
  })

  const tableData = computed<ReportTableRow[]>(() => {
    if (appliedFilters.aggregateDimension === 'ip') {
      return reportData.value.topIp.map((item, index) => ({ rank: index + 1, label: item.name, value: item.value, category: t('monitor.clientIp') }))
    }
    if (appliedFilters.aggregateDimension === 'region') {
      const rows = reportData.value.heatmap.regions.map((region, regionIndex) => {
        const total = reportData.value.heatmap.values
          .filter((item) => Number(item[1]) === regionIndex)
          .reduce((sum, item) => sum + Number(item[2] || 0), 0)
        return { rank: 0, label: region, value: total, category: t('monitor.region') }
      })
      return rows
        .sort((left, right) => right.value - left.value)
        .map((item, index) => ({ ...item, rank: index + 1 }))
    }
    if (appliedFilters.aggregateDimension === 'status') {
      return reportData.value.statusDistribution.map((item, index) => ({ rank: index + 1, label: item.name, value: item.value, category: t('common.status') }))
    }
    return reportData.value.topDomain.map((item, index) => ({ rank: index + 1, label: item.name, value: item.value, category: t('common.domain') }))
  })

  // Which chart slots are visible in each report-type tab.
  //   - traffic  → domain / ip + new latency histogram and QPS curve
  //   - geo      → heat map only
  //   - status   → status pie + rcode stacked trend (both
  //                describe response-code distribution)
  //   - overview → everything, in a defined order so the page grid
  //                and the export sheet/PDF page sequence agree
  const visibleCharts = computed<ReportChartType[]>(() => {
    if (appliedFilters.reportType === 'traffic') {
      return ['domain', 'ip', 'qpsTrend', 'latency', 'slowDomain']
    }
    if (appliedFilters.reportType === 'geo') {
      return ['heatmap']
    }
    if (appliedFilters.reportType === 'status') {
      return ['status', 'rcodeTrend']
    }
    return [
      'domain',
      'ip',
      'heatmap',
      'status',
      'recordType',
      'latency',
      'qpsTrend',
      'rcodeTrend',
      'slowDomain',
    ]
  })

  const reportIsEmpty = computed<boolean>(
    () => !reportData.value.topDomain.length && !reportData.value.topIp.length && !reportData.value.heatmap.values.length && !reportData.value.statusDistribution.length,
  )

  // Resolve the currently-applied filter into a query payload shared
  // by the base /monitor/report endpoint and the new
  // /monitor/report/extended endpoint, so what the user sees on the
  // page is exactly what the backend aggregations were scoped to.
  // Preset windows map to a SQL-style "YYYY-MM-DD HH:MM:SS" pair the
  // handler can compare against created_at directly.
  const toSqlTime = (date: Date): string => {
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  }
  const buildReportQuery = (): { startTime?: string; endTime?: string; domain?: string } => {
    let startTime: string | undefined
    let endTime: string | undefined
    if (appliedFilters.timePreset === 'custom' && appliedFilters.timeRange.length === 2) {
      startTime = appliedFilters.timeRange[0]
      endTime = appliedFilters.timeRange[1]
    } else {
      const hoursByPreset: Record<string, number> = { '1d': 24, '7d': 24 * 7, '30d': 24 * 30 }
      const hours = hoursByPreset[appliedFilters.timePreset] ?? 24 * 7
      const end = new Date()
      const start = new Date(end.getTime() - hours * 60 * 60 * 1000)
      startTime = toSqlTime(start)
      endTime = toSqlTime(end)
    }
    const domain = appliedFilters.domain.trim()
    return { startTime, endTime, domain: domain || undefined }
  }

  const fetchExtended = async (): Promise<void> => {
    extendedLoading.value = true
    try {
      const { data } = await getMonitorReportExtendedApi(buildReportQuery())
      if (data) {
        extended.value = {
          recordTypes: data.recordTypes ?? [],
          latencyBuckets: data.latencyBuckets ?? [],
          qpsTrend: data.qpsTrend ?? { periods: [], values: [] },
          rcodeTrend: data.rcodeTrend ?? { periods: [], series: [] },
          slowDomains: data.slowDomains ?? [],
        }
      }
    } catch (_error) {
      // Extended panel is non-critical — surface a soft warning but
      // don't block the rest of the report from rendering.
      ElMessage.warning(t('monitor.reportExtendedLoadFailed'))
    } finally {
      extendedLoading.value = false
    }
  }

  const fetchReportData = async (): Promise<void> => {
    try {
      await Promise.all([
        monitorStore.fetchMonitorData(),
        fetchExtended(),
      ])
    } catch (_error) {
      ElMessage.error(t('monitor.reportLoadFailed'))
    }
  }

  const handleSearch = async (): Promise<void> => {
    querying.value = true
    Object.assign(appliedFilters, {
      ...filterForm,
      timeRange: [...filterForm.timeRange],
    })
    // Re-run the extended aggregation against the new filter so the
    // five new charts stay in sync with the four legacy ones. The
    // legacy charts re-read from `monitorStore.report` which itself
    // is reactive to whatever the original /monitor/report payload
    // contains; we leave that handler untouched on the search path
    // because it's bundled together with realtime+rules in
    // fetchMonitorData and reissuing it here would over-fetch.
    await fetchExtended()
    querying.value = false
    ElMessage.success(t('monitor.reportFilterApplied'))
  }

  const handleReset = async (): Promise<void> => {
    Object.assign(filterForm, { ...DEFAULT_FILTERS, timeRange: [] })
    Object.assign(appliedFilters, { ...DEFAULT_FILTERS, timeRange: [] })
    await fetchExtended()
    ElMessage.success(t('monitor.reportFilterReset'))
  }

  // Localised chart caption shared by both Excel cells (UTF-8, drawn
  // by Excel's own font stack) and PDF pages (canvas-rasterised PNG
  // — see renderTextToPng — which sidesteps jsPDF's lack of bundled
  // CJK glyphs entirely).
  const chartTitleFor = (type: ReportChartType): string => {
    switch (type) {
      case 'domain': return t('monitor.topDomainStats')
      case 'ip': return t('monitor.topIpStats')
      case 'heatmap': return t('monitor.geoHeatmap')
      case 'status': return t('monitor.statusDist')
      case 'recordType': return t('monitor.recordTypeDist')
      case 'latency': return t('monitor.latencyHistogram')
      case 'qpsTrend': return t('monitor.qpsTrend')
      case 'rcodeTrend': return t('monitor.rcodeTrend')
      case 'slowDomain': return t('monitor.slowDomainTop')
    }
  }
  // Alias kept so existing Excel branch reads naturally.
  const excelChartTitle = chartTitleFor
  // Localised sheet names. Kept short because Excel rejects sheet
  // names > 31 chars and disallows a handful of punctuation.
  const excelSheetNames = () => ({
    topDomain: t('monitor.topDomainStats'),
    topIp: t('monitor.topIpStats'),
    summary: t('monitor.aggregateTable'),
    status: t('monitor.statusDist'),
    charts: t('monitor.exportReport'),
  })
  // Map the raw JSON keys we ship in each data sheet to the column
  // headers the operator should actually see. The keys reference the
  // shape of the objects fed into addDataSheet().
  const excelHeaderMap = (sheet: 'topDomain' | 'topIp' | 'summary' | 'status'): Record<string, string> => {
    switch (sheet) {
      case 'topDomain':
        return { name: t('common.domain'), value: t('monitor.queryCountLabel') }
      case 'topIp':
        return { name: t('monitor.clientIp'), value: t('monitor.visitCountLabel') }
      case 'summary':
        return {
          rank: t('monitor.rank'),
          label: t('monitor.dimValue'),
          value: t('monitor.aggValue'),
          category: t('monitor.dimType'),
        }
      case 'status':
        return {
          name: t('monitor.resolveStatusLabel'),
          value: t('monitor.quantityLabel'),
          statusCode: 'Status Code',
          rawName: 'Raw',
        }
    }
  }
  // Excel sheet names have to satisfy: ≤31 chars, no `:\/?*[]`, and
  // be unique within the workbook. We strip the forbidden chars and
  // clip aggressively to keep ExcelJS happy on aggressive locales.
  const sanitiseSheetName = (name: string, fallback: string): string => {
    const cleaned = (name || '').replace(/[\\/?*[\]:]/g, '').trim()
    const safe = cleaned || fallback
    return safe.length > 31 ? safe.slice(0, 31) : safe
  }

  const exportReport = async (
    command: string,
    chartOptions?: ReportChartOptionsBag,
  ): Promise<void> => {
    if (exporting.value) {
      return
    }

    try {
      exporting.value = true

      // Render every chart the operator currently sees on the page to
      // a PNG once, up-front. Both branches (Excel + PDF) consume the
      // same images so we only pay the rendering cost once even if the
      // user picks "excel" today and "pdf" tomorrow on a re-export.
      const chartTypesToExport = visibleCharts.value.filter(
        (type) => chartOptions?.[type],
      )
      const chartPngs: Partial<Record<ReportChartType, string>> = {}
      for (const type of chartTypesToExport) {
        const option = chartOptions?.[type]
        if (!option) continue
        try {
          chartPngs[type] = await renderEchartsOptionToPng(option, {
            width: 960,
            height: 540,
          })
        } catch (_err) {
          // One bad chart shouldn't kill the whole export — skip and
          // continue. The matching sheet/page slot will be left empty.
          chartPngs[type] = ''
        }
      }

      if (command === 'excel') {
        await exportExcelWithCharts(chartPngs)
      } else {
        await exportPdfWithCharts(chartPngs)
      }
      ElMessage.success(t('monitor.reportExportSuccess'))
    } catch (_error) {
      ElMessage.error(t('monitor.reportExportFailed'))
    } finally {
      exporting.value = false
    }
  }

  // ── Excel: data sheets (existing behaviour) + a Charts sheet that
  // embeds every rendered chart PNG so the workbook visually mirrors
  // the on-screen report. ExcelJS is used here instead of SheetJS
  // because SheetJS community edition cannot embed images at all.
  const exportExcelWithCharts = async (
    chartPngs: Partial<Record<ReportChartType, string>>,
  ): Promise<void> => {
    const workbook = new ExcelJS.Workbook()
    workbook.creator = 'Modern DNS'
    workbook.created = new Date()
    const sheetNames = excelSheetNames()

    // Helper: append an array of plain objects as a sheet with a
    // bold *localised* header row. `headerMap` translates the raw
    // JSON keys (`name`, `value`, …) into operator-facing column
    // labels in the current i18n locale; unmapped keys fall back to
    // the raw key so we never lose a column when a new field is
    // introduced without a translation entry.
    const addDataSheet = (
      sheetName: string,
      fallbackName: string,
      rows: Array<Record<string, any>>,
      headerMap: Record<string, string>,
    ): void => {
      const sheet = workbook.addWorksheet(sanitiseSheetName(sheetName, fallbackName))
      if (!rows.length) {
        return
      }
      const columns = Object.keys(rows[0])
      sheet.columns = columns.map((key) => {
        const header = headerMap[key] || key
        return {
          header,
          key,
          width: Math.max(14, Math.min(48, Math.max(header.length * 2, key.length + 4))),
        }
      })
      sheet.getRow(1).font = { bold: true }
      rows.forEach((row) => sheet.addRow(row))
    }

    addDataSheet(sheetNames.topDomain, 'TopDomain', reportData.value.topDomain, excelHeaderMap('topDomain'))
    addDataSheet(sheetNames.topIp, 'TopIP', reportData.value.topIp, excelHeaderMap('topIp'))
    addDataSheet(sheetNames.summary, 'SummaryTable', tableData.value, excelHeaderMap('summary'))
    addDataSheet(sheetNames.status, 'StatusDistribution', reportData.value.statusDistribution, excelHeaderMap('status'))

    // Charts sheet — stack each chart PNG vertically with a localised
    // caption. The caption text follows the active locale so a
    // Chinese-locale operator sees the same wording they see on the
    // page (e.g. "Top 查询域名统计").
    const chartsSheet = workbook.addWorksheet(sanitiseSheetName(sheetNames.charts, 'Charts'))
    chartsSheet.getColumn(1).width = 4
    chartsSheet.getColumn(2).width = 90
    let cursorRow = 2
    // Order mirrors visibleCharts so the Charts sheet matches the
    // page layout — see the comment on ReportChartType for why this
    // ordering is significant.
    const chartOrder: ReportChartType[] = [
      'domain', 'ip', 'heatmap', 'status',
      'recordType', 'latency', 'qpsTrend', 'rcodeTrend', 'slowDomain',
    ]
    for (const type of chartOrder) {
      const png = chartPngs[type]
      if (!png) continue
      chartsSheet.getCell(`B${cursorRow}`).value = excelChartTitle(type)
      chartsSheet.getCell(`B${cursorRow}`).font = { bold: true, size: 13 }
      const imageId = workbook.addImage({
        base64: dataUrlToBase64(png),
        extension: 'png',
      })
      // The PNG is 960x540 → place it just below the caption row,
      // spanning ~27 rows. tl is { col, row } 0-indexed.
      chartsSheet.addImage(imageId, {
        tl: { col: 1, row: cursorRow },
        ext: { width: 720, height: 405 },
        editAs: 'oneCell',
      })
      cursorRow += 24 // caption + image + a blank line
    }

    const buffer = await workbook.xlsx.writeBuffer()
    triggerDownload(
      new Blob([buffer], {
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      }),
      'monitor-report.xlsx',
    )
  }

  // ── PDF: cover page (title + generation timestamp) and one chart
  // per page. EVERY piece of text is canvas-rasterised before being
  // embedded — see drawText — because jsPDF's built-in Helvetica has
  // no CJK glyphs and Chinese strings would otherwise come out as
  // garbled Latin substitutes. The trade-off is that PDF text is not
  // selectable, which matches the trade-off we already accepted for
  // chart contents.
  const exportPdfWithCharts = async (
    chartPngs: Partial<Record<ReportChartType, string>>,
  ): Promise<void> => {
    const pdf = new jsPDF({ unit: 'pt', format: 'a4', orientation: 'landscape' })
    const pageWidth = pdf.internal.pageSize.getWidth()
    const pageHeight = pdf.internal.pageSize.getHeight()
    const margin = 36

    // Helper that rasterises a single line of text and stamps it at
    // (x, y). y is the line's *top* edge, matching how layout cursors
    // are typically computed in PDF land. Returns the height consumed
    // so the caller can advance the cursor without remeasuring.
    const drawText = (
      text: string,
      x: number,
      y: number,
      opts: { sizePx?: number; bold?: boolean; color?: string } = {},
    ): number => {
      const { sizePx = 12, bold = false, color = '#1d2129' } = opts
      const img = renderTextToPng(text, {
        fontSizePx: sizePx,
        weight: bold ? 'bold' : 'normal',
        color,
      })
      pdf.addImage(img.dataUrl, 'PNG', x, y, img.widthPt, img.heightPt, undefined, 'FAST')
      return img.heightPt
    }

    // Cover page — title + meta lines, all locale-aware.
    const reportTitle = t('monitor.pdfTitle') // e.g. "DNS 监控报表"
    const generatedLabel = t('monitor.generatedAt') // e.g. "生成时间"
    const timeRangeLabel = t('monitor.timeRangeLabel')
    const timeRangeValue =
      appliedFilters.timePreset === 'custom' && appliedFilters.timeRange.length === 2
        ? `${appliedFilters.timeRange[0]} ~ ${appliedFilters.timeRange[1]}`
        : appliedFilters.timePreset

    let cursorY = margin + 10
    cursorY += drawText(reportTitle, margin, cursorY, { sizePx: 22, bold: true })
    cursorY += 8
    cursorY += drawText(
      `${generatedLabel}: ${formatDateTime(new Date().toISOString())}`,
      margin,
      cursorY,
      { sizePx: 11 },
    )
    cursorY += drawText(
      `${timeRangeLabel}: ${timeRangeValue}`,
      margin,
      cursorY,
      { sizePx: 11 },
    )

    const chartOrder: ReportChartType[] = [
      'domain', 'ip', 'heatmap', 'status',
      'recordType', 'latency', 'qpsTrend', 'rcodeTrend', 'slowDomain',
    ]
    const imgWidth = pageWidth - margin * 2
    const imgHeight = (imgWidth * 540) / 960 // preserve 16:9 aspect
    for (const type of chartOrder) {
      const png = chartPngs[type]
      if (!png) continue
      pdf.addPage()
      const titleHeight = drawText(chartTitleFor(type), margin, margin, {
        sizePx: 16,
        bold: true,
      })
      const top = margin + titleHeight + 8
      // Centre vertically within the remaining space if the image
      // happens to be shorter than that.
      const availableHeight = pageHeight - top - margin
      const drawHeight = Math.min(imgHeight, availableHeight)
      const drawWidth = (drawHeight / imgHeight) * imgWidth
      const x = (pageWidth - drawWidth) / 2
      pdf.addImage(png, 'PNG', x, top, drawWidth, drawHeight, undefined, 'FAST')
    }

    pdf.save('monitor-report.pdf')
  }

  // Small utility: tee a Blob into a browser download. Kept inline
  // because the other exports already use anchor-click and we don't
  // want to pull in a heavier file-saver dep just for this.
  const triggerDownload = (blob: Blob, filename: string): void => {
    const href = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = href
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
    URL.revokeObjectURL(href)
  }

  const openChartFullscreen = (type: ReportChartType): void => {
    chartType.value = type
    fullscreenVisible.value = true
  }

  const closeFullscreenDialog = (): void => {
    fullscreenVisible.value = false
  }

  const onFullscreenOpened = (): void => {
    window.dispatchEvent(new Event('resize'))
  }

  return {
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
    extendedLoading,
    chartTitleFor,
    fetchReportData,
    handleSearch,
    handleReset,
    exportReport,
    openChartFullscreen,
    closeFullscreenDialog,
    onFullscreenOpened,
  }
}

export default useReport