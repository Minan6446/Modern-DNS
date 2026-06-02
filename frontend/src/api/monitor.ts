import request from './request'
import type { ApiResponse, SuccessResult } from '../types/api'
import type {
  MonitorModuleData,
  MonitorRealTimeRow,
  MonitorResolveLogRow,
  MonitorReportData,
  MonitorRuleNxdomain,
  MonitorRuleQps,
  MonitorRuleLatency,
  MonitorRuleCacheHit,
} from '../types/modules'

// ── Module data ──────────────────────────────────────────────────────────────

export const getMonitorModuleData = (): Promise<ApiResponse<MonitorModuleData>> => {
  return Promise.all([
    request.get('/monitor/realtime') as Promise<ApiResponse<any>>,
    request.get('/monitor/resolve-logs') as Promise<ApiResponse<any>>,
    request.get('/monitor/rules') as Promise<ApiResponse<any>>,
    request.get('/monitor/report') as Promise<ApiResponse<any>>,
  ]).then(([rt, rl, rules, rep]) => ({
    code: 0,
    message: 'ok',
    data: {
      realTime: (rt.data as any)?.rows ?? [],
      resolveLogs: (rl.data as any)?.rows ?? [],
      rules: {
        qps: (rules.data as any)?.qps ?? {},
        nxdomain: (rules.data as any)?.nxdomain ?? {},
        latency: (rules.data as any)?.latency ?? {},
        cacheHit: (rules.data as any)?.cacheHit ?? {},
        history: (rules.data as any)?.history ?? [],
      },
      report: rep.data ?? {},
    } as MonitorModuleData,
  }))
}

// ── Real-time ─────────────────────────────────────────────────────────────────

export const getRealTimeLogsApi = (params?: {
  domain?: string; sourceIp?: string; status?: string; recordType?: string; page?: number; size?: number
  startTime?: string; endTime?: string
}): Promise<ApiResponse<{ total: number; rows: MonitorRealTimeRow[] }>> => {
  return request.get('/monitor/realtime', { params }) as Promise<ApiResponse<{ total: number; rows: MonitorRealTimeRow[] }>>
}

export const refreshMonitorRealtime = (): Promise<ApiResponse<SuccessResult>> => {
  return request.post('/monitor/realtime/refresh') as Promise<ApiResponse<SuccessResult>>
}

// ── Resolve Logs ──────────────────────────────────────────────────────────────

export const getResolveLogsApi = (params?: {
  page?: number; size?: number; domain?: string; sourceIp?: string; status?: string
  rcode?: string; recordType?: string; startTime?: string; endTime?: string; keyword?: string
}): Promise<ApiResponse<{ total: number; rows: MonitorResolveLogRow[] }>> => {
  return request.get('/monitor/resolve-logs', { params }) as Promise<ApiResponse<{ total: number; rows: MonitorResolveLogRow[] }>>
}

export const exportResolveLogsApi = (payload: { format?: string; scope?: string; domain?: string; timeRange?: string[] }): Promise<ApiResponse<{ success: boolean; exportedAt: string }>> => {
  return request.post('/monitor/resolve-logs/export', payload) as Promise<ApiResponse<{ success: boolean; exportedAt: string }>>
}

// ── Rules ─────────────────────────────────────────────────────────────────────

export const saveQpsRuleApi = (payload: MonitorRuleQps): Promise<ApiResponse<MonitorRuleQps>> => {
  return request.put('/monitor/rules/qps', payload) as Promise<ApiResponse<MonitorRuleQps>>
}

export const saveNxdomainRuleApi = (payload: MonitorRuleNxdomain): Promise<ApiResponse<MonitorRuleNxdomain>> => {
  return request.put('/monitor/rules/nxdomain', payload) as Promise<ApiResponse<MonitorRuleNxdomain>>
}

export const resetQpsRuleApi = (): Promise<ApiResponse<MonitorRuleQps>> => {
  return request.post('/monitor/rules/qps/reset') as Promise<ApiResponse<MonitorRuleQps>>
}

export const resetNxdomainRuleApi = (): Promise<ApiResponse<MonitorRuleNxdomain>> => {
  return request.post('/monitor/rules/nxdomain/reset') as Promise<ApiResponse<MonitorRuleNxdomain>>
}

export const handleRuleHistoryApi = (id: number): Promise<ApiResponse<{ id: number; success: boolean }>> => {
  return request.patch(`/monitor/rule-history/${id}/handle`) as Promise<ApiResponse<{ id: number; success: boolean }>>
}

export const saveLatencyRuleApi = (payload: MonitorRuleLatency): Promise<ApiResponse<MonitorRuleLatency>> => {
  return request.put('/monitor/rules/latency', payload) as Promise<ApiResponse<MonitorRuleLatency>>
}

export const resetLatencyRuleApi = (): Promise<ApiResponse<MonitorRuleLatency>> => {
  return request.post('/monitor/rules/latency/reset') as Promise<ApiResponse<MonitorRuleLatency>>
}

export const saveCacheHitRuleApi = (payload: MonitorRuleCacheHit): Promise<ApiResponse<MonitorRuleCacheHit>> => {
  return request.put('/monitor/rules/cache-hit', payload) as Promise<ApiResponse<MonitorRuleCacheHit>>
}

export const resetCacheHitRuleApi = (): Promise<ApiResponse<MonitorRuleCacheHit>> => {
  return request.post('/monitor/rules/cache-hit/reset') as Promise<ApiResponse<MonitorRuleCacheHit>>
}

// ── Report ────────────────────────────────────────────────────────────────────

export const getMonitorReportApi = (params?: { startTime?: string; endTime?: string; domain?: string }): Promise<ApiResponse<MonitorReportData>> => {
  return request.get('/monitor/report', { params }) as Promise<ApiResponse<MonitorReportData>>
}

// Extended A-tier aggregations (record types, latency histogram, QPS
// trend, rcode stack, slow-domains) — companion of the base report
// endpoint, intentionally on a separate URL so older clients aren't
// forced to deal with the larger payload.
export interface MonitorReportExtendedData {
  recordTypes: Array<{ name: string; value: number }>
  latencyBuckets: Array<{ name: string; value: number }>
  qpsTrend: { periods: string[]; values: number[] }
  rcodeTrend: { periods: string[]; series: Array<{ name: string; data: number[] }> }
  slowDomains: Array<{ name: string; avgLatencyMs: number; maxLatencyMs: number; sampleCount: number }>
}

export const getMonitorReportExtendedApi = (
  params?: { startTime?: string; endTime?: string; domain?: string },
): Promise<ApiResponse<MonitorReportExtendedData>> => {
  return request.get('/monitor/report/extended', { params }) as Promise<ApiResponse<MonitorReportExtendedData>>
}

// ── Alert Subscribe ──────────────────────────────────────────────────────────

export const getAlertSubscribeRules = (): Promise<ApiResponse<any[]>> => {
  return request.get('/monitor/alert-subscribe/rules') as Promise<ApiResponse<any[]>>
}

export const createAlertSubscribeRule = (payload: any): Promise<ApiResponse<any>> => {
  return request.post('/monitor/alert-subscribe/rules', payload) as Promise<ApiResponse<any>>
}

export const updateAlertSubscribeRule = (id: number, payload: any): Promise<ApiResponse<any>> => {
  return request.put(`/monitor/alert-subscribe/rules/${id}`, payload) as Promise<ApiResponse<any>>
}

export const batchUpdateAlertSubscribeRules = (payload: {
  ids: number[]
  status?: '启用' | '禁用'
  duration?: number
  silenceMinutes?: number
  contactGroupId?: number
  channels?: string
}): Promise<ApiResponse<{ success: boolean; updated: number }>> => {
  return request.patch('/monitor/alert-subscribe/rules/batch', payload) as Promise<ApiResponse<{ success: boolean; updated: number }>>
}

export const deleteAlertSubscribeRule = (id: number): Promise<ApiResponse<any>> => {
  return request.delete(`/monitor/alert-subscribe/rules/${id}`) as Promise<ApiResponse<any>>
}

export const toggleAlertSubscribeRule = (id: number, status: string): Promise<ApiResponse<any>> => {
  return request.patch(`/monitor/alert-subscribe/rules/${id}/toggle`, { status }) as Promise<ApiResponse<any>>
}

export interface AlertContactGroup {
  id: number
  name: string
  memberUserIds: string
  remark: string
  status: '启用' | '禁用'
  createdAt: string
  updatedAt: string
}

export interface AlertContactUser {
  id: number
  username: string
  realName: string
  email: string
  phone: string
  status: string
}

export const getAlertContactGroups = (): Promise<ApiResponse<AlertContactGroup[]>> => {
  return request.get('/monitor/alert-subscribe/contact-groups') as Promise<ApiResponse<AlertContactGroup[]>>
}

export const createAlertContactGroup = (payload: Partial<AlertContactGroup>): Promise<ApiResponse<AlertContactGroup>> => {
  return request.post('/monitor/alert-subscribe/contact-groups', payload) as Promise<ApiResponse<AlertContactGroup>>
}

export const updateAlertContactGroup = (id: number, payload: Partial<AlertContactGroup>): Promise<ApiResponse<AlertContactGroup>> => {
  return request.put(`/monitor/alert-subscribe/contact-groups/${id}`, payload) as Promise<ApiResponse<AlertContactGroup>>
}

export const deleteAlertContactGroup = (id: number): Promise<ApiResponse<SuccessResult>> => {
  return request.delete(`/monitor/alert-subscribe/contact-groups/${id}`) as Promise<ApiResponse<SuccessResult>>
}

export const getAlertContactUsers = (): Promise<ApiResponse<AlertContactUser[]>> => {
  return request.get('/monitor/alert-subscribe/users') as Promise<ApiResponse<AlertContactUser[]>>
}

export interface AlertSilenceRule {
  id: number
  name: string
  alertTypePattern: string
  domainPattern: string
  levels: string
  startAt: string
  endAt: string
  status: '启用' | '禁用'
  createdAt: string
  updatedAt: string
}

export interface AlertInhibitRule {
  id: number
  name: string
  sourceAlertType: string
  sourceLevel: string
  targetAlertType: string
  targetLevel: string
  domainScoped: boolean
  status: '启用' | '禁用'
  createdAt: string
  updatedAt: string
}

export const getAlertSilenceRules = (): Promise<ApiResponse<AlertSilenceRule[]>> => {
  return request.get('/monitor/alert-subscribe/silence-rules') as Promise<ApiResponse<AlertSilenceRule[]>>
}

export const createAlertSilenceRule = (payload: Partial<AlertSilenceRule>): Promise<ApiResponse<AlertSilenceRule>> => {
  return request.post('/monitor/alert-subscribe/silence-rules', payload) as Promise<ApiResponse<AlertSilenceRule>>
}

export const updateAlertSilenceRule = (id: number, payload: Partial<AlertSilenceRule>): Promise<ApiResponse<AlertSilenceRule>> => {
  return request.put(`/monitor/alert-subscribe/silence-rules/${id}`, payload) as Promise<ApiResponse<AlertSilenceRule>>
}

export const deleteAlertSilenceRule = (id: number): Promise<ApiResponse<SuccessResult>> => {
  return request.delete(`/monitor/alert-subscribe/silence-rules/${id}`) as Promise<ApiResponse<SuccessResult>>
}

export const getAlertInhibitRules = (): Promise<ApiResponse<AlertInhibitRule[]>> => {
  return request.get('/monitor/alert-subscribe/inhibit-rules') as Promise<ApiResponse<AlertInhibitRule[]>>
}

export const createAlertInhibitRule = (payload: Partial<AlertInhibitRule>): Promise<ApiResponse<AlertInhibitRule>> => {
  return request.post('/monitor/alert-subscribe/inhibit-rules', payload) as Promise<ApiResponse<AlertInhibitRule>>
}

export const updateAlertInhibitRule = (id: number, payload: Partial<AlertInhibitRule>): Promise<ApiResponse<AlertInhibitRule>> => {
  return request.put(`/monitor/alert-subscribe/inhibit-rules/${id}`, payload) as Promise<ApiResponse<AlertInhibitRule>>
}

export const deleteAlertInhibitRule = (id: number): Promise<ApiResponse<SuccessResult>> => {
  return request.delete(`/monitor/alert-subscribe/inhibit-rules/${id}`) as Promise<ApiResponse<SuccessResult>>
}

// ── Slow Query ───────────────────────────────────────────────────────────────

export const getSlowQueries = (params?: { threshold?: number; keyword?: string; queryType?: string; range?: string }): Promise<ApiResponse<any>> => {
  return request.get('/monitor/slow-query', { params }) as Promise<ApiResponse<any>>
}

// ── Client Analysis ──────────────────────────────────────────────────────────

export const getClientAnalysis = (params?: { range?: string; keyword?: string; region?: string }): Promise<ApiResponse<any>> => {
  return request.get('/monitor/client-analysis', { params }) as Promise<ApiResponse<any>>
}
