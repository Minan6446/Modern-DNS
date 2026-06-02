import request from './request'
import type { ApiResponse, IdResult } from '../types/api'
import type { CacheDomainRule, CacheGlobalStrategy, CacheModuleData } from '../types/modules'

// Two distinct call shapes the backend accepts on POST /cache/clear:
//
//  1. Row-level: { ids: [...] }   — used by the「缓存浏览」per-row clear
//  2. Scope-level: { scope, domains, timeRange, preview }
//     — used by the「手动清理」preview + execute flow
//
// `preview: true` runs the SCAN + filter without DEL'ing anything,
// so the dialog shows an authoritative count before the operator
// commits. See backend/internal/handler/cache.go for the full contract.
export type CacheClearScope = 'all' | 'expired' | 'domain'

export type ClearCachePayload = {
  ids?: Array<number | string>
  domain?: string
  scope?: CacheClearScope
  domains?: string
  timeRange?: string[]
  preview?: boolean
}

export type ClearCacheResult = {
  clearedCount: number
  clearedAt?: string
  scope?: string
  scopeLabel?: string
  preview?: boolean
}

export type CacheClearLogEntry = {
  id: number
  scope: string
  scopeLabel: string
  domains: string
  timeStart: string
  timeEnd: string
  clearedCount: number
  operator: string
  clientIp: string
  detail: string
  time: string
}

// ── Module data ─────────────────────────────────────────────────────────────────

export const getCacheModuleData = (): Promise<ApiResponse<CacheModuleData>> => {
  return Promise.all([
    request.get('/cache/strategy') as Promise<ApiResponse<{ global: CacheGlobalStrategy; domainRules: CacheDomainRule[] }>>,
    request.get('/cache/entries') as Promise<ApiResponse<any[]>>,
  ]).then(([strategyRes, entriesRes]) => ({
    code: 0,
    message: 'ok',
    data: {
      domainCacheTree: entriesRes.data ?? [],
      strategy: {
        global: (strategyRes.data as any)?.global ?? {},
        domainRules: (strategyRes.data as any)?.domainRules ?? [],
      },
    },
  })) as Promise<ApiResponse<CacheModuleData>>
}

// ── Strategy ─────────────────────────────────────────────────────────────────

export const saveGlobalCacheStrategy = (payload: CacheGlobalStrategy): Promise<ApiResponse<CacheGlobalStrategy>> => {
  return request.put('/cache/strategy/global', payload) as Promise<ApiResponse<CacheGlobalStrategy>>
}

export const saveDomainCacheRule = (payload: Partial<CacheDomainRule> & Pick<CacheDomainRule, 'domain' | 'customTtl' | 'customRetain' | 'status'>): Promise<ApiResponse<Partial<CacheDomainRule>>> => {
  if (payload.id) {
    return request.put(`/cache/strategy/domain-rules/${payload.id}`, payload) as Promise<ApiResponse<Partial<CacheDomainRule>>>
  }
  return request.post('/cache/strategy/domain-rules', payload) as Promise<ApiResponse<Partial<CacheDomainRule>>>
}

export const deleteDomainCacheRule = (id: number): Promise<ApiResponse<IdResult>> => {
  return request.delete(`/cache/strategy/domain-rules/${id}`) as Promise<ApiResponse<IdResult>>
}

export const batchDeleteDomainCacheRules = (ids: number[]): Promise<ApiResponse<{ ids: number[] }>> => {
  return request.delete('/cache/strategy/domain-rules/batch', { data: { ids } }) as Promise<ApiResponse<{ ids: number[] }>>
}

// ── Cache entries ─────────────────────────────────────────────────────────────

export const getCacheEntries = (params?: { pattern?: string }): Promise<ApiResponse<any[]>> => {
  return request.get('/cache/entries', { params }) as Promise<ApiResponse<any[]>>
}

// ── Clear ─────────────────────────────────────────────────────────────────────

export const clearCacheRecords = (payload: ClearCachePayload): Promise<ApiResponse<ClearCacheResult>> => {
  return request.post('/cache/clear', payload) as Promise<ApiResponse<ClearCacheResult>>
}

// ── Clear logs (manual purge history) ────────────────────────────────────────

export const getCacheClearLogs = (limit = 50): Promise<ApiResponse<CacheClearLogEntry[]>> =>
  request.get('/cache/clear/logs', { params: { limit } }) as Promise<ApiResponse<CacheClearLogEntry[]>>

export const purgeCacheClearLogs = (): Promise<ApiResponse<{ cleared: boolean }>> =>
  request.delete('/cache/clear/logs') as Promise<ApiResponse<{ cleared: boolean }>>
