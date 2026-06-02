import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import {
  clearCacheRecords,
  deleteDomainCacheRule,
  getCacheClearLogs,
  getCacheModuleData,
  purgeCacheClearLogs,
  saveDomainCacheRule,
  saveGlobalCacheStrategy,
  type CacheClearLogEntry,
  type CacheClearScope,
} from '../api/cache'
import type { CacheDomainRule, CacheGlobalStrategy, CacheModuleData, CacheNode } from '../types/modules'
import { nowDateTime } from '../utils/datetime'

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))

const flattenTree = (rows: CacheNode[] = []): CacheNode[] => {
  const result: CacheNode[] = []
  const walk = (items: CacheNode[]): void => {
    items.forEach((item) => {
      result.push(item)
      if (item.children?.length) {
        walk(item.children)
      }
    })
  }
  walk(rows)
  return result
}

const removeNodesByIds = (rows: CacheNode[], idsSet: Set<number>) =>
  rows
    .filter((item) => !idsSet.has(item.id))
    .map((item) => ({
      ...item,
      children: item.children?.length ? removeNodesByIds(item.children, idsSet) : undefined,
    }))

export const useCacheStore = defineStore('cache', () => {
  const loading = ref(false)
  const submitting = ref(false)
  const domainCacheTree = ref<CacheNode[]>([])
  const globalStrategy = ref<CacheGlobalStrategy>({
    ttlMax: 86400,
    minRetain: 300,
    autoCleanup: true,
    cleanupCycle: 'hourly',
  })
  const domainStrategies = ref<CacheDomainRule[]>([])
  const lastUpdated = ref('')

  const fetchCacheData = async () => {
    loading.value = true
    try {
      const { data } = await getCacheModuleData() as { data: CacheModuleData }
      domainCacheTree.value = clone(data.domainCacheTree || [])
      globalStrategy.value = clone(data.strategy?.global || globalStrategy.value)
      domainStrategies.value = clone(data.strategy?.domainRules || [])
      lastUpdated.value = nowDateTime()
    } finally {
      loading.value = false
    }
  }

  const flatDomainCache = computed(() => flattenTree(domainCacheTree.value))

  const clearByIds = async (ids: number[]): Promise<number> => {
    submitting.value = true
    try {
      const normalized = ids.map(Number)
      await clearCacheRecords({ ids: normalized })
      const idsSet = new Set(normalized)
      domainCacheTree.value = removeNodesByIds(domainCacheTree.value, idsSet)
      return normalized.length
    } finally {
      submitting.value = false
    }
  }

  const saveGlobalStrategy = async (payload: CacheGlobalStrategy): Promise<void> => {
    submitting.value = true
    try {
      await saveGlobalCacheStrategy(payload)
      globalStrategy.value = clone(payload)
    } finally {
      submitting.value = false
    }
  }

  const resetGlobalStrategy = async () => {
    await fetchCacheData()
  }

  const saveDomainRule = async (payload: Partial<CacheDomainRule> & Pick<CacheDomainRule, 'domain' | 'customTtl' | 'customRetain' | 'status'>): Promise<void> => {
    submitting.value = true
    try {
      const { data } = await saveDomainCacheRule(payload) as { data: any }
      if (payload.id) {
        const target = domainStrategies.value.find((item) => item.id === payload.id)
        if (target) {
          Object.assign(target, data)
        }
      } else {
        domainStrategies.value.unshift(data as CacheDomainRule)
      }
    } finally {
      submitting.value = false
    }
  }

  const deleteDomainRule = async (id: number): Promise<void> => {
    submitting.value = true
    try {
      await deleteDomainCacheRule(id)
      domainStrategies.value = domainStrategies.value.filter((item) => item.id !== id)
    } finally {
      submitting.value = false
    }
  }

  // Manual-purge flow. Backend does the SCAN + filter + DEL atomically
  // so the frontend doesn't have to load the full Redis cache to know
  // what would match. `previewClear` and `executeClear` share the same
  // payload shape; the server distinguishes by the `preview` flag.
  type ClearScopePayload = {
    scope: CacheClearScope
    domains?: string
    timeRange?: string[]
  }

  const previewClear = async (payload: ClearScopePayload): Promise<number> => {
    const { data } = await clearCacheRecords({ ...payload, preview: true })
    return Number(data?.clearedCount ?? 0)
  }

  const executeClear = async (
    payload: ClearScopePayload,
  ): Promise<{ count: number; scopeLabel: string }> => {
    submitting.value = true
    try {
      const { data } = await clearCacheRecords({ ...payload, preview: false })
      // The cleared-keys snapshot in domainCacheTree is built from
      // the same Redis HGETALL the backend just deleted from. Easiest
      // way to keep it in sync without re-fetching the whole tree is
      // a refresh — the entries endpoint is a single SCAN, cheap.
      await fetchCacheData()
      return {
        count: Number(data?.clearedCount ?? 0),
        scopeLabel: String(data?.scopeLabel ?? ''),
      }
    } finally {
      submitting.value = false
    }
  }

  // Persisted purge history shown in the「清理历史」panel. Loading and
  // truncation both live in the store so multiple tabs / mounted
  // pages share the same array reference.
  const clearLogs = ref<CacheClearLogEntry[]>([])
  const clearLogsLoading = ref(false)

  const fetchClearLogs = async (limit = 50): Promise<void> => {
    clearLogsLoading.value = true
    try {
      const { data } = await getCacheClearLogs(limit)
      clearLogs.value = Array.isArray(data) ? data : []
    } finally {
      clearLogsLoading.value = false
    }
  }

  const purgeClearLogs = async (): Promise<void> => {
    await purgeCacheClearLogs()
    clearLogs.value = []
  }

  return {
    loading,
    submitting,
    domainCacheTree,
    flatDomainCache,
    globalStrategy,
    domainStrategies,
    lastUpdated,
    fetchCacheData,
    clearByIds,
    previewClear,
    executeClear,
    saveGlobalStrategy,
    resetGlobalStrategy,
    saveDomainRule,
    deleteDomainRule,
    clearLogs,
    clearLogsLoading,
    fetchClearLogs,
    purgeClearLogs,
  }
})
