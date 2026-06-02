import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { useCacheStore } from '../../stores/cache'
import type { CacheNode } from '../../types/modules'
import { loadTableState, saveTableState } from '../../utils/tableState'

type SortOrder = 'ascending' | 'descending' | null

type CacheFilters = {
  keyword: string
  recordType: string
  persistStatus: string
  timeRange: string[]
}

type CachePager = {
  page: number
  size: number
}

type CacheSorter = {
  prop: keyof CacheNode
  order: Exclude<SortOrder, null>
}

type CacheViewState = {
  filters: CacheFilters
  pager: CachePager
  sorter: CacheSorter
  selectedNodeId: number | null
}

type CacheTreeNode = CacheNode & {
  children?: CacheTreeNode[]
}

const TABLE_STATE_KEY = 'modern-dns:cache-domain:table-state'
const VIRTUAL_CACHE_PREFIX = '__virtual__:'
const CN_SECOND_LEVEL_SUFFIXES = new Set(['com', 'net', 'org', 'gov', 'edu', 'ac', 'mil', 'co'])

const makeVirtualId = (key: string): number => {
  let hash = 0
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 131 + key.charCodeAt(i)) % 2147483647
  }
  return -(hash + 1)
}

const normalizeDomain = (raw: string): string => String(raw || '').trim().replace(/\.$/, '').toLowerCase()

const getDomainSuffix = (domain: string): string => {
  const normalized = normalizeDomain(domain)
  const labels = normalized.split('.').filter(Boolean)
  if (labels.length <= 2) {
    return normalized
  }

  const tld = labels[labels.length - 1]
  const secondLevel = labels[labels.length - 2]
  const thirdLevel = labels[labels.length - 3]
  if (tld.length === 2 && CN_SECOND_LEVEL_SUFFIXES.has(secondLevel) && thirdLevel) {
    return `${thirdLevel}.${secondLevel}.${tld}`
  }
  return `${secondLevel}.${tld}`
}

const isVirtualNode = (row: Pick<CacheNode, 'cacheId'> | null | undefined): boolean =>
  String(row?.cacheId || '').startsWith(VIRTUAL_CACHE_PREFIX)

const flattenTree = (rows: CacheTreeNode[] = []): CacheTreeNode[] => {
  const result: CacheTreeNode[] = []
  const walk = (items: CacheTreeNode[]): void => {
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

const findNodeById = (rows: CacheTreeNode[], id: number): CacheTreeNode | null => {
  for (const row of rows) {
    if (row.id === id) {
      return row
    }
    if (row.children?.length) {
      const child = findNodeById(row.children, id)
      if (child) {
        return child
      }
    }
  }
  return null
}

const sortRows = (rows: CacheTreeNode[], sorter: CacheSorter): CacheTreeNode[] => {
  const next = [...rows]
  if (!sorter.prop || !sorter.order) {
    return next
  }
  const factor = sorter.order === 'ascending' ? 1 : -1
  next.sort((left, right) => {
    const leftValue = String(left[sorter.prop] ?? '')
    const rightValue = String(right[sorter.prop] ?? '')
    return leftValue.localeCompare(rightValue) * factor
  })
  return next
}

const sortTree = (rows: CacheTreeNode[], sorter: CacheSorter): CacheTreeNode[] => {
  const next = [...rows]
  if (sorter.prop && sorter.order) {
    const factor = sorter.order === 'ascending' ? 1 : -1
    next.sort((left, right) => {
      const leftValue = isVirtualNode(left) ? left.domain : String(left[sorter.prop] ?? '')
      const rightValue = isVirtualNode(right) ? right.domain : String(right[sorter.prop] ?? '')
      return leftValue.localeCompare(rightValue) * factor
    })
  }
  return next.map((item) => ({
    ...item,
    children: item.children?.length ? sortTree(item.children, sorter) : [],
  }))
}

const isCacheNode = (value: CacheTreeNode | null): value is CacheTreeNode => value !== null

const buildSuffixTree = (rows: CacheNode[]): CacheTreeNode[] => {
  const suffixMap = new Map<string, Map<string, CacheNode[]>>()
  rows.forEach((row) => {
    const domain = normalizeDomain(row.domain)
    if (!domain) {
      return
    }
    const suffix = getDomainSuffix(domain)
    const domainMap = suffixMap.get(suffix) || new Map<string, CacheNode[]>()
    const bucket = domainMap.get(domain) || []
    bucket.push({ ...row, domain, children: [] })
    domainMap.set(domain, bucket)
    suffixMap.set(suffix, domainMap)
  })

  return Array.from(suffixMap.entries()).map(([suffix, domainMap]) => {
    const domainChildren: CacheTreeNode[] = Array.from(domainMap.entries()).map(([domain, records]) => ({
      id: makeVirtualId(`domain|${suffix}|${domain}`),
      cacheId: `${VIRTUAL_CACHE_PREFIX}domain|${suffix}|${domain}`,
      domain,
      recordType: `${records.length}`,
      recordValue: '',
      ttlRemaining: 0,
      ttlOriginal: 0,
      source: '',
      persisted: '',
      cacheTime: '',
      updatedAt: '',
      children: records,
    }))

    return {
      id: makeVirtualId(`suffix|${suffix}`),
      cacheId: `${VIRTUAL_CACHE_PREFIX}suffix|${suffix}`,
      domain: `.${suffix}`,
      recordType: `${domainChildren.length}`,
      recordValue: '',
      ttlRemaining: 0,
      ttlOriginal: 0,
      source: '',
      persisted: '',
      cacheTime: '',
      updatedAt: '',
      children: domainChildren,
    }
  })
}

export const useDomainCache = () => {
  const { t } = useI18n()
  const cacheStore = useCacheStore()
  const cachedState = loadTableState<CacheViewState>(TABLE_STATE_KEY, {
    filters: { keyword: '', recordType: '', persistStatus: '', timeRange: [] },
    pager: { page: 1, size: 10 },
    sorter: { prop: 'cacheTime', order: 'descending' },
    selectedNodeId: null,
  })

  const filters = reactive<CacheFilters>({
    keyword: cachedState.filters.keyword,
    recordType: cachedState.filters.recordType,
    persistStatus: cachedState.filters.persistStatus,
    timeRange: [...cachedState.filters.timeRange],
  })
  const pager = reactive<CachePager>({
    page: cachedState.pager.page,
    size: cachedState.pager.size,
  })
  const sorter = reactive<CacheSorter>({
    prop: cachedState.sorter.prop,
    order: cachedState.sorter.order,
  })
  const selectedNodeId = ref<number | null>(cachedState.selectedNodeId)
  const selectedRows = ref<CacheNode[]>([])
  const detailDialogVisible = ref(false)
  const detailRecord = ref<CacheNode | null>(null)
  const refreshLoading = ref(false)
  const batchClearLoading = ref(false)
  const singleClearId = ref<number | null>(null)
  const lastUpdated = computed(() => cacheStore.lastUpdated)
  const loading = computed(() => cacheStore.loading)
  const submitting = computed(() => cacheStore.submitting)

  const typeOptions = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA']

  const matchesFilter = (row: CacheNode): boolean => {
    const keyword = filters.keyword.trim()
    const keywordMatch = !keyword || row.domain.includes(keyword) || row.cacheId.includes(keyword)
    const typeMatch = !filters.recordType || row.recordType === filters.recordType
    const persistMatch = !filters.persistStatus || row.persisted === filters.persistStatus
    const timeMatch =
      !filters.timeRange.length ||
      (row.cacheTime >= filters.timeRange[0] && row.cacheTime <= filters.timeRange[1])
    return keywordMatch && typeMatch && persistMatch && timeMatch
  }

  const allRecords = computed<CacheNode[]>(() =>
    flattenTree(cacheStore.domainCacheTree)
      .filter((item) => !isVirtualNode(item))
      .map((item) => ({
        ...item,
        children: [],
      })),
  )

  const filteredRecords = computed<CacheNode[]>(() => allRecords.value.filter((row) => matchesFilter(row)))
  const groupedTree = computed<CacheTreeNode[]>(() => buildSuffixTree(filteredRecords.value))
  const sortedTree = computed<CacheTreeNode[]>(() => sortTree(groupedTree.value, sorter))
  const selectedTreeNode = computed<CacheTreeNode | null>(() => {
    if (!selectedNodeId.value) {
      return null
    }
    return findNodeById(sortedTree.value, selectedNodeId.value)
  })
  const linkedRows = computed<CacheNode[]>(() => {
    if (!selectedTreeNode.value) {
      return sortRows(filteredRecords.value as CacheTreeNode[], sorter)
    }
    const realRows = flattenTree([selectedTreeNode.value]).filter((item) => !isVirtualNode(item))
    return sortRows(realRows, sorter)
  })
  const pagedRows = computed<CacheNode[]>(() => {
    const start = (pager.page - 1) * pager.size
    return linkedRows.value.slice(start, start + pager.size)
  })

  watch(
    () => ({
      filters: { ...filters, timeRange: [...filters.timeRange] },
      pager: { ...pager },
      sorter: { ...sorter },
      selectedNodeId: selectedNodeId.value,
    }),
    (next) => saveTableState(TABLE_STATE_KEY, next),
    { deep: true },
  )

  watch(
    () => filters,
    () => {
      pager.page = 1
    },
    { deep: true },
  )

  watch(sortedTree, (rows) => {
    if (selectedNodeId.value && !findNodeById(rows, selectedNodeId.value)) {
      selectedNodeId.value = null
    }
  })

  const refreshData = async (): Promise<void> => {
    if (refreshLoading.value) {
      return
    }
    refreshLoading.value = true
    try {
      await cacheStore.fetchCacheData()
      ElMessage.success(t('cache.refreshed'))
    } finally {
      refreshLoading.value = false
    }
  }

  const selectTreeNode = (node: CacheNode | null): void => {
    selectedNodeId.value = node?.id ?? null
    pager.page = 1
  }

  const resetSelectedTreeNode = (): void => {
    selectedNodeId.value = null
    pager.page = 1
  }

  const handleSortChange = ({ prop, order }: { prop: string | null; order: SortOrder }): void => {
    sorter.prop = (prop as keyof CacheNode) || 'cacheTime'
    sorter.order = order || 'descending'
  }

  const handlePageChange = (page: number): void => {
    pager.page = page
  }

  const handlePageSizeChange = (size: number): void => {
    pager.page = 1
    pager.size = size
  }

  const handleSelectionChange = (rows: CacheNode[]): void => {
    selectedRows.value = rows
  }

  const openDetail = (row: CacheNode): void => {
    detailRecord.value = row
    detailDialogVisible.value = true
  }

  const copyRecordValue = async (): Promise<void> => {
    if (!detailRecord.value?.recordValue) {
      return
    }
    try {
      await navigator.clipboard.writeText(detailRecord.value.recordValue)
      ElMessage.success(t('cache.recordCopied'))
    } catch (_error) {
      ElMessage.warning(t('cache.copyFailed'))
    }
  }

  const clearSingleCache = async (row: CacheNode): Promise<void> => {
    if (singleClearId.value || cacheStore.submitting) {
      return
    }
    singleClearId.value = row.id
    try {
      const count = await cacheStore.clearByIds([row.id])
      await cacheStore.fetchCacheData()
      selectedRows.value = selectedRows.value.filter((item) => item.id !== row.id)
      ElMessage.success(t('cache.clearedSuccess', { n: count }))
    } finally {
      singleClearId.value = null
    }
  }

  const batchClearCache = async (): Promise<void> => {
    if (batchClearLoading.value || cacheStore.submitting || !selectedRows.value.length) {
      return
    }
    batchClearLoading.value = true
    try {
      const count = await cacheStore.clearByIds(selectedRows.value.map((item) => item.id))
      await cacheStore.fetchCacheData()
      selectedRows.value = []
      ElMessage.success(t('cache.batchClearedSuccess', { n: count }))
    } finally {
      batchClearLoading.value = false
    }
  }

  const formatDateTime = (value: string): string => {
    if (!value) {
      return t('common.none')
    }
    return value.replace('T', ' ').slice(0, 19)
  }

  const isTtlWarning = (value: number | string): boolean => Number(value) > 0 && Number(value) < 30

  const sourceTagType = (value: string): 'success' | 'warning' | 'info' => {
    if (value === '本地配置' || value.toLowerCase() === 'local config') {
      return 'success'
    }
    if (value === '递归解析' || value.toLowerCase() === 'recursive resolve') {
      return 'warning'
    }
    return 'info'
  }

  const typeTagType = (type: string): 'success' | 'warning' | 'info' | 'primary' => {
    const map: Record<string, 'success' | 'warning' | 'info' | 'primary'> = {
      A: 'success',
      TXT: 'warning',
      AAAA: 'primary',
      MX: 'info',
    }
    return map[type] || 'info'
  }

  const persistTagType = (value: string): 'success' | 'info' =>
    (value === '已持久化' || value.toLowerCase() === 'persisted' ? 'success' : 'info')

  onMounted(async () => {
    await cacheStore.fetchCacheData()
  })

  return {
    loading,
    submitting,
    refreshLoading,
    batchClearLoading,
    singleClearId,
    lastUpdated,
    typeOptions,
    filters,
    sorter,
    pager,
    selectedRows,
    selectedNodeId,
    selectedTreeNode,
    sortedTree,
    linkedRows,
    pagedRows,
    detailDialogVisible,
    detailRecord,
    refreshData,
    selectTreeNode,
    resetSelectedTreeNode,
    handleSortChange,
    handlePageChange,
    handlePageSizeChange,
    handleSelectionChange,
    openDetail,
    copyRecordValue,
    clearSingleCache,
    batchClearCache,
    formatDateTime,
    isTtlWarning,
    sourceTagType,
    typeTagType,
    persistTagType,
  }
}

export default useDomainCache