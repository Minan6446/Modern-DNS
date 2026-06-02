import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { batchDeleteAlertEvents, getAlerts, handleAlertEvent, markAllAlertsRead } from '../api/dashboard'

export interface AlertNotice {
  id: number
  level: string
  type: string
  domain: string
  content: string
  suppressType: string
  suppressReason: string
  status: string
  read: boolean
  triggeredAt: string
  updatedAt: string
}

export const useAlertStore = defineStore('alert', () => {
  const notices = ref<AlertNotice[]>([])
  const loading = ref(false)
  // True row count from the DB. Distinct from `notices.length`, which
  // is only the slice the server returned (default 500). The「告警
  // 总数」KPI tile reads this so the number doesn't lie when the table
  // is page-bounded.
  const total = ref(0)

  const unreadCount = computed(() => notices.value.filter(n => !n.read).length)

  const fetchAlerts = async (limit = 500) => {
    loading.value = true
    try {
      const res = await getAlerts({ limit })
      const data = (res as any).data ?? res
      const rows = data?.rows ?? []
      total.value = Number(data?.total ?? rows.length)
      notices.value = rows.map((r: any) => ({
        id: r.id,
        level: r.level || 'info',
        type: r.type || '',
        domain: r.domain || '',
        content: r.content || '',
        suppressType: r.suppressType || '',
        suppressReason: r.suppressReason || '',
        status: r.status || '未读',
        read: !!r.read,
        triggeredAt: r.triggeredAt || '',
        updatedAt: r.updatedAt || '',
      }))
    } finally {
      loading.value = false
    }
  }

  const markRead = (id: number) => {
    const item = notices.value.find(n => n.id === id)
    if (item) item.read = true
  }

  const markAllRead = async () => {
    await markAllAlertsRead()
    notices.value.forEach(n => { n.read = true })
  }

  const handleAlert = async (id: number) => {
    await handleAlertEvent(id)
    const item = notices.value.find(n => n.id === id)
    if (item) {
      item.status = '已处理'
      item.read = true
    }
  }

  const clearHandled = () => {
    notices.value = notices.value.filter(n => n.status !== '已处理')
  }

  // Server-side batch delete. The previous in-memory `clearHandled`
  // only filtered the local array, so a refresh brought all the
  // already-handled rows back. This persists.
  const batchDelete = async (ids: number[]): Promise<number> => {
    if (!ids.length) return 0
    const res = await batchDeleteAlertEvents(ids)
    const deleted = Number((res as any)?.data?.deleted ?? ids.length)
    const removeSet = new Set(ids)
    notices.value = notices.value.filter(n => !removeSet.has(n.id))
    return deleted
  }

  return {
    notices,
    loading,
    total,
    unreadCount,
    fetchAlerts,
    markRead,
    markAllRead,
    handleAlert,
    clearHandled,
    batchDelete,
  }
})
