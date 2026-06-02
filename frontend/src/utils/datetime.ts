const pad2 = (value: number): string => String(value).padStart(2, '0')

export const formatDateTime = (value: unknown, empty = '--'): string => {
  const raw = String(value ?? '').trim()
  if (!raw) return empty
  if (raw === '—') return raw

  const date = new Date(raw)
  if (Number.isNaN(date.getTime())) {
    const normalized = raw.replace('T', ' ').replace(/\//g, '-').trim()
    if (/^\d{4}-\d{2}-\d{2}$/.test(normalized)) return normalized
    const match = normalized.match(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/)
    if (match) return `${match[1]} ${match[2]}`
    return raw
  }

  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())} ${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`
}

export const nowDateTime = (): string => formatDateTime(new Date())
