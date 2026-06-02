import request from './request'
import type { ApiResponse } from '../types/api'

// System-level meta endpoints that don't belong to any specific module
// (auth / domain / forward / ...). Kept in a tiny dedicated file so we
// don't have to grow the already-large setting.ts for one-line APIs.

export interface WhoamiResult {
  /** Client IP as seen by the backend (respects trusted-proxy chain). */
  ip: string
}

/** 获取当前客户端 IP，用于「填入我的 IP」按钮 */
export const whoami = (): Promise<ApiResponse<WhoamiResult>> =>
  request.get('/system/whoami')
