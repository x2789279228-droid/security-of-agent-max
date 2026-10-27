import { useSearchParams } from 'react-router-dom'

/**
 * 案卷链 · 实体深链(P2)
 * 同一 event_id 在 Monitor/Logs/SecurityAudit/CostTab 各有孤立入口,
 * 通过 ?event= 参数把五处串成一条可追的链;参数留在 URL,刷新/分享可复现。
 */

/** 读取 ?event= 深链参数;缺失/非法返回 null */
export function useEventParam(): number | null {
  const [params] = useSearchParams()
  const n = Number(params.get('event'))
  return Number.isFinite(n) && n > 0 ? n : null
}

export const eventHref = {
  monitor: (id: number) => `/monitor?event=${id}`,
  audit: (id: number) => `/security-audit?event=${id}`,
  logs: (id: number) => `/logs?event=${id}`,
}
