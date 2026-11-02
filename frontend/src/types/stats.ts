/**
 * /api/stats 响应形状 — 与后端 routers/chat.py::_stats_payload 逐字段对齐 (R18)。
 *
 * 修复前: Monitor/Home/BattleScreen 各自 useState<any> + 防御式 Number(...) 兜底,
 * 后端字段改名前端编译期无感知(历史上已漂移过一次: response_ms_median 兼容回退)。
 * 此类型是单一事实源; 后端改动时先改这里, tsc 会把消费点全部标红。
 */

export interface AuditLlmStats {
  total: number
  completed: number
  pending: number
  /** 兼容回退: 部分版本在此带响应中位数(ms) */
  response_ms_median?: number
}

export interface StatsResponse {
  memories_count: number
  conversations_count: number
  security_events: number
  security_pending: number
  tree_nodes: number
  tree_leaves: number
  redis_keys: number
  audit_llm: AuditLlmStats
  services: {
    pgvector: string
    redis: string
    llm: string
    embedding: string
  }
  /** 兼容回退: 旧版后端在顶层带响应中位数(ms); 新版在 audit_llm 下 */
  response_ms_median?: number
}
