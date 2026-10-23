export type ServiceId = 'vector' | 'window' | 'summary'
export type ServiceHealth = 'ok' | 'warn' | 'error'

/**
 * 依赖探针状态（2026-10-03 新增）
 * unknown = 尚未探测（首屏/请求失败），必须与 ok 区分，
 * 否则会退回本项目此前"硬编码绿色"的误导行为。
 */
export type DependencyStatus = 'ok' | 'error'

export interface DependencyProbe {
  status: DependencyStatus
  latency_ms: number
  detail: string
}

export interface DependencyHealth {
  status: 'ok' | 'degraded'
  services: Record<'postgres' | 'redis' | 'qdrant' | 'llm', DependencyProbe>
  _note: string
}

export interface Service {
  id: ServiceId
  name: string
  description: string
  health: ServiceHealth
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface SecurityLog {
  id: number
  session_id: string
  event_type: string
  severity: Severity
  src_ip: string
  dst_ip: string
  message: string
  analyzed: boolean
  audit_quality?: 'llm' | 'tools' | 'rule' | 'fallback' | 'shed' | 'budget' | 'rate_limited' | string | null
  created_at: string
  is_anomaly?: boolean
  anomaly_score?: number
}
