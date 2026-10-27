import { useState, useEffect } from 'react'
import { PageFrame } from '../components/common/PageFrame'
import { api } from '../lib/api'

interface Capability {
  id: string
  name: string
  status: 'verified' | 'experimental' | 'disabled'
  enabled: boolean
  count: number
  evidence: string
  last_verified: string
  demo: string
  notes: string
}

const CAP_META: Record<string, { label: string; desc: string }> = {
  ingest_kafka: { label: '日志接入', desc: 'Kafka / 连续水位 / DLQ' },
  flink_validation: { label: 'Flink 校验', desc: 'Schema / Sigma 聚合' },
  audit_pipeline: { label: '多智能体审计', desc: 'Decomposer → Reviewer' },
  response_engine: { label: '响应处置', desc: '审批 / 封禁 / 隔离 / TTL' },
  case_workorder: { label: '案例与工单', desc: '建案 / 派单 / 复盘' },
  rag: { label: 'RAG 知识检索', desc: '混合召回 / 重排' },
  self_play: { label: '红蓝自博弈', desc: '样本 / 候选规则 / 晋升' },
  mcp_guard: { label: 'MCP Guard', desc: '工具白名单 / RBAC / 行为签名' },
  threat_intel: { label: '威胁情报', desc: 'IOC / MISP / TAXII' },
  ndr: { label: 'NDR 流量', desc: 'PCAP / 协议 / 流聚合' },
  tls_fingerprint: { label: 'TLS 指纹', desc: 'JA3 / 证书 / SNI' },
  edr: { label: 'EDR 融合', desc: 'Sysmon / Windows 事件' },
  zeroday: { label: '0day 沙箱', desc: 'CAPE 行为分析' },
  phishing: { label: '反钓鱼', desc: '7 类检测器' },
  observability: { label: '可观测性', desc: 'OTel / Prometheus / 告警' },
  temporal: { label: 'Temporal', desc: '可选工作流加速器' },
}

export default function CapabilitiesDashboard() {
  const [caps, setCaps] = useState<Capability[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    api.get('/capabilities/status')
      .then((r: any) => {
        if (alive) setCaps(r?.capabilities ?? [])
      })
      .catch((e: any) => {
        if (alive) setError(e?.message || '能力状态加载失败')
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => { alive = false }
  }, [])

  const verifiedCount = caps.filter((c) => c.status === 'verified').length
  const experimentalCount = caps.filter((c) => c.status === 'experimental').length
  const disabledCount = caps.filter((c) => c.status === 'disabled').length
  const runtimeOn = caps.filter((c) => c.enabled).length
  const totalCount = caps.reduce((s, c) => s + c.count, 0)

  return (
    <PageFrame
      title="能力总览"
      hint="只展示登记过的能力；状态分为已验证 / 实验 / 关闭。"
      marginalia="——能力是资产，但只有被证据证明才是。"
    >
      {/* 顶部摘要 */}
      <div className="mb-10 grid grid-cols-2 gap-px border border-line bg-line md:grid-cols-4">
        <StatCell label="已验证" value={verifiedCount} hint={`/ ${caps.length} 总能力`} />
        <StatCell label="实验能力" value={experimentalCount} hint="有代码，缺真实环境证据" />
        <StatCell label="已关闭" value={disabledCount} hint={`${runtimeOn} 项运行开关为开`} />
        <StatCell label="事件累计" value={totalCount} hint="LIFETIME" />
      </div>

      {error ? (
        <p role="alert" className="border border-alert/40 bg-alert/5 px-5 py-4 text-[12px] text-alert">
          能力状态加载失败：{error}
        </p>
      ) : loading ? (
        <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint">加载中 …</p>
      ) : (
        <div className="grid grid-cols-1 border-t border-line md:grid-cols-2 lg:grid-cols-3">
          {caps.map((c, i) => {
            const meta = CAP_META[c.id] ?? { label: c.name, desc: '' }
            const tone =
              c.status === 'verified'
                ? 'text-ok'
                : c.status === 'experimental'
                  ? 'text-warn'
                  : 'text-ink-faint'
            const dot =
              c.status === 'verified'
                ? 'bg-ok'
                : c.status === 'experimental'
                  ? 'bg-warn'
                  : 'bg-ink-faint/40'
            return (
              <div
                key={c.id}
                className={`group relative p-7 bg-paper transition-colors hover:bg-mist ${
                  i % 3 !== 2 ? 'lg:border-r border-line' : ''
                } ${i < caps.length - (caps.length % 3 || 3) ? 'border-b border-line' : ''}`}
              >
                {/* 顶部编号 + 证据状态 */}
                <div className="flex items-center justify-between border-b border-ink/80 pb-3">
                  <span className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint tabular-nums">
                    CAP · {String(i + 1).padStart(2, '0')}
                  </span>
                  <span className={`inline-flex items-center gap-1.5 font-mono text-[10px] tracking-[0.22em] uppercase ${tone}`}>
                    <span className={`h-1.5 w-1.5 ${dot}`} aria-hidden />
                    {c.status.toUpperCase()}
                  </span>
                </div>

                <div className="mt-5">
                  <div className="font-serif text-[22px] font-black tracking-[-0.02em] text-ink">
                    {meta.label}
                  </div>
                  <div className="mt-1 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                    {meta.desc}
                  </div>
                  {c.notes && (
                    <p className="mt-3 text-[11px] leading-5 text-ink-soft">{c.notes}</p>
                  )}
                </div>

                <div className="mt-6 flex items-baseline justify-between gap-3 border-t border-line pt-4">
                  <div className="flex items-baseline gap-3">
                    <span className="font-serif text-[32px] font-black tabular-nums text-ink leading-none">
                      {c.count.toLocaleString()}
                    </span>
                    <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                      Events
                    </span>
                  </div>
                  <span
                    className={`font-mono text-[10px] tracking-[0.22em] uppercase ${
                      c.enabled ? 'text-ok' : 'text-ink-faint'
                    }`}
                  >
                    {c.enabled ? 'RUNNING' : 'IDLE'}
                  </span>
                </div>
                <p className="mt-2 truncate font-mono text-[9px] tracking-[0.08em] text-ink-faint" title={c.evidence}>
                  {c.last_verified ? `verified ${c.last_verified} · ` : ''}
                  {c.evidence || 'no evidence registered'}
                </p>
              </div>
            )
          })}
        </div>
      )}

      {!error && !loading && caps.length === 0 && (
        <p className="border-t border-line py-12 text-[13px] text-ink-faint">
          暂无能力状态数据（调用 <span className="font-mono">/api/capabilities/status</span>）。
        </p>
      )}

      {/* 演示数据口径披露(P3) */}
      <p className="mt-6 border-t border-line pt-3 font-mono text-[10px] leading-relaxed tracking-[0.08em] text-ink-faint">
        口径说明:演示环境部分感知/运营数据可由 /api/demo/seed 灌入,行级标注 demo-seed,可一键清空,与真实数据严格分离。
      </p>
    </PageFrame>
  )
}

function StatCell({
  label,
  value,
  hint,
}: {
  label: string
  value: number | string
  hint?: string
}) {
  return (
    <div className="bg-paper px-6 py-5">
      <p className="font-mono text-[10px] tracking-[0.26em] uppercase text-ink-faint">
        {label}
      </p>
      <p className="mt-2 font-serif text-[32px] font-black tabular-nums leading-none text-ink">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </p>
      {hint && <p className="mt-2 text-[11px] text-ink-faint">{hint}</p>}
    </div>
  )
}