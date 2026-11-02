import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { PageTransition } from '../components/common/PageTransition'
import { PageFrame } from '../components/common/PageFrame'
import { KpiStat } from '../components/ui/KpiStat'
import { LiveBadge } from '../components/ui/LiveBadge'
import { NAV_GROUPS } from '../layouts/nav'
import { ROUTES } from '../lib/constants'
import { api } from '../lib/api'
import { useEventStreamLifecycle, useEventStreamStore } from '../lib/eventStream'
import { formatWatchClock, watchShiftAt } from '../lib/watchShift'
import type { SecurityLog } from '../types'
import type { StatsResponse } from '../types/stats'

/**
 * Home · 工作台首页（v8 重构）
 *
 * 纯工作台：值班行 → KPI 带 → 双列（实时事件流 ｜ 模块入口）→ 演示入口行。
 * 不再承担品牌叙事与导航枢纽职能 —— 导航已交还 TopNav。
 */
export default function Home() {
  const navigate = useNavigate()
  const [recentLogs, setRecentLogs] = useState<SecurityLog[]>([])
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [attackCount, setAttackCount] = useState(0)
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    api.logsEvents({ limit: '8' }).then((d) => setRecentLogs(Array.isArray(d) ? d : [])).catch(() => {})
    api.stats().then(setStats).catch(() => {})
  }, [])

  // R15(P1-13): 走全站共享 SSE 内核(eventStream 单例)
  useEventStreamLifecycle()
  useEffect(() => {
    return useEventStreamStore.subscribe((state, prev) => {
      if (state.arrivalTick === prev.arrivalTick) return
      const newest = state.buffer[0]
      if (!newest || newest.kind !== 'event') return
      if (newest.type === 'security_event' && newest.data?.is_anomaly) {
        setAttackCount((c) => c + 1)
      } else if (newest.type === 'audit_complete' && newest.data?.threat_detected) {
        setAttackCount((c) => c + 2)
      }
    })
  }, [])

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(id)
  }, [])

  const audited = stats?.audit_llm?.completed ?? 0
  const total = stats?.security_events ?? 0
  const pending = stats?.security_pending ?? 0
  const memories = stats?.memories_count ?? 0
  const responseMs = stats?.audit_llm?.response_ms_median ?? stats?.response_ms_median ?? 240

  const shift = watchShiftAt(now)
  const shiftText = shift.night ? shift.label : `${shift.earthly}时 · ${shift.label}`
  const alerted = pending > 0 || attackCount > 0

  return (
    <PageTransition>
      <PageFrame
        title="工作台"
        hint="平台实时运行态势 · 事件流每 2s 推送。"
        extra={
          <div className="flex items-center gap-4">
            <span className="text-[12px] text-ink-faint tabular-nums">
              值班 · {shiftText} {formatWatchClock(now)}
            </span>
            <LiveBadge live={!alerted} label={alerted ? '有待处理' : '一切正常'} />
          </div>
        }
      >
        {/* KPI 带 */}
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-[6px] border border-line bg-line md:grid-cols-3 xl:grid-cols-6">
          <KpiCell>
            <KpiStat label="待处理" value={pending} tone={pending > 0 ? 'warn' : 'ok'} hint={pending > 0 ? '等待复核或处置' : '队列已清空'} />
          </KpiCell>
          <KpiCell>
            <KpiStat label="已完成审计" value={audited} hint={total > 0 ? `占比 ${Math.round((audited / total) * 100)}%` : '—'} />
          </KpiCell>
          <KpiCell>
            <KpiStat label="已接入事件" value={total} live hint="实时接入总量" />
          </KpiCell>
          <KpiCell>
            <KpiStat label="语义记忆" value={memories} hint="RAG 知识沉淀" />
          </KpiCell>
          <KpiCell>
            <KpiStat label="响应中位" value={`${responseMs} ms`} tone="accent" hint="审计-响应链路" />
          </KpiCell>
          <KpiCell>
            <KpiStat label="攻击脉冲" value={attackCount} tone={attackCount > 0 ? 'alert' : 'neutral'} hint={attackCount > 0 ? '当前会话累计' : '无活跃攻击'} />
          </KpiCell>
        </div>

        {/* 双列：实时事件流 ｜ 模块入口 */}
        <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          {/* 实时事件流 */}
          <section className="overflow-hidden rounded-[6px] border border-line bg-card">
            <header className="flex items-center justify-between border-b border-line px-4 py-2.5">
              <h2 className="text-[13px] font-medium text-ink">最近事件</h2>
              <Link to={ROUTES.LOGS} className="text-[12px] text-accent hover:opacity-80">
                全部日志 →
              </Link>
            </header>
            <ul className="divide-y divide-line">
              {recentLogs.length === 0 && (
                <li className="px-4 py-10 text-center text-[13px] text-ink-faint">
                  暂无事件 —— 可在
                  <button className="mx-1 text-accent" onClick={() => navigate(ROUTES.SENSING)}>感知中心</button>
                  灌入演示数据
                </li>
              )}
              {recentLogs.map((log) => (
                <li key={log.id}>
                  <button
                    type="button"
                    onClick={() => navigate(`${ROUTES.LOGS}?event=${log.id}`)}
                    className="flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-inset"
                  >
                    <SeverityDot severity={log.severity} />
                    <span className="w-28 shrink-0 truncate font-mono text-[12px] text-ink">
                      {log.event_type}
                    </span>
                    <span className="hidden min-w-0 flex-1 truncate text-[12px] text-ink-soft sm:block">
                      {log.src_ip} → {log.dst_ip}
                    </span>
                    <span className="ml-auto shrink-0 font-mono text-[11px] tabular-nums text-ink-faint">
                      {formatTime(log.created_at)}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </section>

          {/* 模块入口 */}
          <section className="overflow-hidden rounded-[6px] border border-line bg-card">
            <header className="flex items-center justify-between border-b border-line px-4 py-2.5">
              <h2 className="text-[13px] font-medium text-ink">功能模块</h2>
              <span className="text-[11px] text-ink-faint">4 组 · 12 页</span>
            </header>
            <div className="grid grid-cols-1 gap-px bg-line sm:grid-cols-2">
              {NAV_GROUPS.flatMap((g) => g.items.map((item) => ({ ...item, group: g.title }))).map(
                (item) => (
                  <Link
                    key={item.path}
                    to={item.path}
                    className="group bg-card px-4 py-3 transition-colors hover:bg-inset"
                  >
                    <p className="flex items-center gap-2 text-[13px] font-medium text-ink">
                      {item.label}
                      <span className="text-[11px] font-normal text-ink-faint">{item.group}</span>
                      <span
                        aria-hidden
                        className="ml-auto text-[12px] text-ink-faint opacity-0 transition-opacity group-hover:opacity-100"
                      >
                        →
                      </span>
                    </p>
                    {item.hint && (
                      <p className="mt-0.5 truncate text-[11px] leading-snug text-ink-faint">
                        {item.hint}
                      </p>
                    )}
                  </Link>
                ),
              )}
            </div>
          </section>
        </div>

        {/* 演示入口行 */}
        <section className="mt-4 rounded-[6px] border border-line bg-card px-4 py-3">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <span className="text-[13px] font-medium text-ink">演示</span>
            <DemoLink label="攻击剧本 · 六幕连放" onClick={() => navigate(ROUTES.DEMO)} />
            <DemoLink label="作战大屏（kiosk）" onClick={() => navigate(ROUTES.SCREEN)} />
            <DemoLink label="系统全景海报" onClick={() => navigate(ROUTES.POSTER)} />
            <span className="ml-auto text-[11px] text-ink-faint">舞台页 · 用于答辩与路演</span>
          </div>
        </section>
      </PageFrame>
    </PageTransition>
  )
}

function KpiCell({ children }: { children: React.ReactNode }) {
  return <div className="bg-card px-4 py-3.5">{children}</div>
}

const SEVERITY_TONE: Record<string, string> = {
  critical: 'bg-alert',
  high: 'bg-warn',
  medium: 'bg-signal',
  low: 'bg-ink-faint',
  info: 'bg-ink-faint',
}

function SeverityDot({ severity }: { severity: string }) {
  return (
    <span
      aria-hidden
      className={`h-1.5 w-1.5 shrink-0 rounded-full ${SEVERITY_TONE[severity] ?? 'bg-ink-faint'}`}
    />
  )
}

function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function DemoLink({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-[4px] border border-line px-3 py-1.5 text-[12px] text-ink-soft transition-colors hover:border-accent hover:text-accent"
    >
      {label}
    </button>
  )
}

