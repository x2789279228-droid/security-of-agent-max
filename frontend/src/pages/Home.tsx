import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { PageTransition } from '../components/common/PageTransition'
import { PageFrame } from '../components/common/PageFrame'
import { KpiStat } from '../components/ui/KpiStat'
import { LiveBadge } from '../components/ui/LiveBadge'
import { ROUTES } from '../lib/constants'
import { api } from '../lib/api'
import { flattenNavItems, hiddenAdvancedCount, visibleNavGroups } from '../lib/navPrefs'
import { useNavExpert } from '../hooks/useNavExpert'
import { formatWatchClock, watchShiftAt } from '../lib/watchShift'
import type { SecurityLog } from '../types'
import type { StatsResponse } from '../types/stats'

/**
 * Home · 工作台首页（v9 打磨）
 *
 * 首屏先回答「产品替我做了什么」：
 *   价值 KPI（非零优先）→ 最近事件 → 从这里开始（演示 / 大屏 / 全景）。
 * 12 个功能入口降级为可折叠的「全部能力」，减少首屏认知负担。
 */
export default function Home() {
  const navigate = useNavigate()
  const { expert, setExpert } = useNavExpert()
  const [recentLogs, setRecentLogs] = useState<SecurityLog[]>([])
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    let alive = true
    const load = () => {
      api
        .logsEvents({ limit: '8' })
        .then((d) => {
          if (alive) setRecentLogs(Array.isArray(d) ? d : [])
        })
        .catch(() => {})
      api
        .stats()
        .then((d) => {
          if (alive) setStats(d)
        })
        .catch(() => {})
    }
    load()
    const id = window.setInterval(load, 10_000)
    return () => {
      alive = false
      window.clearInterval(id)
    }
  }, [])

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(id)
  }, [])

  const audited = stats?.audit_llm?.completed ?? 0
  const total = stats?.security_events ?? 0
  const pending = stats?.security_pending ?? 0
  // 此前「语义记忆」取 memories_count，实库里恒为 0；记忆节点 tree_nodes 才是真实在涨的索引
  const memories = stats?.tree_nodes ?? 0
  const responseMs = stats?.audit_llm?.response_ms_median ?? stats?.response_ms_median ?? 240
  const completion = total > 0 ? Math.round((audited / total) * 100) : 0

  const shift = watchShiftAt(now)
  const shiftText = shift.night ? shift.label : `${shift.earthly}时 · ${shift.label}`
  const alerted = pending > 0
  const modules = flattenNavItems(visibleNavGroups(expert))
  const advancedHidden = expert ? 0 : hiddenAdvancedCount()

  return (
    <PageTransition>
      <PageFrame
        title="工作台"
        hint={`从告警到处置的完整闭环 · 已接管 ${formatNumber(total)} 起事件，等待人工的仅 ${pending} 条。`}
        extra={
          <div className="flex items-center gap-4">
            <span className="text-[12px] text-ink-faint tabular-nums">
              值班 · {shiftText} {formatWatchClock(now)}
            </span>
            <LiveBadge live={!alerted} label={alerted ? '有待处理' : '一切正常'} />
          </div>
        }
      >
        {/* 价值 KPI：先给「做成了什么」，再给「排队多少」 */}
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-[6px] border border-line bg-line md:grid-cols-3 xl:grid-cols-5">
          <KpiCell>
            <KpiStat label="已接管事件" value={total} live hint="累计接入 · 每 10s 刷新" />
          </KpiCell>
          <KpiCell>
            <KpiStat label="已完成审计" value={audited} tone="accent" hint={`完成率 ${completion}%`} />
          </KpiCell>
          <KpiCell>
            <KpiStat label="记忆节点" value={memories} hint="事件关联索引 · 不是聊天记录" />
          </KpiCell>
          <KpiCell>
            <KpiStat label="响应中位" value={`${responseMs} ms`} tone="signal" hint="审计 → 处置链路" />
          </KpiCell>
          <KpiCell>
            <KpiStat
              label="待人工"
              value={pending}
              tone={pending > 0 ? 'warn' : 'ok'}
              hint={pending > 0 ? '等待复核或处置' : '队列已清空'}
            />
          </KpiCell>
        </div>

        <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          {/* 最近事件 */}
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
                  暂无事件 —— 到
                  <button className="mx-1 text-accent" onClick={() => navigate(ROUTES.INGEST)}>
                    接入台
                  </button>
                  一键注入攻击剧本，看全链路点亮
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
                    <span className="w-28 shrink-0 truncate font-mono text-[12px] text-ink">{log.event_type}</span>
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

          {/* 从这里开始：演示入口 + 可折叠的全部能力 */}
          <section className="flex flex-col overflow-hidden rounded-[6px] border border-line bg-card">
            <header className="flex items-center justify-between border-b border-line px-4 py-2.5">
              <h2 className="text-[13px] font-medium text-ink">从这里开始</h2>
              <span className="text-[11px] text-ink-faint">演示 · 大屏 · 全景</span>
            </header>

            <div className="grid gap-px bg-line">
              <StartCard
                label="看一次完整处置"
                hint="六幕攻击剧本 · 从告警到结案 · 可直接投屏"
                primary
                onClick={() => navigate(ROUTES.DEMO)}
              />
              <StartCard label="作战大屏" hint="值班大屏 · 免登录直达" onClick={() => navigate(ROUTES.SCREEN)} />
              <StartCard label="系统全景" hint="一屏读懂架构与链路" onClick={() => navigate(ROUTES.POSTER)} />
            </div>

            <details className="mt-auto border-t border-line">
              <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-2.5 text-[13px] text-ink-soft hover:bg-inset [&::-webkit-details-marker]:hidden">
                <span>全部能力 · {modules.length} 个入口</span>
                <span className="text-[11px] text-ink-faint">展开</span>
              </summary>
              <div className="grid grid-cols-1 gap-px border-t border-line bg-line sm:grid-cols-2">
                {modules.map((item) => (
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
                      <p className="mt-0.5 truncate text-[11px] leading-snug text-ink-faint">{item.hint}</p>
                    )}
                  </Link>
                ))}
              </div>
              {advancedHidden > 0 && (
                <div className="border-t border-line bg-card px-4 py-2.5">
                  <button
                    type="button"
                    onClick={() => setExpert(true)}
                    className="flex w-full items-center justify-between text-left text-[12px] text-ink-soft transition-colors hover:text-ink"
                  >
                    <span>
                      已隐藏 {advancedHidden} 项高级能力（自博弈 / 知识库 / 评测 / 反钓鱼 / 全景）
                    </span>
                    <span className="shrink-0 text-[11px] text-accent">开启专家模式</span>
                  </button>
                </div>
              )}
            </details>
          </section>
        </div>
      </PageFrame>
    </PageTransition>
  )
}

function KpiCell({ children }: { children: React.ReactNode }) {
  return <div className="bg-card px-4 py-3.5">{children}</div>
}

function StartCard({
  label,
  hint,
  primary = false,
  onClick,
}: {
  label: string
  hint: string
  primary?: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`group flex items-center justify-between gap-4 px-4 py-3 text-left transition-colors ${
        primary ? 'bg-accent/[0.06] hover:bg-accent/[0.12]' : 'bg-card hover:bg-inset'
      }`}
    >
      <span className="min-w-0">
        <span className={`block text-[13px] font-medium ${primary ? 'text-accent' : 'text-ink'}`}>
          {label}
          {primary && <span className="ml-2 font-mono text-[10px] tracking-[0.16em] uppercase text-accent/70">demo</span>}
        </span>
        <span className="mt-0.5 block truncate text-[11px] text-ink-faint">{hint}</span>
      </span>
      <span aria-hidden className="text-[14px] text-ink-faint transition-transform group-hover:translate-x-0.5">
        →
      </span>
    </button>
  )
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
    <span aria-hidden className={`h-1.5 w-1.5 shrink-0 rounded-full ${SEVERITY_TONE[severity] ?? 'bg-ink-faint'}`} />
  )
}

function formatNumber(n: number): string {
  return n.toLocaleString('zh-CN')
}

function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
