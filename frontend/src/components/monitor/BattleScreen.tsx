import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { HealthGauge } from '../ui/HealthGauge'
import { KpiStat } from '../ui/KpiStat'
import { LiveBadge } from '../ui/LiveBadge'
import { WatchShift } from '../ui/WatchShift'
import AgentRelayStrip from './AgentRelayStrip'
import ActiveRelayCards from './ActiveRelayCards'
import AttackGeoMap from './AttackGeoMap'
import LedgerPanel from './LedgerPanel'
import ThoughtChainPanel from './ThoughtChainPanel'
import ToolAnomalyBanner from './ToolAnomalyBanner'
import { useWallKeepalive } from '../../hooks/useWallKeepalive'
import { severityOf, useEventStreamStore, getLastActivityTs, type StreamEvent, type StreamStatus } from '../../lib/eventStream'
import type { RelayState } from '../../lib/agentPipeline'

/**
 * 审计大屏(Monitor 战模式,阶段 4) — 1920×1080 投影优先的三列无滚动网格。
 *
 * 层叠四手法(零遮挡):
 * ① 主舞台前移 — ThoughtChainPanel 跨装订线各延伸 16px,暮金框+辉光,z 层最高
 * ② 卷宗标签骑缝 — 面板标题骑在上边缘(半内半外)
 * ③ 时序性重叠 — 新事件行滑入、critical vignette 瞬时全屏
 * ④ 微错位堆叠 — 左列 KPI 卡 3px 级联错位;封条骑底缝
 *
 * 幕布续命(阶段 6):SSE 离线超过宽限期自动切入回放剧本(useWallKeepalive),
 * 顶栏徽章与底栏跑马灯明示「回放口径」—— 不伪装成 LIVE。
 * 距离字号:正文按 3-5m 观看距离校准(12-13px 起);思维链主舞台经 .wall-zoom 整体放大。
 */

type ServiceHealth = 'ok' | 'warn' | 'alert' | 'error' | 'unknown'

const BATTLE_SERVICE_TONE: Record<ServiceHealth, { color: string; label: string }> = {
  ok: { color: '#5da583', label: 'NOMINAL' },
  warn: { color: '#d4a054', label: 'DEGRADED' },
  alert: { color: '#e05a4e', label: 'ALERT' },
  error: { color: '#e05a4e', label: 'ALERT' },
  unknown: { color: '#33475a', label: 'UNKNOWN' },
}

/** 卷宗标签骑缝:标签骑在面板上边缘,一半在内一半在外 */
function BattlePanel({
  tab,
  children,
  className = '',
}: {
  tab: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <section className={`relative border border-[#24384a] bg-[#1a2d3f] ${className}`}>
      <span
        className="absolute -top-[12px] left-4 border border-[#24384a] bg-[#0e1a26] px-2.5 py-0.5 font-mono text-[11px] tracking-[0.26em] uppercase text-[#8fa0ad]"
        aria-hidden
      >
        {tab}
      </span>
      {children}
    </section>
  )
}

const fmtClock = (ts: number) => {
  const d = new Date(ts)
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, '0')).join(':')
}

const SEV_COLOR: Record<string, string> = {
  critical: '#e05a4e',
  high: '#d4a054',
  medium: '#74a7b5',
  low: '#33475a',
  info: '#33475a',
}

export interface BattleScreenProps {
  services: Record<string, ServiceHealth>
  serviceDetails: Record<string, string | undefined>
  streamStatus: StreamStatus
  visible: StreamEvent[]
  typeCounts: Record<string, number>
  bufferCount: number
  selectedEventId: number | null
  onSelectEvent: (id: number) => void
  onCloseThought: () => void
  idleHint: string
  hydrated: unknown[]
  hydratedRecent: RelayState[]
  onDemo: () => void
  demoBusy: boolean
  stats: any
  onExit: () => void
}

const CRITICAL_FLASH_COOLDOWN_MS = 3000

export default function BattleScreen(props: BattleScreenProps) {
  const {
    services, serviceDetails, streamStatus, visible, typeCounts, bufferCount,
    selectedEventId, onSelectEvent, onCloseThought, idleHint,
    hydrated, hydratedRecent, onDemo, demoBusy, stats, onExit,
  } = props

  const arrivalTick = useEventStreamStore((s) => s.arrivalTick)

  // 幕布续命:断流宽限期后切入回放;徽章明示口径
  const replayActive = useWallKeepalive(streamStatus)

  // 进场:data-mode=battle + 请求全屏;退场还原
  useEffect(() => {
    const el = document.documentElement
    const prev = el.dataset.mode
    el.dataset.mode = 'battle'
    document.documentElement.requestFullscreen?.().catch(() => { /* 全屏被拒时以窗口模式运行 */ })
    return () => {
      if (prev === undefined) delete el.dataset.mode
      else el.dataset.mode = prev
      if (document.fullscreenElement) document.exitFullscreen().catch(() => {})
    }
  }, [])

  // Esc 退出大屏
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onExit()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onExit])

  // 心跳年龄(5s 刷新;从未活动时显示 —)
  const [heartbeatAge, setHeartbeatAge] = useState(() => Math.round((Date.now() - getLastActivityTs()) / 1000))
  useEffect(() => {
    const t = setInterval(() => setHeartbeatAge(Math.round((Date.now() - getLastActivityTs()) / 1000)), 5000)
    return () => clearInterval(t)
  }, [])
  const heartbeatLabel = getLastActivityTs() === 0 ? '—' : `${Math.min(heartbeatAge, 9999)}s 前`

  // critical 到达:边缘红色 vignette 一闪(600ms,3s 冷却)
  const [flashTick, setFlashTick] = useState(0)
  const lastFlashRef = useRef(0)
  const lastTopIdRef = useRef<number | null>(null)
  useEffect(() => {
    const top = visible[0]
    if (!top || top.id === lastTopIdRef.current) return
    lastTopIdRef.current = top.id
    const sev = severityOf(top.type, top.data)
    if (sev !== 'critical') return
    const now = Date.now()
    if (now - lastFlashRef.current < CRITICAL_FLASH_COOLDOWN_MS) return
    lastFlashRef.current = now
    setFlashTick((n) => n + 1)
  }, [visible, arrivalTick])

  const streamLines = visible.slice(0, 12)
  const criticals = visible
    .filter((e) => e.kind === 'event' && severityOf(e.type, e.data) === 'critical')
    .slice(0, 8)

  const securityPending = Math.max(0, Number(stats?.security_pending ?? 0) || 0)

  return (
    <div className="fixed inset-0 z-[70] flex flex-col bg-[#0e1a26] text-[#dfe7e3]">
      {/* critical 爆闪 vignette */}
      <AnimatePresence>
        {flashTick > 0 && (
          <motion.div
            key={flashTick}
            className="pointer-events-none fixed inset-0 z-[80]"
            style={{ boxShadow: 'inset 0 0 140px rgba(224,90,78,0.55)' }}
            initial={{ opacity: 0.9 }}
            animate={{ opacity: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.6, ease: 'easeOut' }}
            aria-hidden
          />
        )}
      </AnimatePresence>

      {/* ── 顶栏 64px ── */}
      <header className="flex h-16 shrink-0 items-center gap-5 border-b border-[#24384a] px-6">
        <span className="font-serif text-[24px] font-black tracking-[-0.02em]">守望</span>
        <span className="font-mono text-[12px] tracking-[0.3em] uppercase text-[#c9a574]">审计作战</span>
        <WatchShift />
        <span className="h-4 w-px bg-[#24384a]" aria-hidden />
        {replayActive ? (
          <span className="inline-flex items-center gap-2 border border-[#c9a574]/50 bg-[#c9a574]/10 px-2.5 py-1 font-mono text-[11px] tracking-[0.2em] uppercase text-[#c9a574]">
            <LiveBadge live={false} label="回放口径" className="!text-[#d9bc8b]" />
          </span>
        ) : (
          <span className={`inline-flex items-center gap-2 font-mono text-[11px] tracking-[0.2em] uppercase ${
            streamStatus === 'online' ? 'text-[#5da583]' : 'text-[#d4a054]'
          }`}>
            <LiveBadge live={streamStatus === 'online'} label={streamStatus === 'online' ? 'LIVE' : streamStatus.toUpperCase()} />
          </span>
        )}
        <span className="font-mono text-[12px] tabular-nums text-[#78889a]">心跳 {heartbeatLabel}</span>
        <span className="font-mono text-[12px] tabular-nums text-[#78889a]">缓冲 {bufferCount}</span>
        <div className="ml-auto flex items-center gap-2.5">
          <button
            onClick={onDemo}
            disabled={demoBusy}
            className="border border-[#c9a574]/50 px-3.5 py-2 font-mono text-[11px] tracking-[0.2em] uppercase text-[#c9a574] hover:bg-[#203349] transition-colors disabled:opacity-40"
          >
            ▶ 演示剧本
          </button>
          <button
            onClick={onExit}
            className="border border-[#33475a] px-3.5 py-2 font-mono text-[11px] tracking-[0.2em] uppercase text-[#a7b4bd] hover:border-[#c9a574]/50 hover:text-[#c9a574] transition-colors"
            title="退出大屏(Esc)"
          >
            F 退出大屏
          </button>
        </div>
      </header>

      {/* ── 三列网格 ── */}
      <div className="grid min-h-0 flex-1 grid-cols-[320px_1fr_400px] gap-5 p-5">
        {/* 左列 */}
        <aside className="flex min-h-0 flex-col gap-5">
          {/* 依赖健康(紧凑四行) */}
          <BattlePanel tab="依赖健康" className="shrink-0 px-4 pb-3 pt-5">
            <div className="divide-y divide-[#233850]">
              {Object.entries(services).map(([id, health]) => {
                const tone = BATTLE_SERVICE_TONE[health] ?? BATTLE_SERVICE_TONE.unknown
                return (
                  <div key={id} className="flex items-center gap-3 py-2.5">
                    <HealthGauge health={health === 'ok' ? 'ok' : health === 'warn' ? 'warn' : health === 'unknown' ? 'warn' : 'error'} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-[13px] uppercase tracking-[0.14em] text-[#a7b4bd]">{id}</p>
                      {serviceDetails[id] && (
                        <p className="truncate font-mono text-[11px] text-[#78889a]" title={serviceDetails[id]}>{serviceDetails[id]}</p>
                      )}
                    </div>
                    <span className="font-mono text-[11px] tracking-[0.18em]" style={{ color: tone.color }}>{tone.label}</span>
                  </div>
                )
              })}
            </div>
          </BattlePanel>

          {/* 攻击态势图 — 离线 IP 地理 + 攻击弧线 (ip2region 全离线, 答辩机无外呼)。
              2026-10-27 布局: 取代左栏独立的速率面板 (RelayStrip 内已含 RateHistogram,
              同屏重复); 弹性高度吸收左栏余量, 保证 1080p 零滚动下 KPI+账本不被裁切 */}
          <BattlePanel tab="攻击态势 · 来源地理" className="flex min-h-0 flex-1 flex-col px-3 pb-2 pt-5">
            <div className="min-h-0 flex-1">
              <AttackGeoMap />
            </div>
          </BattlePanel>

          {/* KPI 微错位堆叠 —— 「待处理」是英雄数字:>0 即整屏裂口(112px 朱砂),=0 归于纸色 */}
          <BattlePanel tab="作战指标 · 队列" className="shrink-0 px-4 pb-4 pt-5">
            <div className="flex flex-col gap-3 overflow-hidden">
              <div style={{ marginLeft: 0 }}>
                <KpiStat
                  label="待处理队列"
                  value={securityPending}
                  tone={securityPending > 0 ? 'alert' : 'neutral'}
                  size="wall"
                  live={securityPending > 0}
                  hint={securityPending > 0 ? '待审查 · 优先消化' : '队列已清空'}
                />
                {securityPending > 0 && (
                  <div className="mt-1 flex items-center gap-2" aria-hidden>
                    <span className="h-[3px] w-16 bg-[#e05a4e]" />
                    <span className="font-mono text-[10px] tracking-[0.24em] uppercase text-[#e05a4e]">rupture</span>
                  </div>
                )}
              </div>
              {/* 2026-10-27: 已分析/累计两枚 KPI 让位给账本 —— 入队/落库/幂等
                  已覆盖同一信息, 1080p 左栏容不下四件套 */}
              {/* 零丢失账本: 入队 = 落库 + 幂等吸收 (压测报告核心结论上墙) */}
              <div className="mt-1 border-t border-line pt-2.5" style={{ marginLeft: 6 }}>
                <LedgerPanel />
              </div>
            </div>
          </BattlePanel>
        </aside>

        {/* 中列:主舞台 */}
        <main className="flex min-h-0 min-w-0 flex-col gap-5">
          {/* 接力管线(放大) */}
          <BattlePanel tab="多 Agent 审查接力" className="shrink-0 px-5 pb-4 pt-6">
            <AgentRelayStrip />
          </BattlePanel>

          {/* 思维链主舞台 — 层叠手法①:跨装订线前移 16px,暮金框+辉光,z 最高。
              wall-zoom:整体放大(距离字号),ThoughtDag 自带 ResizeObserver 会随缩放重测连线 */}
          <div className="relative z-10 -mx-4 flex min-h-0 flex-1">
            <section
              className="relative flex min-h-0 w-full flex-col border border-[#c9a574]/35 bg-[#1a2d3f]"
              style={{ boxShadow: '0 0 44px rgba(201,165,116,0.14), 0 18px 48px -22px rgba(0,0,0,0.6)' }}
            >
              <span
                className="absolute -top-[12px] left-4 border border-[#c9a574]/45 bg-[#0e1a26] px-3 py-0.5 font-mono text-[11px] tracking-[0.3em] uppercase text-[#c9a574]"
                aria-hidden
              >
                思维链 · 主舞台
              </span>
              <div className="wall-zoom min-h-0 flex-1 overflow-auto">
                <ThoughtChainPanel
                  eventId={selectedEventId}
                  onClose={onCloseThought}
                  onJumpEvent={onSelectEvent}
                  idleHint={idleHint}
                />
              </div>
            </section>
          </div>

          {/* 活跃接力卡 */}
          <div className="shrink-0">
            <ActiveRelayCards
              hydrated={hydrated}
              hydratedRecent={hydratedRecent}
              selectedEventId={selectedEventId}
              onSelect={onSelectEvent}
              onDemo={onDemo}
              demoBusy={demoBusy}
            />
          </div>
        </main>

        {/* 右列 */}
        <aside className="flex min-h-0 flex-col gap-5">
          {/* 实时事件流:固定 12 行窗口,超出顶部推走(层叠手法③:新行滑入) */}
          <BattlePanel tab="实时事件流" className="flex min-h-0 flex-1 flex-col px-3 pb-3 pt-6">
            <div className="flex min-h-0 flex-1 flex-col gap-1 overflow-hidden">
              {streamLines.length === 0 ? (
                <p className="m-auto text-center font-serif text-[16px] italic text-[#78889a]">等待事件流入……</p>
              ) : (
                streamLines.map((e) => {
                  const sev = severityOf(e.type, e.data)
                  const meta = e.type
                  const message = String(e.data?.message || e.data?.event || e.type).slice(0, 40)
                  return (
                    <button
                      key={e.id}
                      onClick={() => e.seq > 0 && onSelectEvent(e.seq)}
                      className="group flex shrink-0 items-center gap-2.5 border border-transparent px-1.5 py-[7px] text-left hover:border-[#24384a] hover:bg-[#203349]"
                    >
                      <motion.span
                        initial={{ opacity: 0, x: -14 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.25, ease: 'easeOut' }}
                        className="flex min-w-0 flex-1 items-center gap-2.5"
                      >
                        <span
                          className="h-4 w-1 shrink-0"
                          style={{ background: SEV_COLOR[sev] ?? SEV_COLOR.info }}
                          aria-hidden
                        />
                        <span className="shrink-0 font-mono text-[12px] tabular-nums text-[#78889a]">{fmtClock(e.ts)}</span>
                        <span className="shrink-0 font-mono text-[12px] tracking-[0.1em] text-[#8fc0cc]">{meta}</span>
                        {e.replay && (
                          <span className="shrink-0 border border-[#c9a574]/40 px-1 py-px font-mono text-[9px] tracking-[0.14em] text-[#c9a574]/70" aria-hidden>
                            回放
                          </span>
                        )}
                        <span className="truncate font-mono text-[13px] text-[#a7b4bd] group-hover:text-[#dfe7e3]">{message}</span>
                      </motion.span>
                    </button>
                  )
                })
              )}
            </div>
          </BattlePanel>

          {/* 类型计数 */}
          <BattlePanel tab="事件类型计数" className="shrink-0 px-4 pb-3.5 pt-5">
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(typeCounts).length === 0 && (
                <span className="font-mono text-[11px] text-[#78889a]">—</span>
              )}
              {Object.entries(typeCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8)
                .map(([type, n]) => (
                  <span key={type} className="border border-[#24384a] px-2 py-1 font-mono text-[12px] text-[#a7b4bd]">
                    {type} <b className="tabular-nums text-[#c9a574]">{n}</b>
                  </span>
                ))}
            </div>
          </BattlePanel>

          {/* 工具行为签名 */}
          <div className="shrink-0">
            <ToolAnomalyBanner />
          </div>
        </aside>
      </div>

      {/* ── 底栏:封条跑马灯(骑在三列下缝)── */}
      <footer className="relative h-10 shrink-0 overflow-hidden border-t border-[#c9a574]/25 bg-[#0b1520]">
        <div className="duty-tape flex h-full items-center whitespace-nowrap">
          {[0, 1].map((copy) => (
            <div key={copy} className="flex items-center gap-10 pr-10">
              {(criticals.length > 0
                ? criticals.map((e) => (
                    <span key={`${copy}-${e.id}`} className="flex items-center gap-2 font-mono text-[13px] text-[#c9d6cf]">
                      <span className="text-[#e05a4e]">●</span>
                      <span className="tabular-nums text-[#78889a]">{fmtClock(e.ts)}</span>
                      {String(e.data?.message || e.type)}
                    </span>
                  ))
                : replayActive ? (
                  <span className="font-mono text-[13px] text-[#c9a574]">
                    回放口径 · 后端离线,幕布以剧本事件保持呼吸 · 事件 ID 9xxx 段为合成回放,不计入真实统计
                  </span>
                ) : (
                  <span className="font-mono text-[13px] text-[#78889a]">
                    管线在跳,证明它活着 · Decomposer → Builder → Executor → Reviewer → CAD → Response · 口径:实时流水线,SSE 驱动
                  </span>
                ))}
            </div>
          ))}
        </div>
      </footer>
    </div>
  )
}
