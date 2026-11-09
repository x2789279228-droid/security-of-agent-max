import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { List, useDynamicRowHeight, type ListImperativeAPI } from 'react-window'
import { motion } from 'framer-motion'
import { PageFrame } from '../components/common/PageFrame'
import StreamStatusBar from '../components/monitor/StreamStatusBar'
import AgentRelayStrip from '../components/monitor/AgentRelayStrip'
import ActiveRelayCards from '../components/monitor/ActiveRelayCards'
import EventDeck from '../components/monitor/EventDeck'
import EventToolbar, { type Filters } from '../components/monitor/EventToolbar'
import EventRow from '../components/monitor/EventRow'
import ThoughtChainPanel from '../components/monitor/ThoughtChainPanel'
import ToolAnomalyBanner from '../components/monitor/ToolAnomalyBanner'
import BattleScreen from '../components/monitor/BattleScreen'
import { HealthGauge } from '../components/ui/HealthGauge'
import { KpiStat } from '../components/ui/KpiStat'
import { LiveBadge } from '../components/ui/LiveBadge'
import { api } from '../lib/api'
import { ROUTES } from '../lib/constants'
import { useEventParam } from '../lib/entityNav'
import { deriveRelaysMemo } from '../lib/agentPipeline'
import { pickThoughtEventId } from '../lib/thoughtChain'
import { useArrivalBurst } from '../hooks/useArrivalBurst'
import { pulseFocus, useFocusStore } from '../stores/focusStore'
import { useServiceStore } from '../stores/serviceStore'
import type { StatsResponse } from '../types/stats'
import {
  severityOf,
  useEventStreamLifecycle,
  useEventStreamStore,
  type StreamEvent,
} from '../lib/eventStream'

const DEMO_EVENT = {
  event: 'C2_BEACON',
  severity: 'critical',
  src_ip: '192.168.1.105',
  dst_ip: '23.129.64.33',
  message: '演示审查：内部主机疑似与C2服务器通信',
  confidence: 85,
  _demo: true,
}

// 0.1s 扫描规则：健康=松绿、告警=柿黄、异常=朱砂；标签颜色随健康度走
// 2026-10-03: key 与后端 /health/dependencies 返回的探测项对齐（postgres/redis/qdrant/llm），
// 避免"前端叫 pgvector、后端探的是 qdrant"这种对不上的展示。
const serviceMeta: Record<string, { label: string; desc: string }> = {
  postgres: { label: 'PostgreSQL', desc: '事件与审计存储' },
  redis: { label: 'Redis', desc: '滑动窗口 / 限流' },
  qdrant: { label: 'Qdrant', desc: '向量检索' },
  llm: { label: 'LLM', desc: '审计与摘要（配置态）' },
}

const SERVICE_TONE: Record<string, { gauge: 'ok' | 'warn' | 'error'; bar: string; text: string; dot: string; glow: string; badge: string }> = {
  // unknown 必须是中性灰，不能借用 ok 的绿色 —— 否则"还没探测"看起来像"正常"
  unknown: {
    gauge: 'warn',
    bar: 'bg-line',
    text: 'text-ink-faint',
    dot: 'bg-line',
    glow: '',
    badge: 'border-line text-ink-faint',
  },
  ok: {
    gauge: 'ok',
    bar: 'bg-ok',
    text: 'text-ok',
    dot: 'bg-ok',
    glow: '',
    badge: 'border-ok text-ok',
  },
  warn: {
    gauge: 'warn',
    bar: 'bg-warn',
    text: 'text-warn',
    dot: 'bg-warn',
    glow: '',
    badge: 'border-warn text-warn',
  },
  alert: {
    gauge: 'error',
    bar: 'bg-alert',
    text: 'text-alert',
    dot: 'bg-alert',
    glow: '',
    badge: 'border-alert text-alert',
  },
  error: {
    gauge: 'error',
    bar: 'bg-alert',
    text: 'text-alert',
    dot: 'bg-alert',
    glow: '',
    badge: 'border-alert text-alert',
  },
}

const STREAM_EXTRA_LABEL: Record<string, string> = {
  idle: '未连接',
  connecting: '连接中',
  online: 'LIVE',
  reconnecting: '重连中',
  offline: '离线',
}

const STATS_MIN_INTERVAL = 2_000 // stats 刷新最短间隔（/api/stats 已 Redis 计数秒回,可近实时刷新）
let lastStatsAt = 0

export default function Monitor({ kiosk = false }: { kiosk?: boolean }) {
  const services = useServiceStore((s) => s.services)
  const serviceDetails = useServiceStore((s) => s.details)
  const streamStatus = useEventStreamStore((s) => s.status)

  // 连接生命周期托管（引用计数单例通道，含断点续传与保活监测）
  useEventStreamLifecycle()

  // 事件涌入档位：surge 时事件列表顶边加青蓝扫描线
  const { level: burstLevel } = useArrivalBurst()

  // ── 依赖健康探测（2026-10-03 新增）──
  // 修复前：services 初值硬编码 'ok'，且 setService/setAll 零调用点，
  // 健康环无论依赖是否可用都显示绿色 NOMINAL。
  // 现在真实轮询 /health/dependencies；首屏与失败均显示 UNKNOWN，不伪装正常。
  const setServiceAll = useServiceStore((s) => s.setAll)
  const setUnprobed = useServiceStore((s) => s.setUnprobed)
  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const r = await api.dependencyHealth()
        if (alive) setServiceAll(r.services)
      } catch {
        // 探测请求本身失败（401/网络/后端 5xx）→ 回落 UNKNOWN，不沿用上次结果
        if (alive) setUnprobed()
      }
    }
    void tick()
    const t = setInterval(tick, 10_000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [setServiceAll, setUnprobed])

  // 首屏 hydration：进行中 + 最近完成 + 可展示思维链（SSE 窗口可能只剩自博弈行）
  const [hydratedPipelines, setHydratedPipelines] = useState<any[]>([])
  const [hydratedRecent, setHydratedRecent] = useState<any[]>([])
  const [thoughtCandidates, setThoughtCandidates] = useState<any[]>([])
  useEffect(() => {
    api.activePipelines()
      .then((r) => setHydratedPipelines(r.pipelines ?? []))
      .catch(() => {})
    api.recentPipelines()
      .then((r) => setHydratedRecent(r.pipelines ?? []))
      .catch(() => {})
    api.recentThoughtChains()
      .then((r) => setThoughtCandidates(r.chains ?? []))
      .catch(() => {})
  }, [])

  // 运行指标：初始加载 + 任一事件到达后节流刷新（最短间隔 5s，避免高压时高频打全表统计）
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const arrivalTick = useEventStreamStore((s) => s.arrivalTick)
  useEffect(() => {
    api.stats().then(setStats).catch(() => {})
  }, [])
  useEffect(() => {
    if (!arrivalTick) return
    const wait = Math.max(0, lastStatsAt + STATS_MIN_INTERVAL - Date.now())
    const t = setTimeout(() => {
      lastStatsAt = Date.now()
      api.stats().then(setStats).catch(() => {})
    }, wait)
    return () => clearTimeout(t)
  }, [arrivalTick])

  // 待处理 KPI 的滚动窗口：每次 stats 到达推入真实样本；首帧用当前值播种一段平滑合成
  // 历史（仅形状，不改变数值语义），后续全部由真实刷新覆盖。窗口 ≤ 24 点。
  const pendingSparkRef = useRef<number[]>([])
  const [pendingSpark, setPendingSpark] = useState<number[]>([])
  useEffect(() => {
    if (!stats) return
    const v = Math.max(0, Number(stats.security_pending ?? 0) || 0)
    const buf = pendingSparkRef.current
    if (buf.length === 0) {
      for (let i = 0; i < 11; i++) {
        const t = i / 10
        buf.push(Math.max(0, Math.round(v * (0.72 + 0.28 * t) + Math.sin(i * 1.9) * v * 0.07)))
      }
    }
    buf.push(v)
    if (buf.length > 24) buf.splice(0, buf.length - 24)
    setPendingSpark([...buf])
  }, [stats])

  // 实时事件流状态与筛选
  const buffer = useEventStreamStore((s) => s.buffer)
  const [filters, setFilters] = useState<Filters>({
    type: 'all',
    severity: 'all',
    stage: 'all',
    query: '',
  })
  const [paused, setPaused] = useState(false)
  const [frozen, setFrozen] = useState<StreamEvent[] | null>(null)

  // W2-3(复审 P2-3): 序列化结果按事件 id 缓存 — 修复前每次 flush(高压 ~20/s)
  // 对 500 条事件各做一次 JSON.stringify+toLowerCase, 是 surge 场景 CPU 热点。
  const searchIndexRef = useRef(new Map<number, string>())
  const searchIndex = searchIndexRef.current
  const filtered = useMemo(() => {
    const q = filters.query.trim().toLowerCase()
    const keep = searchIndex.size > 4096 ? (searchIndex.clear(), searchIndex) : searchIndex
    return buffer.filter((e) => {
      if (e.kind !== 'event') return true // 空洞/重启标记行始终保留，保证过程可解释
      if (filters.type !== 'all' && e.type !== filters.type) return false
      if (filters.severity !== 'all' && severityOf(e.type, e.data) !== filters.severity) return false
      if (filters.stage !== 'all') {
        const stage = String(e.data?.stage ?? e.data?.agent_id ?? '')
        if (stage !== filters.stage) return false
      }
      if (q) {
        // e.id = 本地渲染自增, 唯一(seq 对合成标记恒 0)
        let s = keep.get(e.id)
        if (s === undefined) {
          s = JSON.stringify(e.data ?? {}).toLowerCase()
          keep.set(e.id, s)
        }
        if (!s.includes(q)) return false
      }
      return true
    })
  }, [buffer, filters, searchIndex])

  // 暂停推送：冻结当前视图，新事件继续进入缓冲但不渲染；恢复时一次性放行
  const visible = paused && frozen ? frozen : filtered

  const togglePause = useCallback(() => {
    if (paused) {
      setPaused(false)
      setFrozen(null)
    } else {
      setPaused(true)
      setFrozen(filtered)
    }
  }, [paused, filtered])

  // 暂停期间累计的新事件数
  const pendingNew = useMemo(() => {
    if (!paused || !frozen) return 0
    const maxFrozenId = frozen.reduce((m, e) => Math.max(m, e.id), -1)
    return buffer.reduce((n, e) => (e.id > maxFrozenId && e.kind === 'event' ? n + 1 : n), 0)
  }, [paused, frozen, buffer])

  // 展开状态上提到页面层：虚拟滚动下行的卸载/重挂不应丢失展开状态
  const [expandedIds, setExpandedIds] = useState<Set<number>>(() => new Set())
  const toggleExpanded = useCallback((id: number) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])
  const [selectedEventId, setSelectedEventId] = useState<number | null>(null)
  const [dismissedThought, setDismissedThought] = useState(false)
  const [awaitingLive, setAwaitingLive] = useState(false)
  const [demoBusy, setDemoBusy] = useState(false)
  const [demoError, setDemoError] = useState('')

  // 联动脉冲（FocusLink）：接力卡/事件堆选中事件 → 事件行闪光 + 滚入视口
  const pulse = useFocusStore((s) => s.pulse)
  const listRef = useRef<ListImperativeAPI | null>(null)
  const visibleRef = useRef<StreamEvent[]>([])
  useEffect(() => {
    visibleRef.current = visible
  }, [visible])

  const selectEvent = useCallback((eventId: number) => {
    if (!eventId) return
    setDismissedThought(false)
    setAwaitingLive(false)
    setSelectedEventId((prev) => (prev === eventId ? prev : eventId))
    pulseFocus('event', eventId)
    const idx = visibleRef.current.findIndex(
      (e) => e.kind === 'event' && Number(e.data?.event_id) === eventId,
    )
    if (idx >= 0) listRef.current?.scrollToRow({ index: idx, align: 'smart', behavior: 'smooth' })
  }, [])
  const closeThought = useCallback(() => {
    setSelectedEventId(null)
    setDismissedThought(true)
    setAwaitingLive(false)
  }, [])

  // 案卷链深链:/logs 或事件案卷跳转而来,自动选中该事件思维链
  const deepEventId = useEventParam()
  useEffect(() => {
    if (deepEventId) selectEvent(deepEventId)
  }, [deepEventId, selectEvent])

  useEffect(() => {
    if (dismissedThought) return
    const liveId = deriveRelaysMemo(buffer).active[0]?.eventId || 0
    if (liveId && (awaitingLive || selectedEventId == null)) {
      setSelectedEventId(liveId)
      setAwaitingLive(false)
      return
    }
    if (selectedEventId != null) return
    const fromBuffer = pickThoughtEventId(buffer)
    if (fromBuffer) {
      setSelectedEventId(fromBuffer)
      return
    }
    if (awaitingLive) return
    const fromDb = Number(thoughtCandidates[0]?.event_id) || 0
    if (fromDb) setSelectedEventId(fromDb)
  }, [buffer, dismissedThought, selectedEventId, thoughtCandidates, awaitingLive])

  const runDemo = useCallback(async () => {
    setDemoBusy(true)
    setDemoError('')
    setDismissedThought(false)
    setAwaitingLive(true)
    try {
      const sid = `demo-monitor-${crypto.randomUUID().slice(0, 8)}`
      const data = await api.ingestLog(DEMO_EVENT, sid)
      const eid = Number(data?.event_id) || 0
      if (eid) {
        setAwaitingLive(false)
        setSelectedEventId(eid)
      }
    } catch (e: any) {
      setDemoError(e?.message || '演示审查启动失败')
      setAwaitingLive(false)
    } finally {
      setDemoBusy(false)
    }
  }, [])

  const recentFromThoughts = useMemo(
    () => thoughtCandidates.map((c) => ({
      event_id: c.event_id,
      current_stage: 'reviewer',
      completed_stages: ['decomposer', 'tool_builder', 'executor', 'reviewer'],
      done: true,
      started_at: c.created_at ? Date.parse(String(c.created_at)) / 1000 : 0,
      session_id: '',
      trace_id: '',
    })),
    [thoughtCandidates],
  )
  const recentHydration = hydratedRecent.length > 0 ? hydratedRecent : recentFromThoughts

  const candidateId = Number(thoughtCandidates[0]?.event_id) || 0
  const idleHint = dismissedThought
    ? (candidateId
      ? `已关闭。点击接力卡片或最近完成，查看该事件思维链（最近 #${candidateId}）`
      : '已关闭。点击接力卡片、最近完成或带 event_id 的审计行，查看思维链。')
    : awaitingLive
      ? '演示审查已提交，流水线事件到达后将自动打开该事件思维链'
      : '当前没有可展示的 Audit-LLM 思维链。请注入一条安全事件，或在本页跑演示审查。'

  // 虚拟滚动：仅 mount 可视区行（此前 500 行全量 mount + framer-motion FLIP 是渲染卡顿主因）
  const rowHeight = useDynamicRowHeight({ defaultRowHeight: 56 })

  // 类型计数由 store 增量维护（eventStream flushBatch），避免每条事件 O(n) 重扫
  const typeCounts = useEventStreamStore((s) => s.typeCounts)

  const shownEvents = useMemo(
    () => visible.reduce((n, e) => (e.kind === 'event' ? n + 1 : n), 0),
    [visible],
  )

  // ── 大屏模式(阶段 4):F 键或按钮进入,BattleScreen 自管 data-mode/全屏,Esc 退出 ──
  // kiosk(/screen)挂载即入大屏,退出改走首页而不是折回普通监控页。
  const navigate = useNavigate()
  const [battle, setBattle] = useState(kiosk)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() !== 'f' || e.ctrlKey || e.metaKey || e.altKey) return
      const target = e.target as HTMLElement | null
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)) return
      e.preventDefault()
      setBattle((v) => {
        if (v) return false
        return window.innerWidth >= 1280 // 投影适配下限,过小退回纵向页
      })
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  if (battle) {
    return (
      <BattleScreen
        services={services}
        serviceDetails={serviceDetails}
        streamStatus={streamStatus}
        visible={visible}
        typeCounts={typeCounts}
        bufferCount={buffer.length}
        selectedEventId={selectedEventId}
        onSelectEvent={selectEvent}
        onCloseThought={closeThought}
        idleHint={idleHint}
        hydrated={hydratedPipelines}
        hydratedRecent={recentHydration}
        onDemo={runDemo}
        demoBusy={demoBusy}
        stats={stats}
        onExit={() => (kiosk ? navigate(ROUTES.HOME) : setBattle(false))}
      />
    )
  }

  const securityPending = Math.max(0, Number(stats?.security_pending ?? 0) || 0)

  return (
    <PageFrame
      title="系统监控"
      hint="服务健康 · 多 Agent 审查接力 · 实时事件流。"
      extra={
        <div className="flex items-center gap-3">
          <LiveBadge
            live={streamStatus === 'online'}
            label={STREAM_EXTRA_LABEL[streamStatus] ?? streamStatus}
          />
          <button
            onClick={() => window.innerWidth >= 1280 && setBattle(true)}
            className="nav-btn"
            title="三列作战大屏(F 键进入,Esc 退出)"
          >
            ▦ 大屏模式
          </button>
        </div>
      }
    >

      {/* 指标细带 — 一行六格、发丝线分隔，嵌在页头之下作「总读数」；待处理 > 0 是整屏裂口 */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
        className="mb-4 grid grid-cols-2 divide-x divide-line-soft border-y border-line-soft md:grid-cols-5"
      >
        <div className="px-4 first:pl-0 md:pl-5 md:first:pl-0">
          <KpiStat
            label="待处理"
            value={securityPending}
            tone={securityPending > 0 ? 'hero' : 'ok'}
            spark={pendingSpark}
            live={securityPending > 0}
            hint={securityPending > 0 ? '待审查队列 · 优先消化' : '队列已清空'}
            size="sm"
          />
        </div>
        <div className="px-4 md:pl-5">
          <KpiStat label="已分析" value={Number(stats?.audit_llm?.completed ?? 0) || 0} tone="ok" size="sm" />
        </div>
        <div className="px-4 md:pl-5">
          <KpiStat label="安全事件" value={Number(stats?.security_events ?? 0) || 0} tone="neutral" size="sm" />
        </div>
        <div className="px-4 md:pl-5">
          <KpiStat label="记忆树节点" value={Number(stats?.tree_nodes ?? 0) || 0} tone="neutral" size="sm" />
        </div>
        <div className="px-4 md:pl-5">
          <KpiStat label="Redis Keys" value={Number(stats?.redis_keys ?? 0) || 0} tone="neutral" size="sm" />
        </div>
      </motion.div>

      {/* 主控制台 — 非对称双列：左轨静态仪表(依赖健康+最近事件)，右宽列活流水(接力→思维链→事件流) */}
      <div className="grid grid-cols-1 items-start gap-3 xl:grid-cols-[300px_minmax(0,1fr)]">
        {/* 左轨 */}
        <aside className="flex flex-col gap-3 xl:sticky xl:top-16">
          <section className="border border-line bg-paper">
            <header className="meta-caps border-b border-line px-4 py-2.5">
              依赖健康 · Services
            </header>
            <div>
              {Object.entries(services).map(([id, health], i) => {
                const tone = SERVICE_TONE[health] ?? SERVICE_TONE.unknown
                const meta = serviceMeta[id] ?? { label: id, desc: id }
                const detail = serviceDetails[id]
                const badgeText =
                  health === 'ok' ? 'NOMINAL' : health === 'error' ? 'ALERT' : 'UNKNOWN'
                return (
                  <motion.div
                    key={id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.35, delay: i * 0.05 }}
                    className={`relative flex items-center gap-3 border-line px-4 py-3 transition-colors duration-200 hover:bg-mist/60 ${
                      i < Object.entries(services).length - 1 ? 'border-b' : ''
                    }`}
                  >
                    <span className={`absolute left-0 top-0 bottom-0 w-[3px] ${tone.bar}`} />
                    <HealthGauge health={tone.gauge} size={30} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[13px] font-semibold text-ink">{meta.label}</p>
                      <p className="truncate text-[11px] text-ink-soft">{meta.desc}</p>
                      {detail && (
                        <p className="truncate font-mono text-[10px] text-ink-faint" title={detail}>
                          {detail}
                        </p>
                      )}
                    </div>
                    <span className={`shrink-0 border px-2 py-0.5 font-mono text-[9px] tracking-[0.14em] uppercase ${tone.badge}`}>
                      {badgeText}
                    </span>
                  </motion.div>
                )
              })}
            </div>
          </section>
          <EventDeck onSelectEvent={selectEvent} />
        </aside>

        {/* 右宽列 */}
        <div className="flex min-w-0 flex-col gap-3">

      {/* ── 多 Agent 审查接力 ── */}
      <div className="rule-double mb-4 flex items-center justify-between pb-3">
        <div className="flex items-baseline gap-4">
          <h2 className="text-[16px] font-semibold tracking-tight text-ink">
            多 Agent 审查接力
          </h2>
          <span className="font-mono text-[10px] tracking-[0.06em] text-ink-faint">
            Decomposer → Builder → Exec → Reviewer
          </span>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={runDemo}
            disabled={demoBusy}
            className="rounded-[3px] border border-accent bg-accent px-3 py-1.5 font-mono text-[12px] tracking-[0.16em] uppercase text-on-accent transition-colors hover:bg-accent-hover disabled:opacity-50"
          >
            {demoBusy ? '演示启动中 …' : '跑一条演示'}
          </button>
          <span className="font-mono text-[11px] tracking-[0.06em] text-ink-faint tabular-nums">
            显示 {shownEvents} / 缓冲 {buffer.length}
          </span>
        </div>
      </div>
      {demoError && (
        <p className="mb-3 text-[12px] text-alert">{demoError}</p>
      )}

      <ToolAnomalyBanner />

      <div className="rounded-[6px] border border-line bg-card overflow-hidden">
        <StreamStatusBar paused={paused} onTogglePause={togglePause} />
        <div className="border-t border-line">
          <AgentRelayStrip
            onFilterStage={(stage) =>
              setFilters((f) => ({ ...f, stage: f.stage === stage ? 'all' : stage }))
            }
          />
        </div>
        <EventToolbar filters={filters} onChange={setFilters} typeCounts={typeCounts} />
      </div>

      <ActiveRelayCards
        hydrated={hydratedPipelines}
        hydratedRecent={recentHydration}
        selectedEventId={selectedEventId}
        onSelect={selectEvent}
        onDemo={runDemo}
        demoBusy={demoBusy}
      />

      <ThoughtChainPanel
        eventId={selectedEventId}
        onClose={closeThought}
        onJumpEvent={selectEvent}
        idleHint={idleHint}
      />

      {/* 事件列表 — surge 档顶边扫描线（青蓝信息流通道，红只留给单条 critical） */}
      <div
        className={`watch-scan relative overflow-hidden border bg-paper ${
          burstLevel === 'surge' ? 'border-accent/60' : 'border-line'
        }`}
      >
        {burstLevel === 'surge' && (
          <span
            className="surge-sweep pointer-events-none absolute left-0 top-0 z-20 h-[2px] w-1/4"
            style={{
              background:
                'linear-gradient(90deg, transparent, var(--glow-info), transparent)',
            }}
            aria-hidden
          />
        )}
        {visible.length === 0 ? (
          <div className="p-14 text-center text-sm text-ink-faint">
            {buffer.length === 0
              ? '等待 Agent 接力… 连接建立后将自动回放最近的历史事件'
              : '当前筛选条件下没有匹配的事件'}
          </div>
        ) : (
          <List
            listRef={listRef}
            rowComponent={EventRow}
            rowCount={visible.length}
            rowHeight={rowHeight}
            rowProps={{
              events: visible,
              expandedIds,
              onToggle: toggleExpanded,
              selectedEventId,
              onSelectEvent: selectEvent,
              pulse,
            }}
            overscanCount={8}
            style={{ height: 520 }}
          />
        )}

        {paused && pendingNew > 0 && (
          <button
            onClick={togglePause}
            className="absolute bottom-4 right-6 flex items-center gap-1.5 rounded-[3px] border border-accent/60 bg-paper px-3 py-1.5 text-[12px] font-medium text-ink"
          >
            ↓ {pendingNew} 条新事件 · 点击恢复推送
          </button>
        )}
      </div>
        </div>
      </div>
    </PageFrame>
  )
}
