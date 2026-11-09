import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { WatchShift } from '../components/ui/WatchShift'
import { LiveBadge } from '../components/ui/LiveBadge'
import AgentRelayStrip from '../components/monitor/AgentRelayStrip'
import { api } from '../lib/api'
import { ROUTES } from '../lib/constants'
import { AGENT_RELAY_STAGES, STAGE_DUTIES, STAGE_LABELS, deriveRelays } from '../lib/agentPipeline'
import { useEventStreamLifecycle, useEventStreamStore } from '../lib/eventStream'
import { useWallKeepalive } from '../hooks/useWallKeepalive'

/**
 * 系统全景海报(/poster · 阶段 7) — 一屏读懂「守望」:会呼吸的架构图。
 *
 * 为「扫屏 30 秒 / 拍一张照片」的评委设计:
 * - 暗色作战语言(battle token),架构流水线横贯全屏,每格挂活数据;
 * - 第二行是多 Agent 审查接力(暮金框主舞台) —— 海报的心脏,实时跳动;
 * - SSE 断流 6s 自动切入回放口径(useWallKeepalive),幕布永不死;
 * - 无滚动、无交互依赖:投屏即海报,拍屏即可转述。
 */

const STAGES = [
  { num: '01', name: '接入', en: 'INGEST', sub: '多源采集 · SSE 推送' },
  { num: '02', name: '缓冲', en: 'BUS', sub: 'Kafka 链路 · Redis 计数' },
  { num: '03', name: '检测', en: 'DETECT', sub: 'SigmaHQ 导入 · 影子并行' },
  { num: '04', name: '编排', en: 'ORCHESTRATE', sub: '四层 Agent + CAD 监督' },
  { num: '05', name: '审计', en: 'AUDIT', sub: '思维链 · grounding 验证' },
  { num: '06', name: '响应', en: 'RESPOND', sub: '策略 · 审批 · 可回滚' },
] as const

export default function Poster() {
  const navigate = useNavigate()

  // 暗色作战舞台:token 翻转,退出还原
  useEffect(() => {
    const el = document.documentElement
    const prev = el.dataset.mode
    el.dataset.mode = 'battle'
    return () => {
      if (prev === undefined) delete el.dataset.mode
      else el.dataset.mode = prev
    }
  }, [])

  // Esc 回首页
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') navigate(ROUTES.HOME)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [navigate])

  useEventStreamLifecycle()
  const streamStatus = useEventStreamStore((s) => s.status)
  const buffer = useEventStreamStore((s) => s.buffer)
  const receivedTotal = useEventStreamStore((s) => s.receivedTotal)
  const replayActive = useWallKeepalive(streamStatus)

  // ── 活数据:stats 节流轮询 + 规则数/评测标题一次性 ──
  const [stats, setStats] = useState<any>(null)
  const [sigmaCount, setSigmaCount] = useState<number | null>(null)
  const [benchTitles, setBenchTitles] = useState<string[]>([])
  useEffect(() => {
    const tick = () => api.stats().then(setStats).catch(() => {})
    tick()
    const t = setInterval(tick, 5_000)
    return () => clearInterval(t)
  }, [])
  useEffect(() => {
    api.opsRules('sigma').then((r) => setSigmaCount(Array.isArray(r) ? r.length : null)).catch(() => {})
    api.benchmarkReports().then((r) => setBenchTitles((r.reports ?? []).map((x) => x.title))).catch(() => {})
  }, [])

  // 事件速率:最近 60s 到达数。从共享缓冲的时间戳统计 —— arrivalTimes 不计回放,
  // 会让海报在回放口径下露出死格;buffer 两态通用。时间经 interval 采样,渲染期保持纯函数。
  const [nowTs, setNowTs] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNowTs(Date.now()), 2_000)
    return () => clearInterval(t)
  }, [])
  const eps = buffer.filter((e) => e.ts >= nowTs - 60_000).length

  const relays = useMemo(() => deriveRelays(buffer), [buffer])
  const activeRelays = relays.active.length
  const recentRelay = relays.recent[0] ?? null
  const pending = Math.max(0, Number(stats?.security_pending ?? 0) || 0)
  const treeNodes = Number(stats?.tree_nodes ?? 0) || 0
  const totalEvents = Number(stats?.security_events ?? 0) || 0
  const redisKeys = Number(stats?.redis_keys ?? 0) || 0
  const audited = Number(stats?.audit_llm?.completed ?? 0) || 0

  // 0 值在海报上是"没在动"，直接换成状态词，避免评委看到一排 0
  const cards: {
    num: string; name: string; en: string; sub: string
    value: number | null; fallback: string; note: string; tone: 'dusk' | 'plain' | 'gold' | 'alert'
  }[] = [
    { ...STAGES[0], value: eps || null, fallback: '待事件', note: eps > 0 ? '条 / 最近 60s' : '链路在线 · 等待流入', tone: 'dusk' },
    { ...STAGES[1], value: redisKeys || null, fallback: '—', note: 'redis keys 在管', tone: 'plain' },
    { ...STAGES[2], value: sigmaCount || null, fallback: '—', note: sigmaCount == null ? '需凭据读取' : '条自研规则在库', tone: 'plain' },
    { ...STAGES[3], value: activeRelays || null, fallback: '待命', note: activeRelays > 0 ? '条接力进行中' : '无进行中接力 · 岗位就绪', tone: 'gold' },
    { ...STAGES[4], value: audited || null, fallback: '—', note: '条思维链已完结', tone: 'plain' },
    { ...STAGES[5], value: pending || null, fallback: '清空', note: pending > 0 ? '条待处理 · 优先消化' : '队列已清空 · 全部闭环', tone: pending > 0 ? 'alert' : 'plain' },
  ]

  const numTone: Record<string, string> = {
    dusk: 'text-[#c9a574]',
    gold: 'text-[#c9a574]',
    alert: 'text-[#e05a4e]',
    plain: 'text-[#dfe7e3]',
  }

  return (
    <div className="fixed inset-0 z-[70] flex flex-col overflow-hidden bg-[#0e1a26] text-[#dfe7e3]">
      {/* ── 顶栏 ── */}
      <header className="flex h-14 shrink-0 items-center gap-5 border-b border-[#24384a] px-6">
        <span className="font-serif text-[22px] font-semibold tracking-[-0.02em]">守望</span>
        <span className="font-mono text-[11px] tracking-[0.3em] uppercase text-[#c9a574]">系统全景 · Poster</span>
        <span className="h-4 w-px bg-[#24384a]" aria-hidden />
        {replayActive ? (
          <LiveBadge live={false} label="回放口径" className="!text-[#d9bc8b]" />
        ) : (
          <LiveBadge live={streamStatus === 'online'} label={streamStatus === 'online' ? 'LIVE' : '本地'} />
        )}
        <div className="ml-auto flex items-center gap-2.5">
          <button
            onClick={() => navigate(ROUTES.SCREEN)}
            className="border border-[#c9a574]/50 px-3.5 py-1.5 font-mono text-[10px] tracking-[0.2em] uppercase text-[#c9a574] hover:bg-[#182838] transition-colors"
          >
            进入作战大屏 →
          </button>
          <button
            onClick={() => navigate(ROUTES.HOME)}
            className="border border-[#33475a] px-3.5 py-1.5 font-mono text-[10px] tracking-[0.2em] uppercase text-[#a7b4bd] hover:border-[#c9a574]/50 hover:text-[#c9a574] transition-colors"
            title="退出海报(Esc)"
          >
            退出
          </button>
        </div>
      </header>

      {/* ── 标题带 ── */}
      <div className="flex shrink-0 items-end justify-between gap-8 px-8 pb-5 pt-6">
        <div>
          <p className="font-mono text-[11px] tracking-[0.4em] uppercase text-[#c9a574]">One-Screen System Poster</p>
          <h1 className="mt-2 font-serif text-[38px] font-semibold leading-[0.98] tracking-[-0.04em] text-[#f1e8d6] 2xl:text-[56px]">
            一屏,读完一次完整处置
          </h1>
          <p className="mt-2 max-w-[46rem] font-serif text-[14px] leading-relaxed text-[#a7b4bd]">
            接入 → 缓冲 → 检测 → 四层 Agent 编排 → 审计 → 响应:每一格都是活数据,断流时以回放口径保持呼吸。
          </p>
        </div>
        <div className="hidden shrink-0 md:block">
          <WatchShift variant="hero" />
        </div>
      </div>

      {/* ── 流水线:六格横贯 ── */}
      <div className="grid shrink-0 grid-cols-2 gap-4 px-8 sm:grid-cols-3 xl:grid-cols-6">
        {cards.map((c, i) => (
          <section
            key={c.num}
            className={`relative border bg-[#1a2d3f] px-4 pb-4 pt-5 ${
              c.tone === 'gold'
                ? 'border-[#c9a574]/45 shadow-[0_0_36px_rgba(201,165,116,0.12)]'
                : c.tone === 'alert'
                  ? 'border-[#e05a4e]/50'
                  : 'border-[#24384a]'
            }`}
          >
            <span
              className={`absolute -top-[10px] left-3 border px-2 py-0.5 font-mono text-[10px] tracking-[0.26em] uppercase ${
                c.tone === 'gold'
                  ? 'border-[#c9a574]/45 bg-[#0e1a26] text-[#c9a574]'
                  : 'border-[#24384a] bg-[#0e1a26] text-[#78889a]'
              }`}
              aria-hidden
            >
              {c.num} · {c.en}
            </span>
            <div className="flex items-baseline gap-2">
              <p className="font-serif text-[17px] font-bold text-[#dfe7e3]">{c.name}</p>
              {c.tone === 'gold' && activeRelays > 0 && (
                <span className="live-arc text-[#c9a574]" aria-hidden />
              )}
            </div>
            <p
              className={`mt-2 font-serif font-semibold tabular-nums leading-none tracking-[-0.04em] ${numTone[c.tone]} ${
                typeof c.value === 'number' ? 'text-[32px] 2xl:text-[46px]' : 'text-[22px] 2xl:text-[26px]'
              }`}
            >
              {c.value ?? c.fallback}
            </p>
            <p className="mt-2 truncate font-mono text-[11px] text-[#78889a]">{c.note}</p>
            <p className="mt-0.5 truncate font-mono text-[10px] tracking-[0.12em] text-[#5c6b7a]">{c.sub}</p>
            {/* 连接丝带:非末格右缘的流动线 */}
            {i < cards.length - 1 && (
              <span className="segment-flow absolute -right-4 top-1/2 hidden h-px w-3 xl:block" aria-hidden />
            )}
          </section>
        ))}
      </div>

      {/* ── 主舞台:多 Agent 审查接力(海报的心脏)── */}
      <div className="mx-8 mt-6 flex min-h-0 flex-1 flex-col">
        <section
          className="relative flex min-h-0 flex-1 flex-col border border-[#c9a574]/35 bg-[#1a2d3f] px-6 pb-5 pt-7"
          style={{ boxShadow: '0 0 44px rgba(201,165,116,0.14), 0 18px 48px -22px rgba(0,0,0,0.6)' }}
        >
          <span
            className="absolute -top-[12px] left-4 border border-[#c9a574]/45 bg-[#0e1a26] px-3 py-0.5 font-mono text-[11px] tracking-[0.3em] uppercase text-[#c9a574]"
            aria-hidden
          >
            多 Agent 审查接力 · Decomposer → Builder → Executor → Reviewer → CAD → Response
          </span>
          <div className="flex min-h-0 flex-1 flex-col">
            {/* 最近完成：海报不应该在"无进行中接力"时只剩一条空管线 */}
            <div className="flex shrink-0 flex-wrap items-center gap-2 pb-4">
              <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#78889a]">最近完成</span>
              {recentRelay ? (
                <>
                  <span className="border border-[#c9a574]/35 px-2 py-0.5 font-mono text-[11px] text-[#d9bc8b]">
                    #{recentRelay.eventId}
                  </span>
                  <span className="border border-[#24384a] px-2 py-0.5 font-mono text-[11px] text-[#a7b4bd]">
                    六站 {Object.values(recentRelay.stages).filter((s) => s === 'success').length}/6
                  </span>
                  <span className="border border-[#24384a] px-2 py-0.5 font-mono text-[11px] text-[#a7b4bd]">
                    {recentRelay.done ? '已完成' : '进行中'}
                  </span>
                </>
              ) : (
                <span className="font-mono text-[11px] text-[#5c6b7a]">
                  等待第一条审查接力 · 下方为实时接力条
                </span>
              )}
              <span className="ml-auto font-mono text-[10px] text-[#5c6b7a]">
                每个岗位都有产物 · 断流时以回放口径保持呼吸
              </span>
            </div>
            <div className="flex min-h-0 flex-1 items-center">
              <div className="wall-zoom w-full">
                <AgentRelayStrip />
              </div>
            </div>

            {/* 六站职责：把"六个岗位"讲成非专业观众也能读懂的六句话（窄屏隐藏，避免 768p 挤压） */}
            <div className="mt-4 hidden shrink-0 grid-cols-6 gap-2 2xl:grid">
              {AGENT_RELAY_STAGES.map((s) => (
                <div key={s} className="border border-[#24384a] bg-[#0e1a26]/50 px-2.5 py-2">
                  <p className="font-mono text-[10px] tracking-[0.14em] text-[#c9a574]">
                    {STAGE_LABELS[s] ?? s}
                  </p>
                  <p className="mt-1 text-[10px] leading-snug text-[#a7b4bd]">{STAGE_DUTIES[s] ?? ''}</p>
                </div>
              ))}
            </div>

            {/* 口径：诚实标注三种数据来源（窄屏隐藏） */}
            <div className="mt-3 hidden shrink-0 flex-wrap items-center gap-2 border-t border-[#24384a] pt-3 2xl:flex">
              <span className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#78889a]">口径</span>
              <span className="border border-[#24384a] px-2 py-0.5 font-mono text-[10px] text-[#a7b4bd]">实时 · SSE 驱动</span>
              <span className="border border-[#24384a] px-2 py-0.5 font-mono text-[10px] text-[#a7b4bd]">降级 · 超时合成并明示</span>
              <span className="border border-[#24384a] px-2 py-0.5 font-mono text-[10px] text-[#a7b4bd]">演练 · 纯前端时间轴</span>
              <span className="ml-auto font-mono text-[10px] text-[#5c6b7a]">
                CAD 为独立监督位，不参与内容生产
              </span>
            </div>
          </div>
        </section>
      </div>

      {/* ── 底带:记忆 / 累计 / 评测战绩 ── */}
      <div className="grid shrink-0 grid-cols-2 gap-4 px-8 py-5 lg:grid-cols-5">
        {[
          { k: '记忆树节点', v: treeNodes, note: '审计记忆沉淀' },
          { k: '安全事件累计', v: totalEvents, note: '全量事件入库' },
          { k: '会话接收', v: receivedTotal, note: '本次连线实收' },
        ].map((x) => (
          <div key={x.k} className="border border-[#24384a] bg-[#1a2d3f] px-4 py-3">
            <p className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#78889a]">{x.k}</p>
            <p className="mt-1 font-serif text-[28px] font-semibold tabular-nums leading-none text-[#dfe7e3]">{x.v}</p>
            <p className="mt-1 font-mono text-[10px] text-[#5c6b7a]">{x.note}</p>
          </div>
        ))}
        <div className="border border-[#24384a] bg-[#1a2d3f] px-4 py-3">
          <p className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#78889a]">评测战绩</p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {benchTitles.length === 0 && <span className="font-mono text-[10px] text-[#5c6b7a]">—</span>}
            {benchTitles.slice(0, 3).map((t) => (
              <span key={t} className="border border-[#c9a574]/35 px-2 py-0.5 font-mono text-[10px] text-[#d9bc8b]">
                {t}
              </span>
            ))}
          </div>
        </div>

        <div className="border border-[#24384a] bg-[#1a2d3f] px-4 py-3">
          <p className="font-mono text-[10px] tracking-[0.22em] uppercase text-[#78889a]">能力覆盖</p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {['实时检测', '多 Agent 研判', '证据链', '审批处置', '回滚', '记忆索引', '自博弈', '可观测'].map((t) => (
              <span key={t} className="border border-[#24384a] px-2 py-0.5 font-mono text-[10px] text-[#a7b4bd]">
                {t}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── 底栏:口径跑马灯 ── */}
      <footer className="relative h-9 shrink-0 overflow-hidden border-t border-[#c9a574]/25 bg-[#0b1520]">
        <div className="duty-tape flex h-full items-center whitespace-nowrap">
          {[0, 1].map((copy) => (
            <div key={copy} className="flex items-center gap-10 pr-10">
              <span className="font-mono text-[12px] text-[#78889a]">
                {replayActive
                  ? '回放口径 · 后端离线,海报以剧本事件保持呼吸 · 合成事件不计入真实统计'
                  : '口径:实时流水线,SSE 驱动 · 管线在跳,证明它活着 · Decomposer → Builder → Executor → Reviewer → CAD → Response'}
              </span>
            </div>
          ))}
        </div>
      </footer>
    </div>
  )
}
