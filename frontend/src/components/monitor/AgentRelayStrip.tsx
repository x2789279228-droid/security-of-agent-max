/**
 * 多 Agent 审查接力条 v2 — Monitor 过程展示主画面(流式化)
 *
 * Decomposer → Tool Builder → Executor → Reviewer → CAD → Response
 * - 定向接力包:数据包从上一阶段位置飞到本次事件阶段(不再全程横穿)
 * - 节点滴流:每节点下方实时显示该阶段最新一条思维步骤标题
 * - 流动丝带:running 节点相邻线段流动渐变,管子"在输液"
 * - 活秒表:running 节点显示实时耗时;完成计数变化时数字 pop
 * 全部由 50ms 微批 SSE 缓冲派生,零后端改动;reduced-motion 退化为静态线+瞬换字。
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  AGENT_RELAY_STAGES,
  STAGE_LABELS,
  deriveRelaysMemo,
  latestThoughtByStage,
} from '../../lib/agentPipeline'
import { spring } from '../../lib/constants'
import { useEventStreamStore } from '../../lib/eventStream'
import { pulseFocus } from '../../stores/focusStore'
import RateHistogram from './RateHistogram'

// 节点三态：进行中=松绿柔光；有错误=朱砂；空闲=暗淡卡片（0.1s 可辨）
const NODE_TONE = {
  running: 'border-ok/70 bg-ok/[0.07] shadow-[0_0_14px_rgba(62,122,100,0.14)]',
  error: 'border-alert/70 bg-alert/[0.08] shadow-[0_0_14px_rgba(194,58,50,0.14)]',
  idle: 'border-line bg-mist/40 opacity-75',
} as const

/** 节点中心横向位置(6 等分中点) */
const stageFrac = (i: number) => ((i + 0.5) / AGENT_RELAY_STAGES.length) * 100

function Node({
  label,
  running,
  completed,
  errors,
  flashKey = 0,
  active,
  runningSince,
  nowMs,
  drip,
  onClick,
}: {
  label: string
  running: number
  completed: number
  errors: number
  flashKey?: number
  active?: boolean
  runningSince?: number
  nowMs: number
  drip?: { title: string; confidence?: number | null }
  onClick?: () => void
}) {
  const tone: keyof typeof NODE_TONE =
    running > 0 || active ? 'running' : errors > 0 ? 'error' : 'idle'
  const elapsed = runningSince ? Math.max(0, Math.round((nowMs - runningSince) / 1000)) : 0
  return (
    <button
      type="button"
      onClick={onClick}
      title={`点击：筛选 ${label} 阶段相关事件并高亮`}
      className={`relative z-10 flex min-w-[78px] cursor-pointer flex-col items-center gap-0.5 rounded-lg border px-2.5 py-2 text-center transition-colors ${NODE_TONE[tone]} hover:border-accent/70`}
    >
      <span className={`whitespace-nowrap text-[10px] tracking-wide ${tone === 'idle' ? 'text-ink-faint' : 'text-ink-soft'}`}>{label}</span>
      <motion.span
        key={`${running}-${completed}-${errors}`}
        initial={{ scale: 1.3, opacity: 0.6 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.22 }}
        className={`font-mono text-[15px] font-semibold tabular-nums ${tone === 'error' ? 'text-alert' : running > 0 || tone === 'running' ? 'text-accent' : 'text-ink-soft'}`}
      >
        {running > 0 ? (
          <span>{running}</span>
        ) : (
          completed
        )}
      </motion.span>
      <span className="whitespace-nowrap text-[10px] text-ink-faint tabular-nums">
        {running > 0 ? (runningSince ? `进行中 ${elapsed}s` : '进行中') : errors > 0 ? `完成 · 错${errors}` : '本会话完成'}
      </span>
      {/* 节点滴流:该阶段最新思维步骤 */}
      <motion.span
        key={drip ? `${drip.title}-${drip.confidence ?? ''}` : 'drip-empty'}
        initial={{ opacity: 0, y: 3 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        title={drip?.title}
        className={`max-w-[92px] truncate text-[9px] leading-tight ${tone === 'idle' ? 'text-ink-faint/70' : 'text-ink-faint'}`}
      >
        {drip ? drip.title : '—'}
      </motion.span>
      {flashKey > 0 && (
        <motion.span
          key={flashKey}
          initial={{ opacity: 0.35 }}
          animate={{ opacity: 0 }}
          transition={{ duration: 0.7 }}
          className="pointer-events-none absolute inset-0 rounded-lg bg-accent/25"
        />
      )}
    </button>
  )
}

interface Packet {
  id: number
  fromPct: number
  toPct: number
  error: boolean
}

export default function AgentRelayStrip({
  onFilterStage,
}: {
  /** 节点点击 → Monitor 写入现有 filters.stage（再次点击同阶段则清除） */
  onFilterStage?: (stage: string) => void
}) {
  const buffer = useEventStreamStore((s) => s.buffer)
  const arrivalTick = useEventStreamStore((s) => s.arrivalTick)
  const reduced = useReducedMotion() ?? false

  const { nodeStats, active, stageRunningSince } = useMemo(() => deriveRelaysMemo(buffer), [buffer])
  const drips = useMemo(() => latestThoughtByStage(buffer), [buffer])

  const [packet, setPacket] = useState<Packet | null>(null)
  const [pulseStage, setPulseStage] = useState<string>('')
  const [flashMap, setFlashMap] = useState<Record<string, number>>({})
  const [nowMs, setNowMs] = useState(() => Date.now())
  const lastStageIdxRef = useRef(-1)
  const lastRunRef = useRef(0)
  const packetIdRef = useRef(0)

  const hasRunning = Object.keys(stageRunningSince).length > 0

  // 活秒表:仅存在 running 阶段时逐秒走
  useEffect(() => {
    if (!hasRunning) return
    const t = setInterval(() => setNowMs(Date.now()), 1000)
    return () => clearInterval(t)
  }, [hasRunning])

  // 最近一条 agent_stage 驱动定向接力包与节点脉冲
  useEffect(() => {
    if (!arrivalTick) return
    const now = Date.now()
    if (now - lastRunRef.current < 150) return
    lastRunRef.current = now

    const top = buffer.find((e) => e.kind === 'event' && e.type === 'agent_stage')
    const stage = top ? String(top.data?.stage || '') : ''
    const isError = top ? String(top.data?.status || '') === 'error' : false
    const idx = AGENT_RELAY_STAGES.indexOf(stage as (typeof AGENT_RELAY_STAGES)[number])
    if (idx >= 0) {
      setPulseStage(stage)
      setFlashMap((m) => ({ ...m, [stage]: (m[stage] ?? 0) + 1 }))
      if (!reduced) {
        packetIdRef.current += 1
        const fromPct = lastStageIdxRef.current >= 0
          ? stageFrac(lastStageIdxRef.current)
          : stageFrac(Math.max(0, idx - 1))
        setPacket({ id: packetIdRef.current, fromPct, toPct: stageFrac(idx), error: isError })
        lastStageIdxRef.current = idx
      }
    }
  }, [arrivalTick, buffer, reduced])

  const activeStageSet = useMemo(() => {
    const set = new Set<string>()
    for (const r of active) {
      if (r.currentStage) set.add(r.currentStage)
    }
    return set
  }, [active])

  return (
    <div className="flex flex-col gap-5 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="relative min-w-0 flex-1">
        <div className="mb-2 flex items-center justify-between gap-2">
          <p className="text-[11px] text-ink-faint">
            多 Agent 审查接力 · 分解 → 工具 → 执行 → 复核 → CAD → 响应
          </p>
          <span className="font-mono text-[11px] text-ink-faint tabular-nums">
            进行中 {active.length}
          </span>
        </div>

        {/* 分段线(内缩容器 5 等分,对齐节点中心):running 节点相邻段流动丝带 */}
        <div className="absolute left-[39px] right-[39px] top-[calc(50%+8px)] h-px">
          {AGENT_RELAY_STAGES.slice(0, -1).map((_, i) => {
            const flowing = !reduced && (activeStageSet.has(AGENT_RELAY_STAGES[i]) || activeStageSet.has(AGENT_RELAY_STAGES[i + 1]))
            return (
              <span
                key={i}
                className={`absolute top-0 h-px ${flowing ? 'segment-flow' : 'bg-line'}`}
                style={{ left: `${(i / 5) * 100}%`, width: '20%' }}
                aria-hidden
              />
            )
          })}
          {/* 运作光束：随活动阶段平移的青蓝光条（无 running 时隐没，reduced 退化为丝带） */}
          {(() => {
            const beamIdx = AGENT_RELAY_STAGES.findIndex((s) => activeStageSet.has(s))
            if (beamIdx < 0 || reduced) return null
            return (
              <motion.span
                className="pointer-events-none absolute top-[-1px] h-[3px] w-12 rounded-full"
                style={{ background: 'linear-gradient(90deg, transparent, var(--glow-info), transparent)' }}
                initial={false}
                animate={{ left: `calc(${stageFrac(beamIdx)}% - 24px)`, opacity: 0.9 }}
                transition={spring.gentle}
                aria-hidden
              />
            )
          })()}
        </div>

        {/* 定向接力包:从上一阶段位置飞向本次事件阶段 */}
        {packet && (
          <motion.span
            key={packet.id}
            className={`absolute z-20 h-2 w-2 rounded-full ${
              packet.error
                ? 'bg-alert shadow-[0_0_8px_rgba(194,58,50,0.35)]'
                : 'bg-ok shadow-[0_0_8px_rgba(62,122,100,0.35)]'
            }`}
            style={{ marginLeft: -4, top: 'calc(50% + 8px)' }}
            initial={{ left: `${packet.fromPct}%`, opacity: 0 }}
            animate={{ left: `${packet.toPct}%`, opacity: [0, 1, 1, 0.85] }}
            transition={{ duration: 0.35, ease: 'easeOut' }}
            onAnimationComplete={() => setPacket(null)}
          />
        )}

        <div className="relative flex items-start justify-between gap-1.5 overflow-x-auto pb-1">
          {AGENT_RELAY_STAGES.map((stage) => {
            const stats = nodeStats[stage] ?? { running: 0, completed: 0, errors: 0 }
            return (
              <Node
                key={stage}
                label={STAGE_LABELS[stage] ?? stage}
                running={stats.running}
                completed={stats.completed}
                errors={stats.errors}
                flashKey={flashMap[stage] ?? 0}
                active={activeStageSet.has(stage) || pulseStage === stage}
                runningSince={stageRunningSince[stage]}
                nowMs={nowMs}
                drip={drips[stage]}
                onClick={() => {
                  pulseFocus('stage', stage)
                  onFilterStage?.(stage)
                }}
              />
            )
          })}
        </div>
      </div>

      <RateHistogram />
    </div>
  )
}
