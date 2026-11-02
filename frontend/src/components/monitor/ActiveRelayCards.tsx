/**
 * Agent 接力卡片 — 进行中 + 最近完成；空闲时给演示入口，不再整段消失
 */
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AGENT_RELAY_STAGES,
  STAGE_LABELS,
  deriveRelaysMemo,
  runningLabel,
  type RelayState,
  type StageCellStatus,
} from '../../lib/agentPipeline'
import { ROUTES } from '../../lib/constants'
import { useEventStreamStore } from '../../lib/eventStream'

// 阶段格三色：运行=松绿脉冲；成功=暮青；错误/超时=朱砂；空闲=青底
const cellClass: Record<StageCellStatus, string> = {
  idle: 'bg-qing',
  running: 'bg-ok animate-pulse shadow-[0_0_8px_rgba(62,122,100,0.35)]',
  success: 'bg-accent/60',
  error: 'bg-alert',
  timeout: 'bg-alert/70',
}

function emptyStages(): Record<string, StageCellStatus> {
  const m: Record<string, StageCellStatus> = {}
  for (const s of AGENT_RELAY_STAGES) m[s] = 'idle'
  return m
}

/** 将 /observability/active-pipelines 或 recent-pipelines 载荷转为 RelayState */
export function relayFromHydration(p: any): RelayState {
  const stages = emptyStages()
  const stageSince: Record<string, number> = {}
  for (const s of p.completed_stages || []) {
    if (s in stages) stages[s] = 'success'
  }
  const cur = String(p.current_stage || '')
  const done = Boolean(p.done)
  if (cur in stages) {
    if (done) {
      if (stages[cur] === 'idle') stages[cur] = 'success'
    } else {
      stages[cur] = 'running'
    }
  }
  const startedAt = typeof p.started_at === 'number'
    ? Math.round(p.started_at * 1000)
    : Date.now()
  return {
    eventId: Number(p.event_id) || 0,
    sessionId: String(p.session_id || ''),
    traceId: String(p.trace_id || ''),
    currentStage: cur,
    stages,
    stageSince,
    startedAt,
    updatedAt: startedAt,
    lastError: '',
    done,
  }
}

function Card({
  relay,
  now,
  selected,
  onSelect,
  completed,
}: {
  relay: RelayState
  now: number
  selected?: boolean
  onSelect?: (eventId: number) => void
  completed?: boolean
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect?.(relay.eventId)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') onSelect?.(relay.eventId)
      }}
      className={`min-w-[220px] flex-1 cursor-pointer rounded-xl border bg-card/80 backdrop-blur-sm px-3 py-2.5 transition-colors ${
        selected
          ? 'border-accent/70 shadow-[0_4px_16px_rgba(58,101,112,0.14)]'
          : relay.lastError
            ? 'border-alert/40 hover:border-alert/70'
            : 'border-line hover:border-accent/50'
      }`}
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className={`font-mono text-[12px] font-semibold ${relay.lastError ? 'text-alert' : 'text-accent'}`}>
          #{relay.eventId}
        </span>
        <span className={`text-[11px] tabular-nums ${completed ? 'text-ok' : 'text-ink-faint'}`}>
          {completed ? '已完成' : runningLabel(relay.startedAt, now)}
        </span>
      </div>
      <p className="mt-0.5 truncate text-[12px] text-ink-soft">
        {completed ? '末站：' : '当前：'}
        <span className="font-semibold text-ink">
          {STAGE_LABELS[relay.currentStage] ?? relay.currentStage}
        </span>
        {relay.lastError && (
          <span className="ml-1 text-alert">· {relay.lastError.slice(0, 40)}</span>
        )}
      </p>
      <div className="mt-2 flex gap-1">
        {AGENT_RELAY_STAGES.map((s) => (
          <div
            key={s}
            title={`${STAGE_LABELS[s]} · ${relay.stages[s]}`}
            className={`h-1.5 flex-1 rounded-sm ${cellClass[relay.stages[s] ?? 'idle']}`}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between text-[9px] text-ink-faint">
        <span>分解</span>
        <span>响应</span>
      </div>
    </div>
  )
}

function CardRow({
  title,
  items,
  now,
  selectedEventId,
  onSelect,
  completed,
}: {
  title: string
  items: RelayState[]
  now: number
  selectedEventId: number | null
  onSelect?: (eventId: number) => void
  completed?: boolean
}) {
  return (
    <div className="mb-3">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[13px] font-semibold text-ink">{title}</h3>
        <span className="font-mono text-[11px] text-ink-faint">{items.length} 条</span>
      </div>
      <div className="flex gap-2 overflow-x-auto pb-1">
        {items.slice(0, 8).map((r) => (
          <Card
            key={r.eventId}
            relay={r}
            now={now}
            selected={r.eventId === selectedEventId}
            onSelect={onSelect}
            completed={completed}
          />
        ))}
      </div>
    </div>
  )
}

export default function ActiveRelayCards({
  hydrated = [],
  hydratedRecent = [],
  selectedEventId = null,
  onSelect,
  onDemo,
  demoBusy = false,
}: {
  hydrated?: any[]
  hydratedRecent?: any[]
  selectedEventId?: number | null
  onSelect?: (eventId: number) => void
  onDemo?: () => void
  demoBusy?: boolean
}) {
  const buffer = useEventStreamStore((s) => s.buffer)
  const { active: fromStream, recent: recentFromStream } = useMemo(
    () => deriveRelaysMemo(buffer),
    [buffer],
  )

  // ── 死态回放（PipelineAlive）：无进行中接力时，把最近一次成功管线
  //    按 600ms/阶段在本地重演两轮 —— 纯前端动画，不调后端、不注入事件。
  //    消灭评委走近时的"死屏时刻"。真实接力到达时本组件切出空态分支，回放自然让位。
  const [replay, setReplay] = useState<{
    relay: RelayState
    step: number
    round: number
    finishing: boolean
    t0: number
  } | null>(null)

  useEffect(() => {
    if (!replay) return
    const last = AGENT_RELAY_STAGES.length - 1
    const t = setTimeout(
      () => {
        setReplay((r) => {
          if (!r) return r
          if (r.finishing) return null
          if (r.step < last) return { ...r, step: r.step + 1 }
          if (r.round > 1) return { ...r, step: 0, round: r.round - 1 }
          return { ...r, finishing: true }
        })
      },
      replay.finishing ? 900 : 600,
    )
    return () => clearTimeout(t)
  }, [replay])

  const active = useMemo(() => {
    if (fromStream.length > 0) return fromStream
    return (hydrated || [])
      .map(relayFromHydration)
      .filter((r) => r.eventId > 0)
  }, [fromStream, hydrated])

  const recent = useMemo(() => {
    const map = new Map<number, RelayState>()
    for (const r of (hydratedRecent || []).map(relayFromHydration)) {
      if (r.eventId > 0) map.set(r.eventId, { ...r, done: true })
    }
    for (const r of recentFromStream) {
      map.set(r.eventId, r)
    }
    const activeIds = new Set(active.map((a) => a.eventId))
    return [...map.values()]
      .filter((r) => !activeIds.has(r.eventId))
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, 8)
  }, [recentFromStream, hydratedRecent, active])

  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    if (active.length === 0) return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [active.length])

  if (active.length === 0 && recent.length === 0) {
    const replayable = hydratedRecent.find((p) => Number(p?.event_id) > 0)
    return (
      <div className="mb-5 rounded-xl border border-dashed border-line bg-card/50 px-5 py-4">
        {replay ? (
          <div className="mb-3">
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-[13px] font-semibold text-ink">
                最近一次接力 · 重演
                <span className="ml-2 border border-dan px-1.5 py-px font-mono text-[9px] tracking-[0.06em] text-ink-faint">
                  回放中 · 非实时
                </span>
              </h3>
              <span className="font-mono text-[11px] text-ink-faint tabular-nums">
                第 {replay.round}/2 轮
              </span>
            </div>
            <div className="flex gap-2 overflow-x-auto pb-1">
              <Card
                relay={{
                  ...replay.relay,
                  // 回放的"活秒表"按阶段步进合成，不用真实历史时刻
                  startedAt: replay.t0,
                  currentStage: replay.finishing
                    ? 'response'
                    : AGENT_RELAY_STAGES[replay.step],
                  stages: (() => {
                    const m = emptyStages()
                    AGENT_RELAY_STAGES.forEach((s, i) => {
                      m[s] =
                        replay.finishing || i < replay.step
                          ? 'success'
                          : i === replay.step
                            ? 'running'
                            : 'idle'
                    })
                    return m
                  })(),
                }}
                now={replay.t0 + (replay.step + 1) * 600}
                completed={false}
              />
            </div>
            {replay.finishing && (
              <p className="mt-2 ok-flash inline-block rounded-lg px-2 py-1 text-[12px] text-ok">
                ✓ 接力完成 · 已归档
              </p>
            )}
          </div>
        ) : (
          <p className="text-[13px] font-semibold text-ink">当前没有进行中的审查接力</p>
        )}
        {!replay && (
          <p className="mt-1 text-[12px] text-ink-faint">
            自博弈默认不注入 ingest，监控页不会出现 Audit-LLM 接力。可在本页跑一条演示审查，或到安全审计注入事件。
          </p>
        )}
        <div className="mt-3 flex flex-wrap gap-2">
          {replayable && (
            <button
              type="button"
              onClick={() =>
                setReplay({
                  relay: relayFromHydration(replayable),
                  step: 0,
                  round: 2,
                  finishing: false,
                  t0: Date.now(),
                })
              }
              className="rounded-lg border border-accent/60 px-3 py-1.5 text-[12px] text-accent transition-colors hover:bg-accent/10"
              title="把最近一次成功管线在本地按阶段重演两轮（纯前端动画，不调后端）"
            >
              ▶ 回放最近一次接力
            </button>
          )}
          {onDemo && (
            <button
              type="button"
              onClick={onDemo}
              disabled={demoBusy}
              className="rounded-lg bg-accent px-3 py-1.5 text-[12px] font-semibold text-on-accent border border-accent transition-colors hover:bg-accent-hover disabled:opacity-60"
            >
              {demoBusy ? '演示审查启动中…' : '跑一条演示审查'}
            </button>
          )}
          <Link
            to={ROUTES.SECURITY_AUDIT}
            className="rounded-lg border border-line px-3 py-1.5 text-[12px] text-ink-soft transition-colors hover:border-accent/60 hover:text-accent"
          >
            安全审计注入
          </Link>
          <Link
            to={ROUTES.SELF_PLAY}
            className="rounded-lg border border-line px-3 py-1.5 text-[12px] text-ink-soft transition-colors hover:border-accent/60 hover:text-accent"
          >
            红蓝自博弈（勾选注入）
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="mb-5">
      {active.length > 0 && (
        <CardRow
          title="进行中的审查接力"
          items={active}
          now={now}
          selectedEventId={selectedEventId}
          onSelect={onSelect}
        />
      )}
      {recent.length > 0 && (
        <CardRow
          title="最近完成"
          items={recent}
          now={now}
          selectedEventId={selectedEventId}
          onSelect={onSelect}
          completed
        />
      )}
    </div>
  )
}
