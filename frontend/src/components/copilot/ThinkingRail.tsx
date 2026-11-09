/**
 * ThinkingRail · AI 思考过程可视化（2026-11 AI Web 改造）
 *
 * 两层：
 *  1. 阶段步进 — 流水线固定三步（读上下文 → 检索知识库 → 生成回答），
 *     done/active/skipped 三态；skipped = 降级路径（无上下文/检索失败），
 *     如实标注不伪装。
 *  2. reasoning 流 — 真实模型思考增量（网关 reasoning 字段），等宽小字
 *     墨青色，流式滚动；无 reasoning（网关不拆分思考）时整段不渲染。
 *
 * 面板默认展开进行中的一轮；完成后折叠为一行摘要（点击展开回看）。
 */
import { useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import type { CopilotTurn, StageStep } from '../../hooks/useCopilotStream'
import { STAGE_LABELS } from '../../hooks/useCopilotStream'

function StageDot({ status }: { status: StageStep['status'] }) {
  if (status === 'done') {
    return (
      <span className="mt-[3px] inline-flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full bg-accent/15">
        <svg width="9" height="9" viewBox="0 0 10 10" fill="none">
          <path d="M1.5 5.5L4 8L8.5 2.5" stroke="var(--color-accent)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
    )
  }
  if (status === 'skipped') {
    return (
      <span className="mt-[3px] inline-flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full border border-line-soft">
        <span className="h-px w-1.5 bg-ink-faint" />
      </span>
    )
  }
  return (
    <span className="mt-[3px] inline-flex h-3.5 w-3.5 shrink-0 items-center justify-center">
      <span className="absolute h-3.5 w-3.5 rounded-full border border-accent/50" />
      <span className="h-1.5 w-1.5 animate-ping rounded-full bg-accent/70 [animation-duration:1.2s]" />
      <span className="absolute h-1.5 w-1.5 rounded-full bg-accent" />
    </span>
  )
}

export function ThinkingRail({ turn }: { turn: CopilotTurn }) {
  const [open, setOpen] = useState(!turn.done)
  const reasoningRef = useRef<HTMLDivElement>(null)

  // 流式 reasoning 自动滚底（仅在展开时）
  useEffect(() => {
    if (open && reasoningRef.current) {
      reasoningRef.current.scrollTop = reasoningRef.current.scrollHeight
    }
  }, [turn.reasoning, open])

  // 新一轮开始时自动展开，完成 800ms 后折叠
  useEffect(() => {
    if (turn.done) {
      const t = setTimeout(() => setOpen(false), 800)
      return () => clearTimeout(t)
    }
    setOpen(true)
  }, [turn.done])

  const hasStages = turn.stages.length > 0
  const hasReasoning = turn.reasoning.trim().length > 0
  if (!hasStages && !hasReasoning) return null

  const activeStage = turn.stages.find((s) => s.status === 'active')

  return (
    <div className="rounded-[4px] border border-line-soft bg-paper-warm/40">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-mist/50"
      >
        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-faint">
          {turn.done ? '思考轨迹' : '思考中'}
        </span>
        {!turn.done && activeStage && (
          <span className="text-[11.5px] text-accent">{STAGE_LABELS[activeStage.stage]}…</span>
        )}
        {turn.done && (
          <span className="text-[11.5px] text-ink-soft">
            {turn.stages.map((s) => STAGE_LABELS[s.stage]).join(' · ')}
          </span>
        )}
        <motion.span animate={{ rotate: open ? 180 : 0 }} className="ml-auto text-ink-faint">
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
            <path d="M2 3.5L5 6.5L8 3.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </motion.span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden"
          >
            <div className="border-t border-line-soft px-3 py-2.5">
              {hasStages && (
                <ol className="space-y-1.5">
                  {turn.stages.map((s) => (
                    <li key={s.stage} className="flex items-start gap-2.5">
                      <StageDot status={s.status} />
                      <div className="min-w-0">
                        <span className={`text-[12px] ${s.status === 'skipped' ? 'text-ink-faint' : 'text-ink'}`}>
                          {STAGE_LABELS[s.stage]}
                        </span>
                        {s.detail && (
                          <span className={`ml-2 text-[11.5px] ${s.status === 'skipped' ? 'text-alert/80' : 'text-ink-faint'}`}>
                            {s.detail}
                          </span>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              )}
              {hasReasoning && (
                <div
                  ref={reasoningRef}
                  className="mt-2.5 max-h-44 overflow-y-auto whitespace-pre-wrap rounded-[3px] bg-mist/60 px-3 py-2 font-mono text-[11px] leading-relaxed text-ink-soft"
                >
                  {turn.reasoning}
                  {!turn.done && <span className="ml-0.5 inline-block h-3 w-[6px] animate-pulse bg-accent/60 align-[-2px]" />}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
