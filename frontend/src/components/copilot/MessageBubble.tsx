/**
 * MessageBubble · Copilot 单轮问答气泡（2026-11 传智杯 AI Web 改造）
 *
 * 编辑部风：用户消息 = 右对齐墨底便签；AI 回答 = 左对齐纸面案卷
 * （ThinkingRail 思考轨 + 流式 Markdown + 引用条 + 用量脚注）。
 * 每条消息由调用方包 ErrorBoundary —— 单条渲染崩溃不拖垮整页。
 */
import { AnimatePresence, motion } from 'framer-motion'
import type { CopilotTurn } from '../../hooks/useCopilotStream'
import { Markdown } from './Markdown'
import { ThinkingRail } from './ThinkingRail'
import { CitationChips } from './CitationChips'

const severityTone: Record<string, string> = {
  critical: 'text-alert',
  high: 'text-warn',
  medium: 'text-ink-soft',
  low: 'text-ink-faint',
  info: 'text-ink-faint',
}

export function MessageBubble({ turn, onRetry }: { turn: CopilotTurn; onRetry?: (turn: CopilotTurn) => void }) {
  const tokens = turn.usage?.total_tokens
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
      className="space-y-2.5"
    >
      {/* 用户提问 */}
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-[4px] bg-ink px-3.5 py-2.5 text-[13px] leading-relaxed text-paper">
          <p className="whitespace-pre-wrap break-words">{turn.question}</p>
          {(turn.imageName || turn.eventId != null) && (
            <p className="mt-1.5 flex flex-wrap gap-x-3 font-mono text-[10px] uppercase tracking-wide text-paper/60">
              {turn.eventId != null && <span>事件 #{turn.eventId}</span>}
              {turn.imageName && <span>附件 · {turn.imageName}</span>}
            </p>
          )}
        </div>
      </div>

      {/* AI 回答 */}
      <div className="max-w-[92%] space-y-2.5">
        <ThinkingRail turn={turn} />

        {/* 告警上下文卡（深链带 event 时展示） */}
        {turn.eventCtx && (
          <div className="rounded-[4px] border border-line bg-paper px-3.5 py-3">
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-faint">
                告警上下文 · #{turn.eventCtx.event_id}
              </span>
              <span className={`font-mono text-[10px] uppercase ${severityTone[turn.eventCtx.severity] ?? 'text-ink-faint'}`}>
                {turn.eventCtx.severity}
              </span>
            </div>
            <p className="mt-1 text-[12.5px] text-ink">{turn.eventCtx.event_type} — {turn.eventCtx.message}</p>
            {turn.eventCtx.audit_status === 'completed' && (
              <p className="mt-1 font-mono text-[11px] text-ink-soft">
                平台审计：{JSON.stringify(turn.eventCtx.reviewer_verdict ?? {})}
              </p>
            )}
          </div>
        )}

        <div className="rounded-[4px] border border-line bg-paper px-4 py-3">
          {turn.visionNote && (
            <p className="mb-2 rounded-[3px] bg-warn/10 px-2.5 py-1.5 text-[11.5px] text-warn">
              ⚠ {turn.visionNote}
            </p>
          )}
          {turn.answer ? (
            <>
              <Markdown text={turn.answer} />
              {!turn.done && (
                <span className="ml-0.5 inline-block h-3.5 w-[7px] animate-pulse bg-accent/70 align-[-2px]" />
              )}
            </>
          ) : (
            !turn.error && (
              <p className="flex items-center gap-2 text-[12.5px] text-ink-soft">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
                正在思考…
              </p>
            )
          )}

          {turn.error && (
            <div className="mt-2 rounded-[3px] border border-alert/30 bg-alert/5 px-3 py-2">
              <p className="text-[12px] text-alert">{turn.error}</p>
              {onRetry && turn.done && (
                <button
                  type="button"
                  onClick={() => onRetry(turn)}
                  className="mt-1.5 cursor-pointer text-[11.5px] text-accent underline underline-offset-2"
                >
                  重试
                </button>
              )}
            </div>
          )}

          <CitationChips citations={turn.citations} />

          {turn.done && !turn.error && (tokens != null || turn.latencyMs != null) && (
            <p className="mt-2 flex gap-3 border-t border-line-soft pt-2 font-mono text-[10px] uppercase tracking-wide text-ink-faint">
              {tokens != null && <span>tokens {tokens}</span>}
              {turn.latencyMs != null && <span>{(turn.latencyMs / 1000).toFixed(1)}s</span>}
            </p>
          )}
        </div>
      </div>
    </motion.div>
  )
}

/** AnimatePresence 伴生组件导出（页面用布局动画） */
export const BubblePresence = AnimatePresence
