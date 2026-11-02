import { useEffect, useRef, useState } from 'react'
import type { ThoughtStep } from '../../lib/demoScript'
import { KIND_LABELS } from '../../lib/demoScript'

/**
 * 思维链打字机(签名时刻①) — agent 思考逐字浮现。
 * 后端一次推一批 steps,这里以固定节奏逐条逐字释放;step_id 幂等去重在导演层完成。
 */

const CHAR_MS_TITLE = 16
const STEP_GAP_MS = 420

const STATUS_TONE: Record<string, { chip: string; text: string }> = {
  success: { chip: 'border-[#5da583]/45 text-[#7fd4a8]', text: 'text-[#c9d6cf]' },
  error: { chip: 'border-[#e05a4e]/50 text-[#e8887c]', text: 'text-[#d6bab4]' },
  discarded: { chip: 'border-[#d4a054]/45 text-[#d9b06b]', text: 'text-[#c4b7a2]' },
  abstain: { chip: 'border-[#74a7b5]/45 text-[#8fc0cc]', text: 'text-[#b5c8cd]' },
  blocked: { chip: 'border-[#e05a4e]/50 text-[#e8887c]', text: 'text-[#d6bab4]' },
}

function StepRow({ step, titleChars, bodyChars }: { step: ThoughtStep; titleChars: number; bodyChars: number }) {
  const tone = STATUS_TONE[step.status] ?? STATUS_TONE.success
  const title = step.title.slice(0, titleChars)
  const body = step.summary.slice(0, bodyChars)
  const done = titleChars >= step.title.length && bodyChars >= step.summary.length
  return (
    <div className="relative pl-4">
      <span className="absolute left-0 top-[7px] h-1.5 w-1.5 rotate-45 bg-warn" aria-hidden />
      <p className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
        <span className="font-mono text-[10px] tracking-[0.2em] uppercase text-[#78889a]">
          {step.stage} · {KIND_LABELS[step.kind] ?? step.kind}
        </span>
        <span className={`border px-1.5 py-px font-mono text-[10px] tracking-[0.14em] uppercase ${tone.chip}`}>
          {step.status}
        </span>
        <span className="text-[16px] font-bold text-[#e8eee9]">
          {title}
          {!done && <span className="ml-px inline-block h-[1em] w-[2px] translate-y-[2px] animate-pulse bg-warn" aria-hidden />}
        </span>
        {step.confidence != null && (
          <span className="font-mono text-[10px] tabular-nums text-[#78889a]">置信 {step.confidence.toFixed(2)}</span>
        )}
      </p>
      {body && (
        <p className={`mt-1 max-w-[36rem] text-[14px] leading-relaxed ${tone.text}`}>
          {body}
          {!done && <span className="ml-px inline-block h-[1em] w-[2px] translate-y-[2px] animate-pulse bg-warn/70" aria-hidden />}
        </p>
      )}
    </div>
  )
}

export function ThoughtTypewriter({
  steps,
  paused,
  className,
}: {
  steps: ThoughtStep[]
  paused: boolean
  className?: string
}) {
  // 释放进度:已完整展示的步数 + 当前步的 title/body 已显字符数
  const [progress, setProgress] = useState({ doneSteps: 0, titleChars: 0, bodyChars: 0 })
  const stateRef = useRef(progress)
  stateRef.current = progress
  const pausedRef = useRef(paused)
  pausedRef.current = paused
  const reducedRef = useRef(false)

  useEffect(() => {
    reducedRef.current = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  }, [])

  useEffect(() => {
    if (reducedRef.current) {
      setProgress({ doneSteps: steps.length, titleChars: 0, bodyChars: 0 })
      return
    }
    const t = setInterval(() => {
      if (pausedRef.current) return
      const cur = stateRef.current
      const step = steps[cur.doneSteps]
      if (!step) return
      if (cur.titleChars < step.title.length) {
        setProgress({ ...cur, titleChars: cur.titleChars + 1 })
      } else if (cur.bodyChars < step.summary.length) {
        setProgress({ ...cur, bodyChars: Math.min(step.summary.length, cur.bodyChars + 2) })
      } else {
        setProgress({ doneSteps: cur.doneSteps + 1, titleChars: 0, bodyChars: -STEP_GAP_MS })
      }
      // bodyChars 负值用作步间停顿的倒计垫片
    }, Math.max(8, CHAR_MS_TITLE))
    return () => clearInterval(t)
  }, [steps])

  const visible = steps.slice(0, Math.min(progress.doneSteps + 1, steps.length))

  return (
    <div className={className}>
      <div className="flex flex-col gap-4">
        {visible.map((step, i) => {
          if (i < progress.doneSteps) {
            return <StepRow key={step.stepId || i} step={step} titleChars={Infinity} bodyChars={Infinity} />
          }
          const bodyShown = Math.max(0, progress.bodyChars)
          const waiting = progress.bodyChars < 0
          return (
            <StepRow
              key={step.stepId || i}
              step={step}
              titleChars={waiting ? step.title.length : progress.titleChars}
              bodyChars={waiting ? 0 : bodyShown}
            />
          )
        })}
        {steps.length === 0 && (
          <p className="text-[14px] italic text-[#78889a]">等待思维链信号……</p>
        )}
      </div>
      {steps.length > 0 && progress.doneSteps >= steps.length && (
        <p className="mt-4 border-t border-[#24384a] pt-3 font-mono text-[10px] tracking-[0.06em] text-[#78889a]">
          思维链完结 · {steps.length} 步
        </p>
      )}
    </div>
  )
}
