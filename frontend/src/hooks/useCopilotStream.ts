/**
 * useCopilotStream — Copilot 问答流状态机（2026-11 AI Web 改造）
 *
 * 消费 POST /api/copilot/stream 的 SSE 帧并归约为可渲染的对话状态。
 * 归约逻辑抽成纯函数 `applyFrame`（scripts/copilotStream.test.ts 单测），
 * hook 只负责 fetch 生命周期（ask / stop / clear）。
 *
 * 帧协议见 backend/copilot_service.py：
 *   meta | stage | context | citations | vision_note | reasoning | token | done | error
 */
import { useCallback, useRef, useState } from 'react'
// .ts 扩展显式写出 —— scripts/*.test.ts 的 node:test 直跑需要真实文件名解析
// （allowImportingTsExtensions 已开，vite 构建不受影响）
import { consumeSseStream } from '../lib/streamSse.ts'

// ── 类型 ──────────────────────────────────────────────────────────────────

export interface CopilotCitation {
  index: number
  chunk_id?: string
  doc_id?: string
  title: string
  source: string
  score?: number
  snippet: string
}

export type StageName = 'context' | 'rag' | 'answer'

/** ThinkingRail 的阶段步进（按流水线固定顺序） */
export interface StageStep {
  stage: StageName
  detail: string
  /** active = 进行中；done = 完成；skipped = 降级/跳过（如实标注） */
  status: 'active' | 'done' | 'skipped'
}

export interface CopilotEventCtx {
  event_id: number
  event_type: string
  severity: string
  message: string
  src_ip?: string
  dst_ip?: string
  audit_status?: string
  reviewer_verdict?: Record<string, unknown>
  evidence_brief?: string[]
}

/** 一轮问答（问题 → 流式回答） */
export interface CopilotTurn {
  id: number
  question: string
  /** 附件（诚实展示文件名/来源，不装作纯文本） */
  imageName?: string
  /** 附件原图（data URL）—— 留存供失败重试时带回，修复 retry 静默丢图 */
  imageBase64?: string
  eventId?: number
  eventCtx?: CopilotEventCtx | null
  stages: StageStep[]
  reasoning: string
  answer: string
  citations: CopilotCitation[]
  visionNote?: string
  error?: string
  done: boolean
  usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number }
  latencyMs?: number
}

export const STAGE_ORDER: StageName[] = ['context', 'rag', 'answer']

export const STAGE_LABELS: Record<StageName, string> = {
  context: '读取告警上下文',
  rag: '检索知识库',
  answer: '生成回答',
}

// ── 纯归约（可单测）───────────────────────────────────────────────────────

let seq = 0
export function nextTurnId(): number {
  seq += 1
  return seq
}

export type CopilotAction =
  | { kind: 'begin'; turn: CopilotTurn }
  | { kind: 'frame'; turnId: number; event: string; data: unknown }
  | { kind: 'fail'; turnId: number; message: string }
  | { kind: 'clear' }

/** upsert 阶段步进：首次出现按流水线顺序插入并标记 active；重复帧刷新 detail */
export function upsertStage(steps: StageStep[], stage: StageName, detail: string, status: StageStep['status']): StageStep[] {
  const existing = steps.find((s) => s.stage === stage)
  if (existing) {
    return steps.map((s) => (s.stage === stage ? { ...s, detail, status } : s))
  }
  const next = [...steps, { stage, detail, status }]
  next.sort((a, b) => STAGE_ORDER.indexOf(a.stage) - STAGE_ORDER.indexOf(b.stage))
  return next
}

export function applyFrame(turn: CopilotTurn, event: string, data: unknown): CopilotTurn {
  const d = (data ?? {}) as Record<string, any>
  switch (event) {
    case 'meta':
      return turn // session_id 目前前端不消费；模型名经 capabilities 展示
    case 'stage': {
      const stage = d.stage as StageName
      if (!STAGE_ORDER.includes(stage)) return turn
      return { ...turn, stages: upsertStage(turn.stages, stage, String(d.detail ?? ''), 'active') }
    }
    case 'context':
      return { ...turn, eventCtx: (d.event as CopilotEventCtx) ?? null }
    case 'citations':
      return { ...turn, citations: Array.isArray(d.citations) ? d.citations : [] }
    case 'vision_note':
      return { ...turn, visionNote: String(d.text ?? '') }
    case 'reasoning':
      return { ...turn, reasoning: turn.reasoning + String(d.text ?? '') }
    case 'token':
      return { ...turn, answer: turn.answer + String(d.text ?? '') }
    case 'error':
      return {
        ...turn,
        error: String(d.text ?? '未知错误'),
        stages: turn.stages.map((s) => (s.status === 'active' ? { ...s, status: 'skipped' as const } : s)),
      }
    case 'done': {
      // 以 done.content 为权威（重置流式累积，防丢帧），并结转阶段状态
      const content = typeof d.content === 'string' && d.content.length > 0 ? d.content : turn.answer
      return {
        ...turn,
        answer: content,
        citations: Array.isArray(d.citations) && d.citations.length > 0 ? d.citations : turn.citations,
        usage: d.usage ?? turn.usage,
        latencyMs: typeof d.latency_ms === 'number' ? d.latency_ms : turn.latencyMs,
        done: true,
        stages: turn.stages.map((s) =>
          s.status === 'active'
            ? { ...s, status: s.stage === 'rag' && turn.citations.length === 0 && Array.isArray(d.citations) && d.citations.length === 0 ? ('skipped' as const) : ('done' as const) }
            : s,
        ),
      }
    }
    default:
      return turn
  }
}

export function applyAction(state: CopilotTurn[], action: CopilotAction): CopilotTurn[] {
  switch (action.kind) {
    case 'begin':
      return [...state, action.turn]
    case 'frame':
      return state.map((t) => (t.id === action.turnId ? applyFrame(t, action.event, action.data) : t))
    case 'fail':
      return state.map((t) =>
        t.id === action.turnId ? { ...t, error: action.message, done: true } : t,
      )
    case 'clear':
      return []
  }
}

// ── Hook ──────────────────────────────────────────────────────────────────

export interface AskOptions {
  eventId?: number
  imageBase64?: string
  imageName?: string
}

export function useCopilotStream() {
  const [turns, setTurns] = useState<CopilotTurn[]>([])
  const [running, setRunning] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  const stop = useCallback(() => {
    abortRef.current?.abort()
  }, [])

  const clear = useCallback(() => {
    stop()
    setTurns([])
  }, [stop])

  const ask = useCallback(
    async (question: string, opts: AskOptions = {}, history?: { role: string; content: string }[]) => {
      const q = question.trim()
      if (!q || running) return
      const turn: CopilotTurn = {
        id: nextTurnId(),
        question: q,
        imageName: opts.imageName,
        imageBase64: opts.imageBase64,
        eventId: opts.eventId,
        stages: [],
        reasoning: '',
        answer: '',
        citations: [],
        done: false,
      }
      setTurns((prev) => applyAction(prev, { kind: 'begin', turn }))
      setRunning(true)
      const ctrl = new AbortController()
      abortRef.current = ctrl
      try {
        await consumeSseStream({
          path: '/api/copilot/stream',
          signal: ctrl.signal,
          body: {
            question: q,
            event_id: opts.eventId ?? null,
            image_data_url: opts.imageBase64 ?? '',
            history: history ?? [],
            mode: 'auto',
          },
          onFrame: (event, data) => {
            let parsed: unknown = null
            try {
              parsed = JSON.parse(data)
            } catch {
              parsed = {}
            }
            setTurns((prev) => applyAction(prev, { kind: 'frame', turnId: turn.id, event, data: parsed }))
          },
        })
        // 流正常关闭但未收到 done（网关中断）：如实标注
        setTurns((prev) =>
          prev.map((t) => (t.id === turn.id && !t.done ? { ...t, done: true, error: t.error ?? '连接中断，回答可能不完整' } : t)),
        )
      } catch (e) {
        const aborted = e instanceof DOMException && e.name === 'AbortError'
        setTurns((prev) =>
          applyAction(prev, {
            kind: 'fail',
            turnId: turn.id,
            message: aborted ? '已停止生成' : e instanceof Error ? e.message : '请求失败',
          }),
        )
      } finally {
        setRunning(false)
        if (abortRef.current === ctrl) abortRef.current = null
      }
    },
    [running],
  )

  return { turns, running, ask, stop, clear }
}
