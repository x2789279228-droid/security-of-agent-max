/**
 * AI 分析 Copilot · 值班副驾驶（2026-11 AI Web 改造）
 *
 * 平台的"AI 在场"主入口：对话式安全分析 —— 告警追问（深链 ?event=）、
 * 知识库检索问答（RAG 引用溯源）、截图研判（多模态，未配置视觉模型时
 * 诚实置灰）。回答流式渲染（reasoning + token 双轨），全站多处入口汇入：
 *   监控事件行「追问」/ 审计页「让 AI 解读」/ 知识库「生成引用回答」。
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { PageFrame } from '../components/common/PageFrame'
import { ErrorBoundary } from '../components/common/ErrorBoundary'
import { MessageBubble } from '../components/copilot/MessageBubble'
import { ImageAttach, fileToAttachedImage, type AttachedImage } from '../components/copilot/ImageAttach'
import { useCopilotStream, type CopilotTurn } from '../hooks/useCopilotStream'
import { api } from '../lib/api'

interface Capabilities {
  model: string
  vision_enabled: boolean
  vision_model: string
  rag_available: boolean
  over_budget: boolean
}

const SUGGESTIONS = [
  '这个告警是真的攻击吗？判断依据是什么？',
  '给出下一步处置建议（区分自动动作与人工操作）',
  '用知识库解释这类攻击的手法与检测要点',
]

export default function Copilot() {
  const [params] = useSearchParams()
  const deepEventId = params.get('event') ? Number(params.get('event')) : undefined
  const deepQuery = params.get('q')?.trim() ?? ''
  const deepImage = params.get('mode') === 'rag' // 知识库入口：强制走引用问答口径

  const { turns, running, ask, stop, clear } = useCopilotStream()
  const [caps, setCaps] = useState<Capabilities | null>(null)
  const [capsError, setCapsError] = useState('')
  const [input, setInput] = useState(deepQuery && deepImage ? deepQuery : '')
  const [image, setImage] = useState<AttachedImage | null>(null)
  const [attachErr, setAttachErr] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)
  const autoAsked = useRef(false)

  useEffect(() => {
    api.copilotCapabilities().then(setCaps).catch((e) => setCapsError(e instanceof Error ? e.message : '能力自省失败'))
  }, [])

  // 自动滚底：新 token / 新轮次都跟随
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [turns])

  const send = useCallback(
    (text: string, opts?: { eventId?: number }) => {
      const q = text.trim()
      if (!q || running) return
      ask(
        q,
        { eventId: opts?.eventId, imageBase64: image?.dataUrl, imageName: image?.name },
        // 带最近 3 轮作上下文（user/assistant 对）
        turns.slice(-3).flatMap((t) => [
          { role: 'user', content: t.question },
          ...(t.answer ? [{ role: 'assistant', content: t.answer }] : []),
        ]),
      )
      setInput('')
      setImage(null)
      setAttachErr('')
    },
    [ask, image, running, turns],
  )

  // 深链自动提问（?event=123 或知识库 ?mode=rag&q=…）：只触发一次
  useEffect(() => {
    if (autoAsked.current || running || !caps) return
    if (!deepQuery && deepEventId == null) return
    autoAsked.current = true
    const q = deepQuery || `请分析事件 #${deepEventId}：这是真实攻击吗？给出结论、依据与处置建议。`
    ask(q, { eventId: deepEventId })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caps, deepEventId, deepQuery, running])

  const retry = useCallback(
    (t: CopilotTurn) => {
      // 2026-11-09: 修复带图提问失败后重试静默丢图 —— 附件随轮次留存并带回
      ask(t.question, { eventId: t.eventId, imageBase64: t.imageBase64, imageName: t.imageName })
    },
    [ask],
  )

  return (
    <PageFrame
      title="AI 分析 Copilot"
      hint="值班副驾驶 — 告警追问 · 知识检索 · 截图研判 — 流式回答，引用可溯源"
      extra={
        <>
          {caps && (
            <span className="hidden font-mono text-[10px] uppercase tracking-[0.14em] text-ink-faint md:inline">
              {caps.model || 'LLM'}
              {caps.vision_enabled ? ' · vision' : ''}
            </span>
          )}
          {turns.length > 0 && (
            <button
              type="button"
              onClick={clear}
              className="cursor-pointer font-mono text-[10px] uppercase tracking-[0.14em] text-ink-faint transition-colors hover:text-alert"
            >
              清空会话
            </button>
          )}
        </>
      }
    >
      <div className="grid gap-4 lg:grid-cols-[1fr_300px]">
        {/* 会话主列 */}
        <div className="flex h-[calc(100vh-220px)] min-h-[480px] flex-col rounded-[4px] border border-line bg-mist/30">
          <div ref={scrollRef} className="flex-1 space-y-5 overflow-y-auto px-4 py-4" onPaste={(e) => {
            const file = Array.from(e.clipboardData?.files ?? [])[0]
            if (file && caps?.vision_enabled) {
              fileToAttachedImage(file).then((img) => { setImage(img); setAttachErr('') }).catch((ex) => setAttachErr(ex instanceof Error ? ex.message : '图片处理失败'))
            }
          }}>
            {turns.length === 0 ? (
              <div className="flex h-full flex-col items-center justify-center gap-5 px-6 text-center">
                <div>
                  <p className="text-[15px] font-medium text-ink">值班副驾驶在此</p>
                  <p className="mt-1 text-[12.5px] text-ink-soft">
                    {capsError
                      ? `能力自省失败：${capsError}`
                      : caps?.over_budget
                        ? '今日 LLM 预算已用尽 — 明日恢复或调高 SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS'
                        : '从监控事件行、审计页或知识库带着上下文来问，或直接输入问题'}
                  </p>
                </div>
                <div className="flex flex-wrap justify-center gap-2">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      type="button"
                      disabled={running || !!caps?.over_budget}
                      onClick={() => send(s, { eventId: deepEventId })}
                      className="cursor-pointer rounded-[4px] border border-line bg-paper px-3 py-2 text-[12px] text-ink-soft transition-colors hover:border-accent/50 hover:text-ink disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {s}
                    </button>
                  ))}
                </div>
                {caps && !caps.vision_enabled && (
                  <p className="max-w-md font-mono text-[10.5px] leading-relaxed text-ink-faint">
                    视觉模型未配置（SHARED_MEMORY_LLM_VISION_MODEL）— 截图研判暂不可用，其余能力正常
                  </p>
                )}
              </div>
            ) : (
              turns.map((t) => (
                <ErrorBoundary key={t.id} fallbackTitle="消息渲染异常">
                  <MessageBubble turn={t} onRetry={retry} />
                </ErrorBoundary>
              ))
            )}
          </div>

          {/* 输入区 */}
          <div className="border-t border-line bg-paper px-4 py-3">
            <div className="flex items-end gap-2.5">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
                    e.preventDefault()
                    send(input)
                  }
                }}
                rows={Math.min(4, Math.max(1, input.split('\n').length))}
                placeholder={running ? '生成中… 可先编辑下一个问题' : '向 Copilot 提问（Enter 发送，Shift+Enter 换行）'}
                className="max-h-32 min-h-[38px] flex-1 resize-none rounded-[4px] border border-line-input bg-paper px-3 py-2 text-[13px] leading-relaxed text-ink outline-none transition-colors placeholder:text-ink-faint focus:border-accent"
              />
              <ImageAttach
                visionEnabled={!!caps?.vision_enabled}
                disabled={running}
                image={image}
                onChange={(img) => { setImage(img); setAttachErr('') }}
              />
              {running ? (
                <button
                  type="button"
                  onClick={stop}
                  className="h-9 shrink-0 cursor-pointer rounded-[4px] border border-alert/40 px-4 text-[12.5px] text-alert transition-colors hover:bg-alert/5"
                >
                  停止
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => send(input)}
                  disabled={!input.trim() || !!caps?.over_budget}
                  className="h-9 shrink-0 cursor-pointer rounded-[4px] border border-accent bg-accent px-4 text-[12.5px] text-on-accent transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
                >
                  发送
                </button>
              )}
            </div>
            {attachErr && <p className="mt-1.5 text-[11px] text-alert">{attachErr}</p>}
          </div>
        </div>

        {/* 侧栏：能力 + 使用说明 */}
        <aside className="hidden space-y-3 lg:block">
          <div className="rounded-[4px] border border-line bg-paper px-4 py-3.5">
            <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-faint">能力自省</p>
            <ul className="mt-2.5 space-y-2 text-[12px]">
              <li className="flex items-center justify-between gap-2">
                <span className="text-ink-soft">LLM 模型</span>
                <span className="font-mono text-[11px] text-ink">{caps?.model || '—'}</span>
              </li>
              <li className="flex items-center justify-between gap-2">
                <span className="text-ink-soft">知识库引用</span>
                <span className={`font-mono text-[11px] ${caps?.rag_available ? 'text-ok' : 'text-ink-faint'}`}>
                  {caps?.rag_available ? '可用' : '—'}
                </span>
              </li>
              <li className="flex items-center justify-between gap-2">
                <span className="text-ink-soft">截图研判</span>
                <span className={`font-mono text-[11px] ${caps?.vision_enabled ? 'text-ok' : 'text-ink-faint'}`}>
                  {caps?.vision_enabled ? '可用' : '未配置'}
                </span>
              </li>
            </ul>
            <p className="mt-3 border-t border-line-soft pt-2.5 text-[11px] leading-relaxed text-ink-faint">
              流水线三步只读：读告警上下文 → 检索知识库 → 流式生成。
              工具白名单固定，不自由调用；响应默认不可自动执行，处置建议需经响应引擎审批。
            </p>
          </div>
          <div className="rounded-[4px] border border-line-soft bg-paper-warm/40 px-4 py-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-faint">带上下文来问</p>
            <ul className="mt-2 space-y-1.5 text-[11.5px] leading-relaxed text-ink-soft">
              <li>· 监控 / 日志事件行 →「追问 AI」</li>
              <li>· 审计页证据链 →「让 AI 解读」</li>
              <li>· 知识库检索 →「生成引用回答」</li>
            </ul>
          </div>
        </aside>
      </div>
    </PageFrame>
  )
}
