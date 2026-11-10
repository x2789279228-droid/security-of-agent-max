/**
 * POST-SSE 流式消费层 — Copilot 问答（2026-11 AI Web 改造）
 *
 * 为什么不用 EventSource：它只支持 GET，而 Copilot 问答是 POST + 大 payload
 * （问题/历史/图片 data URL）。后端 sse_starlette 的 POST-SSE 已有先例
 * （/api/chat/stream），这里用 fetch + ReadableStream 手工解析 SSE 帧。
 *
 * 结构分两层：
 *  - SseParser：纯字节→帧解析器（跨 chunk 边界安全、CRLF 兼容、多 data 行、
 *    冒号注释行跳过）——纯逻辑，node:test 可单测（scripts/streamSse.test.ts）；
 *  - consumeSseStream：fetch 封装（Bearer 认证、401 同 fetchJSON 口径、
 *    AbortController 取消、非 200 抛结构化错误）。
 */

export interface SseFrame {
  event: string
  data: string
}

/**
 * 增量 SSE 解析器。feed() 随便怎么切块都行（一个字节一个字节来也对），
 * 完整帧通过 onFrame 回调吐出；流结束后调 end() 冲掉残余缓冲。
 */
export class SseParser {
  private buf = ''
  private curEvent = ''
  private dataLines: string[] = []
  private readonly onFrame: (frame: SseFrame) => void

  constructor(onFrame: (frame: SseFrame) => void) {
    this.onFrame = onFrame
  }

  feed(chunk: string): void {
    // 规范 CRLF → LF（SSE 规范允许两种行结束符）
    this.buf += chunk.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    let idx: number
    // 逐行推进；最后一段可能是半个行，留到下一块
    while ((idx = this.buf.indexOf('\n')) >= 0) {
      const line = this.buf.slice(0, idx)
      this.buf = this.buf.slice(idx + 1)
      this.handleLine(line)
    }
  }

  /** 流结束：冲掉无终止空行的最后一帧（宽容处理网关忘发空行的情况）。 */
  end(): void {
    if (this.buf) {
      this.handleLine(this.buf.replace(/\r\n/g, '\n').replace(/\r/g, '\n'))
      this.buf = ''
    }
    this.flush()
  }

  private handleLine(line: string): void {
    if (line === '') {
      // 空行 = 帧边界
      this.flush()
      return
    }
    if (line.startsWith(':')) return // 注释/心跳行
    if (line.startsWith('event:')) {
      this.curEvent = line.slice(6).trim()
      return
    }
    if (line.startsWith('data:')) {
      // 规范：冒号后若紧跟一个空格则剥掉
      const raw = line.slice(5)
      this.dataLines.push(raw.startsWith(' ') ? raw.slice(1) : raw)
      return
    }
    // id:/retry: 等字段与本层无关，忽略
  }

  private flush(): void {
    if (this.dataLines.length === 0) {
      this.curEvent = ''
      return
    }
    const frame: SseFrame = { event: this.curEvent || 'message', data: this.dataLines.join('\n') }
    this.curEvent = ''
    this.dataLines = []
    try {
      this.onFrame(frame)
    } catch (e) {
      // 回调异常不拖垮整个流 —— 由消费方自行决定语义
      console.error('[streamSse] onFrame handler error:', e)
    }
  }
}

/** 与 api.ts fetchJSON 同口径的 401/错误处理 */
async function raiseForResponse(res: Response): Promise<never> {
  if (res.status === 401) {
    // 开放体验模式(2026-11-10): 同 api.ts 口径 —— 不清 Visitor 令牌/不跳登录
    if (localStorage.getItem('sm_open_tour') === '1') {
      throw new Error('开放体验模式下出现认证异常，请刷新页面重试')
    }
    const hadToken = !!localStorage.getItem('sm_token')
    localStorage.removeItem('sm_token')
    localStorage.removeItem('sm_user')
    if (hadToken && !window.location.pathname.startsWith('/login')) {
      window.location.href = '/login'
    }
    throw new Error('认证已过期，请重新登录')
  }
  let detail = res.statusText
  try {
    const body = await res.json()
    if (body.detail) detail = body.detail
  } catch { /* 非 JSON 响应体 */ }
  throw new Error(`API ${res.status}: ${detail}`)
}

export interface ConsumeSseOptions {
  /** 完整路径（含 /api 前缀），调用方传字面量 —— 前后端契约守卫才能对账 */
  path: string
  body: unknown
  signal?: AbortSignal
  onFrame: (event: string, data: string) => void
}

/**
 * POST + Bearer + SSE 消费。resolve 于流正常结束；abort 抛 AbortError；
 * HTTP 非 200 抛 Error（与 fetchJSON 同文案口径）。
 */
export async function consumeSseStream(opts: ConsumeSseOptions): Promise<void> {
  const token = localStorage.getItem('sm_token')
  const res = await fetch(opts.path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(opts.body),
    signal: opts.signal,
  })
  if (!res.ok) await raiseForResponse(res)
  if (!res.body) throw new Error('流式响应为空')

  const parser = new SseParser((frame) => opts.onFrame(frame.event, frame.data))
  const decoder = new TextDecoder('utf-8')
  const reader = res.body.getReader()
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      parser.feed(decoder.decode(value, { stream: true }))
    }
    parser.feed(decoder.decode()) // 冲出解码器尾字节
    parser.end()
  } finally {
    reader.releaseLock()
  }
}
