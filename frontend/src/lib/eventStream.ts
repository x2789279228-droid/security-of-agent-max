/**
 * 实时事件流共享内核 — Monitor 页实时事件流的单一数据源
 *
 * 模块级单例 EventSource + zustand store：
 * - 覆盖后端全部 8 类事件（旧实现只监听 3 类，alert/pipeline_health 等被静默丢弃）
 * - 断线续传：业务游标是 SecurityEvent.id。手动重建走 ?last_event_id=。
 *   浏览器自动重连还会带 Last-Event-ID。界面状态不写 id 行，避免污染这个游标。
 * - 服务端重启（epoch 变化）只作废界面状态的去重表，业务游标保留。
 *   complete=false / cursor_reset 插入空洞标记。critical 队列缺口由 ping 的
 *   missed_critical 触发重连，不再拿内存 seq 做僵尸判断。
 */
import { useEffect } from 'react'
import { create } from 'zustand'
import { api } from './api'

export type StreamStatus = 'idle' | 'connecting' | 'online' | 'reconnecting' | 'offline'

export interface StreamEvent {
  id: number              // 本地渲染自增
  seq: number             // 业务游标 SecurityEvent.id；界面状态和合成标记为 0
  dedupKey?: string
  kind: 'event' | 'gap' | 'restart'
  type: string            // 业务事件类型；合成标记为 __gap__ / __restart__
  data: any
  ts: number              // 展示时间(ms)，取服务端 _ts，缺失时退化为本地时间
  replay?: boolean        // 经断线续传回放补发而来
}

// ── 事件类型注册表 ── 新增后端事件类型时在此登记即可被管线捕获 ──
// 徽章色：security_event=磷光 LIVE；alert/tool_anomaly=朱砂；其余类型按职能分色
export const EVENT_META: Record<string, { label: string; badge: string }> = {
  security_event:            { label: '事件接入', badge: 'border border-accent/40 bg-accent/10 text-accent' },
  alert:                     { label: '告警',     badge: 'border border-alert/50 bg-alert/15 text-alert' },
  agent_stage:               { label: 'Agent 阶段', badge: 'border border-hui/45 bg-hui/10 text-hui' },
  agent_thought:             { label: '思维步骤', badge: 'border border-line bg-mist text-ink-faint' },
  audit_complete:            { label: '审计完成', badge: 'border border-accent/35 bg-accent/5 text-accent' },
  audit_degraded:            { label: '审计降级', badge: 'border border-warn/45 bg-warn/10 text-warn' },
  response_action:           { label: '响应执行', badge: 'border border-warn/45 bg-warn/10 text-warn' },
  pipeline_health:           { label: '管道健康', badge: 'border border-hui/35 bg-hui/5 text-hui' },
  edr_correlation:           { label: 'EDR关联', badge: 'border border-dan/60 bg-transparent text-ink-soft' },
  data_security_llm_verdict: { label: '数据安全裁定', badge: 'border border-dan/60 bg-transparent text-ink-soft' },
  phishing_llm_verdict:      { label: '钓鱼裁定', badge: 'border border-warn/40 bg-warn/5 text-warn' },
  selfplay_round:            { label: '自博弈回合', badge: 'border border-dashed border-accent/45 bg-accent/5 text-accent' },
  selfplay_match:            { label: '自博弈对局', badge: 'border border-dashed border-warn/50 bg-warn/5 text-warn' },
  tool_anomaly:              { label: '工具偏离', badge: 'border border-alert/50 bg-alert/15 text-alert' },
}
export const TYPE_KEYS = Object.keys(EVENT_META)
export const metaOf = (type: string) => EVENT_META[type]

// ── 严重度注册表 ── 0.1s 规则：critical=朱砂 / high=琥珀 / medium=信号蓝 / low+info=微光
export const SEVERITY_META: Record<string, { label: string; chip: string; bar: string; rank: number }> = {
  critical: { label: '严重', chip: 'bg-alert/15 text-alert border border-alert/40',  bar: 'bg-alert w-[3px]', rank: 4 },
  high:     { label: '高',   chip: 'bg-warn/15 text-warn border border-warn/40',     bar: 'bg-warn w-[3px]',  rank: 3 },
  medium:   { label: '中',   chip: 'bg-hui/10 text-hui border border-hui/40',        bar: 'bg-hui w-[3px]',   rank: 2 },
  low:      { label: '低',   chip: 'border border-line bg-mist text-ink-faint',      bar: 'bg-dan w-[2px]',   rank: 1 },
  info:     { label: '信息', chip: 'text-ink-faint',                                 bar: 'bg-line w-px',     rank: 0 },
}
export function severityOf(type: string, data: any): keyof typeof SEVERITY_META {
  const s = String(data?.severity ?? '').toLowerCase()
  if (s in SEVERITY_META) return s as keyof typeof SEVERITY_META
  const subtype = String(data?.type ?? '').toLowerCase()
  if (type === 'pipeline_health' && (subtype === 'sla_breach' || subtype === 'alert')) return 'high'
  if (type === 'alert' || type === 'tool_anomaly') return 'high'
  if (type === 'pipeline_health') return 'medium'
  if (type === 'agent_stage' && (data?.status === 'error' || data?.status === 'timeout')) return 'high'
  return 'info'
}

// ── store ──
const BUFFER_MAX = 500

interface EventStreamState {
  status: StreamStatus
  subscribers: number       // 服务端在线订阅者数（connected 载荷）
  attempts: number          // 当前一轮断线的连续重试次数
  reconnects: number        // 会话内累计成功重连次数
  receivedTotal: number     // 本会话累计到达的业务事件数（含回放补发）
  replayedTotal: number     // 其中经断线续传回放的条数
  buffer: StreamEvent[]     // 新事件在前，上限 BUFFER_MAX
  overflow: number          // 因缓冲上限被挤出的条数
  typeCounts: Record<string, number> // 按类型增量维护的缓冲计数（避免 O(n) 重扫）
  arrivalTick: number       // 实到业务事件计数器，驱动管线动画/统计联动
}

const useEventStreamStore = create<EventStreamState>(() => ({
  status: 'idle',
  subscribers: 0,
  attempts: 0,
  reconnects: 0,
  receivedTotal: 0,
  replayedTotal: 0,
  buffer: [],
  overflow: 0,
  typeCounts: {},
  arrivalTick: 0,
}))

export { useEventStreamStore }

// ── 控制器状态（非响应式模块变量）──
let es: EventSource | null = null
let consumers = 0
let closeTimer: ReturnType<typeof setTimeout> | undefined
let watchdogTimer: ReturnType<typeof setInterval> | undefined
let localId = 0
let errStreak = 0
let lastActivityTs = 0
const CURSOR_STORAGE_KEY = 'soc_event_cursor'

function readStoredCursor(): number | null {
  try {
    const n = Number(sessionStorage.getItem(CURSOR_STORAGE_KEY))
    return Number.isFinite(n) && n > 0 ? n : null
  } catch {
    return null
  }
}

function writeStoredCursor(id: number) {
  try { sessionStorage.setItem(CURSOR_STORAGE_KEY, String(id)) } catch { /* 隐私模式忽略 */ }
}

let knownEventId: number | null = readStoredCursor()  // SecurityEvent.id，刷新页面后仍用于补查
let storedEpoch: number | null = null   // 服务端进程纪元
let replayDebt = 0                      // 服务端宣告的本轮回放条数，随到达递减
let lastAutoRetryTs = 0                 // 最近一次针对终态的自动重建时刻
let lastGapReconnectTs = 0              // critical 缺口触发的重连，避免紧接着再连一次
let lastMissedCritical = 0
let lastCriticalLost = 0
let pendingRefreshIds: number[] = []
let replayPages = 0
let continueAfterReplay = false
const seenKeys = new Set<string>()
const arrivalTimes: number[] = []       // 最近实到时刻，供速率直方图采样

const IDLE_GRACE_MS = 10_000            // 页面离开后保留连接的宽限期
const SILENT_RESTART_MS = 25_000        // 完全静默（连 ping 都没有）的兜底重连阈值；须大于 ping 周期(15s)
const GAP_RECONNECT_COOLDOWN_MS = 3_000

function bumpActivity() {
  lastActivityTs = Date.now()
}

// ── 微批刷新：高吞吐时把 50ms 窗口内的多条事件合并为一次 store 写入 ──
// 此前每条事件都新建 buffer 数组并 setState，500 条缓冲 × 每条事件
// 触发所有订阅组件与 useMemo 全量重算，是前端卡顿的第二主因。
const FLUSH_INTERVAL_MS = 50
const pendingBatch: StreamEvent[] = []
let flushTimer: ReturnType<typeof setTimeout> | undefined

function flushBatch() {
  flushTimer = undefined
  if (!pendingBatch.length) return
  const batch = pendingBatch.reverse() // 到达序（旧→新）→ 渲染序（新→旧）
  pendingBatch.length = 0
  const st = useEventStreamStore.getState()
  let buffer = [...batch, ...st.buffer]
  let overflow = st.overflow
  const counts = { ...st.typeCounts }
  let received = 0
  let replayed = 0
  let arrived = 0
  for (const evt of batch) {
    if (evt.kind !== 'event') continue
    counts[evt.type] = (counts[evt.type] ?? 0) + 1
    received += 1
    if (evt.replay) replayed += 1
    else arrived += 1
  }
  while (buffer.length > BUFFER_MAX) {
    const dropped = buffer.pop()
    if (dropped) {
      if (dropped.dedupKey) seenKeys.delete(dropped.dedupKey)
      if (dropped.kind === 'event') {
        const n = (counts[dropped.type] ?? 0) - 1
        if (n > 0) counts[dropped.type] = n
        else delete counts[dropped.type]
      }
    }
    overflow += 1
  }
  useEventStreamStore.setState({
    buffer,
    overflow,
    typeCounts: counts,
    receivedTotal: st.receivedTotal + received,
    replayedTotal: st.replayedTotal + replayed,
    arrivalTick: st.arrivalTick + arrived,
  })
}

function enqueue(evt: StreamEvent) {
  pendingBatch.push(evt)
  if (!flushTimer) flushTimer = setTimeout(flushBatch, FLUSH_INTERVAL_MS)
}

/** 合成标记行（空洞/重启）；避免连续重复堆叠 */
function insertMarker(kind: 'gap' | 'restart') {
  const lastPending = pendingBatch[pendingBatch.length - 1]
  if (lastPending?.kind === kind) return
  const top = useEventStreamStore.getState().buffer[0]
  if (top && top.kind === kind) return
  localId += 1
  enqueue({ id: localId, seq: 0, kind, type: kind === 'gap' ? '__gap__' : '__restart__', data: {}, ts: Date.now() })
}

function cursorOf(type: string, data: any, lastEventId: string): { key: string; eventId: number } {
  if (data?._cursor_kind === 'epoch_seq') {
    const ephemeral = String(data?._ephemeral_id || lastEventId || '')
    return { key: ephemeral ? `p:${ephemeral}` : '', eventId: 0 }
  }
  if (data?._cursor_kind === 'event_id') {
    const eid = Number(data?._event_id ?? data?.event_id)
    if (Number.isFinite(eid) && eid > 0) return { key: `e:${type}:${eid}`, eventId: eid }
  }
  // 旧服务端没有 cursor_kind：整数 id 仍按业务游标处理。
  const legacy = Number(lastEventId) || Number(data?._event_id) || 0
  if (data?._cursor_kind == null && Number.isFinite(legacy) && legacy > 0) {
    return { key: `e:${type}:${legacy}`, eventId: legacy }
  }
  return { key: '', eventId: 0 }
}

function patchExisting(key: string, data: any, ts: number) {
  const pendingIdx = pendingBatch.findIndex((e) => e.dedupKey === key)
  if (pendingIdx >= 0) {
    pendingBatch[pendingIdx] = { ...pendingBatch[pendingIdx], data, ts }
    return
  }
  const st = useEventStreamStore.getState()
  const idx = st.buffer.findIndex((e) => e.dedupKey === key)
  if (idx < 0) return
  const buffer = st.buffer.slice()
  buffer[idx] = { ...buffer[idx], data, ts }
  useEventStreamStore.setState({ buffer })
}

function ingestEvent(
  type: string,
  data: any,
  lastEventId: string,
  rawTs: unknown,
  opts: { replay?: boolean } = {},
) {
  const { key, eventId } = cursorOf(type, data, lastEventId)
  const refresh = Boolean(data?._refresh)
  if (key && seenKeys.has(key)) {
    if (refresh || data?._replay) patchExisting(key, data, typeof rawTs === 'number' ? Math.round(rawTs * 1000) : Date.now())
    return
  }
  if (key) seenKeys.add(key)
  if (eventId > 0 && (knownEventId === null || eventId > knownEventId)) {
    knownEventId = eventId
    writeStoredCursor(eventId)
  }
  const ts = typeof rawTs === 'number' ? Math.round(rawTs * 1000) : Date.now()
  if (!opts.replay) {
    arrivalTimes.push(ts)
    while (arrivalTimes.length && arrivalTimes[0] < ts - 70_000) arrivalTimes.shift()
  }
  localId += 1
  enqueue({ id: localId, seq: eventId, dedupKey: key || undefined, kind: 'event', type, data, ts, replay: !!opts.replay })
}

function parsePayload(raw: string): any | null {
  try { return JSON.parse(raw) } catch { return null }
}

function handleConnected(raw: string) {
  bumpActivity()
  const payload = parsePayload(raw) ?? {}
  const st = useEventStreamStore.getState()
  if (typeof payload.epoch === 'number') {
    if (storedEpoch !== null && storedEpoch !== payload.epoch) {
      // 进程重启只作废界面状态的去重键。SecurityEvent.id 跨重启仍然有效。
      insertMarker('restart')
      for (const key of [...seenKeys]) {
        if (key.startsWith('p:')) seenKeys.delete(key)
      }
    }
    storedEpoch = payload.epoch
  }
  const replayed = typeof payload.replayed === 'number' ? Math.max(0, payload.replayed) : 0
  const canPage = (
    payload.complete === false
    && !payload.cursor_reset
    && !payload.db_error
    && !payload.cursor_ignored
    && replayed > 0
    && typeof payload.next_after_id === 'number'
    && replayPages < 8
  )
  if (payload.cursor_reset) {
    insertMarker('gap')
    if (typeof payload.max_event_id === 'number' && payload.max_event_id >= 0) {
      knownEventId = payload.max_event_id
      writeStoredCursor(payload.max_event_id)
    }
    continueAfterReplay = false
    replayPages = 0
  } else if (canPage) {
    continueAfterReplay = true
    replayPages += 1
  } else if (payload.complete === false || payload.cursor_ignored) {
    insertMarker('gap')
    continueAfterReplay = false
    replayPages = 0
  } else {
    continueAfterReplay = false
    replayPages = 0
  }
  replayDebt = replayed
  lastMissedCritical = 0
  lastCriticalLost = 0
  useEventStreamStore.setState({
    status: 'online',
    subscribers: typeof payload.subscribers === 'number' ? payload.subscribers : st.subscribers,
    attempts: 0,
    reconnects: errStreak > 0 ? st.reconnects + 1 : st.reconnects,
  })
  errStreak = 0
}

function maybeContinueReplay() {
  if (replayDebt > 0 || !continueAfterReplay) return
  continueAfterReplay = false
  streamReconnect()
}

function handleNamedMessage(type: string, raw: string, lastEventId: string) {
  bumpActivity()
  const data = parsePayload(raw)
  const isReplay = replayDebt > 0
  if (isReplay) replayDebt -= 1
  if (data) ingestEvent(type, data, lastEventId, data._ts, { replay: isReplay })
  maybeContinueReplay()
}

function handlePing(raw: string) {
  bumpActivity()
  // critical 队列满时服务端不丢已入队告警，而是在 ping 里报告缺口。
  // 这里重连并把 refresh_ids 交回去，由数据库补查，不比较内存 seq。
  const payload = parsePayload(raw) ?? {}
  const missed = Number(payload.missed_critical) || 0
  const lost = Number(payload.critical_lost) || 0
  if (missed <= lastMissedCritical && lost <= lastCriticalLost) return
  if (Date.now() - lastGapReconnectTs < GAP_RECONNECT_COOLDOWN_MS) return
  lastMissedCritical = missed
  lastCriticalLost = lost
  lastGapReconnectTs = Date.now()
  if (lost > 0) insertMarker('gap')
  const ids = Array.isArray(payload.refresh_ids) ? payload.refresh_ids : []
  pendingRefreshIds = ids.map((n: unknown) => Number(n)).filter((n: number) => Number.isFinite(n) && n > 0).slice(0, 32)
  streamReconnect()
}

function openStream() {
  if (es) return
  const refresh = pendingRefreshIds
  pendingRefreshIds = []
  const source = api.eventsStream(knownEventId ?? undefined, refresh)
  if (!source) {
    // 未登录(无 token):不建连,交给认证流程引导登录页
    errStreak += 1
    useEventStreamStore.setState({ status: 'offline', attempts: errStreak })
    return
  }
  es = source
  useEventStreamStore.setState({ status: 'connecting' })

  source.addEventListener('connected', (e: MessageEvent) => handleConnected(e.data))
  source.addEventListener('ping', (e: MessageEvent) => handlePing(e.data))
  for (const type of TYPE_KEYS) {
    source.addEventListener(type, (e: MessageEvent) =>
      handleNamedMessage(type, e.data, (e as MessageEvent).lastEventId),
    )
  }
  source.onerror = () => {
    errStreak += 1
    // EventSource 对网络中断保持 CONNECTING 并自动重试；只有致命错误才进入 CLOSED
    const closed = source.readyState === 2
    useEventStreamStore.setState({
      status: closed ? 'offline' : 'reconnecting',
      attempts: errStreak,
    })
    // EventSource 拿不到 HTTP 状态码：连续失败时借一次受保护请求，
    // 若 token 已过期，fetchJSON 的 401 处理会清凭证并跳登录页，
    // 避免认证失败被看门狗无限重连掩盖（表现为永远"重连中/被踢"）
    if (errStreak === 3) {
      api.stats().catch(() => {})
    }
  }

  watchdogTimer = setInterval(() => {
    if (!es) return
    const { status } = useEventStreamStore.getState()
    if (status === 'online' && Date.now() - lastActivityTs > SILENT_RESTART_MS) {
      streamReconnect() // 订阅者可能已被服务端槽位淘汰（静默失联），强制重建
      return
    }
    // 反向代理会把"上游不可达"包装成非 200 响应，EventSource 按规范视为致命错误
    // 直接进入 CLOSED 不再重试——终态由看门狗以 10s 间隔接管重建
    if (
      status === 'offline' &&
      Date.now() - Math.max(lastAutoRetryTs, lastActivityTs) > 10_000
    ) {
      lastAutoRetryTs = Date.now()
      streamReconnect()
    }
  }, 5_000)
}

function closeStream() {
  if (closeTimer) { clearTimeout(closeTimer); closeTimer = undefined }
  if (watchdogTimer) { clearInterval(watchdogTimer); watchdogTimer = undefined }
  if (flushTimer) { clearTimeout(flushTimer); flushTimer = undefined }
  flushBatch() // 丢弃连接前把未落 store 的攒批事件冲刷出去
  if (es) { es.close(); es = null }
  errStreak = 0
  useEventStreamStore.setState({ status: 'idle', attempts: 0 })
}

// ── 对外控制接口 ──

export function streamReconnect() {
  if (es) { es.close(); es = null }
  errStreak = 0
  lastActivityTs = 0
  openStream()
}

export function streamClear() {
  if (flushTimer) { clearTimeout(flushTimer); flushTimer = undefined }
  pendingBatch.length = 0
  const st = useEventStreamStore.getState()
  for (const e of st.buffer) if (e.dedupKey) seenKeys.delete(e.dedupKey)
  useEventStreamStore.setState({ buffer: [], overflow: 0, typeCounts: {} })
}

export function getArrivalTimes(): readonly number[] {
  return arrivalTimes
}

/** 最近一次通道活动（任意消息含心跳）的本地时刻，供状态条展示心跳年龄 */
export function getLastActivityTs(): number {
  return lastActivityTs
}

/** 页面生命周期：引用计数管理连接，多组件共用一条通道 */
export function useEventStreamLifecycle() {
  useEffect(() => {
    consumers += 1
    if (closeTimer) { clearTimeout(closeTimer); closeTimer = undefined }
    if (!es) openStream()
    return () => {
      consumers -= 1
      if (consumers <= 0) {
        closeTimer = setTimeout(() => {
          if (consumers <= 0) closeStream()
        }, IDLE_GRACE_MS)
      }
    }
  }, [])
}
