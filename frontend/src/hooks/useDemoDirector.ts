import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import { useEventStreamLifecycle, useEventStreamStore } from '../lib/eventStream'
import { AGENT_RELAY_STAGES, type AgentRelayStage } from '../lib/agentPipeline'
import {
  SCENES,
  REHEARSAL_TIMELINE,
  fallbackSignals,
  signalsFromEvent,
  MAX_STEPS,
  type DemoSignal,
  type SceneId,
  type SourceMode,
  type ThoughtStep,
} from '../lib/demoScript'

/**
 * 剧本导演 — 三模数据源共用的幕次状态机(阶段 3)
 *
 * live:      SSE 按 event_id 过滤映射为信号;每幕有超时阀
 * degraded:  超时后合成信号推进(明示「降级」)
 * rehearsal: 演练时间轴自产信号(无后端,供视频录制)
 * 渲染层只读本状态机,不直接消费事件缓冲。
 */

export type SceneStatus = 'pending' | 'playing' | 'done' | 'skipped'

export interface StageCell {
  status: 'idle' | 'running' | 'success' | 'error' | 'timeout'
  simulated: boolean
}

export interface DirectorState {
  running: boolean
  finished: boolean
  paused: boolean
  mode: SourceMode
  sceneIdx: number
  sceneStatus: Record<SceneId, SceneStatus>
  sceneSimulated: Record<SceneId, boolean>
  eventId: number | null
  elapsedMs: number
  event: { type: string; src: string; dst: string; message: string } | null
  detection: { title: string; detail: string } | null
  stages: Record<AgentRelayStage, StageCell>
  steps: ThoughtStep[]
  stepsDropped: number
  response: { blocked: boolean; summary: string; simulated: boolean } | null
  degradedNote: string | null
  seal: { text: string; sub: string } | null
  error: string
}

/** 可暂停的单调时间轴:演练编排与幕超时共用,暂停时整体冻结 */
class Timeline {
  private items: { at: number; fn: () => void }[] = []
  private startedAt = 0
  private base = 0
  private timer: ReturnType<typeof setTimeout> | null = null
  private paused = false

  push(at: number, fn: () => void) {
    this.items.push({ at, fn })
    // 状态机会在回调里追加"延迟完成"项（可能早于队列中已有时间点）；
    // 必须保持按时间排序，否则 setTimeout 只盯 items[0]，早到的完成项会被漏掉。
    this.items.sort((a, b) => a.at - b.at)
    if (!this.paused) this.tick()
  }

  now(): number {
    return this.base + (this.paused ? 0 : performance.now() - this.startedAt)
  }

  start() {
    this.clear()
    this.base = 0
    this.startedAt = performance.now()
    this.paused = false
  }

  private tick() {
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = null
    }
    if (this.paused) return
    const now = this.now()
    const due = this.items.filter((i) => i.at <= now)
    this.items = this.items.filter((i) => i.at > now)
    for (const d of due) d.fn()
    const next = this.items[0]
    if (next) {
      this.timer = setTimeout(() => this.tick(), Math.max(16, next.at - now))
    }
  }

  pause() {
    if (this.paused) return
    this.base = this.now()
    this.paused = true
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = null
    }
  }

  resume() {
    if (!this.paused) return
    this.startedAt = performance.now()
    this.paused = false
    this.tick()
  }

  clear() {
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
    this.items = []
  }
}

const DEMO_EVENT = {
  event: 'C2_BEACON',
  severity: 'critical',
  src_ip: '192.168.1.105',
  dst_ip: '23.129.64.33',
  message: '剧本演示：内部主机疑似与C2服务器周期性通信',
  confidence: 85,
  _demo: true,
}

function initialStages(): Record<AgentRelayStage, StageCell> {
  const m = {} as Record<AgentRelayStage, StageCell>
  for (const s of AGENT_RELAY_STAGES) m[s] = { status: 'idle', simulated: false }
  return m
}

function initialSceneStatus(): Record<SceneId, SceneStatus> {
  const m = {} as Record<SceneId, SceneStatus>
  for (const s of SCENES) m[s.id] = 'pending'
  return m
}

function initialSceneSimulated(): Record<SceneId, boolean> {
  const m = {} as Record<SceneId, boolean>
  for (const s of SCENES) m[s.id] = false
  return m
}

const INITIAL: DirectorState = {
  running: false,
  finished: false,
  paused: false,
  mode: 'live',
  sceneIdx: -1,
  sceneStatus: initialSceneStatus(),
  sceneSimulated: initialSceneSimulated(),
  eventId: null,
  elapsedMs: 0,
  event: null,
  detection: null,
  stages: initialStages(),
  steps: [],
  stepsDropped: 0,
  response: null,
  degradedNote: null,
  seal: null,
  error: '',
}

function sealFrom(response: DirectorState['response']): { text: string; sub: string } {
  if (!response) return { text: '待审批', sub: '策略判定需人工确认 · 案卷已归档(演示口径)' }
  if (response.blocked) return { text: '已阻断', sub: response.summary }
  return { text: '已处置', sub: response.summary }
}

export function useDemoDirector() {
  useEventStreamLifecycle()

  const [state, setState] = useState<DirectorState>(INITIAL)
  const timelineRef = useRef<Timeline>(new Timeline())
  const modeRef = useRef<SourceMode>('live')
  const sceneIdxRef = useRef(-1)
  const eventIdRef = useRef<number | null>(null)
  const runningRef = useRef(false)
  const finishedRef = useRef(false)
  const pausedRef = useRef(false)
  const lastStepAtRef = useRef(0)
  const seenStepIdsRef = useRef(new Set<string>())
  const stepsRef = useRef<ThoughtStep[]>([])
  const responseRef = useRef<DirectorState['response']>(null)
  const droppedRef = useRef(0)
  const bufferLastIdRef = useRef(0)
  /** 本幕进入时刻（基于导演时间轴）——用于 minSceneMs 最短停留 */
  const sceneEnteredAtRef = useRef(0)
  /** 已触发完成的本幕（防止 reviewer end + audit_complete 双触发） */
  const sceneDoneRef = useRef<Partial<Record<SceneId, boolean>>>({})

  // ── 幕次推进 ──
  const enterScene = useCallback((idx: number) => {
    if (idx >= SCENES.length) return
    sceneIdxRef.current = idx
    sceneEnteredAtRef.current = timelineRef.current.now()
    const def = SCENES[idx]
    setState((s) => ({
      ...s,
      sceneIdx: idx,
      sceneStatus: { ...s.sceneStatus, [def.id]: 'playing' },
    }))
    if (def.id === 'verdict') {
      // 结案：按最短停留决定落印时刻（演练模式允许放慢，留出收尾镜头）
      const hold = modeRef.current === 'rehearsal' ? Math.max(900, def.minSceneMs) : 900
      timelineRef.current.push(timelineRef.current.now() + hold, () => {
        setState((s) => ({ ...s, finished: true, seal: sealFrom(responseRef.current) }))
        finishedRef.current = true
      })
      return
    }
    // 实时/降级模式挂超时阀;演练模式由时间轴驱动,不挂阀
    if (modeRef.current !== 'rehearsal') {
      const at = timelineRef.current.now() + def.timeoutMs
      timelineRef.current.push(at, () => {
        if (!runningRef.current || finishedRef.current) return
        if (sceneIdxRef.current !== idx) return
        // 超时降级:合成信号推进,明示徽章
        setState((s) => ({
          ...s,
          mode: 'degraded',
          sceneSimulated: { ...s.sceneSimulated, [def.id]: true },
        }))
        for (const sig of fallbackSignals(def.id)) applySignal(sig, true)
      })
    }
    // 第五幕进入时若响应信号早已到达(流水线先于旁白完成),稍作展示后进入结案
    if (def.id === 'respond' && responseRef.current) {
      timelineRef.current.push(timelineRef.current.now() + 1400, () => {
        if (sceneIdxRef.current === idx && !finishedRef.current) {
          setState((s) => ({ ...s, sceneStatus: { ...s.sceneStatus, respond: 'done' } }))
          enterScene(idx + 1)
        }
      })
    }
  }, [])

  /**
   * 完成一幕。
   *
   * 演练模式：如果信号到得比 minSceneMs 早，就等到最短停留时间再切幕 ——
   * 否则第 1 幕会在一两秒内闪过去，观众什么都看不清。实时/降级模式行为不变。
   * 同幕的完成信号（reviewer end / audit_complete 等）只生效一次。
   */
  const completeScene = useCallback((sceneId: SceneId, simulated: boolean) => {
    if (sceneDoneRef.current[sceneId]) return
    const idx = SCENES.findIndex((d) => d.id === sceneId)
    if (idx < 0) return
    sceneDoneRef.current[sceneId] = true

    const finish = () => {
      if (sceneIdxRef.current !== idx) return
      setState((s) => ({
        ...s,
        sceneStatus: { ...s.sceneStatus, [sceneId]: 'done' },
        sceneSimulated: simulated ? { ...s.sceneSimulated, [sceneId]: true } : s.sceneSimulated,
      }))
      enterScene(idx + 1)
    }

    const minMs = modeRef.current === 'rehearsal' ? (SCENES[idx].minSceneMs || 0) : 0
    const remain = minMs - (timelineRef.current.now() - sceneEnteredAtRef.current)
    if (remain > 0) {
      timelineRef.current.push(timelineRef.current.now() + remain, finish)
    } else {
      finish()
    }
  }, [enterScene])

  // ── 信号消费(三模共用)──
  const applySignal = useCallback((sig: DemoSignal, simulated: boolean) => {
    switch (sig.kind) {
      case 'security_event':
        setState((s) => ({
          ...s,
          event: {
            type: 'C2_BEACON',
            src: '192.168.1.105',
            dst: '23.129.64.33',
            message: DEMO_EVENT.message,
          },
        }))
        if (sceneIdxRef.current === 0) completeScene('intrusion', simulated)
        break
      case 'detect_signal':
        setState((s) => ({ ...s, detection: { title: sig.title, detail: sig.detail } }))
        if (sceneIdxRef.current === 1) completeScene('detect', simulated)
        break
      case 'stage':
        setState((s) => {
          const cell = s.stages[sig.stage]
          const nextStatus =
            sig.phase === 'start' ? 'running' : (sig.status === 'success' ? 'success' : (sig.status as StageCell['status'] ?? 'success'))
          return {
            ...s,
            stages: { ...s.stages, [sig.stage]: { status: nextStatus, simulated: cell.simulated || simulated } },
          }
        })
        // 接力幕何时算完成：实时模式在复核者结束即可推进（不等响应）；
        // 演练模式等六个岗位全部点亮后再进推理幕，避免第 3 幕只有半条流水线。
        const relayDoneStage = modeRef.current === 'rehearsal' ? 'response' : 'reviewer'
        if (sig.phase === 'end' && sig.stage === relayDoneStage && sceneIdxRef.current === 2) {
          completeScene('relay', simulated)
        }
        break
      case 'thought':
        lastStepAtRef.current = Date.now()
        if (sig.step.stepId && seenStepIdsRef.current.has(sig.step.stepId)) break
        if (sig.step.stepId) seenStepIdsRef.current.add(sig.step.stepId)
        if (stepsRef.current.length >= MAX_STEPS) {
          droppedRef.current += 1
          setState((s) => ({ ...s, stepsDropped: droppedRef.current }))
          break
        }
        stepsRef.current = [...stepsRef.current, sig.step]
        setState((s) => ({ ...s, steps: stepsRef.current }))
        break
      case 'response':
        responseRef.current = { blocked: sig.blocked, summary: sig.summary, simulated }
        setState((s) => ({ ...s, response: responseRef.current }))
        if (sceneIdxRef.current === 4) {
          // 走 completeScene 让「最短停留」生效：高危动作要留时间给观众看清审批语义
          completeScene('respond', simulated)
        }
        break
      case 'audit_complete':
        if (sceneIdxRef.current === 2) completeScene('relay', simulated)
        break
      case 'audit_degraded':
        setState((s) => ({ ...s, degradedNote: sig.note }))
        break
    }
  }, [completeScene])

  const applySignalRef = useRef(applySignal)
  applySignalRef.current = applySignal

  // ── 实时模式:消费共享 SSE 缓冲 ──
  const buffer = useEventStreamStore((s) => s.buffer)
  useEffect(() => {
    if (!runningRef.current || modeRef.current === 'rehearsal') return
    const eid = eventIdRef.current
    if (!eid) return
    const fresh = buffer.filter((e) => e.id > bufferLastIdRef.current)
    if (!fresh.length) return
    bufferLastIdRef.current = fresh[fresh.length - 1].id
    for (const evt of fresh) {
      for (const sig of signalsFromEvent(evt, eid)) {
        applySignalRef.current(sig, false)
      }
    }
  }, [buffer, state.running])

  // ── 节拍:计时 + 推理幕排空判定 ──
  useEffect(() => {
    const t = setInterval(() => {
      if (!runningRef.current || pausedRef.current || finishedRef.current) return
      const elapsed = timelineRef.current.now()
      setState((s) => ({ ...s, elapsedMs: elapsed }))
      // 推理幕:审计流程已推进到本幕、步骤流停歇 1.6s → 进入处置
      // 演练模式额外要求本幕已停留 minSceneMs，让思维链有机会铺满（否则一闪而过）
      const inSceneMs = timelineRef.current.now() - sceneEnteredAtRef.current
      const reasonMinMs = SCENES[3]?.minSceneMs ?? 0
      if (
        sceneIdxRef.current === 3 &&
        stepsRef.current.length > 0 &&
        Date.now() - lastStepAtRef.current > 1600 &&
        elapsed > 4000 &&
        (modeRef.current !== 'rehearsal' || inSceneMs >= reasonMinMs)
      ) {
        setState((s) => ({ ...s, sceneStatus: { ...s.sceneStatus, reason: 'done' } }))
        enterScene(4)
      }
    }, 200)
    return () => clearInterval(t)
  }, [enterScene])

  // ── 对外控制 ──
  const resetState = useCallback(() => {
    timelineRef.current.clear()
    runningRef.current = false
    finishedRef.current = false
    pausedRef.current = false
    sceneIdxRef.current = -1
    eventIdRef.current = null
    modeRef.current = 'live'
    lastStepAtRef.current = 0
    sceneEnteredAtRef.current = 0
    sceneDoneRef.current = {}
    seenStepIdsRef.current = new Set()
    stepsRef.current = []
    responseRef.current = null
    droppedRef.current = 0
    bufferLastIdRef.current = 0
    setState({ ...INITIAL, sceneStatus: initialSceneStatus(), sceneSimulated: initialSceneSimulated(), stages: initialStages() })
  }, [])

  const start = useCallback(async () => {
    resetState()
    runningRef.current = true
    setState((s) => ({ ...s, running: true }))
    timelineRef.current.start()
    enterScene(0)
    try {
      const sid = `demo-script-${crypto.randomUUID().slice(0, 8)}`
      const data = await api.ingestLog(DEMO_EVENT, sid)
      const eid = Number(data?.event_id) || 0
      eventIdRef.current = eid || null
      setState((s) => ({ ...s, eventId: eid || null }))
    } catch (e: any) {
      setState((s) => ({
        ...s,
        error: `事件注入失败:${e?.message || '网络异常'} — 可切换演练模式离线演示`,
        running: false,
      }))
      runningRef.current = false
    }
  }, [enterScene, resetState])

  const startRehearsal = useCallback(() => {
    resetState()
    modeRef.current = 'rehearsal'
    runningRef.current = true
    setState((s) => ({ ...s, running: true, mode: 'rehearsal' }))
    timelineRef.current.start()
    enterScene(0)
    for (const item of REHEARSAL_TIMELINE) {
      timelineRef.current.push(item.atMs, () => applySignalRef.current(item.signal, false))
    }
  }, [enterScene, resetState])

  const togglePause = useCallback(() => {
    if (!runningRef.current || finishedRef.current) return
    pausedRef.current = !pausedRef.current
    if (pausedRef.current) timelineRef.current.pause()
    else timelineRef.current.resume()
    setState((s) => ({ ...s, paused: pausedRef.current }))
  }, [])

  /** 手动跳幕:当前幕标记 skipped(不合成伪成功信号,结案文案按真实到达的信号定) */
  const skipScene = useCallback(() => {
    if (!runningRef.current || finishedRef.current || pausedRef.current) return
    const idx = sceneIdxRef.current
    if (idx < 0 || idx >= SCENES.length - 1) return
    const id = SCENES[idx].id
    if (id === 'verdict') return
    setState((s) => ({ ...s, sceneStatus: { ...s.sceneStatus, [id]: 'skipped' } }))
    enterScene(idx + 1)
  }, [enterScene])

  const reset = useCallback(() => resetState(), [resetState])

  // 卸载清理
  useEffect(() => () => timelineRef.current.clear(), [])

  return { state, start, startRehearsal, togglePause, skipScene, reset }
}
