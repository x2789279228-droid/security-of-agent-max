/**
 * 攻击剧本 — 幕次定义、信号模型、事件映射与演练时间轴(阶段 3)
 *
 * 三模数据源共用同一信号总线:
 * - live:      SSE 事件按 event_id 过滤后映射为信号
 * - degraded:  某幕超时,用合成信号推进(明示徽章)
 * - rehearsal: 按预设时间轴自产全合成信号(无后端,供视频录制)
 * 渲染层只读导演状态,三种来源最终汇聚到同一个状态机。
 */
import type { StreamEvent } from './eventStream'
import { AGENT_RELAY_STAGES, type AgentRelayStage } from './agentPipeline'

export type { AgentRelayStage }

// ── 幕次 ──
export type SceneId = 'intrusion' | 'detect' | 'relay' | 'reason' | 'respond' | 'verdict'

export interface SceneDef {
  id: SceneId
  num: string
  title: string
  caption: string
  /** 舞台页底注：用一句白话解释这一幕在做什么（非安全专业观众也能跟上） */
  keyLine: string
  /** 演练模式下的最短停留毫秒 —— 防止信号来得太快把一幕压成 1 秒（live 模式不生效） */
  minSceneMs: number
  /** 实时模式下等待事件的超时阀;到点用合成信号推进(明示降级) */
  timeoutMs: number
}

export const SCENES: SceneDef[] = [
  {
    id: 'intrusion', num: '第一幕', title: '入侵',
    caption: '内部主机与 C2 基础设施建立周期性外联',
    keyLine: '一条可疑外联出现——系统还欠它一个判断。',
    minSceneMs: 8_000, timeoutMs: 6_000,
  },
  {
    id: 'detect', num: '第二幕', title: '检测',
    caption: 'Sigma 规则与异常检测点亮威胁信号',
    keyLine: '规则先看见它，Agent 再来确认它是不是真的。',
    minSceneMs: 12_000, timeoutMs: 15_000,
  },
  {
    id: 'relay', num: '第三幕', title: '接力',
    caption: '六个 Agent 岗位依次接管，每一步都有产物',
    keyLine: '拆任务 → 配工具 → 取证 → 复核 → 监督，责任分开。',
    minSceneMs: 34_000, timeoutMs: 45_000,
  },
  {
    id: 'reason', num: '第四幕', title: '推理',
    caption: '判断是怎么一步步做出来的',
    keyLine: '不是一句话下结论：每条断言都要挂到证据上。',
    minSceneMs: 36_000, timeoutMs: 40_000,
  },
  {
    id: 'respond', num: '第五幕', title: '处置',
    caption: '响应引擎按策略落地处置动作',
    keyLine: '该拦的拦、该等的等、该回滚的能回滚。',
    minSceneMs: 20_000, timeoutMs: 30_000,
  },
  {
    id: 'verdict', num: '第六幕', title: '结案',
    caption: '案卷归档,一方红印落定',
    keyLine: '处置留痕，下一次遇到同类事件会更快。',
    minSceneMs: 16_000, timeoutMs: 20_000,
  },
]

export type SourceMode = 'live' | 'degraded' | 'rehearsal'

export const MODE_BADGE: Record<SourceMode, { label: string; cls: string }> = {
  live: { label: '实时', cls: 'border border-[#5da583]/50 bg-[#5da583]/10 text-[#7fd4a8]' },
  degraded: { label: '降级', cls: 'border border-[#d4a054]/50 bg-[#d4a054]/10 text-[#e5b96b]' },
  rehearsal: { label: '演练', cls: 'border border-[#c9a574]/50 bg-[#c9a574]/10 text-[#d9bc8b]' },
}

// ── 思维链步骤 ──
export interface ThoughtStep {
  stepId: string
  stage: string
  kind: string
  title: string
  summary: string
  status: string
  confidence?: number | null
}

export const KIND_LABELS: Record<string, string> = {
  signal: '检测信号',
  plan: '审核计划',
  tool_map: '工具映射',
  tool: '工具调用',
  rag: '知识片段',
  claim: '威胁断言',
  discard: '丢弃断言',
  hop: '推理跳数',
  verdict: '汇总结论',
  gate: '确认闸门',
  review: '复核裁决',
  cad: 'CAD 监督',
  response: '响应',
}

/** 剧本策展:只上演这些 kind,其余计数折叠为「+N 步」 */
export const CURATED_KINDS = new Set([
  'signal', 'plan', 'tool_map', 'claim', 'verdict', 'gate', 'cad', 'review', 'response',
])
export const MAX_STEPS = 14

// ── 信号总线 ──
export type DemoSignal =
  | { kind: 'security_event'; eventId: number }
  | { kind: 'detect_signal'; title: string; detail: string }
  | { kind: 'stage'; stage: AgentRelayStage; phase: 'start' | 'end'; status?: string }
  | { kind: 'thought'; step: ThoughtStep }
  | { kind: 'response'; blocked: boolean; summary: string }
  | { kind: 'audit_complete' }
  | { kind: 'audit_degraded'; note: string }

const isRelayStage = (s: string): s is AgentRelayStage =>
  (AGENT_RELAY_STAGES as readonly string[]).includes(s)

/**
 * 实时模式:把 SSE 事件映射为剧本信号(仅处理 data.event_id === demoEventId 的事件,
 * 由调用方过滤)。agent_thought 一次推一批 steps,在此逐个展开。
 */
export function signalsFromEvent(evt: StreamEvent, demoEventId: number): DemoSignal[] {
  if (evt.kind !== 'event') return []
  const d = evt.data ?? {}
  const eid = Number(d.event_id ?? evt.seq ?? 0)
  const out: DemoSignal[] = []

  switch (evt.type) {
    case 'security_event':
      if (demoEventId && evt.seq === demoEventId) out.push({ kind: 'security_event', eventId: demoEventId })
      break
    case 'agent_thought': {
      if (!demoEventId || eid !== demoEventId) break
      const steps = Array.isArray(d.steps) ? d.steps : []
      for (const s of steps) {
        const kind = String(s?.kind || '')
        const stage = String(s?.stage || '')
        if (stage === 'ingest' && kind === 'signal') {
          out.push({ kind: 'detect_signal', title: String(s?.title || '检测信号'), detail: String(s?.summary || '') })
          continue
        }
        if (!CURATED_KINDS.has(kind)) continue
        out.push({
          kind: 'thought',
          step: {
            stepId: String(s?.step_id || ''),
            stage,
            kind,
            title: String(s?.title || KIND_LABELS[kind] || kind),
            summary: String(s?.summary || ''),
            status: String(s?.status || 'success'),
            confidence: typeof s?.confidence === 'number' ? s.confidence : null,
          },
        })
      }
      break
    }
    case 'agent_stage': {
      if (!demoEventId || eid !== demoEventId) break
      const stage = String(d.stage || '')
      if (!isRelayStage(stage)) break
      out.push({ kind: 'stage', stage, phase: d.phase === 'start' ? 'start' : 'end', status: String(d.status || 'success') })
      break
    }
    case 'audit_complete':
      if (!demoEventId || eid === demoEventId) out.push({ kind: 'audit_complete' })
      break
    case 'audit_degraded':
      if (!demoEventId || eid === demoEventId) out.push({ kind: 'audit_degraded', note: String(d.reason || d.note || 'LLM 审计降级,规则收口通道') })
      break
    case 'response_action': {
      if (!demoEventId || eid !== demoEventId) break
      const statusRaw = String(d.status || 'triggered')
      const blocked = statusRaw === 'blocked' || statusRaw === 'abstain' || Boolean(d.blocked)
      out.push({ kind: 'response', blocked, summary: String(d.summary || d.reason || (blocked ? '响应阻断' : `响应 ${d.threat_type || statusRaw}`)) })
      break
    }
  }
  return out
}

/** 各幕超时降级:合成信号(明示「降级」徽章,不伪装实时) */
export function fallbackSignals(scene: SceneId): DemoSignal[] {
  switch (scene) {
    case 'intrusion':
      return [{ kind: 'security_event', eventId: 0 }]
    case 'detect':
      return [{
        kind: 'detect_signal',
        title: 'Sigma 命中 · C2 信标',
        detail: '周期性外联间隔规律,匹配 C2 信标特征(演示降级口径)',
      }]
    case 'relay':
      return [
        { kind: 'stage', stage: 'decomposer', phase: 'end', status: 'success' },
        { kind: 'stage', stage: 'tool_builder', phase: 'end', status: 'success' },
        { kind: 'stage', stage: 'executor', phase: 'end', status: 'success' },
        { kind: 'stage', stage: 'reviewer', phase: 'end', status: 'success' },
        { kind: 'audit_complete' },
      ]
    case 'reason':
      return [
        {
          kind: 'thought',
          step: {
            stepId: `demo-verdict-${Date.now()}`,
            stage: 'executor',
            kind: 'verdict',
            title: '威胁 · 置信 0.90',
            summary: '外联行为匹配 C2 信标特征,建议阻断(演示降级口径)',
            status: 'success',
            confidence: 0.9,
          },
        },
        { kind: 'audit_complete' },
      ]
    case 'respond':
      return [{
        kind: 'response',
        blocked: false,
        summary: '策略判定需审批 · 已生成处置工单转人工确认(演示降级口径)',
      }]
    case 'verdict':
      return []
  }
}

/**
 * 演练时间轴：纯前端合成，节奏可控，供录屏与无后端环境使用。
 *
 * 设计原则（2026-11 打磨）：
 * - 总时长 ~142s，每幕至少 8–36s（此前整条只有 9.4s，导致每一幕一闪而过、面板没内容）；
 * - 第三幕把六个岗位依次点亮，直到 response 阶段结束才进入推理幕；
 * - 第四幕 9 条思维链分 ~26s 释放，让打字机有内容可铺；
 * - 最后结案幕由导演按 minSceneMs 落印。改这里即可整体加速/放慢，无需动状态机。
 */
export const REHEARSAL_TIMELINE: { atMs: number; signal: DemoSignal }[] = [
  // 第一幕·入侵（0–8s）
  { atMs: 1_500, signal: { kind: 'security_event', eventId: -1 } },

  // 第二幕·检测（8–20s）
  { atMs: 9_500, signal: { kind: 'detect_signal', title: 'Sigma 命中 · C2 信标外联', detail: '周期 ≈ 60s 外联 23.129.64.33，匹配信标规则（演练口径）' } },

  // 第三幕·接力（20–70s）：六个岗位依次接管
  { atMs: 22_000, signal: { kind: 'stage', stage: 'decomposer', phase: 'start' } },
  { atMs: 26_000, signal: { kind: 'thought', step: { stepId: 'rh-1', stage: 'decomposer', kind: 'plan', title: '审核深度 standard · 3 子任务', summary: '规则+情报双路判定：走标准深度审查，拆分情报比对 / 资产核实 / 知识检索', status: 'success' } } },
  { atMs: 29_000, signal: { kind: 'stage', stage: 'decomposer', phase: 'end' } },
  { atMs: 31_000, signal: { kind: 'stage', stage: 'tool_builder', phase: 'start' } },
  { atMs: 35_000, signal: { kind: 'thought', step: { stepId: 'rh-2', stage: 'tool_builder', kind: 'tool_map', title: '3 个工具', summary: 'threat.lookup → asset.query → knowledge.search，全部映射完成', status: 'success' } } },
  { atMs: 38_000, signal: { kind: 'stage', stage: 'tool_builder', phase: 'end' } },
  { atMs: 40_000, signal: { kind: 'stage', stage: 'executor', phase: 'start' } },
  { atMs: 45_000, signal: { kind: 'thought', step: { stepId: 'rh-3', stage: 'executor', kind: 'claim', title: 'C2 通信 · 置信 0.91', summary: '外联间隔规律，目的 IP 命中威胁情报 IOC，证据链 3 条引用完整', status: 'success', confidence: 0.91 } } },
  { atMs: 50_000, signal: { kind: 'stage', stage: 'executor', phase: 'end' } },
  { atMs: 52_000, signal: { kind: 'stage', stage: 'reviewer', phase: 'start' } },
  { atMs: 56_000, signal: { kind: 'thought', step: { stepId: 'rh-4', stage: 'reviewer', kind: 'review', title: '复核通过 · 证据链完整', summary: '独立复核未发现矛盾断言，确认威胁成立', status: 'success' } } },
  { atMs: 59_000, signal: { kind: 'stage', stage: 'reviewer', phase: 'end' } },
  { atMs: 60_000, signal: { kind: 'stage', stage: 'cad_verify', phase: 'start' } },
  { atMs: 63_000, signal: { kind: 'thought', step: { stepId: 'rh-5', stage: 'cad_verify', kind: 'cad', title: '穿透验证 2/2', summary: '独立核验 2 条关键断言全部成立，熔断器未触发', status: 'success' } } },
  { atMs: 66_000, signal: { kind: 'stage', stage: 'cad_verify', phase: 'end' } },
  { atMs: 67_000, signal: { kind: 'stage', stage: 'response', phase: 'start' } },
  { atMs: 70_000, signal: { kind: 'stage', stage: 'response', phase: 'end' } },
  { atMs: 70_000, signal: { kind: 'audit_complete' } },

  // 第四幕·推理（70–106s）：9 条思维链，逐条铺满
  { atMs: 74_000, signal: { kind: 'thought', step: { stepId: 'rh-6', stage: 'executor', kind: 'claim', title: '证据 3 条 · 引用可追溯', summary: '威胁情报 IOC 命中；资产归属财务部；MITRE T1071 匹配，三条断言均可回查', status: 'success', confidence: 0.91 } } },
  { atMs: 82_000, signal: { kind: 'thought', step: { stepId: 'rh-7', stage: 'reviewer', kind: 'review', title: '三源交叉 · 无矛盾', summary: '情报 / 资产 / 知识三路证据一致，未发现相互矛盾的断言', status: 'success' } } },
  { atMs: 90_000, signal: { kind: 'thought', step: { stepId: 'rh-8', stage: 'cad_verify', kind: 'cad', title: '监督通过 · 熔断未触发', summary: 'CAD 独立反查 PG/Qdrant，未采信 Agent 自述；幻觉风险低于阈值', status: 'success' } } },
  { atMs: 98_000, signal: { kind: 'thought', step: { stepId: 'rh-9', stage: 'executor', kind: 'verdict', title: '确认 C2 外联 · 建议阻断', summary: '综合置信 0.91，建议阻断出站并生成处置工单（演练口径）', status: 'success', confidence: 0.91 } } },

  // 第五幕·处置（106–126s）
  { atMs: 114_000, signal: { kind: 'response', blocked: true, summary: '阻断 192.168.1.105 → 23.129.64.33 · 高危动作已过审批闸门（演练口径）' } },
]
