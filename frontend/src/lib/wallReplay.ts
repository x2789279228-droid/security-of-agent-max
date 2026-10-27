/**
 * 大屏回放剧本(幕布续命) — 后端失联超过宽限期后,BattleScreen 用它保持呼吸。
 *
 * 口径哲学与剧本页一致:明示,不伪装 ——
 * - 事件走 injectWallReplay 进入真实 ingest 管线,整面墙同呼吸;
 * - event_id 使用 9_000_000+ 保留段,与真实 SecurityEvent 一眼可分;
 * - 顶栏徽章切换为「回放口径」,底栏跑马灯注明。
 * 每次运行从三个场景里随机取一个,完整走完六站接力后换下一个。
 */
import { injectWallReplay } from './eventStream'

/** SSE 断流持续多久后切入回放(须短于投影冷场的容忍,长于重连抖动) */
export const WALL_REPLAY_OFFLINE_GRACE_MS = 6_000

const WALL_EVENT_ID_BASE = 9_000_000

interface Scenario {
  event: string
  severity: 'critical' | 'high'
  src: string
  dst: string
  message: string
  claim: { title: string; summary: string; conf: number }
  response: { action: string; target: string; blocked: boolean; summary: string }
}

const SCENARIOS: Scenario[] = [
  {
    event: 'C2_BEACON',
    severity: 'critical',
    src: '192.168.1.105',
    dst: '23.129.64.33',
    message: '内部主机与 C2 基础设施建立周期性外联',
    claim: { title: 'C2 通信 · 置信 0.91', summary: '外联间隔规律,目的 IP 命中威胁情报 IOC,证据链引用完整', conf: 0.91 },
    response: { action: 'firewall.block', target: '192.168.1.105 → 23.129.64.33', blocked: true, summary: '防火墙阻断规则已下发,主机转入隔离观察' },
  },
  {
    event: 'SSH_BRUTE_FORCE',
    severity: 'high',
    src: '203.0.113.77',
    dst: '192.168.2.10',
    message: '外部地址对边界 SSH 服务发起高频口令尝试',
    claim: { title: '暴力破解 · 置信 0.87', summary: '60s 内 47 次认证失败,源地址命中灰名单,行为符合口令喷洒特征', conf: 0.87 },
    response: { action: 'acl.deny', target: '203.0.113.77', blocked: true, summary: '边界 ACL 已封禁源地址,认证失败速率回落' },
  },
  {
    event: 'DATA_EXFIL',
    severity: 'high',
    src: '192.168.3.21',
    dst: '198.51.100.9',
    message: '办公终端向外部网盘发起大流量上行传输',
    claim: { title: '数据外发 · 置信 0.82', summary: '非工作时段 1.2GB 上行,目的域新注册,匹配外发行为基线偏离', conf: 0.82 },
    response: { action: 'ticket.open', target: '192.168.3.21 持有人', blocked: false, summary: '策略判定需人工确认,处置工单已建立并通知资产负责人' },
  },
]

export interface ReplayItem {
  type: string
  data: Record<string, any>
  /** 距上一条注入的间隔 ms */
  gapMs: number
}

let wallEventSeq = WALL_EVENT_ID_BASE

const rand = (min: number, max: number) => min + Math.round(Math.random() * (max - min))

/** 组一个场景的完整六站接力(注入顺序即播放顺序) */
function buildRun(s: Scenario): ReplayItem[] {
  const eid = ++wallEventSeq
  const sid = `wall-${eid}`
  const tid = eid.toString(36)
  let stepNo = 0
  let prevStep = ''

  const items: ReplayItem[] = []

  const thought = (stage: string, kind: string, title: string, summary: string, conf?: number) => {
    const stepId = `w-${eid}-${++stepNo}`
    items.push({
      type: 'agent_thought',
      data: {
        event_id: eid, step_id: stepId, stage, kind, title, summary, status: 'success',
        parent_ids: prevStep ? [prevStep] : [],
        ...(conf != null ? { confidence: conf } : {}),
      },
      gapMs: rand(1100, 1900),
    })
    prevStep = stepId
  }
  const stage = (name: string, phase: 'start' | 'end', status = 'success') => {
    items.push({
      type: 'agent_stage',
      data: { event_id: eid, stage: name, phase, status, session_id: sid, trace_id: tid },
      gapMs: phase === 'end' ? rand(700, 1200) : rand(400, 700),
    })
  }

  // 事件接入
  items.push({
    type: 'security_event',
    data: { event_id: eid, event: s.event, severity: s.severity, src_ip: s.src, dst_ip: s.dst, message: s.message, confidence: 85 },
    gapMs: 0,
  })

  stage('decomposer', 'start')
  thought('decomposer', 'plan', '审核深度 standard · 3 子任务', '规则+情报双路判定:拆分情报比对/资产核实/知识检索')
  stage('decomposer', 'end')

  stage('tool_builder', 'start')
  thought('tool_builder', 'tool_map', '3 个工具', 'threat.lookup → asset.query → knowledge.search,全部映射完成')
  stage('tool_builder', 'end')

  stage('executor', 'start')
  thought('executor', 'claim', s.claim.title, s.claim.summary, s.claim.conf)
  stage('executor', 'end')

  stage('reviewer', 'start')
  thought('reviewer', 'review', '复核通过 · 证据链完整', '独立复核未发现矛盾断言,确认判定成立')
  stage('reviewer', 'end')

  stage('cad_verify', 'start')
  thought('cad_verify', 'cad', '穿透验证 2/2', '独立核验关键断言全部成立,熔断器未触发')
  stage('cad_verify', 'end')

  items.push({
    type: 'response_action',
    data: {
      event_id: eid, action: s.response.action, target: s.response.target,
      blocked: s.response.blocked, summary: s.response.summary, status: 'success',
    },
    gapMs: rand(900, 1400),
  })
  stage('response', 'start', 'success')
  stage('response', 'end')

  items.push({ type: 'audit_complete', data: { event_id: eid, session_id: sid }, gapMs: rand(1200, 2000) })
  return items
}

/**
 * 启动回放循环,返回停止函数。每条注入之间按 gapMs 停顿;
 * 一个场景播完随机换下一个,调用方只管启停。
 */
export function startWallReplay(): () => void {
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined
  let run: ReplayItem[] = []
  let idx = 0

  const step = () => {
    if (stopped) return
    if (idx >= run.length) {
      run = buildRun(SCENARIOS[Math.floor(Math.random() * SCENARIOS.length)])
      idx = 0
    }
    const item = run[idx++]
    injectWallReplay(item.type, item.data)
    timer = setTimeout(step, item.gapMs)
  }
  step()

  return () => {
    stopped = true
    if (timer) clearTimeout(timer)
  }
}
