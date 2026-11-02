import {
  ALERT, WARN, OK, ACCENT, SIGNAL, INK_FAINT, TRACK,
} from './semanticColors'

/** 语义色的 12% 透明底（随肤翻转） */
export function mixBg(v: string) {
  return `color-mix(in srgb, ${v} 12%, transparent)`
}

/**
 * 运营中心语义 token — 严重度/状态/动作/关键性 → 全站语义四色。
 * 全部值为 CSS 变量引用（var(--color-*)），亮/暗肤自动翻转；
 * 需要"底色"时用 color-mix(in srgb, var 12%, transparent)，同样随肤翻转。
 *
 * 用法：import { SEVERITY_TONE } from '@/lib/operationsTokens'
 *      <span style={{ color: SEVERITY_TONE.critical }} />
 */

/* ── 严重度 5 档 ── */
export const SEVERITY_TONE = {
  critical: ALERT, // 朱砂
  high: WARN,      // 柿黄
  medium: SIGNAL,  // 灰青
  low: INK_FAINT,
  info: INK_FAINT,
} as const

/* ── 状态语义 5 档 ── */
export const STATUS_TONE = {
  success: OK,       // 松绿
  pending: WARN,     // 柿黄
  failed: ALERT,     // 朱砂
  info: ACCENT,      // 暮青
  neutral: INK_FAINT,
  active: SIGNAL,    // 灰青
} as const

/* ── chip 形态三元组 ── */
export function chipTone(hex: string, bgA = '1f', ringA = '4d') {
  return { fg: hex, bg: `${hex}${bgA}`, ring: `${hex}${ringA}` }
}

/* ── 案例状态 7 档 ── */
export const CASE_STATUS_TONE: Record<string, { label: string; color: string }> = {
  open: { label: '待处理', color: ALERT },
  investigating: { label: '调查中', color: SIGNAL },
  pending_approval: { label: '待审批', color: WARN },
  responding: { label: '处置中', color: ACCENT },
  resolved: { label: '已解决', color: ACCENT },
  closed: { label: '已关闭', color: INK_FAINT },
  false_positive: { label: '误报', color: INK_FAINT },
}

/* ── 审计 trail 14 种 action 配色 ── */
export const ACTION_TONE: Record<string, string> = {
  'case.transition': ACCENT,
  'case.assign': SIGNAL,
  'case.disposition': SIGNAL,
  'order.approve': OK,
  'order.reject': ALERT,
  'rule.publish': SIGNAL,
  'rule.rollback': WARN,
  'asset.create': ACCENT,
  'asset.update': SIGNAL,
  'asset.decommission': INK_FAINT,
  'source.register': ACCENT,
  'source.revoke': ALERT,
}

/* ── 学习闭环状态 5 档 ── */
export const LEARN_STATUS_TONE: Record<string, { label: string; color: string }> = {
  proposed: { label: '待复核', color: WARN },
  auto_applied: { label: '自动应用', color: OK },
  applied: { label: '已应用', color: ACCENT },
  dismissed: { label: '已驳回', color: INK_FAINT },
  rolled_back: { label: '已回滚', color: SIGNAL },
}

/* ── 资产关键性 4 档（含背景色 + 中文标签）── */
export const CRITICALITY_TONE: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: ALERT, bg: mixBg(ALERT), label: '核心' },
  high: { color: WARN, bg: mixBg(WARN), label: '重要' },
  medium: { color: SIGNAL, bg: mixBg(SIGNAL), label: '一般' },
  low: { color: INK_FAINT, bg: mixBg(INK_FAINT), label: '低' },
}

/* ── KPI 卡片 6 张 ── */
export const KPI_TONE = {
  mttr: WARN,            // MTTR 偏高则警示 → 柿黄
  mttd: ACCENT,          // MTTD 中性的检测时间 → 暮青
  case_count: SIGNAL,    // 案例数 → 灰青（信息）
  fp_rate: SIGNAL,       // 误报率 → 灰青（注意力）
  sla_breach_rate: ALERT, // SLA 违约率 → 朱砂（警告）
  order_count: OK,       // 工单数 → 松绿（正常）
} as const

/* ── CostTab 6 张卡片（含动态 danger 切换）── */
export const COST_TONE = {
  todayUsage: ACCENT,    // 今日用量 → 暮青
  dailyBudget: SIGNAL,   // 日预算 → 灰青
  remaining: OK,         // 剩余预算 → 松绿
  windowUsage: WARN,     // 窗口用量 → 柿黄
  estimatedCost: SIGNAL, // 估算费用 → 灰青
  cacheHit: ACCENT,      // 缓存命中 → 暮青
} as const

/* ── FeedbackTab 4 类计数 ── */
export const FEEDBACK_COUNT_TONE = {
  false_positive: ALERT,
  true_positive: OK,
  missed_threat: WARN,
  rule_suggestion: ACCENT,
} as const

/* ── OverviewTab 5 个指标卡 ── */
export const OVERVIEW_METRIC_TONE = {
  openCases: SIGNAL,     // 待处理案例 — 灰青（信息）
  slaBreached: ALERT,    // SLA 超时 — 朱砂
  fpRate: SIGNAL,        // 误报率 — 灰青（注意力）
  activeOrders: WARN,    // 活跃工单 — 柿黄（待处理）
  pendingApprovals: ACCENT, // 待审批 — 暮青（信息）
} as const

/* ── 时间线节点色（CaseDrawer / OverviewTab）── */
export const TIMELINE_NODE = {
  response: SIGNAL, // 响应 → 灰青
  other: ACCENT,    // 其他 → 暮青
} as const

/* ── 图表渐变（暮青 → 灰青 → 松绿，无金）── */
export const CHART_GRADIENT =
  'linear-gradient(120deg, var(--color-accent) 0%, var(--color-signal) 42%, var(--color-ok) 100%)'

export const CHART_GRADIENT_DIVERGING =
  'linear-gradient(90deg, var(--color-ok) 0%, var(--color-warn) 50%, var(--color-alert) 100%)'

/** KpiTab/CostTab 单色折线（≥0 用品牌渐变，=0 用空底色） */
export const BAR_FILL_EMPTY = TRACK

/* ── 通用 token（语义 + 数值）── */
export { INK_FAINT, TRACK }

/** OverviewTab 实时活动流的竖向渐变线 */
export const ACTIVITY_LINE_GRADIENT = CHART_GRADIENT

/** 反馈类型计数（误报/确认/漏报/建议） — 同 FEEDBACK_COUNT_TONE，保留别名方便阅读 */
export const FEEDBACK_TONE = FEEDBACK_COUNT_TONE
