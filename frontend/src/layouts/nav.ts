import { ROUTES } from '../lib/constants'

/**
 * 四篇章两级导航：
 * - 一级 = 篇章页签（值班/处置/对抗/感知），点击展开组内页面
 * - 二级 = 当前篇章内的页面页签（由 TopNav 依据当前路由渲染）
 *
 * v9：增加 tier —— core 默认展示，advanced 仅在「专家模式」展开。
 * 目的：默认导航只保留值班主线（7 项），高级能力（自博弈/知识库/评测/反钓鱼/全景）
 * 不消失、可一键展开，既降低首屏认知负担，也不牺牲功能完整性。
 */

export type NavTier = 'core' | 'advanced'

export interface NavItem {
  path: string
  label: string
  short: string
  hint?: string
  /** core = 默认显示；advanced = 专家模式显示（默认仍保留在命令面板里） */
  tier?: NavTier
}

export interface NavGroup {
  title: string
  items: NavItem[]
}

export const NAV_GROUPS: NavGroup[] = [
  {
    title: '值班',
    items: [
      { path: ROUTES.HOME, label: '首页', short: '首页', hint: '品牌首页与实时控制台', tier: 'core' },
      { path: ROUTES.INGEST, label: '接入台', short: '接入', hint: '攻击剧本一键注入 · 手动录日志 · 管道状态', tier: 'core' },
      { path: ROUTES.LOGS, label: '日志中心', short: '日志', hint: '实时日志接入与告警分流', tier: 'core' },
      { path: ROUTES.MONITOR, label: '监控', short: '监控', hint: '实时作战监控 · 多 Agent 接力 · 思维链', tier: 'core' },
      { path: ROUTES.COPILOT, label: 'AI Copilot', short: 'Copilot', hint: '对话式安全分析 · 流式 · 知识引用 · 截图研判', tier: 'core' },
      { path: ROUTES.POSTER, label: '系统全景', short: '全景', hint: '一屏读懂系统 · 会呼吸的架构海报', tier: 'advanced' },
    ],
  },
  {
    title: '处置',
    items: [
      { path: ROUTES.SECURITY_AUDIT, label: '安全审计', short: '审计', hint: '四层 Audit-LLM 流水线 · CAD 监督', tier: 'core' },
      { path: ROUTES.RESPONSE, label: '响应引擎', short: '响应', hint: '策略 · 审批 · 执行与回滚', tier: 'core' },
      { path: ROUTES.OPERATIONS, label: '运营中心', short: '运营', hint: '案例工单复盘 · 学习闭环 · 链路追踪', tier: 'core' },
    ],
  },
  {
    title: '对抗',
    items: [
      { path: ROUTES.SELF_PLAY, label: '红蓝自博弈', short: '自博弈', hint: '红蓝对局与蓝方学习闭环', tier: 'advanced' },
      { path: ROUTES.RAG, label: '知识库', short: '知识', hint: 'RAG 检索 · Grounding 验证 · 评测', tier: 'advanced' },
      { path: ROUTES.BENCHMARK, label: '评测战绩', short: '评测', hint: 'CSIC-2010 回放 · 对抗保持率 · 分层消融', tier: 'advanced' },
    ],
  },
  {
    title: '感知',
    items: [
      { path: ROUTES.SENSING, label: '感知中心', short: '感知', hint: '流量 · 加密 · 情报 · 沙箱 · 终端 · 能力总览', tier: 'core' },
      { path: ROUTES.ANTI_PHISHING, label: '反钓鱼', short: '钓鱼', hint: '六通道检测 · BEC 识别 · 演练闭环', tier: 'advanced' },
    ],
  },
]

export const PATH_LABEL: Record<string, string> = Object.fromEntries(
  NAV_GROUPS.flatMap((g) => g.items.map((i) => [i.path, i.label])),
)

/** 当前路由所属篇章（未命中返回 null，如 /demo、/benchmark 未登记时） */
export function groupOf(pathname: string) {
  return NAV_GROUPS.find((g) => g.items.some((i) => i.path === pathname)) ?? null
}

export function isAdvancedNavItem(item: NavItem): boolean {
  return item.tier === 'advanced'
}
