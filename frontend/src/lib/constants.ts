export const spring = {
  ui: { type: 'spring' as const, stiffness: 300, damping: 20 },
  gentle: { type: 'spring' as const, stiffness: 200, damping: 22 },
  stiff: { type: 'spring' as const, stiffness: 400, damping: 30 },
  bouncy: { type: 'spring' as const, stiffness: 350, damping: 12 },
  tilt: { type: 'spring' as const, stiffness: 150, damping: 12, mass: 0.5 },
  page: { type: 'spring' as const, stiffness: 200, damping: 25 },
  stagger: { staggerChildren: 0.04 },
}

export const ROUTES = {
  HOME: '/',
  LOGS: '/logs',
  MONITOR: '/monitor',
  SECURITY_AUDIT: '/security-audit',
  RESPONSE: '/response',
  RAG: '/rag',
  OPERATIONS: '/operations',
  SELF_PLAY: '/self-play',
  // 感知中心(阶段 5 合并页,旧 NDR 路由重定向至此)
  SENSING: '/sensing',
  ANTI_PHISHING: '/phishing',
  // 评测战绩(阶段 2)
  BENCHMARK: '/benchmark',
  // 攻击剧本沉浸演示（阶段 3）
  DEMO: '/demo',
  // 作战大屏 kiosk 直达（路演机免登录,/screen?token=&event=）
  SCREEN: '/screen',
  // 系统全景海报（一屏读懂 · 会呼吸的架构图）
  POSTER: '/poster',
  // AI 分析 Copilot（2026-11 AI Web 改造：对话式安全分析）
  COPILOT: '/copilot',
  // 接入台（2026-11 AI Web 改造：日志注入窗口 · 攻击剧本库）
  INGEST: '/ingest',
} as const

/** 守望签名 — 暮青 → 灰青 → 松绿 → 柿黄 */
export { AI_GRADIENT, AI_GRADIENT_STOPS, BRAND, BRAND_COLORS } from './brand'
