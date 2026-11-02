export const BRAND = {
  name: '守望',
  nameEn: 'SHOUWANG',
  lockup: 'SHOUWANG · Night Watch SOC',
  product: '自主安全运营',
  tagline: '灯火未熄。每一条日志，都在被守望。',
  manifesto: '第一秒看见威胁，下一秒它已被拦住。',
  footer: '守望 · Night Watch SOC',
} as const

/** 案卷深室（Vault Ledger）：深室底、黛墨字、暮青动作、松绿健康、朱砂只留给威胁、暮金唯一点缀。 */
export const BRAND_COLORS = {
  // 图表专用（Sparkline/RateHistogram 内联 SVG）：暗肤校准的语义色，亮肤下同样可读
  vault: '#1D242D',
  night: '#0F1216',
  card: '#161B21',
  paper: '#161B21',
  surface: '#0F1216',
  ink: '#E9EDF2',
  accent: '#4FB3CF',
  ok: '#3ECF8E',
  alert: '#F0554A',
  warn: '#E8A33D',
  signal: '#57A9DE',
  dusk: '#D9B36A',
  onAccent: '#071318',
} as const

/** 暮青 → 灰青 → 松绿（dusk → pine）。无金。 */
export const AI_GRADIENT =
  'linear-gradient(120deg, #3A6570 0%, #4A7A88 45%, #3E7A64 100%)'
export const AI_GRADIENT_STOPS = ['#3A6570', '#4A7A88', '#3E7A64', '#C08A3A']
