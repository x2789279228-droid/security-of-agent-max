import { useEffect, useMemo, useRef, useState } from 'react'
import type { SecurityLog, Severity } from '../../types'

/* ============================================================
   攻击态势星图 · 恒定夜空舷窗
   —— 替换旧「严重度堆叠塔」：来源/目标各成一颗小行星，
      攻击 = 级别色彗星由外环（来源）飞向内环（目标），
      命中 = 冲击环，审计完成 = 连线沉淀为霜色星座线。
   语义映射（参考 008-constellation-field 的星点/连线/流星语言）：
   - 空闲   双环反向极慢公转 + 星点闪烁
   - 到达   彗星沿弧线突袭（critical 最快最亮）
   - 命中   目标泛冲击环 + 受击闪白；critical 追加二次环与星云泛红
   - 审计   虚线流动 → 沉淀实线 + 中点归档星
   恒定色板（不随亮暗肤翻转，对应 index.css 的 --color-star-*）：
   #0c2950 普鲁士蓝 / #2f5485 钴蓝 / #657c9d 苍蓝 / #8ca0bc 霜色
   ============================================================ */

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const SEV_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '提示',
}
/* 夜空上的级别色：比 token 亮一档（恒定暗底，无需双肤） */
const SEV_SKY: Record<Severity, string> = {
  critical: '#ff6b5e',
  high: '#e8b45a',
  medium: '#7fb3d8',
  low: '#9fb0c8',
  info: '#6f8199',
}
const STAR_PALE = '#657c9d'
const STAR_FROST = '#8ca0bc'
const CORE_SRC = '#c9855a' /* 来源：陶土芯 —— 呼应下方案卷的陶土棕 */
const CORE_DST = '#bcd0ea' /* 目标：霜蓝芯 —— 夜空资产带 */

const MAX_SRC = 12 /* 外环：来源小行星上限 */
const MAX_DST = 10 /* 内环：目标小行星上限 */
const MAX_EDGES = 120 /* 同时绘制的连线 */
const MAX_COMETS = 24 /* 在途彗星上限（超出丢弃最旧） */
const ORBIT_SQUASH = 0.92 /* 轨道纵向微压，制造轻微透视 */

interface SkyNode {
  ip: string
  role: 'src' | 'dst'
  count: number
  lastSeverity: Severity
  lastTs: number
  visible: boolean
  angle: number
  speed: number /* rad/s，含方向：外环顺、内环逆 */
  size: number
  spin: number
  spinSpeed: number
  verts: number[] /* 不规则轮廓的半径系数 */
  flash: number /* 受击闪光 0..1，循环内衰减 */
}

interface SkyEdge {
  src: string
  dst: string
  count: number
  pending: number
  topSeverity: Severity
  lastTs: number
}

/* 连线动画状态：与派生边解耦存放，logs 重建时不丢沉淀进度 */
interface EdgeFx {
  settleAt: number /* 沉淀动画起点 ms；0=无 */
  starAlpha: number /* 归档星常驻透明度 0..1 */
}

interface Comet {
  srcIp: string
  dstIp: string
  severity: Severity
  born: number
  dur: number
  trail: { x: number; y: number }[]
  tempSrc: boolean /* 来源不在展示环上：用影子点起跳 */
  tempDst: boolean
}

interface Pulse {
  x: number
  y: number
  born: number
  dur: number
  max: number
  severity: Severity
}

interface Shooter {
  x: number
  y: number
  vx: number
  vy: number
  life: number
}

interface StarField {
  x: number
  y: number
  r: number
  phase: number
  tw: number
  warm: boolean
}

/* W2-3(复审 P1-4): mulberry32 — 由节点 key 确定性生成外观参数。
   修复前 render 期 Math.random() 依赖"已登记则跳过"掩盖 StrictMode
   双渲染不一致, Concurrent 特性下是脆弱模式。 */
function hashSeed(s: string): number {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}

function mulberry32(seed: number): () => number {
  let a = seed
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function hashAngle(s: string): number {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return ((h >>> 0) % 3600) / 3600 * Math.PI * 2
}

function makeVerts(rng: () => number): number[] {
  const n = 8 + Math.floor(rng() * 3)
  return Array.from({ length: n }, () => 0.72 + rng() * 0.42)
}

const TRUNC_LEN = 20
function truncIp(ip: string): string {
  return ip.length > TRUNC_LEN ? ip.slice(0, TRUNC_LEN - 1) + '…' : ip
}

export interface AttackConstellationProps {
  logs: SecurityLog[]
  recentIds: Record<number, number>
  stampedIds: Record<number, number>
  active: Severity | ''
  connected: boolean
  onSelectIp?: (ip: string) => void
  onSelectSeverity?: (s: Severity) => void
}

export default function AttackConstellation({
  logs,
  recentIds,
  stampedIds,
  active,
  connected,
  onSelectIp,
  onSelectSeverity,
}: AttackConstellationProps) {
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const tipRef = useRef<HTMLDivElement | null>(null)
  const hudNodeRef = useRef<HTMLSpanElement | null>(null)
  const hudEdgeRef = useRef<HTMLSpanElement | null>(null)
  const hudFlyRef = useRef<HTMLSpanElement | null>(null)

  /* —— 派生数据（每次 logs 变化重算，同步进 ref 供 rAF 读取） —— */
  const derived = useMemo(() => {
    const srcAgg = new Map<string, { count: number; sev: Severity; ts: number }>()
    const dstAgg = new Map<string, { count: number; sev: Severity; ts: number }>()
    const edgeMap = new Map<string, SkyEdge>()
    const sevRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    for (const l of logs) {
      if (!l.src_ip && !l.dst_ip) continue
      const ts = Date.parse(l.created_at) || 0
      if (l.src_ip) {
        const a = srcAgg.get(l.src_ip) || { count: 0, sev: 'info' as Severity, ts: 0 }
        a.count++
        if (sevRank[l.severity] < sevRank[a.sev]) a.sev = l.severity
        if (ts > a.ts) a.ts = ts
        srcAgg.set(l.src_ip, a)
      }
      if (l.dst_ip) {
        const a = dstAgg.get(l.dst_ip) || { count: 0, sev: 'info' as Severity, ts: 0 }
        a.count++
        if (sevRank[l.severity] < sevRank[a.sev]) a.sev = l.severity
        if (ts > a.ts) a.ts = ts
        dstAgg.set(l.dst_ip, a)
      }
      if (l.src_ip && l.dst_ip) {
        const key = `${l.src_ip}|${l.dst_ip}`
        const e = edgeMap.get(key) || {
          src: l.src_ip,
          dst: l.dst_ip,
          count: 0,
          pending: 0,
          topSeverity: 'info' as Severity,
          lastTs: 0,
        }
        e.count++
        if (!l.analyzed) e.pending++
        if (sevRank[l.severity] < sevRank[e.topSeverity]) e.topSeverity = l.severity
        if (ts > e.lastTs) e.lastTs = ts
        edgeMap.set(key, e)
      }
    }
    const byCount = (m: Map<string, { count: number; ts: number }>) =>
      [...m.entries()].sort((a, b) => b[1].count - a[1].count || b[1].ts - a[1].ts)
    const topSrc = new Set(byCount(srcAgg).slice(0, MAX_SRC).map(([ip]) => ip))
    const topDst = new Set(byCount(dstAgg).slice(0, MAX_DST).map(([ip]) => ip))
    const edges = [...edgeMap.values()]
      .sort((a, b) => b.lastTs - a.lastTs)
      .slice(0, MAX_EDGES)
    const extraSrc = Math.max(0, srcAgg.size - MAX_SRC)
    const extraDst = Math.max(0, dstAgg.size - MAX_DST)
    return { srcAgg, dstAgg, topSrc, topDst, edges, extraSrc, extraDst }
  }, [logs])

  const derivedRef = useRef(derived)
  derivedRef.current = derived

  /* —— 小行星登记表：跨渲染持久，公转相位不被数据刷新打断 —— */
  const nodeRegRef = useRef<Map<string, SkyNode>>(new Map())
  const ringSlotsRef = useRef<{ src: number; dst: number }>({ src: 0, dst: 0 })

  if (typeof window !== 'undefined') {
    /* 渲染期同步登记表（纯数据更新，无副作用）：
       新 IP 入环拿黄金角空位；跌出 top-N 的标记隐藏但保留相位。 */
    const reg = nodeRegRef.current
    const slots = ringSlotsRef.current
    const { srcAgg, dstAgg, topSrc, topDst } = derived
    for (const [ip, agg] of srcAgg) {
      const key = `src|${ip}`
      let n = reg.get(key)
      if (!n && topSrc.has(ip)) {
        const rng = mulberry32(hashSeed(key))
        n = {
          ip,
          role: 'src',
          count: 0,
          lastSeverity: agg.sev,
          lastTs: agg.ts,
          visible: true,
          angle: hashAngle(ip) + (slots.src++ % 8) * (Math.PI * 2 / 8) * 0.38,
          speed: 0.021 + rng() * 0.012,
          size: 5,
          spin: rng() * Math.PI * 2,
          spinSpeed: (rng() < 0.5 ? -1 : 1) * (0.1 + rng() * 0.2),
          verts: makeVerts(rng),
          flash: 0,
        }
        reg.set(key, n)
      }
      if (n) {
        n.count = agg.count
        n.lastSeverity = agg.sev
        n.lastTs = agg.ts
        n.visible = topSrc.has(ip)
      }
    }
    for (const [ip, agg] of dstAgg) {
      const key = `dst|${ip}`
      let n = reg.get(key)
      if (!n && topDst.has(ip)) {
        const rng = mulberry32(hashSeed(key))
        n = {
          ip,
          role: 'dst',
          count: 0,
          lastSeverity: agg.sev,
          lastTs: agg.ts,
          visible: true,
          angle: hashAngle(ip) + (slots.dst++ % 6) * (Math.PI * 2 / 6) * 0.5,
          speed: -(0.03 + rng() * 0.015),
          size: 5,
          spin: rng() * Math.PI * 2,
          spinSpeed: (rng() < 0.5 ? -1 : 1) * (0.08 + rng() * 0.16),
          verts: makeVerts(rng),
          flash: 0,
        }
        reg.set(key, n)
      }
      if (n) {
        n.count = agg.count
        n.lastSeverity = agg.sev
        n.lastTs = agg.ts
        n.visible = topDst.has(ip)
      }
    }
    /* 登记表防膨胀：隐藏且陈旧的节点淘汰 */
    if (reg.size > 80) {
      for (const [k, n] of reg) {
        if (!n.visible) reg.delete(k)
      }
    }
    /* 权重 → 体型：3–11px 对数标度 */
    let maxCount = 1
    for (const n of reg.values()) if (n.visible && n.count > maxCount) maxCount = n.count
    for (const n of reg.values()) {
      const w = Math.log2(1 + n.count) / Math.log2(1 + maxCount)
      n.size = 3.2 + w * 7.5
    }
  }

  /* —— 动画状态 refs —— */
  const edgeFxRef = useRef<Map<string, EdgeFx>>(new Map())
  const cometsRef = useRef<Comet[]>([])
  const pulsesRef = useRef<Pulse[]>([])
  const shootersRef = useRef<Shooter[]>([])
  const starsRef = useRef<StarField[]>([])
  const skyFlashRef = useRef<{ x: number; y: number; a: number } | null>(null)
  const rafIdRef = useRef<number | null>(null)
  const hoverRef = useRef<string | null>(null)
  const launchedRef = useRef<Set<number>>(new Set())
  const settledRef = useRef<Set<number>>(new Set())
  const lastFrameRef = useRef<number>(0)
  const shooterNextRef = useRef<number>(3000)

  const [hover, setHover] = useState<{ key: string; ip: string; role: 'src' | 'dst'; count: number; sev: Severity } | null>(null)

  /* 供 rAF 闭包读取的当前 props/hover 桥（不触发监听重建） */
  const propsActiveRef = useRef(active)
  propsActiveRef.current = active
  const hoverBridgeRef = useRef(hover)
  hoverBridgeRef.current = hover

  const reduceMotion = useMemo(
    () => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    [],
  )

  /* —— 新到事件 → 发射彗星 —— */
  useEffect(() => {
    const logsById = new Map(logs.map((l) => [l.id, l]))
    const now = Date.now()
    for (const [idStr, ts] of Object.entries(recentIds)) {
      const id = Number(idStr)
      if (launchedRef.current.has(id)) continue
      launchedRef.current.add(id)
      if (now - ts > 8000) continue /* 迟到的标记不再补飞 */
      const log = logsById.get(id)
      if (!log || !log.src_ip || !log.dst_ip) continue
      const comets = cometsRef.current
      if (comets.length >= MAX_COMETS) comets.shift()
      const dur = reduceMotion ? 0 : log.severity === 'critical' ? 900 : log.severity === 'high' ? 1200 : 1600
      comets.push({
        srcIp: log.src_ip,
        dstIp: log.dst_ip,
        severity: log.severity,
        born: performance.now(),
        dur,
        trail: [],
        tempSrc: !derivedRef.current.topSrc.has(log.src_ip),
        tempDst: !derivedRef.current.topDst.has(log.dst_ip),
      })
    }
    if (launchedRef.current.size > 4000) launchedRef.current = new Set([...launchedRef.current].slice(-1000))
  }, [recentIds, logs, reduceMotion])

  /* —— 审计完成 → 连线沉淀 —— */
  useEffect(() => {
    for (const [idStr] of Object.entries(stampedIds)) {
      const id = Number(idStr)
      if (settledRef.current.has(id)) continue
      settledRef.current.add(id)
      const log = logs.find((l) => l.id === id)
      if (!log || !log.src_ip || !log.dst_ip) continue
      const key = `${log.src_ip}|${log.dst_ip}`
      const fx = edgeFxRef.current.get(key) || { settleAt: 0, starAlpha: 0 }
      if (!fx.settleAt) fx.settleAt = performance.now()
      fx.starAlpha = 1
      edgeFxRef.current.set(key, fx)
    }
    if (settledRef.current.size > 4000) settledRef.current = new Set([...settledRef.current].slice(-1000))
    /* W2-3(复审 P1-4): edgeFx 按 src|dst 键只增不减 — IP 对 churn 的长会话
       缓慢泄漏(对照 settledRef 同款裁剪纪律) */
    if (edgeFxRef.current.size > 2000) {
      const keep = [...edgeFxRef.current.entries()]
        .sort((a, b) => (b[1].settleAt || 0) - (a[1].settleAt || 0))
        .slice(0, 500)
      edgeFxRef.current = new Map(keep)
    }
  }, [stampedIds, logs])

  /* —— 渲染主循环 —— */
  useEffect(() => {
    const wrap = wrapRef.current
    const canvas = canvasRef.current
    if (!wrap || !canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let W = 0
    let H = 0
    let dpr = 1
    let running = true
    let inView = true

    const resize = () => {
      const rect = wrap.getBoundingClientRect()
      W = Math.max(320, rect.width)
      H = Math.max(260, rect.height)
      dpr = Math.min(window.devicePixelRatio || 1, 2)
      canvas.width = Math.round(W * dpr)
      canvas.height = Math.round(H * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      /* 背景星场：随尺寸重建 */
      const count = Math.min(140, Math.round((W * H) / 15000))
      starsRef.current = Array.from({ length: count }, () => ({
        x: Math.random() * W,
        y: Math.random() * H,
        r: 0.5 + Math.random() * 1.1,
        phase: Math.random() * Math.PI * 2,
        tw: 0.3 + Math.random() * 1.2,
        warm: Math.random() < 0.08,
      }))
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(wrap)

    const armFrame = () => {
      if (rafIdRef.current === null) {
        lastFrameRef.current = performance.now()
        rafIdRef.current = requestAnimationFrame(frame)
      }
    }
    const onVis = () => {
      running = !document.hidden
      if (running && inView) armFrame()
    }
    document.addEventListener('visibilitychange', onVis)
    const io = new IntersectionObserver((ents) => {
      inView = ents.some((e) => e.isIntersecting)
      if (inView && running) armFrame()
    })
    io.observe(wrap)

    /* —— 坐标解析：节点或影子点 —— */
    const orbitRadii = () => {
      const base = Math.min(W, H)
      return { ri: base * 0.21, ro: base * 0.4 }
    }
    const nodePos = (n: SkyNode): { x: number; y: number } => {
      const { ri, ro } = orbitRadii()
      const r = (n.role === 'src' ? ro : ri) + (n.role === 'src' ? Math.sin(n.angle * 3) * 6 : 0)
      return {
        x: W / 2 + Math.cos(n.angle) * r,
        y: H / 2 + Math.sin(n.angle) * r * ORBIT_SQUASH,
      }
    }
    const resolvePoint = (ip: string, role: 'src' | 'dst'): { x: number; y: number; temp: boolean } => {
      const reg = nodeRegRef.current
      const n = reg.get(`${role}|${ip}`)
      if (n && n.visible) return { ...nodePos(n), temp: false }
      const { ri, ro } = orbitRadii()
      const a = hashAngle(ip) + performance.now() * 0.00002
      const r = role === 'src' ? ro : ri
      return { x: W / 2 + Math.cos(a) * r, y: H / 2 + Math.sin(a) * r * ORBIT_SQUASH, temp: true }
    }

    /* —— 悬停拾取 —— */
    const onMove = (ev: MouseEvent) => {
      const rect = canvas.getBoundingClientRect()
      const mx = ev.clientX - rect.left
      const my = ev.clientY - rect.top
      let best: SkyNode | null = null
      let bestD = 1e9
      for (const n of nodeRegRef.current.values()) {
        if (!n.visible) continue
        const p = nodePos(n)
        const d = Math.hypot(p.x - mx, p.y - my)
        if (d < Math.max(11, n.size + 6) && d < bestD) {
          bestD = d
          best = n
        }
      }
      const key = best ? `${best.role}|${best.ip}` : null
      if (key !== hoverRef.current) {
        hoverRef.current = key
        if (best) {
          setHover({ key: key!, ip: best.ip, role: best.role, count: best.count, sev: best.lastSeverity })
        } else {
          setHover(null)
        }
      }
      canvas.style.cursor = best ? 'pointer' : 'default'
    }
    const onLeave = () => {
      hoverRef.current = null
      setHover(null)
    }
    const onClick = () => {
      const key = hoverRef.current
      if (!key || !onSelectIp) return
      const n = nodeRegRef.current.get(key)
      if (n) onSelectIp(n.ip)
    }
    canvas.addEventListener('mousemove', onMove)
    canvas.addEventListener('mouseleave', onLeave)
    canvas.addEventListener('click', onClick)

    /* —— 绘制小行星 —— */
    const drawAsteroid = (n: SkyNode, p: { x: number; y: number }, dim: boolean) => {
      const core = n.role === 'src' ? CORE_SRC : CORE_DST
      const base = dim ? 0.5 : 1
      ctx.save()
      ctx.translate(p.x, p.y)
      ctx.rotate(n.spin)
      ctx.beginPath()
      const nv = n.verts.length
      for (let i = 0; i <= nv; i++) {
        const a = (i / nv) * Math.PI * 2
        const rr = n.size * n.verts[i % nv]
        const x = Math.cos(a) * rr
        const y = Math.sin(a) * rr
        if (i === 0) ctx.moveTo(x, y)
        else ctx.lineTo(x, y)
      }
      ctx.closePath()
      const g = ctx.createRadialGradient(-n.size * 0.3, -n.size * 0.3, n.size * 0.1, 0, 0, n.size * 1.2)
      g.addColorStop(0, core)
      g.addColorStop(1, n.role === 'src' ? '#5e3a24' : '#31435e')
      ctx.globalAlpha = base
      ctx.fillStyle = g
      ctx.fill()
      ctx.strokeStyle = core
      ctx.globalAlpha = base * 0.55
      ctx.lineWidth = 1
      ctx.stroke()
      ctx.restore()
      /* 受击闪白 */
      if (n.flash > 0.01) {
        ctx.save()
        ctx.globalAlpha = n.flash * 0.75
        ctx.strokeStyle = '#ffffff'
        ctx.lineWidth = 1.4
        ctx.beginPath()
        ctx.arc(p.x, p.y, n.size + 4 + (1 - n.flash) * 10, 0, Math.PI * 2)
        ctx.stroke()
        ctx.restore()
      }
      /* IP 标签 */
      ctx.save()
      ctx.globalAlpha = (dim ? 0.22 : 0.5) * (hoverRef.current?.startsWith(n.role) ? 1 : 0.85)
      ctx.fillStyle = STAR_FROST
      ctx.font = '9px "IBM Plex Mono", ui-monospace, monospace'
      ctx.textAlign = 'center'
      ctx.fillText(truncIp(n.ip), p.x, p.y + n.size + 12)
      ctx.restore()
    }

    /* —— 主循环 —— */
    let hudTick = 0
    const frame = (now: number) => {
      if (!running || !inView) {
        /* W2-3(复审 P3): 停表 — 隐藏/移出视口不再每帧自调度空转,
           由 visibility/intersection 回调重新点火 */
        rafIdRef.current = null
        return
      }
      const dt = Math.min(64, now - (lastFrameRef.current || now))
      lastFrameRef.current = now
      const reg = nodeRegRef.current
      const d = derivedRef.current
      const activeSev = propsActiveRef.current
      const hoverKey = hoverRef.current

      /* 公转/自转 */
      if (!reduceMotion) {
        for (const n of reg.values()) {
          if (!n.visible) continue
          n.angle += n.speed * (dt / 1000)
          n.spin += n.spinSpeed * (dt / 1000)
          if (n.flash > 0) n.flash = Math.max(0, n.flash - dt / 900)
        }
      }

      ctx.clearRect(0, 0, W, H)

      /* 背景星场（闪烁） */
      for (const s of starsRef.current) {
        const a = reduceMotion ? 0.4 : 0.22 + 0.42 * (0.5 + 0.5 * Math.sin((now / 1000) * s.tw + s.phase))
        ctx.globalAlpha = a
        ctx.fillStyle = s.warm ? '#d4b98a' : STAR_FROST
        ctx.beginPath()
        ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2)
        ctx.fill()
      }
      ctx.globalAlpha = 1

      /* 装饰流星（低频） */
      if (!reduceMotion && now > shooterNextRef.current) {
        shooterNextRef.current = now + 6000 + Math.random() * 9000
        const fromLeft = Math.random() < 0.5
        shootersRef.current.push({
          x: fromLeft ? -40 : W + 40,
          y: Math.random() * H * 0.4,
          vx: (fromLeft ? 1 : -1) * (0.35 + Math.random() * 0.25),
          vy: 0.16 + Math.random() * 0.1,
          life: 1,
        })
      }
      for (let i = shootersRef.current.length - 1; i >= 0; i--) {
        const sh = shootersRef.current[i]
        sh.x += sh.vx * dt
        sh.y += sh.vy * dt
        sh.life -= dt / 1100
        if (sh.life <= 0 || sh.x < -80 || sh.x > W + 80) {
          shootersRef.current.splice(i, 1)
          continue
        }
        const grad = ctx.createLinearGradient(sh.x, sh.y, sh.x - sh.vx * 90, sh.y - sh.vy * 90)
        grad.addColorStop(0, `rgba(220,235,255,${(0.7 * sh.life).toFixed(3)})`)
        grad.addColorStop(1, 'rgba(220,235,255,0)')
        ctx.strokeStyle = grad
        ctx.lineWidth = 1.2
        ctx.beginPath()
        ctx.moveTo(sh.x, sh.y)
        ctx.lineTo(sh.x - sh.vx * 90, sh.y - sh.vy * 90)
        ctx.stroke()
      }

      /* —— 连线 —— */
      const { ri, ro } = orbitRadii()
      void ri
      void ro
      const posCache = new Map<string, { x: number; y: number }>()
      const posOf = (ip: string, role: 'src' | 'dst') => {
        const k = `${role}|${ip}`
        let p = posCache.get(k)
        if (!p) {
          const n = reg.get(k)
          p = n && n.visible ? nodePos(n) : (() => {
            const a = hashAngle(ip) + now * 0.00002
            const base = Math.min(W, H)
            const r = role === 'src' ? base * 0.4 : base * 0.21
            return { x: W / 2 + Math.cos(a) * r, y: H / 2 + Math.sin(a) * r * ORBIT_SQUASH }
          })()
          posCache.set(k, p)
        }
        return p
      }
      const edgeTouches = (ip: string) => hoverKey !== null && (hoverKey === `src|${ip}` || hoverKey === `dst|${ip}`)
      for (const e of d.edges) {
        const a = posOf(e.src, 'src')
        const b = posOf(e.dst, 'dst')
        const fx = edgeFxRef.current.get(`${e.src}|${e.dst}`)
        const hi = edgeTouches(e.src) || edgeTouches(e.dst)
        /* 级别筛选：不含该级别的连线压暗 */
        const sevHit = !activeSev || e.topSeverity === activeSev
        /* 待审流动虚线 */
        if (e.pending > 0) {
          ctx.save()
          ctx.setLineDash([4, 7])
          ctx.lineDashOffset = reduceMotion ? 0 : -(now / 45) % 11
          ctx.strokeStyle = SEV_SKY[e.topSeverity]
          ctx.globalAlpha = (hi ? 0.75 : 0.34) * (sevHit ? 1 : 0.22)
          ctx.lineWidth = 1
          ctx.beginPath()
          ctx.moveTo(a.x, a.y)
          ctx.lineTo(b.x, b.y)
          ctx.stroke()
          ctx.restore()
        }
        /* 已沉淀实线（霜色星座线） */
        if (fx && fx.starAlpha > 0) {
          let alpha = hi ? 0.5 : 0.1 + Math.min(0.14, e.count * 0.025)
          if (!sevHit) alpha *= 0.25
          /* 刚沉淀：0.9s 亮扫 */
          const since = fx.settleAt ? now - fx.settleAt : 1e9
          const sweep = since < 900 ? (1 - since / 900) : 0
          ctx.save()
          ctx.setLineDash([])
          ctx.strokeStyle = STAR_FROST
          ctx.globalAlpha = Math.min(0.85, alpha + sweep * 0.5)
          ctx.lineWidth = 1 + sweep * 0.8
          ctx.beginPath()
          ctx.moveTo(a.x, a.y)
          ctx.lineTo(b.x, b.y)
          ctx.stroke()
          /* 归档星：中点亮起 */
          if (fx.starAlpha > 0) {
            const mx = (a.x + b.x) / 2
            const my = (a.y + b.y) / 2
            const sa = fx.starAlpha * (0.55 + (reduceMotion ? 0 : 0.25 * Math.sin(now / 500)))
            ctx.globalAlpha = sa
            ctx.strokeStyle = '#e8f0fa'
            ctx.lineWidth = 1
            const sr = 3
            ctx.beginPath()
            ctx.moveTo(mx - sr, my)
            ctx.lineTo(mx + sr, my)
            ctx.moveTo(mx, my - sr)
            ctx.lineTo(mx, my + sr)
            ctx.stroke()
            ctx.beginPath()
            ctx.arc(mx, my, 1.3, 0, Math.PI * 2)
            ctx.fillStyle = '#e8f0fa'
            ctx.fill()
          }
          ctx.restore()
        }
      }

      /* —— 彗星 —— */
      const comets = cometsRef.current
      for (let i = comets.length - 1; i >= 0; i--) {
        const c = comets[i]
        const t = c.dur > 0 ? Math.min(1, (now - c.born) / c.dur) : 1
        const A = resolvePoint(c.srcIp, 'src')
        const B = resolvePoint(c.dstIp, 'dst')
        /* 贝塞尔控制点：中点向侧外推，弧向与外环一致 */
        const mxp = (A.x + B.x) / 2
        const myp = (A.y + B.y) / 2
        const dx = B.x - A.x
        const dy = B.y - A.y
        const len = Math.hypot(dx, dy) || 1
        const side = hashAngle(c.srcIp + c.dstIp) > Math.PI ? 1 : -1
        const bow = Math.min(70, len * 0.22) * side
        const C = { x: mxp + (-dy / len) * bow, y: myp + (dx / len) * bow }
        const ease = reduceMotion ? 1 : t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2
        const x = (1 - ease) * (1 - ease) * A.x + 2 * (1 - ease) * ease * C.x + ease * ease * B.x
        const y = (1 - ease) * (1 - ease) * A.y + 2 * (1 - ease) * ease * C.y + ease * ease * B.y

        if (!reduceMotion) {
          c.trail.push({ x, y })
          if (c.trail.length > 16) c.trail.shift()
          const col = SEV_SKY[c.severity]
          for (let k = 1; k < c.trail.length; k++) {
            const p0 = c.trail[k - 1]
            const p1 = c.trail[k]
            const f = k / c.trail.length
            ctx.strokeStyle = col
            ctx.globalAlpha = f * 0.55
            ctx.lineWidth = 0.6 + f * 1.8
            ctx.beginPath()
            ctx.moveTo(p0.x, p0.y)
            ctx.lineTo(p1.x, p1.y)
            ctx.stroke()
          }
          ctx.globalAlpha = 1
          ctx.save()
          ctx.shadowColor = col
          ctx.shadowBlur = 12
          ctx.fillStyle = col
          ctx.beginPath()
          ctx.arc(x, y, 2.6, 0, Math.PI * 2)
          ctx.fill()
          ctx.restore()
        }

        /* 影子端点（不在展示环上的 IP） */
        if (A.temp && t < 1) {
          ctx.globalAlpha = 0.5 * (1 - t * 0.5)
          ctx.fillStyle = CORE_SRC
          ctx.beginPath()
          ctx.arc(A.x, A.y, 3, 0, Math.PI * 2)
          ctx.fill()
          ctx.globalAlpha = 1
        }
        if (B.temp && t < 1) {
          ctx.globalAlpha = 0.5 * (1 - t * 0.5)
          ctx.fillStyle = CORE_DST
          ctx.beginPath()
          ctx.arc(B.x, B.y, 3, 0, Math.PI * 2)
          ctx.fill()
          ctx.globalAlpha = 1
        }

        /* 命中 */
        if (t >= 1) {
          comets.splice(i, 1)
          const target = reg.get(`dst|${c.dstIp}`)
          if (target && target.visible) target.flash = 1
          const bp = posOf(c.dstIp, 'dst')
          const boost = c.severity === 'critical' ? 1.7 : c.severity === 'high' ? 1.25 : 1
          pulsesRef.current.push({
            x: bp.x,
            y: bp.y,
            born: now,
            dur: c.severity === 'critical' ? 950 : 700,
            max: 22 * boost,
            severity: c.severity,
          })
          if (c.severity === 'critical' && !reduceMotion) {
            pulsesRef.current.push({ x: bp.x, y: bp.y, born: now + 160, dur: 1150, max: 46, severity: c.severity })
            skyFlashRef.current = { x: bp.x, y: bp.y, a: 0.14 }
          }
          /* 命中即等待审计：对应边若尚无沉淀记录，保持虚线（不在此处置） */
        }
      }

      /* —— 冲击环 —— */
      for (let i = pulsesRef.current.length - 1; i >= 0; i--) {
        const pu = pulsesRef.current[i]
        const k = (now - pu.born) / pu.dur
        if (k < 0) continue
        if (k >= 1) {
          pulsesRef.current.splice(i, 1)
          continue
        }
        const r = pu.max * (reduceMotion ? 1 : k)
        ctx.globalAlpha = (1 - k) * 0.8
        ctx.strokeStyle = SEV_SKY[pu.severity]
        ctx.lineWidth = pu.severity === 'critical' ? 2 : 1.3
        ctx.beginPath()
        ctx.arc(pu.x, pu.y, Math.max(1, r), 0, Math.PI * 2)
        ctx.stroke()
        ctx.globalAlpha = 1
      }

      /* critical 星云泛红 */
      const sf = skyFlashRef.current
      if (sf && sf.a > 0.005) {
        const g = ctx.createRadialGradient(sf.x, sf.y, 0, sf.x, sf.y, Math.min(W, H) * 0.7)
        g.addColorStop(0, `rgba(255, 90, 70, ${sf.a.toFixed(3)})`)
        g.addColorStop(1, 'rgba(255, 90, 70, 0)')
        ctx.fillStyle = g
        ctx.fillRect(0, 0, W, H)
        if (!reduceMotion) sf.a -= dt / 1400
      }

      /* —— 小行星（悬停时他者压暗） —— */
      for (const n of reg.values()) {
        if (!n.visible) continue
        const p = nodePos(n)
        const dim = hoverKey !== null && hoverKey !== `${n.role}|${n.ip}`
        drawAsteroid(n, p, dim)
      }

      /* 空场提示 */
      if (d.edges.length === 0 && reg.size === 0) {
        ctx.globalAlpha = 0.5
        ctx.fillStyle = STAR_PALE
        ctx.font = '11px "IBM Plex Mono", ui-monospace, monospace'
        ctx.textAlign = 'center'
        ctx.fillText('星空静默 · 等待事件接入 …', W / 2, H / 2)
        ctx.globalAlpha = 1
      }

      /* HUD 数字直写（低频） */
      if (now - hudTick > 400) {
        hudTick = now
        let visible = 0
        for (const n of reg.values()) if (n.visible) visible++
        if (hudNodeRef.current) hudNodeRef.current.textContent = String(visible)
        if (hudEdgeRef.current) hudEdgeRef.current.textContent = String(d.edges.length)
        if (hudFlyRef.current) hudFlyRef.current.textContent = String(comets.length)
      }

      /* 浮签跟随节点 */
      if (hoverBridgeRef.current && tipRef.current) {
        const key = hoverRef.current
        const n = key ? reg.get(key) : null
        if (n && n.visible) {
          const p = nodePos(n)
          const tip = tipRef.current
          const tw = tip.offsetWidth
          const th = tip.offsetHeight
          let tx = p.x + n.size + 12
          let ty = p.y - th - 8
          if (tx + tw > W - 8) tx = p.x - n.size - 12 - tw
          if (ty < 8) ty = p.y + n.size + 12
          tip.style.transform = `translate(${Math.round(tx)}px, ${Math.round(ty)}px)`
        }
      }

      rafIdRef.current = requestAnimationFrame(frame)
    }
    rafIdRef.current = requestAnimationFrame(frame)

    return () => {
      if (rafIdRef.current !== null) cancelAnimationFrame(rafIdRef.current)
      ro.disconnect()
      io.disconnect()
      document.removeEventListener('visibilitychange', onVis)
      canvas.removeEventListener('mousemove', onMove)
      canvas.removeEventListener('mouseleave', onLeave)
      canvas.removeEventListener('click', onClick)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reduceMotion])

  /* hover 状态桥接进循环（声明见上方渲染主体，此处不再重复） */

  return (
    <div
      ref={wrapRef}
      className="star-map h-[340px] border border-line max-md:h-[300px] lg:h-[430px]"
      data-testid="attack-constellation"
    >
      <canvas ref={canvasRef} aria-label="攻击态势星图：来源外环、目标内环，彗星表示实时攻击" />

      <div className="star-hud" style={{ top: 14, left: 18 }}>
        <div>
          <span className={connected ? 'live-dot' : 'live-dot off'} aria-hidden />
          态势星图 · {connected ? 'field active' : 'link down'}
        </div>
        <div>
          节点 <b ref={hudNodeRef}>0</b> · 连线 <b ref={hudEdgeRef}>0</b> · 在途 <b ref={hudFlyRef}>0</b>
        </div>
      </div>

      <div className="star-hud" style={{ top: 14, right: 18, textAlign: 'right' }}>
        <div>来源 · 外环</div>
        <div>目标 · 内环</div>
        <div>审计沉淀 · 霜色连线</div>
      </div>

      <div className="star-hud" style={{ bottom: 14, left: 18 }}>
        悬停查看 · 点击来源过滤
      </div>

      <div className="star-legend" role="group" aria-label="按级别筛选星图">
        {SEV_ORDER.map((s) => (
          <button
            key={s}
            type="button"
            aria-pressed={active === s}
            onClick={() => onSelectSeverity?.(s)}
            data-testid={`star-legend-${s}`}
          >
            <span className="swatch" style={{ background: SEV_SKY[s] }} aria-hidden />
            {SEV_LABEL[s]}
          </button>
        ))}
      </div>

      {hover && (
        <div className="star-tip" ref={tipRef} style={{ left: 0, top: 0 }}>
          <div className="tip-ip">{hover.ip}</div>
          <div className="tip-role">
            {hover.role === 'src' ? '攻击来源 · 外环' : '被测目标 · 内环'}
          </div>
          <div className="tip-meta">
            事件 {hover.count} · 最近 {SEV_LABEL[hover.sev]}
          </div>
        </div>
      )}
    </div>
  )
}
