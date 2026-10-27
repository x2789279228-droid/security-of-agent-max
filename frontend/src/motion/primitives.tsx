import { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'

/**
 * 动效原语(阶段 6) — 全站统一时序与入场原语。
 * 原则:叙事张扬、页面克制 —— 数字滚动/条形绘入只在值变化与进场时触发,不循环。
 */

export const MOTION = {
  fast: 0.15,
  base: 0.25,
  slow: 0.45,
  /** ease-out-quart,与 index.css 各 keyframes 同族 */
  ease: [0.22, 1, 0.36, 1] as [number, number, number, number],
}

export const prefersReducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

/** 数字滚入:from='zero' 进场归零滚起;from='previous' 从上一值滚到新值(高频变化数字用) */
export function CountUp({
  value,
  decimals = 0,
  duration = 950,
  from = 'zero',
  className,
}: {
  value: number
  decimals?: number
  duration?: number
  from?: 'zero' | 'previous'
  className?: string
}) {
  const prevRef = useRef(value)
  const [display, setDisplay] = useState(() => {
    if (prefersReducedMotion()) return value
    return from === 'zero' ? 0 : value
  })
  useEffect(() => {
    if (prefersReducedMotion()) {
      prevRef.current = value
      setDisplay(value)
      return
    }
    const startVal = from === 'previous' ? prevRef.current : 0
    prevRef.current = value
    if (startVal === value) {
      setDisplay(value)
      return
    }
    let raf = 0
    const start = performance.now()
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / duration)
      const eased = 1 - Math.pow(1 - p, 3)
      setDisplay(startVal + (value - startVal) * eased)
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value, duration, from])
  return (
    <span className={className}>
      {display.toLocaleString('zh-CN', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}
    </span>
  )
}

/** 条形绘入:进场时从 0 长到目标宽度(reduced-motion 直接落定) */
export function DrawBar({
  pct,
  tone,
  delay = 0,
  className = 'h-2.5',
}: {
  pct: number
  tone: string
  delay?: number
  className?: string
}) {
  const reduced = useReducedMotion() ?? false
  const clamped = Math.max(2, Math.min(100, pct))
  return (
    <div className={`w-full bg-mist ${className}`}>
      <motion.div
        className={`h-full ${tone}`}
        initial={{ width: reduced ? `${clamped}%` : 0 }}
        whileInView={{ width: `${clamped}%` }}
        viewport={{ once: true, margin: '-30px' }}
        transition={{ duration: 0.7, delay, ease: MOTION.ease }}
      />
    </div>
  )
}

/** 进场揭示:fade-up + 位移,reduced-motion 仅淡入 */
export function Reveal({
  children,
  delay = 0,
  y = 14,
  className,
}: {
  children: React.ReactNode
  delay?: number
  y?: number
  className?: string
}) {
  const reduced = useReducedMotion() ?? false
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: reduced ? 0 : y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-40px' }}
      transition={{ duration: 0.5, delay, ease: MOTION.ease }}
    >
      {children}
    </motion.div>
  )
}
