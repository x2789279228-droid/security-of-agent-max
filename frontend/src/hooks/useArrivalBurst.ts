import { useEffect, useState } from 'react'
import { getArrivalTimes } from '../lib/eventStream'

/**
 * 事件涌入检测 —— 消费 eventStream 的 70s 真实到达时间窗（arrivalTimes，
 * 仅统计非回放事件），1s 轮询算 3s 速率并分档：
 *   calm   无感
 *   active ≥3 条/3s，信息流明显在走
 *   surge  ≥12 条/3s，或 ≥6 条/3s 且达到 10s 基线的 4 倍 —— 突发涌入
 * surge 档驱动监控页事件列表顶边扫描线与状态条 chip（青蓝信息流通道）。
 */

export type BurstLevel = 'calm' | 'active' | 'surge'

export interface ArrivalBurst {
  rate3s: number
  level: BurstLevel
}

export function useArrivalBurst(): ArrivalBurst {
  const [state, setState] = useState<ArrivalBurst>({ rate3s: 0, level: 'calm' })

  useEffect(() => {
    let alive = true
    const tick = () => {
      const times = getArrivalTimes()
      const now = Date.now()
      let c3 = 0
      let c10 = 0
      for (let i = times.length - 1; i >= 0; i--) {
        const age = now - times[i]
        if (age > 10_000) break
        if (age <= 3_000) c3++
        c10++
      }
      const basePerSec = c10 / 10
      const surge = c3 >= 12 || (c3 >= 6 && basePerSec > 0 && c3 / 3 >= basePerSec * 4)
      const level: BurstLevel = surge ? 'surge' : c3 >= 3 ? 'active' : 'calm'
      if (alive) setState((prev) =>
        prev.rate3s === c3 && prev.level === level ? prev : { rate3s: c3, level },
      )
    }
    tick()
    const t = setInterval(tick, 1000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  return state
}
