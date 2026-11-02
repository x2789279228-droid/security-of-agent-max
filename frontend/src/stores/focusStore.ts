import { create } from 'zustand'

/**
 * FocusLink · 跨区联动脉冲
 *
 * 点击某个区域（严重度塔 / Agent 节点 / 接力卡）后，让相关区域
 * （日志表格行 / 事件流行）播放一次 row-flash。5s 自动熄灭；
 * 重复触发重置计时并递增 nonce —— 消费方把 nonce 放进 key 重放动画。
 * 沿用项目 store 惯例：无 action，模块函数 setState。
 */

export type FocusKind = 'severity' | 'event' | 'stage'

export interface FocusPulse {
  kind: FocusKind
  value: string | number
  nonce: number
}

interface FocusState {
  pulse: FocusPulse | null
}

export const useFocusStore = create<FocusState>(() => ({ pulse: null }))

let clearTimer: ReturnType<typeof setTimeout> | undefined
let nonce = 0

export function pulseFocus(kind: FocusKind, value: string | number) {
  if (clearTimer) clearTimeout(clearTimer)
  nonce += 1
  useFocusStore.setState({ pulse: { kind, value, nonce } })
  clearTimer = setTimeout(() => useFocusStore.setState({ pulse: null }), 5000)
}
