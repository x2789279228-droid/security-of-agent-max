import { create } from 'zustand'
import type { DependencyProbe } from '../types'

/**
 * 依赖健康态。
 *
 * 'unknown' 是**必需**的一态 —— 2026-10-03 修复前，本 store 的初值被硬编码为
 * 'ok'，且 setService/setAll 在整个前端零调用点，导致 Monitor 页的健康环
 * 无论依赖是否可用都显示绿色 NOMINAL。首屏与请求失败必须显示 UNKNOWN，
 * 不能回落为"看起来正常"。
 */
export type DependencyState = 'unknown' | 'ok' | 'error'

interface ServiceState {
  services: Record<string, DependencyState>
  details: Record<string, string>
  /** 是否已完成过一次探测。false 时 UI 应显示 UNKNOWN 而非任何"正常"色。 */
  probed: boolean
  setAll: (probes: Record<string, DependencyProbe>) => void
  setUnprobed: () => void
}

/** 后端探针只返回 ok | error；把缺失的服务也归为 unknown 而非跳过。 */
const SERVICE_IDS = ['postgres', 'redis', 'qdrant', 'llm'] as const

export const useServiceStore = create<ServiceState>((set) => ({
  services: Object.fromEntries(SERVICE_IDS.map((id) => [id, 'unknown'])),
  details: {},
  probed: false,
  setAll: (probes) =>
    set({
      services: Object.fromEntries(
        SERVICE_IDS.map((id) => [
          id,
          id in probes ? (probes[id].status === 'ok' ? 'ok' : 'error') : 'unknown',
        ]),
      ),
      details: Object.fromEntries(
        SERVICE_IDS.filter((id) => id in probes).map((id) => [id, probes[id].detail]),
      ),
      probed: true,
    }),
  setUnprobed: () =>
    set({
      services: Object.fromEntries(SERVICE_IDS.map((id) => [id, 'unknown'])),
      details: {},
      probed: false,
    }),
}))
