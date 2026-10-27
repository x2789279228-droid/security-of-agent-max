import { useEffect, useRef, useState } from 'react'
import type { StreamStatus } from '../lib/eventStream'
import { startWallReplay, WALL_REPLAY_OFFLINE_GRACE_MS } from '../lib/wallReplay'

/**
 * 幕布续命(大屏专用) — SSE 持续离线超过宽限期后自动切入回放剧本;
 * 回到 online 立即停止并复位。返回激活态,供顶栏「回放口径」徽章明示。
 *
 * 状态抖动(connecting/reconnecting 反复)会重置宽限期计时,
 * 但看门狗每轮 offline 停留 ≥6s,宽限期总能落地。
 */
export function useWallKeepalive(streamStatus: StreamStatus): boolean {
  const [replayActive, setReplayActive] = useState(false)
  const stopRef = useRef<(() => void) | null>(null)

  useEffect(() => {
    if (streamStatus === 'online') {
      if (stopRef.current) {
        stopRef.current()
        stopRef.current = null
        setReplayActive(false)
      }
      return
    }
    const t = setTimeout(() => {
      if (!stopRef.current) {
        stopRef.current = startWallReplay()
        setReplayActive(true)
      }
    }, WALL_REPLAY_OFFLINE_GRACE_MS)
    return () => clearTimeout(t)
  }, [streamStatus])

  // 卸载兜底:回放定时器不跨页面存活
  useEffect(() => () => stopRef.current?.(), [])

  return replayActive
}
