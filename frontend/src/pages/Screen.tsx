import { useEffect } from 'react'
import { setKioskMode } from '../lib/api'
import { useAuthStore } from '../stores/authStore'
import Monitor from './Monitor'

/**
 * 作战大屏 kiosk 直达(/screen) — 路演机免交互进大屏。
 *
 * - `/screen` 打开即满屏作战大屏,不经过登录守卫与 TopNav;
 * - `?token=<JWT>` 持久化后立即从地址栏抹除(投影现场不留凭据);
 *   无 token 时照样渲染 —— SSE 不建连,由大屏回放口径保持幕布呼吸;
 * - `?event=<id>` 透传给 Monitor 的案卷深链,思维链主舞台直接定位该事件
 *   (剧本页结案后的移交即走这条链)。
 *
 * Esc 退出大屏 → 回首页;带有效 token 时落在值班首页,否则被守卫引去登录页。
 */
export default function Screen() {
  const setAuth = useAuthStore((s) => s.setAuth)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const token = params.get('token')
    if (token) {
      setAuth(token, localStorage.getItem('sm_user') || 'kiosk')
      params.delete('token')
      const qs = params.toString()
      window.history.replaceState(null, '', `${window.location.pathname}${qs ? `?${qs}` : ''}`)
    }
    setKioskMode(true)
    return () => setKioskMode(false)
  }, [setAuth])

  return <Monitor kiosk />
}
