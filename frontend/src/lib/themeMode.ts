import { ROUTES } from './constants'

/**
 * 主题机制 —— 亮/暗双肤由用户偏好决定，默认暗色（SOC 控制台惯例）。
 * localStorage soc_theme_mode=light|dark；未设置时按暗色渲染。
 * 舞台页（攻击剧本 / 作战大屏 / 海报）永远强制暗色，不随偏好翻转。
 * BattleScreen / Demo / Poster 自身的挂/卸载逻辑与此幂等兼容。
 */

const PREF_KEY = 'soc_theme_mode'

/** 舞台路由：无论偏好如何恒为暗色 */
const STAGE_ROUTES = new Set<string>([ROUTES.DEMO, ROUTES.SCREEN, ROUTES.POSTER])

export type ThemePref = 'light' | 'dark'

export function getThemePref(): ThemePref {
  try {
    const v = localStorage.getItem(PREF_KEY)
    return v === 'light' ? 'light' : 'dark'
  } catch {
    return 'dark'
  }
}

export function setThemePref(pref: ThemePref) {
  try {
    localStorage.setItem(PREF_KEY, pref)
  } catch {
    /* 隐私模式等场景下静默降级为会话内生效 */
  }
}

export function applyThemeMode(pathname: string) {
  const dark = getThemePref() === 'dark' || STAGE_ROUTES.has(pathname)
  const el = document.documentElement
  if (dark) el.dataset.mode = 'battle'
  else delete el.dataset.mode
}

/** 当前生效肤（供切换按钮显示"对面"） */
export function resolvedMode(pathname: string): 'light' | 'dark' {
  return getThemePref() === 'dark' || STAGE_ROUTES.has(pathname) ? 'dark' : 'light'
}
