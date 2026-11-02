import { useEffect } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { TopNav } from '../components/common/TopNav'
import { CommandPalette } from '../components/common/CommandPalette'
import { PATH_LABEL, groupOf } from './nav'
import { ROUTES } from '../lib/constants'

/** 不在篇章内的特殊页面标题 */
const SPECIAL_TITLES: Record<string, string> = {
  [ROUTES.DEMO]: '攻击剧本',
  [ROUTES.BENCHMARK]: '评测战绩',
}

export function RootLayout() {
  const location = useLocation()

  // 定位符：篇章 · 页面 — 答辩投屏时评委随时知道在看哪一页
  // （主题切换由 App.tsx 的 ThemeSync 统一负责，此处不再重复处理）
  useEffect(() => {
    const group = groupOf(location.pathname)
    const page = SPECIAL_TITLES[location.pathname] ?? PATH_LABEL[location.pathname]
    document.title = group && page
      ? `${group.title} · ${page} — 守望 SOC`
      : '守望 · Night Watch SOC'
  }, [location.pathname])

  return (
    <div className="app-root relative min-h-screen bg-surface font-sans text-ink">
      {/* v8：TopNav 常驻恢复 —— 四篇章页签 + 检索/主题/登出；Ctrl K 命令面板保留 */}
      <TopNav />
      <main className="min-h-screen">
        <AnimatePresence mode="wait">
          <Outlet key={location.pathname} />
        </AnimatePresence>
      </main>
      <CommandPalette />
    </div>
  )
}
