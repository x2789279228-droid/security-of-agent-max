import { useEffect } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { AnimatePresence } from 'framer-motion'
import { TopNav } from './TopNav'
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
  useEffect(() => {
    const group = groupOf(location.pathname)
    const page = SPECIAL_TITLES[location.pathname] ?? PATH_LABEL[location.pathname]
    document.title = group && page
      ? `${group.title} · ${page} — 守望 SOC`
      : '守望 · Night Watch SOC'
  }, [location.pathname])

  return (
    <div className="relative min-h-screen bg-surface font-sans text-ink">
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
