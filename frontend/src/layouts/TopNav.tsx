import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'
import { WatchShift } from '../components/ui/WatchShift'
import { ROUTES } from '../lib/constants'
import { NAV_GROUPS, groupOf } from './nav'

/**
 * TopNav · 守望 v6 — 两级篇章导航
 *
 * - 行 1（h-14）：品牌左 / 状态中 / 演示 CTA + 检索 + 操作右
 * - 行 2（h-10）：一级篇章页签（值班台/处置台/对抗台/感知台）
 *   + 二级当前篇章内的页面页签（骑缝式展开，点篇章头进入该篇章首页）
 *
 * 篇章即答辩叙事的四个章节：值班 → 处置 → 对抗 → 感知。
 */

export function TopNav() {
  const location = useLocation()
  const navigate = useNavigate()
  const { username, token, logout } = useAuthStore()
  const [menuOpen, setMenuOpen] = useState(false)

  const current = groupOf(location.pathname)

  useEffect(() => setMenuOpen(false), [location.pathname])

  const go = (path: string) => navigate(path)

  const openPalette = () => window.dispatchEvent(new CustomEvent('soc:palette-open'))

  const today = new Date().toLocaleDateString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
  })
  const weekday = new Date().toLocaleDateString('zh-CN', { weekday: 'long' })

  return (
    <header className="sticky top-0 z-40 bg-surface border-b border-line">
      {/* 行 1：品牌 + 状态 + 操作 */}
      <div className="page-shell h-14 flex items-center gap-6">
        {/* 左：品牌 */}
        <button
          onClick={() => go(ROUTES.HOME)}
          aria-label="守望首页"
          className="flex items-baseline gap-3 shrink-0"
        >
          <span className="font-serif text-[20px] font-black tracking-[-0.02em] text-ink leading-none">
            守望
          </span>
          <span className="hidden md:inline font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
            Shouwang · Night Watch SOC
          </span>
        </button>

        {/* 中：状态 meta —— 一行收齐 */}
        <div className="hidden lg:flex items-center gap-5 flex-1 min-w-0 justify-center font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
          <span className="whitespace-nowrap">{today} · {weekday}</span>
          <span className="h-3 w-px bg-line" aria-hidden />
          <span className="inline-flex items-center gap-2 text-accent whitespace-nowrap">
            <span className="live-arc text-accent" aria-hidden />
            <span>Shift Active</span>
          </span>
          <WatchShift className="ml-1" />
        </div>

        {/* 右：演示 CTA + 用户操作 */}
        <div className="flex items-center gap-3 ml-auto shrink-0">
          <button
            onClick={() => go(ROUTES.DEMO)}
            className="nav-btn nav-btn-prime"
            title="六幕攻击剧本：注入 → 检测 → 接力 → 处置 → 结案"
          >
            ▶ 演示剧本
          </button>
          {token ? (
            <>
              <span className="hidden sm:inline font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                {username || 'admin'}
              </span>
              <button
                onClick={() => {
                  logout()
                  navigate('/login')
                }}
                className="nav-btn"
              >
                登出
              </button>
            </>
          ) : (
            <button onClick={() => navigate('/login')} className="nav-btn">
              登录
            </button>
          )}
          <button
            type="button"
            className="lg:hidden font-mono text-[10px] tracking-[0.22em] uppercase text-ink-soft hover:text-ink border-l border-line pl-3"
            aria-expanded={menuOpen}
            aria-label={menuOpen ? '关闭目录' : '打开目录'}
            onClick={() => setMenuOpen((v) => !v)}
          >
            {menuOpen ? 'Close' : 'Menu'}
          </button>
        </div>
      </div>

      {/* 行 2：两级篇章导航 */}
      <nav className="hidden lg:block border-t border-line" aria-label="篇章导航">
        <div className="page-shell h-10 flex items-stretch justify-between">
          <div className="flex items-stretch">
            {NAV_GROUPS.map((group, gi) => {
              const activeGroup = current?.title === group.title
              return (
                <div key={group.title} className="flex items-stretch">
                  {gi > 0 && <span className="self-center mx-2 h-4 w-px bg-line" aria-hidden />}
                  {/* 一级：篇章页签 */}
                  <button
                    onClick={() => go(group.items[0].path)}
                    title={group.items[0].hint}
                    className={`relative px-3 font-mono text-[10px] tracking-[0.24em] uppercase whitespace-nowrap transition-colors ${
                      activeGroup ? 'text-ink' : 'text-ink-faint hover:text-ink-soft'
                    }`}
                  >
                    {group.title}台
                    {activeGroup && (
                      <span className="absolute inset-x-2 bottom-0 h-[2px] bg-vault" aria-hidden />
                    )}
                  </button>
                  {/* 二级：当前篇章的页面页签（骑缝展开） */}
                  {activeGroup && (
                    <>
                      <span className="self-center mx-2 h-4 w-px bg-line" aria-hidden />
                      {group.items.map((item) => {
                        const active = location.pathname === item.path
                        return (
                          <button
                            key={item.path}
                            onClick={() => go(item.path)}
                            title={item.hint}
                            className={`relative px-3 text-[13px] whitespace-nowrap transition-colors ${
                              active ? 'text-ink' : 'text-ink-soft hover:text-ink'
                            }`}
                          >
                            {item.short}
                            {active && (
                              <span className="absolute inset-x-2.5 bottom-0 h-px bg-vault" aria-hidden />
                            )}
                          </button>
                        )
                      })}
                    </>
                  )}
                </div>
              )
            })}
          </div>

          {/* 右：命令面板触发 */}
          <button
            onClick={openPalette}
            className="flex items-center gap-2.5 border-l border-line pl-4 font-mono text-[10px] tracking-[0.18em] uppercase text-ink-faint hover:text-ink transition-colors"
            title="全局检索（Ctrl+K）"
          >
            <span>检索</span>
            <kbd className="border border-line px-1.5 py-0.5 text-[10px] leading-none">Ctrl K</kbd>
          </button>
        </div>
      </nav>

      {menuOpen && (
        <div className="lg:hidden border-t border-line bg-surface">
          <div className="page-shell py-6">
            <button
              onClick={openPalette}
              className="mb-5 border border-line px-3 py-1.5 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-soft"
            >
              检索 · Ctrl K
            </button>
            {NAV_GROUPS.map((group) => (
              <div key={group.title} className="mb-6">
                <p className="mb-2 font-mono text-[10px] tracking-[0.22em] uppercase text-ink-faint">
                  {group.title}台
                </p>
                <div className="flex flex-col gap-1">
                  {group.items.map((item) => {
                    const active = location.pathname === item.path
                    return (
                      <button
                        key={item.path}
                        onClick={() => go(item.path)}
                        className={`py-1.5 text-left text-[16px] ${
                          active ? 'text-ink' : 'text-ink-soft'
                        }`}
                      >
                        {item.label}
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </header>
  )
}
