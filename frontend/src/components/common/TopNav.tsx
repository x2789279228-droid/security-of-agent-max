import { useEffect, useRef, useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { NAV_GROUPS, groupOf } from '../../layouts/nav'
import { useAuthStore } from '../../stores/authStore'
import { resolvedMode, setThemePref } from '../../lib/themeMode'
import { hiddenAdvancedCountInGroup, visibleNavGroups } from '../../lib/navPrefs'
import { useNavExpert } from '../../hooks/useNavExpert'
import { Logo } from '../brand/Logo'

/**
 * TopNav · 全站顶部导航（48px sticky）
 * 左：Logo ｜ 中：四篇章页签（点击展开组内页面） ｜ 右：检索 · 主题 · 用户
 * 自 CornerDock 迁移的三个全局功能：检索入口 / 主题切换 / 登出。
 * 高亮规则：groupOf(pathname) 命中篇章即点亮组页签，组内当前页再亮一级。
 */
export function TopNav() {
  const location = useLocation()
  const navigate = useNavigate()
  const { username, token, logout, openTour } = useAuthStore()
  const { expert, setExpert } = useNavExpert()
  const [openGroup, setOpenGroup] = useState<string | null>(null)
  const navRef = useRef<HTMLElement>(null)
  const mode = resolvedMode(location.pathname)

  const currentGroup = groupOf(location.pathname)?.title ?? null
  // 简洁模式默认只呈现值班主线；高级能力收进专家模式（不删页面，命令面板仍可达）
  const groups = visibleNavGroups(expert, location.pathname)

  // 点击外部 / Esc 收起下拉
  useEffect(() => {
    if (!openGroup) return
    const onDown = (e: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(e.target as Node)) setOpenGroup(null)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpenGroup(null)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [openGroup])

  // 路由变化即收起
  useEffect(() => setOpenGroup(null), [location.pathname])

  const toggleTheme = () => {
    setThemePref(mode === 'dark' ? 'light' : 'dark')
    window.dispatchEvent(new CustomEvent('soc:theme-change'))
  }

  const groupActive = (title: string) =>
    openGroup === title || (openGroup === null && currentGroup === title)

  return (
    <header className="sticky top-0 z-50 border-b border-line bg-nav-veil backdrop-blur-sm">
      <nav
        ref={navRef}
        aria-label="全局导航"
        className="page-shell flex h-12 items-center gap-2"
      >
        <Logo />

        <span aria-hidden className="mx-2 hidden h-4 w-px bg-line sm:block" />

        {/* 四篇章页签 */}
        <div className="flex min-w-0 items-center gap-0.5" role="menubar">
          {groups.map((group) => {
            const active = groupActive(group.title)
            const expanded = openGroup === group.title
            const sourceGroup = NAV_GROUPS.find((g) => g.title === group.title) ?? group
            const hidden = hiddenAdvancedCountInGroup(sourceGroup, location.pathname)
            return (
              <div key={group.title} className="relative">
                <button
                  type="button"
                  role="menuitem"
                  aria-haspopup="menu"
                  aria-expanded={expanded}
                  onClick={() => setOpenGroup(expanded ? null : group.title)}
                  className={`flex h-12 items-center gap-1 px-3 text-[13px] transition-colors ${
                    active
                      ? 'font-medium text-ink after:absolute after:inset-x-2 after:bottom-0 after:h-0.5 after:rounded-full after:bg-accent'
                      : 'text-ink-soft hover:text-ink'
                  }`}
                >
                  {group.title}
                  <span
                    aria-hidden
                    className={`text-[9px] transition-transform ${expanded ? 'rotate-180' : ''}`}
                  >
                    ▾
                  </span>
                </button>

                {expanded && (
                  <div
                    role="menu"
                    className="absolute left-0 top-full z-50 mt-px w-64 rounded-[6px] border border-line bg-card py-1.5 shadow-[var(--shadow-2)]"
                  >
                    {group.items.map((item) => (
                      <NavLink
                        key={item.path}
                        to={item.path}
                        role="menuitem"
                        className={({ isActive }) =>
                          `block px-4 py-2 transition-colors ${
                            isActive
                              ? 'bg-inset text-accent'
                              : 'text-ink hover:bg-inset'
                          }`
                        }
                      >
                        <span className="block text-[13px] font-medium">{item.label}</span>
                        {item.hint && (
                          <span className="mt-0.5 block truncate text-[11px] leading-snug text-ink-faint">
                            {item.hint}
                          </span>
                        )}
                      </NavLink>
                    ))}
                    {group.items.length === 0 && (
                      <p className="px-4 py-2.5 text-[12px] text-ink-faint">
                        本篇章均为高级能力，已收起
                      </p>
                    )}
                    {hidden > 0 && (
                      <div className="mt-1 border-t border-line pt-1">
                        <button
                          type="button"
                          onClick={() => setExpert(true)}
                          className="flex w-full items-center justify-between px-4 py-2 text-left text-[12px] text-ink-soft transition-colors hover:bg-inset hover:text-ink"
                        >
                          <span>已隐藏 {hidden} 项高级能力</span>
                          <span className="text-[11px] text-accent">开启专家模式</span>
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>

        <span className="flex-1" />

        {/* 检索 */}
        <button
          type="button"
          onClick={() => window.dispatchEvent(new CustomEvent('soc:palette-open'))}
          title="全局检索（Ctrl K）"
          className="flex h-8 items-center gap-2 rounded-[4px] border border-line px-2.5 text-[12px] text-ink-faint transition-colors hover:border-ink-faint hover:text-ink"
        >
          <span aria-hidden>⌕</span>
          <span className="hidden md:inline">检索</span>
          <kbd className="hidden rounded border border-line px-1 font-mono text-[10px] md:inline">
            Ctrl K
          </kbd>
        </button>

        {/* 简洁 / 专家模式切换 */}
        <button
          type="button"
          onClick={() => setExpert(!expert)}
          title={expert ? '切回简洁导航（只保留值班主线）' : '显示高级能力（自博弈/知识库/评测/反钓鱼/全景）'}
          aria-pressed={expert}
          className={`flex h-8 items-center rounded-[4px] px-2 font-mono text-[11px] transition-colors ${
            expert
              ? 'bg-accent/10 text-accent hover:bg-accent/15'
              : 'text-ink-faint hover:bg-inset hover:text-ink'
          }`}
        >
          {expert ? '专家' : '简洁'}
        </button>

        {/* 主题切换 */}
        <button
          type="button"
          onClick={toggleTheme}
          title={mode === 'dark' ? '切换到亮色' : '切换到暗色'}
          className="flex h-8 w-8 items-center justify-center rounded-[4px] text-[14px] text-ink-soft transition-colors hover:bg-inset hover:text-ink"
        >
          {mode === 'dark' ? '☀' : '☾'}
        </button>

        {/* 用户 · 登出 —— 开放体验模式下不提供登出(Visitor 无凭证可换,
            点登出只会把用户困在登录页), 改为静态徽章明示模式 */}
        {token ? (
          <div className="flex items-center gap-1.5 pl-1">
            <span className="hidden font-mono text-[11px] text-ink-faint sm:inline">
              {username || 'admin'}
            </span>
            {openTour ? (
              <span
                title="开放体验模式：免登录、全员同等权力（治理策略照常生效）"
                className="flex h-8 items-center rounded-[4px] border border-line px-2 font-mono text-[11px] text-ink-faint"
              >
                开放体验
              </span>
            ) : (
              <button
                type="button"
                onClick={() => {
                  logout()
                  navigate('/login')
                }}
                title="登出"
                className="flex h-8 items-center rounded-[4px] px-2 text-[12px] text-ink-soft transition-colors hover:bg-inset hover:text-alert"
              >
                登出
              </button>
            )}
          </div>
        ) : (
          <NavLink
            to="/login"
            className="ml-1 flex h-8 items-center rounded-[4px] px-3 text-[12px] text-accent hover:bg-inset"
          >
            登录
          </NavLink>
        )}
      </nav>
    </header>
  )
}

