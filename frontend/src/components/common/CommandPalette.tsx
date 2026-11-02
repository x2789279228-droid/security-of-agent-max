import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { NAV_GROUPS } from '../../layouts/nav'
import { ROUTES } from '../../lib/constants'

interface PaletteItem {
  path: string
  label: string
  group: string
  hint?: string
  keywords?: string
}

const QUICK_ACTIONS: PaletteItem[] = [
  { path: ROUTES.DEMO, label: '攻击剧本演示', group: '快捷', hint: '全屏六幕演示：注入 → 检测 → 接力 → 处置 → 结案', keywords: 'demo 演示 剧本 攻击' },
  { path: ROUTES.BENCHMARK, label: '评测战绩', group: '快捷', hint: 'CSIC-2010 回放 · 对抗保持率 · 分层消融', keywords: 'benchmark 评测 战绩 消融 csic' },
  { path: ROUTES.MONITOR, label: '审计大屏', group: '快捷', hint: 'Monitor 大屏模式（可再按 F 进入投影模式）', keywords: '大屏 battle screen 投影 monitor' },
]

const ALL_ITEMS: PaletteItem[] = [
  ...QUICK_ACTIONS,
  ...NAV_GROUPS.flatMap((g) =>
    g.items.map((i) => ({ path: i.path, label: i.label, group: `${g.title}台`, hint: i.hint, keywords: i.short })),
  ),
]

function normalize(s: string) {
  return s.toLowerCase().trim()
}

function matchScore(item: PaletteItem, q: string): number {
  if (!q) return 1
  const query = normalize(q)
  let score = 0
  if (normalize(item.label).includes(query)) score += 4
  if (normalize(item.group).includes(query)) score += 2
  if (item.keywords && normalize(item.keywords).includes(query)) score += 2
  if (normalize(item.hint || '').includes(query)) score += 1
  if (normalize(item.path).includes(query)) score += 1
  return score
}

/**
 * 全局命令面板（Ctrl/Cmd+K）。
 * 检索范围：快捷动作 + 四篇章全部页面。答辩现场快速跳页用。
 */
export function CommandPalette() {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const results = useMemo(() => {
    const scored = ALL_ITEMS.map((item) => ({ item, score: matchScore(item, query) }))
      .filter((r) => r.score > 0)
    scored.sort((a, b) => b.score - a.score)
    return scored.map((r) => r.item)
  }, [query])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((v) => !v)
        setQuery('')
        setActive(0)
      } else if (e.key === 'Escape') {
        setOpen(false)
      }
    }
    // TopNav「检索」按钮等外部触发入口
    const onOpen = () => {
      setOpen(true)
      setQuery('')
      setActive(0)
    }
    document.addEventListener('keydown', onKey)
    window.addEventListener('soc:palette-open', onOpen)
    return () => {
      document.removeEventListener('keydown', onKey)
      window.removeEventListener('soc:palette-open', onOpen)
    }
  }, [])

  useEffect(() => {
    if (open) {
      // 等动画首帧后聚焦，避免浏览器把按键吞进未受控输入
      const t = setTimeout(() => inputRef.current?.focus(), 30)
      return () => clearTimeout(t)
    }
  }, [open])

  useEffect(() => setActive(0), [query])

  useEffect(() => {
    const el = listRef.current?.querySelector('[data-active="true"]')
    el?.scrollIntoView({ block: 'nearest' })
  }, [active, results])

  const go = (path: string) => {
    setOpen(false)
    navigate(path)
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((i) => Math.min(i + 1, results.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((i) => Math.max(i - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const item = results[active]
      if (item) go(item.path)
    }
  }

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-[90] flex items-start justify-center bg-ink/30 pt-[12vh] backdrop-blur-[2px]"
          onMouseDown={() => setOpen(false)}
          role="dialog"
          aria-modal="true"
          aria-label="命令面板"
        >
          <motion.div
            initial={{ opacity: 0, y: -12, scale: 0.985 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.99 }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            className="w-[min(560px,92vw)] border border-line bg-paper shadow-[var(--shadow-3)]"
            onMouseDown={(e) => e.stopPropagation()}
          >
            {/* 输入行 */}
            <div className="border-b border-line px-5 py-3.5">
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={onKeyDown}
                placeholder="跳往…（页面 / 演示 / 评测）"
                className="w-full bg-transparent text-[17px] text-ink outline-none placeholder:text-ink-faint"
                aria-label="检索页面"
              />
            </div>

            {/* 结果列表 */}
            <div ref={listRef} className="max-h-[46vh] overflow-y-auto py-2" role="listbox">
              {results.length === 0 ? (
                <p className="px-5 py-8 text-center text-sm text-ink-faint">没有匹配的页面</p>
              ) : (
                results.map((item, i) => {
                  const activeRow = i === active
                  return (
                    <button
                      key={item.path}
                      data-active={activeRow || undefined}
                      role="option"
                      aria-selected={activeRow}
                      onMouseEnter={() => setActive(i)}
                      onClick={() => go(item.path)}
                      className={`flex w-full items-baseline gap-3 px-5 py-2.5 text-left transition-colors ${
                        activeRow ? 'bg-mist' : ''
                      }`}
                    >
                      <span className="w-14 shrink-0 font-mono text-[10px] tracking-[0.06em] text-ink-faint">
                        {item.group}
                      </span>
                      <span className={`text-[14px] ${activeRow ? 'text-ink' : 'text-ink-soft'}`}>
                        {item.label}
                      </span>
                      {item.hint && (
                        <span className="ml-auto hidden truncate pl-4 font-mono text-[11px] text-ink-faint sm:block">
                          {item.hint}
                        </span>
                      )}
                    </button>
                  )
                })
              )}
            </div>

            {/* 键位提示 */}
            <div className="flex items-center gap-4 border-t border-line px-5 py-2 font-mono text-[10px] tracking-[0.06em] text-ink-faint">
              <span>↑↓ 选择</span>
              <span>↵ 跳转</span>
              <span>esc 关闭</span>
              <span className="ml-auto">守望 · 全局检索</span>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
