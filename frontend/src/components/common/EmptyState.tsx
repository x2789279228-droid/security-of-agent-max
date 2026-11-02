import type { ReactNode } from 'react'

/**
 * EmptyState · 统一空态：极简线条小图 + 「为什么空」+ 下一步动作。
 * 图形 1.5px stroke / currentColor，亮暗肤自适应。
 */

export type EmptyArt = 'radar' | 'search' | 'folder' | 'inbox'

const ART: Record<EmptyArt, ReactNode> = {
  radar: (
    <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="24" cy="24" r="18" opacity="0.4" />
      <circle cx="24" cy="24" r="11" opacity="0.6" />
      <circle cx="24" cy="24" r="1.6" fill="currentColor" stroke="none" />
      <path d="M24 24 L38 14" />
      <path d="M24 6 v3 M24 39 v3 M6 24 h3 M39 24 h3" opacity="0.5" />
    </svg>
  ),
  search: (
    <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="21" cy="21" r="12" opacity="0.7" />
      <path d="M30 30 L40 40" />
      <path d="M16 21 a5 5 0 0 1 5-5" opacity="0.45" />
    </svg>
  ),
  folder: (
    <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 14 a3 3 0 0 1 3-3 h9 l4 4 h13 a3 3 0 0 1 3 3 v16 a3 3 0 0 1 -3 3 H11 a3 3 0 0 1 -3-3 z" opacity="0.7" />
      <path d="M8 22 h32" opacity="0.35" />
    </svg>
  ),
  inbox: (
    <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 26 v-12 a2 2 0 0 1 2-2 h24 a2 2 0 0 1 2 2 v12" opacity="0.7" />
      <path d="M10 26 h8 l3 5 h6 l3-5 h8 v8 a2 2 0 0 1 -2 2 H12 a2 2 0 0 1 -2-2 z" opacity="0.5" />
    </svg>
  ),
}

export function EmptyState({
  art = 'inbox',
  title,
  hint,
  action,
  className = '',
}: {
  art?: EmptyArt
  /** 为什么是空的，如「暂无事件」 */
  title: string
  /** 怎么会有数据 / 下一步去哪 */
  hint?: string
  action?: ReactNode
  className?: string
}) {
  return (
    <div className={`flex flex-col items-center justify-center gap-2 px-6 py-12 text-center ${className}`}>
      <span aria-hidden className="h-12 w-12 text-ink-faint">
        {ART[art]}
      </span>
      <p className="mt-1 text-[13px] font-medium text-ink-soft">{title}</p>
      {hint && <p className="max-w-[22rem] text-[12px] leading-relaxed text-ink-faint">{hint}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}
