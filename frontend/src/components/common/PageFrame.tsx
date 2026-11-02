import type { ReactNode } from 'react'
import { PageTransition } from './PageTransition'

/**
 * PageFrame · 标准页面框架
 *
 * 每个页面统一头部：左 = 标题 / hint；右 = extra 操作区；下 = 正文。
 * 无章节水印、无边注、无衬线 —— 工作界面只保留有信息量的元素。
 */
export function PageFrame({
  title,
  subtitle,
  hint,
  extra,
  children,
}: {
  /** 页面标题，如「日志中心」 */
  title: string
  /** 副标题（保留兼容，建议优先用 hint） */
  subtitle?: string
  /** 一句话说明（用 — 顿句） */
  hint?: string
  /** 右侧操作区 */
  extra?: ReactNode
  children: ReactNode
}) {
  return (
    <PageTransition>
      <div className="page-shell pt-6 pb-12">
        <header className="flex flex-col gap-1.5 border-b border-line pb-3 md:flex-row md:items-end md:justify-between md:gap-8">
          <div className="min-w-0">
            <h1 className="text-[20px] font-semibold leading-tight text-ink">{title}</h1>
            {(hint ?? subtitle) && (
              <p className="mt-1 text-[13px] leading-snug text-ink-soft">{hint ?? subtitle}</p>
            )}
          </div>
          {extra && <div className="flex flex-wrap items-center gap-3 shrink-0">{extra}</div>}
        </header>

        <div className="pt-4">{children}</div>
      </div>
    </PageTransition>
  )
}

/** 下划线 tab（活跃 = 强调色底线；非活跃 = 灰字悬停变墨） */
export const tabOn =
  'relative pb-2 px-1 text-[13px] text-ink font-medium after:absolute after:left-1 after:right-1 after:bottom-0 after:h-0.5 after:rounded-full after:bg-accent'
export const tabOff =
  'relative pb-2 px-1 text-[13px] text-ink-soft hover:text-ink transition-colors'
