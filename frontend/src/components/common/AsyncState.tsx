import type { ReactNode } from 'react'
import { EmptyState, type EmptyArt } from './EmptyState'

/**
 * AsyncState · 统一异步三态（Loading / Empty / Error）
 *
 * 背景：此前各页各写一套——有的 `py-20 text-sm`、有的 emoji「⏳ 加载中…」、
 * 有的把 401 和"暂无数据"混在一起。这里收敛成同一套视觉与语义：
 *   - Loading：骨架条 + 可读标签，role=status；
 *   - Empty：统一 SVG 线条小图 + 为什么空 + 下一步；
 *   - Error：明确"加载失败"而不是"暂无数据"，带重试。
 *
 * 用法一（组合式）：<AsyncState loading={...} error={...} empty={...} emptyTitle="暂无案例">…</AsyncState>
 * 用法二（单独）：<LoadingState /> / <ErrorState message={e} onRetry={reload} />
 */

export function LoadingState({
  rows = 3,
  label = '加载中…',
  className = '',
}: {
  rows?: number
  label?: string
  className?: string
}) {
  return (
    <div role="status" aria-live="polite" className={`px-6 py-10 ${className}`}>
      <div className="mx-auto w-full max-w-[44rem]">
        <div className="mb-4 flex items-center gap-2 text-[12px] text-ink-faint">
          <span aria-hidden className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
          {label}
        </div>
        <div className="space-y-2.5">
          {Array.from({ length: rows }).map((_, i) => (
            <div key={i} className="skeleton h-4" style={{ width: `${88 - i * 9}%` }} />
          ))}
        </div>
      </div>
    </div>
  )
}

export function ErrorState({
  title = '加载失败',
  message,
  hint = '后端服务可能不可达；可稍后重试，或先检查服务状态与网络。',
  onRetry,
  className = '',
}: {
  title?: string
  message?: string
  hint?: string
  onRetry?: () => void
  className?: string
}) {
  const rawMessage = message?.trim() ?? ''
  // 网络层英文报错统一成中文，避免「加载失败 / Failed to fetch」两层信息打架
  const displayMessage = /failed to fetch|networkerror|load failed|network error/i.test(rawMessage)
    ? '无法连接后端服务（网络请求失败）'
    : rawMessage
  return (
    <div role="alert" className={`flex flex-col items-center justify-center gap-2 px-6 py-12 text-center ${className}`}>
      <span
        aria-hidden
        className="flex h-12 w-12 items-center justify-center rounded-full border border-alert/40 bg-alert/10 font-mono text-[20px] font-semibold text-alert"
      >
        !
      </span>
      <p className="mt-1 text-[13px] font-medium text-ink-soft">{title}</p>
      {displayMessage && (
        <p className="max-w-[26rem] break-all text-[12px] leading-relaxed text-ink-faint">{displayMessage}</p>
      )}
      <p className="max-w-[26rem] text-[12px] leading-relaxed text-ink-faint">{hint}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-2 rounded-[4px] border border-line px-3 py-1.5 text-[12px] text-ink-soft transition-colors hover:border-accent/60 hover:text-accent"
        >
          重试
        </button>
      )}
    </div>
  )
}

export function AsyncState({
  loading,
  error,
  empty,
  emptyTitle = '暂无数据',
  emptyHint,
  emptyArt = 'inbox',
  emptyAction,
  loadingRows = 3,
  onRetry,
  children,
  className = '',
}: {
  loading?: boolean
  error?: string | null
  empty?: boolean
  emptyTitle?: string
  emptyHint?: string
  emptyArt?: EmptyArt
  emptyAction?: ReactNode
  loadingRows?: number
  onRetry?: () => void
  children: ReactNode
  className?: string
}) {
  if (loading) return <LoadingState rows={loadingRows} className={className} />
  if (error) return <ErrorState message={error} onRetry={onRetry} className={className} />
  if (empty) {
    return (
      <EmptyState
        art={emptyArt}
        title={emptyTitle}
        hint={emptyHint}
        action={emptyAction}
        className={className}
      />
    )
  }
  return <>{children}</>
}
