import { useEffect, useRef } from 'react'

export interface ConfirmRequest {
  title: string
  /** 复述影响面 —— 确认弹窗最重要的部分，别只写"确定吗" */
  body: React.ReactNode
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
}

interface Props {
  request: ConfirmRequest | null
  onConfirm: () => void
  onCancel: () => void
  busy?: boolean
}

/**
 * 确认弹窗原语（2026-10-03 新增）
 *
 * 为什么需要：修复前全仓 `confirm(` 只有 1 处命中（AssetsTab 下线资产，用原生
 * window.confirm）。响应引擎的 `executeResponse` / `simulateThreat` 是
 * **单击即对生产生效**的按钮 —— 而后端 /api/response/simulate 允许 operator
 * 注入任意 src_ip / severity 触发真实响应（审计 P0-3）。前后端两侧都不设卡。
 *
 * 原生 confirm() 主线程阻塞、无法样式化、无法复述影响面，故不复用。
 * 本组件同时补上焦点管理与 Esc 关闭（原浮层均缺失）。
 */
export function ConfirmDialog({ request, onConfirm, onCancel, busy }: Props) {
  const confirmRef = useRef<HTMLButtonElement>(null)
  const cancelRef = useRef<HTMLButtonElement>(null)

  // 打开时把焦点落在【取消】上 —— 破坏性操作的安全默认值
  useEffect(() => {
    if (request) cancelRef.current?.focus()
  }, [request])

  useEffect(() => {
    if (!request) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onCancel()
        return
      }
      if (e.key === 'Tab') {
        // 焦点陷阱：Tab 在 确认/取消 之间循环，不逃逸到背景
        const nodes = [cancelRef.current, confirmRef.current].filter(Boolean) as HTMLElement[]
        if (nodes.length === 0) return
        const idx = nodes.indexOf(document.activeElement as HTMLElement)
        e.preventDefault()
        const next = e.shiftKey ? idx - 1 : idx + 1
        nodes[(next + nodes.length) % nodes.length].focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [request, onCancel])

  if (!request) return null
  const danger = request.danger ?? false

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/40 p-4"
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel()
      }}
    >
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby="confirm-body"
        className={`w-full max-w-lg border bg-paper shadow-2xl ${danger ? 'border-alert' : 'border-line'}`}
      >
        <div className={`h-[3px] w-full ${danger ? 'bg-alert' : 'bg-ink-faint'}`} aria-hidden />
        <div className="px-6 py-5">
          <h2
            id="confirm-title"
            className={`text-[20px] font-bold tracking-tight ${danger ? 'text-alert' : 'text-ink'}`}
          >
            {request.title}
          </h2>
          <div id="confirm-body" className="mt-3 text-sm leading-relaxed text-ink-soft">
            {request.body}
          </div>
        </div>
        <div className="flex items-center justify-end gap-3 border-t border-line px-6 py-4">
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="border border-line px-4 py-2 font-mono text-[12px] uppercase tracking-[0.16em] text-ink-soft hover:border-ink-faint disabled:opacity-50"
          >
            {request.cancelLabel ?? '取消'}
          </button>
          <button
            ref={confirmRef}
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className={`px-4 py-2 font-mono text-[12px] uppercase tracking-[0.16em] disabled:opacity-50 ${
              danger
                ? 'bg-alert text-paper hover:opacity-90'
                : 'bg-ink text-paper hover:opacity-90'
            }`}
          >
            {request.confirmLabel ?? '确认'}
          </button>
        </div>
      </div>
    </div>
  )
}
