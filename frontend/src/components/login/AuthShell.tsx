import type { ReactNode } from 'react'
import { Logo } from '../brand/Logo'

/**
 * AuthShell · 登录/注册共用外壳
 * 居中单卡 + CSS 材质背景（暗肤：极淡网格 + 顶部冷光；亮肤：纯色）。
 */
export function AuthShell({
  title,
  subtitle,
  children,
}: {
  title: string
  subtitle: string
  children: ReactNode
}) {
  return (
    <div className="auth-material relative flex min-h-screen flex-col items-center justify-center bg-surface px-4 py-10 text-ink">
      <div className="w-full max-w-[400px]">
        <div className="mb-5 flex justify-center">
          <Logo />
        </div>

        <div className="rounded-[8px] border border-line bg-card p-7 shadow-[var(--shadow-2)]">
          <h1 className="text-[18px] font-semibold text-ink">{title}</h1>
          <p className="mt-1 text-[12px] text-ink-faint">{subtitle}</p>
          <div className="mt-6">{children}</div>
        </div>

        <p className="mt-6 text-center text-[11px] text-ink-faint">
          守望 SOC · 自主安全运营平台 · v4 · 2026
        </p>
      </div>
    </div>
  )
}
