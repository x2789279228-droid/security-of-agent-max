import { Link } from 'react-router-dom'
import { ROUTES } from '../../lib/constants'

/**
 * Logo · 全站唯一字标（TopNav / Login / Register 共用）。
 * 方标"守"用强调色底 + 白字，字重 600 —— 不再用印章红与衬线。
 */
export function LogoMark({ size = 22 }: { size?: number }) {
  return (
    <span
      aria-hidden
      className="inline-flex shrink-0 items-center justify-center rounded-[4px] bg-accent font-semibold leading-none text-on-accent"
      style={{ width: size, height: size, fontSize: size * 0.58 }}
    >
      守
    </span>
  )
}

export function Logo({ to = ROUTES.HOME }: { to?: string }) {
  return (
    <Link
      to={to}
      className="flex shrink-0 items-center gap-2"
      aria-label="守望 SOC · 回到首页"
    >
      <LogoMark />
      <span className="text-[14px] font-semibold tracking-[0.01em] text-ink">
        守望 <span className="text-ink-faint">SOC</span>
      </span>
    </Link>
  )
}
