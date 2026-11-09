import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Logo } from '../brand/Logo'
import { ROUTES } from '../../lib/constants'

/**
 * AuthShell · 登录/注册共用外壳（v9 门面打磨）
 *
 * 左侧讲清"这是什么产品、凭什么可信"，右侧保留登录卡。
 * 小屏（<lg）自动退化为原来的居中单卡，不影响功能与测试。
 */

const HIGHLIGHTS = [
  { title: '可信研判', desc: '多 Agent 分工 + CAD 独立监督，结论可回查' },
  { title: '受控处置', desc: '高危动作走审批，动作可回滚、可追溯' },
  { title: '持续演进', desc: '误报反馈与红蓝演练，把经验沉淀成规则' },
]

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
      <div className="grid w-full max-w-[980px] gap-10 lg:grid-cols-[1.05fr_400px] lg:items-center">
        {/* 左侧：品牌与价值（桌面端展示） */}
        <div className="hidden lg:block">
          <div className="flex items-center gap-3">
            <Logo />
            <span className="font-mono text-[11px] tracking-[0.28em] uppercase text-ink-faint">
              自主安全运营平台
            </span>
          </div>

          <h1 className="mt-9 font-serif text-[40px] font-semibold leading-[1.14] tracking-[-0.02em] text-ink">
            让 AI 敢进生产
            <br />
            的安全运营闭环
          </h1>
          <p className="mt-4 max-w-[34rem] text-[14px] leading-relaxed text-ink-soft">
            从告警接入、检测研判，到受控处置与复盘，每一步都留下证据、刹车与回滚路径 ——
            不止会"说"，还敢"做"，也管得住"做错"。
          </p>

          <ul className="mt-8 grid max-w-[34rem] gap-2.5">
            {HIGHLIGHTS.map((h) => (
              <li key={h.title} className="flex items-baseline gap-3 border-l border-accent/40 pl-3">
                <span className="shrink-0 text-[13px] font-medium text-ink">{h.title}</span>
                <span className="text-[12px] text-ink-faint">{h.desc}</span>
              </li>
            ))}
          </ul>

          <div className="mt-9 flex flex-wrap items-center gap-3">
            <Link
              to={ROUTES.SCREEN}
              className="rounded-[4px] border border-line px-3.5 py-2 text-[12px] text-ink-soft transition-colors hover:border-accent/60 hover:text-accent"
            >
              查看作战大屏（免登录） →
            </Link>
            <Link
              to={ROUTES.POSTER}
              className="rounded-[4px] border border-line px-3.5 py-2 text-[12px] text-ink-soft transition-colors hover:border-accent/60 hover:text-accent"
            >
              系统全景
            </Link>
          </div>
        </div>

        {/* 右侧：登录卡 */}
        <div className="w-full max-w-[400px] justify-self-center lg:justify-self-end">
          <div className="mb-5 flex justify-center lg:hidden">
            <Logo />
          </div>

          <div className="rounded-[8px] border border-line bg-card p-7 shadow-[var(--shadow-2)]">
            <h2 className="text-[18px] font-semibold text-ink">{title}</h2>
            <p className="mt-1 text-[12px] text-ink-faint">{subtitle}</p>
            <div className="mt-6">{children}</div>
          </div>

          <p className="mt-6 text-center text-[11px] text-ink-faint">
            守望 SOC · 自主安全运营平台 · v4 · 2026
          </p>
        </div>
      </div>
    </div>
  )
}
