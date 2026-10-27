import { Sparkline } from '../charts/Sparkline'
import { LiveBadge } from './LiveBadge'
import { Tally } from './Tally'

export type KpiTone = 'neutral' | 'ok' | 'warn' | 'alert' | 'hero' | 'accent' | 'signal'

const TONE: Record<KpiTone, { value: string }> = {
  neutral: { value: 'text-ink' },
  ok: { value: 'text-ok' },
  warn: { value: 'text-warn' },
  alert: { value: 'text-alert' },
  hero: { value: 'text-ink' },
  accent: { value: 'text-accent' },
  signal: { value: 'text-signal' },
}

export function KpiStat({
  label,
  value,
  hint,
  tone = 'neutral',
  delta,
  spark,
  live,
  size = 'md',
  className = '',
}: {
  label: string
  value: string | number
  hint?: string
  tone?: KpiTone
  delta?: number
  spark?: number[]
  live?: boolean
  /** lg:作战大屏距离字号;wall:大屏英雄数字(红色裂口时整屏第一主体) */
  size?: 'sm' | 'md' | 'lg' | 'wall'
  className?: string
}) {
  const t = TONE[tone]
  const hero = tone === 'hero'
  const labelSize = size === 'lg' || size === 'wall' ? 'text-[13px]' : 'text-[10px]'
  const valueSize = hero
    ? 'text-[52px] leading-[0.95] md:text-[64px]'
    : size === 'wall'
      ? 'text-[92px] leading-[0.88] md:text-[112px]'
      : size === 'lg'
        ? 'text-[44px] leading-none md:text-[52px]'
        : size === 'sm'
          ? 'text-[22px] leading-none md:text-[26px]'
          : 'text-[32px] leading-none md:text-[36px]'
  const deltaUp = typeof delta === 'number' && delta > 0
  const deltaDown = typeof delta === 'number' && delta < 0

  return (
    <div className={`relative min-w-0 ${hero ? 'pl-5 py-1' : ''} ${className}`}>
      {hero && (
        <span className="absolute left-0 top-1 bottom-1 w-px bg-[#0e1a26]" aria-hidden />
      )}
      <div className="flex items-center justify-between gap-3">
        <p className={`font-mono tracking-[0.22em] uppercase text-ink-faint ${labelSize}`}>
          {label}
        </p>
        {live ? <LiveBadge live /> : null}
      </div>
      <p className={`mt-2 font-serif font-black tabular-nums tracking-[-0.04em] ${t.value} ${valueSize}`}>
        {typeof value === 'number' ? <Tally value={value} /> : value}
      </p>
      <div className="mt-2 flex items-end justify-between gap-3">
        <div className="min-w-0">
          {typeof delta === 'number' && (
            <p
              className={`font-mono text-[11px] tabular-nums ${
                deltaUp ? 'text-alert' : deltaDown ? 'text-ok' : 'text-ink-faint'
              }`}
            >
              {deltaUp ? '▲' : deltaDown ? '▼' : '–'} {Math.abs(delta).toFixed(1)}%
            </p>
          )}
          {hint && <p className="truncate text-[12px] text-ink-faint">{hint}</p>}
        </div>
        {spark && spark.length > 1 && <Sparkline data={spark} tone={tone} />}
      </div>
    </div>
  )
}
