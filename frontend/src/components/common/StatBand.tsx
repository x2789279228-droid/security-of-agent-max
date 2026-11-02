import { CountUp } from '../../motion/primitives'

/**
 * StatBand(P4) — 模块头部统计带:4 格本地聚合指标,感知/情报/沙箱等列表页的点缀皮肤。
 * 数值走 CountUp(高频变化用 from='previous' 由调用方指定),零后端依赖。
 */

export interface StatBandItem {
  label: string
  value: number | string
  hint?: string
  tone?: 'ink' | 'ok' | 'warn' | 'alert'
  /** 数值是小数时指定小数位(仅 number 生效) */
  decimals?: number
}

const TONE_CLS: Record<string, string> = {
  ink: 'text-ink',
  ok: 'text-ok',
  warn: 'text-warn',
  alert: 'text-alert',
}

export function StatBand({ items }: { items: StatBandItem[] }) {
  return (
    <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
      {items.map((it) => (
        <div key={it.label} className="border border-line bg-paper-warm px-4 py-2.5">
          <p className="font-mono text-[10px] tracking-[0.06em] text-ink-faint">{it.label}</p>
          <p className={`mt-1 text-[20px] font-semibold leading-none tabular-nums ${TONE_CLS[it.tone ?? 'ink']}`}>
            {typeof it.value === 'number' ? (
              <CountUp value={it.value} decimals={it.decimals ?? 0} from="previous" duration={500} />
            ) : (
              it.value
            )}
          </p>
          {it.hint && <p className="mt-1 text-[11px] leading-snug text-ink-faint">{it.hint}</p>}
        </div>
      ))}
    </div>
  )
}

/** 分布迷你条:label + 数量 + 占比条,用于协议/类型/verdict 等分类分布 */
export function DistBars({ rows, tone = 'bg-accent' }: { rows: [string, number][]; tone?: string }) {
  const max = Math.max(1, ...rows.map(([, v]) => v))
  return (
    <div className="space-y-1.5">
      {rows.map(([label, n], i) => (
        <div key={label} className="flex items-center gap-2.5">
          <span className="w-24 shrink-0 truncate text-[11px] text-ink-soft">{label}</span>
          <div className="h-1.5 flex-1 bg-mist">
            <div
              className={`h-full ${tone} transition-[width] duration-500`}
              style={{ width: `${Math.max(4, (n / max) * 100)}%`, transitionDelay: `${i * 40}ms` }}
            />
          </div>
          <span className="w-8 shrink-0 text-right font-mono text-[10px] tabular-nums text-ink-faint">{n}</span>
        </div>
      ))}
    </div>
  )
}
