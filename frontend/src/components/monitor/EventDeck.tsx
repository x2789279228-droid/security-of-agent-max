/**
 * EventDeck · 最近事件（v7 重构）
 *
 * 旧版是 3D 透视堆叠（tier 下沉 + 视差倾斜），实测观感是"卡片斜着叠、
 * 文字被裁切"，像渲染故障而非仪表。这里改回仪表本分：最近 8 条事件的
 * 紧凑列表——severity 竖线 + 类型徽标 + 摘要 + 时间，新行一次性脉冲落位，
 * 点击行选中事件、打开思维链。信任 token 双肤，不做任何肤内特判。
 */
import { useMemo } from 'react'
import { motion } from 'framer-motion'
import {
  SEVERITY_META,
  metaOf,
  severityOf,
  useEventStreamStore,
  type StreamEvent,
} from '../../lib/eventStream'

const DECK_TYPES = new Set([
  'security_event',
  'alert',
  'tool_anomaly',
  'response_action',
  'pipeline_health',
])
const DECK_MAX = 8

function briefOf(evt: StreamEvent): string {
  const d = evt.data ?? {}
  const head = d.event_type ?? d.alert_type ?? d.threat_type ?? d.tool_name ?? d.stage ?? evt.type
  const src = d.src_ip ? ` · ${d.src_ip}` : ''
  const extra = d.message ? ` · ${String(d.message).slice(0, 40)}` : ''
  return `${String(head).slice(0, 30)}${src}${extra}`
}

export default function EventDeck({
  onSelectEvent,
}: {
  onSelectEvent?: (eventId: number) => void
}) {
  const buffer = useEventStreamStore((s) => s.buffer)

  const { cards, total } = useMemo(() => {
    const all = buffer.filter((e) => e.kind === 'event' && DECK_TYPES.has(e.type))
    return { cards: all.slice(0, DECK_MAX), total: all.length }
  }, [buffer])

  return (
    <div className="flex h-full min-h-[352px] flex-col border border-line bg-paper">
      <div className="flex items-center justify-between border-b border-line px-4 pb-2 pt-3">
        <p className="meta-caps flex items-center gap-2">
          <span className="live-arc" aria-hidden />
          最近事件
        </p>
        <span className="font-mono text-[10px] tabular-nums text-ink-faint">
          前 {Math.min(DECK_MAX, total)} / {total}
        </span>
      </div>

      <div className="flex min-h-0 flex-1 flex-col">
        {cards.length === 0 ? (
          <p className="m-auto text-center text-[12px] text-ink-faint">
            等待事件流入……
            <br />
            （注入一条事件，或跑一条演示）
          </p>
        ) : (
          <ul className="flex-1 divide-y divide-line-soft overflow-hidden">
            {cards.map((evt) => {
              const sevKey = severityOf(evt.type, evt.data)
              const sev = SEVERITY_META[sevKey]
              const meta = metaOf(evt.type)
              const eid = Number(evt.data?.event_id) || 0
              const timeStr = new Date(evt.ts).toLocaleTimeString('zh-CN', { hour12: false })
              return (
                <li key={evt.id}>
                  <motion.button
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
                    onClick={eid ? () => onSelectEvent?.(eid) : undefined}
                    title={eid ? `点击查看 #${eid} 思维链` : undefined}
                    className="flex w-full items-stretch text-left transition-colors hover:bg-mist/60"
                  >
                    <span className={`${sev.bar} w-[3px] shrink-0 self-stretch`} aria-hidden />
                    <span className="flex min-w-0 flex-1 flex-col justify-center gap-1 px-3 py-2">
                      <span className="flex items-center justify-between gap-2">
                        <span
                          className={`rounded-full px-2 py-px text-[10px] font-semibold ${
                            meta?.badge ?? 'border border-dashed border-dan text-hui'
                          }`}
                        >
                          {meta?.label ?? evt.type}
                        </span>
                        <span className="font-mono text-[10px] tabular-nums text-ink-faint">
                          {timeStr}
                          {evt.replay ? ' · 回放' : ''}
                        </span>
                      </span>
                      <span className="truncate text-[12px] text-ink-soft">{briefOf(evt)}</span>
                    </span>
                  </motion.button>
                </li>
              )
            })}
          </ul>
        )}
      </div>

      <div className="flex items-center justify-between border-t border-line px-4 py-2">
        <span className="font-mono text-[10px] tracking-[0.06em] text-ink-faint">
          {total > DECK_MAX ? `+${total - DECK_MAX} 条更早` : '全部在列'}
        </span>
        <span className="font-mono text-[10px] tracking-[0.06em] text-ink-faint">
          点击行查看思维链
        </span>
      </div>
    </div>
  )
}
