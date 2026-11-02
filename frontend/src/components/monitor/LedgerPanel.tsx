import { useMemo } from 'react'
import { useEventStreamStore } from '../../lib/eventStream'

/**
 * 零丢失账本 — 「入队 = 落库 + 幂等吸收」实时等式(SSE ledger 频道)。
 *
 * 数据源: backend/ledger_broadcast.py 每 3s 一帧, bulk 车道按 key 合并
 * 只留最新。等式口径与 docs/benchmark/PERF-2026-10-26.md 一致:
 *   入队 = 接收 − 拒绝 − 校验失败;  幂等吸收 = 入队 − 落库。
 * 落库来自 stats_counter Redis 绝对计数(低频对账), Redis 缺席时显示 —。
 */

type Frame = Record<string, number | null | undefined>

function fmt(v: number | null | undefined): string {
  return v === null || v === undefined ? '—' : Number(v).toLocaleString('en-US')
}

function Num({ label, v, tone }: { label: string; v: number | null | undefined; tone?: 'ok' | 'warn' }) {
  const color = tone === 'ok' ? 'text-ok' : tone === 'warn' ? 'text-warn' : ''
  return (
    <span className="flex flex-col items-start leading-none">
      <span className={`text-[17px] ${color}`}>{fmt(v)}</span>
      <span className="mt-0.5 text-[9px] tracking-[0.06em] text-ink-faint">{label}</span>
    </span>
  )
}

export default function LedgerPanel() {
  const buffer = useEventStreamStore((s) => s.buffer)

  const frame = useMemo<Frame | null>(() => {
    for (let i = buffer.length - 1; i >= 0; i--) {
      const e = buffer[i]
      if (e.kind === 'event' && e.type === 'ledger') return e.data as Frame
    }
    return null
  }, [buffer])

  // 窗口增量可用(第二帧起)时, 等式行用同口径的窗内数字 —— 恒闭合
  const win = frame?.win_enqueued !== undefined && frame?.win_inserted !== undefined

  return (
    <div className="font-mono tabular-nums">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[10px] tracking-[0.06em] text-ink-faint">零丢失账本 · live</span>
        <span className={`text-[10px] ${frame ? 'text-ok' : 'text-ink-faint'}`}>
          {frame ? `${fmt(frame.eps)} eps` : '等待首帧…'}
        </span>
      </div>

      <div className="mt-1.5 flex items-end gap-2 leading-none">
        <Num label={win ? `入队 · ${fmt(frame?.interval_s)}s窗` : '入队(进程内)'} v={win ? frame?.win_enqueued : frame?.enqueued} />
        <span className="pb-3 text-ink-faint">=</span>
        <Num label={win ? '落库 · 窗' : '落库(累计)'} v={win ? frame?.win_inserted : frame?.inserted} tone="ok" />
        <span className="pb-3 text-ink-faint">+</span>
        <Num label={win ? '幂等吸收 · 窗' : '幂等吸收'} v={win ? frame?.win_absorbed : frame?.absorbed} tone="warn" />
      </div>

      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-ink-faint">
        <span>接收 {fmt(frame?.received)}</span>
        <span>拒绝 {fmt(frame?.rejected)}</span>
        <span>校验失败 {fmt(frame?.validation_failed)}</span>
        <span>落库累计 {fmt(frame?.inserted)}</span>
        <span>lag {fmt(frame?.kafka_lag)}</span>
        <span>DLQ {fmt(frame?.dlq_depth)}</span>
      </div>
    </div>
  )
}
