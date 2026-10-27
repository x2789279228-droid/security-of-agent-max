/**
 * 接缝封条 — 叠压手法:封条横骑在两个区块的接缝上(半压上节,半压下节)。
 * 叙事区专用;作业区(表格/监控面板)不使用。
 */
export function TapeSeam({ text = '案卷连续归档 · 值守不换班' }: { text?: string }) {
  return (
    <div aria-hidden className="pointer-events-none relative z-10 -my-3.5 flex justify-center">
      <span className="inline-block -rotate-[0.6deg] border border-dusk/35 bg-paper-warm/95 px-7 py-1.5 font-mono text-[10px] tracking-[0.32em] uppercase text-ink-faint shadow-[var(--shadow-1)]">
        {text}
      </span>
    </div>
  )
}
